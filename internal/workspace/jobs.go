package workspace

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

// ScanJob is the durable state of one asynchronous collector run.
type ScanJob struct {
	ID          string      `json:"id"`
	Provider    string      `json:"provider"`
	Scope       model.Scope `json:"scope"`
	Status      string      `json:"status"`
	Phase       string      `json:"phase"`
	Error       string      `json:"error,omitempty"`
	SnapshotID  string      `json:"snapshotId,omitempty"`
	Revision    int         `json:"revision"`
	CreatedAt   time.Time   `json:"createdAt"`
	StartedAt   *time.Time  `json:"startedAt,omitempty"`
	UpdatedAt   time.Time   `json:"updatedAt"`
	CompletedAt *time.Time  `json:"completedAt,omitempty"`
}

// ScanJobEvent is an append-only progress event suitable for SSE replay.
type ScanJobEvent struct {
	Sequence  int64     `json:"sequence"`
	JobID     string    `json:"jobId"`
	Status    string    `json:"status"`
	Phase     string    `json:"phase"`
	Message   string    `json:"message,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// CreateScanJob creates a queued Azure scan without persisting credentials.
func (s *Store) CreateScanJob(ctx context.Context, scope model.Scope) (ScanJob, error) {
	id, err := newOpaqueID("scan")
	if err != nil {
		return ScanJob{}, err
	}
	now := time.Now().UTC()
	timestamp := now.Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ScanJob{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO scan_jobs(id, provider, subscription_id, resource_group, status, phase, created_at, updated_at)
        VALUES(?, 'azure', ?, ?, 'queued', 'authentication', ?, ?)`, id, scope.SubscriptionID, scope.ResourceGroup, timestamp, timestamp)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO scan_job_events(job_id,status,phase,message,created_at) VALUES(?,'queued','authentication','scan queued',?)`, id, timestamp)
	}
	if err != nil {
		return ScanJob{}, fmt.Errorf("create scan job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ScanJob{}, fmt.Errorf("commit scan job: %w", err)
	}
	return s.ScanJob(ctx, id)
}

// UpdateScanJob records a phase/status transition and appends a replayable event.
func (s *Store) UpdateScanJob(ctx context.Context, id, status, phase, message, snapshotID string) (ScanJob, error) {
	if !validJobStatus(status) {
		return ScanJob{}, fmt.Errorf("invalid scan job status %q", status)
	}
	now := time.Now().UTC()
	timestamp := now.Format(time.RFC3339Nano)
	terminal := status == "completed" || status == "failed" || status == "cancelled" || status == "interrupted"
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ScanJob{}, err
	}
	defer tx.Rollback()
	var result sql.Result
	if terminal {
		result, err = tx.ExecContext(ctx, `UPDATE scan_jobs SET status=?, phase=?, error=?, snapshot_id=?, updated_at=?, completed_at=?, revision=revision+1,
            started_at=COALESCE(started_at, ?) WHERE id=?`, status, phase, terminalError(status, message), snapshotID, timestamp, timestamp, timestamp, id)
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE scan_jobs SET status=?, phase=?, error='', snapshot_id=?, updated_at=?, revision=revision+1,
            started_at=COALESCE(started_at, ?) WHERE id=?`, status, phase, snapshotID, timestamp, timestamp, id)
	}
	if err != nil {
		return ScanJob{}, fmt.Errorf("update scan job: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ScanJob{}, fmt.Errorf("scan job %q not found", id)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO scan_job_events(job_id,status,phase,message,created_at) VALUES(?,?,?,?,?)`, id, status, phase, message, timestamp)
	if err != nil {
		return ScanJob{}, fmt.Errorf("append scan event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ScanJob{}, fmt.Errorf("commit scan job update: %w", err)
	}
	return s.ScanJob(ctx, id)
}

// ScanJob returns one durable job.
func (s *Store) ScanJob(ctx context.Context, id string) (ScanJob, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,provider,subscription_id,resource_group,status,phase,error,snapshot_id,revision,created_at,started_at,updated_at,completed_at FROM scan_jobs WHERE id=?`, id)
	var job ScanJob
	var created, updated string
	var started, completed sql.NullString
	err := row.Scan(&job.ID, &job.Provider, &job.Scope.SubscriptionID, &job.Scope.ResourceGroup, &job.Status, &job.Phase, &job.Error, &job.SnapshotID, &job.Revision, &created, &started, &updated, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanJob{}, fmt.Errorf("scan job %q not found", id)
	}
	if err != nil {
		return ScanJob{}, fmt.Errorf("read scan job: %w", err)
	}
	job.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return ScanJob{}, err
	}
	job.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return ScanJob{}, err
	}
	if started.Valid {
		value, parseErr := time.Parse(time.RFC3339Nano, started.String)
		if parseErr != nil {
			return ScanJob{}, parseErr
		}
		job.StartedAt = &value
	}
	if completed.Valid {
		value, parseErr := time.Parse(time.RFC3339Nano, completed.String)
		if parseErr != nil {
			return ScanJob{}, parseErr
		}
		job.CompletedAt = &value
	}
	return job, nil
}

// ScanJobEvents returns ordered events after sequence.
func (s *Store) ScanJobEvents(ctx context.Context, id string, after int64) ([]ScanJobEvent, error) {
	if _, err := s.ScanJob(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sequence,job_id,status,phase,message,created_at FROM scan_job_events WHERE job_id=? AND sequence>? ORDER BY sequence`, id, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []ScanJobEvent
	for rows.Next() {
		var event ScanJobEvent
		var created string
		if err := rows.Scan(&event.Sequence, &event.JobID, &event.Status, &event.Phase, &event.Message, &created); err != nil {
			return nil, err
		}
		event.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// InterruptRunningJobs marks jobs left active by a prior local API process.
// Call it when starting the workspace server, not for read-only CLI opens.
func (s *Store) InterruptRunningJobs(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM scan_jobs WHERE status IN ('queued','running')`)
	if err != nil {
		return fmt.Errorf("find interrupted scans: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := s.UpdateScanJob(ctx, id, "interrupted", "interrupted", "application restarted before scan completed", ""); err != nil {
			return err
		}
	}
	return nil
}

func validJobStatus(value string) bool {
	switch value {
	case "queued", "running", "completed", "failed", "cancelled", "interrupted":
		return true
	default:
		return false
	}
}
func terminalError(status, message string) string {
	if status == "completed" {
		return ""
	}
	return message
}

// IsTerminalJob reports whether a job can no longer make progress.
func IsTerminalJob(status string) bool {
	return status == "completed" || status == "failed" || status == "cancelled" || status == "interrupted"
}

// AzureEnvironmentID is stable for a subscription or resource-group scan scope.
func AzureEnvironmentID(scope model.Scope) string {
	base := "azure-" + strings.ToLower(strings.ReplaceAll(scope.SubscriptionID, "-", ""))
	if strings.TrimSpace(scope.ResourceGroup) != "" {
		digest := sha256.Sum256([]byte(strings.ToLower(scope.ResourceGroup)))
		base += "-rg-" + hex.EncodeToString(digest[:6])
	}
	return base
}
