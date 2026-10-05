package workspace

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

// TriageStatus is the persistent review state of a finding in one environment.
type TriageStatus string

const (
	TriageOpen         TriageStatus = "open"
	TriageAcknowledged TriageStatus = "acknowledged"
	TriageAcceptedRisk TriageStatus = "accepted-risk"
	TriageResolved     TriageStatus = "resolved"
)

// TriageRecord is carried forward when a stable finding recurs in later snapshots.
type TriageRecord struct {
	SnapshotID          string       `json:"snapshotId"`
	EnvironmentID       string       `json:"environmentId"`
	FindingID           string       `json:"findingId"`
	Fingerprint         string       `json:"fingerprint"`
	Status              TriageStatus `json:"status"`
	Notes               string       `json:"notes"`
	FirstSeenSnapshotID string       `json:"firstSeenSnapshotId"`
	LastSeenSnapshotID  string       `json:"lastSeenSnapshotId"`
	UpdatedAt           time.Time    `json:"updatedAt"`
}

// FindingFingerprint returns an identifier stable across scans and finding-ID changes.
func FindingFingerprint(finding model.Finding) string {
	resources := append([]string(nil), finding.ResourceIDs...)
	relationships := append([]string(nil), finding.RelationshipIDs...)
	sort.Strings(resources)
	sort.Strings(relationships)
	value := strings.Join([]string{finding.RuleID, strings.Join(resources, "\x1f"), strings.Join(relationships, "\x1f")}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return "finding-" + hex.EncodeToString(digest[:16])
}

func upsertSnapshotTriage(ctx context.Context, tx *sql.Tx, environmentID, snapshotID string, findings []model.Finding, now time.Time) error {
	for _, finding := range findings {
		_, err := tx.ExecContext(ctx, `INSERT INTO finding_triage(
            environment_id, fingerprint, status, notes, finding_id,
            first_seen_snapshot_id, last_seen_snapshot_id, updated_at)
            VALUES(?,?,'open','',?,?,?,?)
            ON CONFLICT(environment_id, fingerprint) DO UPDATE SET
			  first_seen_snapshot_id=CASE
			    WHEN (SELECT generated_at FROM snapshots WHERE id=excluded.first_seen_snapshot_id) <
			         (SELECT generated_at FROM snapshots WHERE id=finding_triage.first_seen_snapshot_id)
			    THEN excluded.first_seen_snapshot_id ELSE finding_triage.first_seen_snapshot_id END,
			  finding_id=CASE
			    WHEN (SELECT generated_at FROM snapshots WHERE id=excluded.last_seen_snapshot_id) >=
			         (SELECT generated_at FROM snapshots WHERE id=finding_triage.last_seen_snapshot_id)
			    THEN excluded.finding_id ELSE finding_triage.finding_id END,
			  last_seen_snapshot_id=CASE
			    WHEN (SELECT generated_at FROM snapshots WHERE id=excluded.last_seen_snapshot_id) >=
			         (SELECT generated_at FROM snapshots WHERE id=finding_triage.last_seen_snapshot_id)
			    THEN excluded.last_seen_snapshot_id ELSE finding_triage.last_seen_snapshot_id END`,
			environmentID, FindingFingerprint(finding), finding.ID, snapshotID, snapshotID, now.Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("catalog finding triage: %w", err)
		}
	}
	return nil
}

// Triage returns the triage state for every finding in a snapshot.
func (s *Store) Triage(ctx context.Context, snapshotID string) ([]TriageRecord, error) {
	snapshot, err := s.Load(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	metadata, err := s.Metadata(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT fingerprint, status, notes, finding_id,
        first_seen_snapshot_id, last_seen_snapshot_id, updated_at
        FROM finding_triage WHERE environment_id=?`, metadata.EnvironmentID)
	if err != nil {
		return nil, fmt.Errorf("list finding triage: %w", err)
	}
	defer rows.Close()
	byFingerprint := make(map[string]TriageRecord)
	for rows.Next() {
		var record TriageRecord
		var updated string
		if err := rows.Scan(&record.Fingerprint, &record.Status, &record.Notes, &record.FindingID, &record.FirstSeenSnapshotID, &record.LastSeenSnapshotID, &updated); err != nil {
			return nil, fmt.Errorf("scan finding triage: %w", err)
		}
		record.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
		if err != nil {
			return nil, fmt.Errorf("parse triage time: %w", err)
		}
		byFingerprint[record.Fingerprint] = record
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list finding triage: %w", err)
	}
	result := make([]TriageRecord, 0, len(snapshot.Findings))
	for _, finding := range snapshot.Findings {
		fingerprint := FindingFingerprint(finding)
		record, ok := byFingerprint[fingerprint]
		if !ok {
			record = TriageRecord{Fingerprint: fingerprint, Status: TriageOpen, FindingID: finding.ID, FirstSeenSnapshotID: snapshotID, LastSeenSnapshotID: snapshotID}
		}
		record.SnapshotID = snapshotID
		record.EnvironmentID = metadata.EnvironmentID
		record.FindingID = finding.ID
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].FindingID < result[j].FindingID })
	return result, nil
}

// UpdateTriage changes the carried-forward state for one finding.
func (s *Store) UpdateTriage(ctx context.Context, snapshotID, findingID string, status TriageStatus, notes string) (TriageRecord, error) {
	if !validTriageStatus(status) {
		return TriageRecord{}, fmt.Errorf("invalid triage status %q", status)
	}
	if len(notes) > 8_000 {
		return TriageRecord{}, errors.New("triage notes exceed 8000 characters")
	}
	snapshot, err := s.Load(ctx, snapshotID)
	if err != nil {
		return TriageRecord{}, err
	}
	metadata, err := s.Metadata(ctx, snapshotID)
	if err != nil {
		return TriageRecord{}, err
	}
	var finding *model.Finding
	for i := range snapshot.Findings {
		if snapshot.Findings[i].ID == findingID {
			finding = &snapshot.Findings[i]
			break
		}
	}
	if finding == nil {
		return TriageRecord{}, fmt.Errorf("finding %q not found in snapshot %q", findingID, snapshotID)
	}
	fingerprint := FindingFingerprint(*finding)
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `INSERT INTO finding_triage(
        environment_id, fingerprint, status, notes, finding_id,
        first_seen_snapshot_id, last_seen_snapshot_id, updated_at)
        VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(environment_id, fingerprint) DO UPDATE SET
          status=excluded.status, notes=excluded.notes, finding_id=excluded.finding_id,
          last_seen_snapshot_id=excluded.last_seen_snapshot_id, updated_at=excluded.updated_at`,
		metadata.EnvironmentID, fingerprint, status, notes, findingID, snapshotID, snapshotID, now.Format(time.RFC3339Nano))
	if err != nil {
		return TriageRecord{}, fmt.Errorf("update finding triage: %w", err)
	}
	var firstSeen string
	err = s.db.QueryRowContext(ctx, `SELECT first_seen_snapshot_id FROM finding_triage WHERE environment_id=? AND fingerprint=?`, metadata.EnvironmentID, fingerprint).Scan(&firstSeen)
	if err != nil {
		return TriageRecord{}, fmt.Errorf("read finding triage: %w", err)
	}
	return TriageRecord{SnapshotID: snapshotID, EnvironmentID: metadata.EnvironmentID, FindingID: findingID, Fingerprint: fingerprint, Status: status, Notes: notes, FirstSeenSnapshotID: firstSeen, LastSeenSnapshotID: snapshotID, UpdatedAt: now}, nil
}

func validTriageStatus(status TriageStatus) bool {
	switch status {
	case TriageOpen, TriageAcknowledged, TriageAcceptedRisk, TriageResolved:
		return true
	default:
		return false
	}
}

func (s *Store) backfillTriageMigration(ctx context.Context) error {
	var applied int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version=3`).Scan(&applied); err != nil {
		return fmt.Errorf("inspect triage migration: %w", err)
	}
	if applied != 0 {
		return nil
	}
	catalog, err := s.Catalog(ctx)
	if err != nil {
		return err
	}
	sort.Slice(catalog.Snapshots, func(i, j int) bool {
		if catalog.Snapshots[i].GeneratedAt.Equal(catalog.Snapshots[j].GeneratedAt) {
			return catalog.Snapshots[i].ID < catalog.Snapshots[j].ID
		}
		return catalog.Snapshots[i].GeneratedAt.Before(catalog.Snapshots[j].GeneratedAt)
	})
	for _, metadata := range catalog.Snapshots {
		snapshot, err := s.Load(ctx, metadata.ID)
		if err != nil {
			return fmt.Errorf("backfill triage for %q: %w", metadata.ID, err)
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if err := upsertSnapshotTriage(ctx, tx, metadata.EnvironmentID, metadata.ID, snapshot.Findings, metadata.ImportedAt); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit triage backfill: %w", err)
		}
	}
	_, err = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(3,?)`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("record triage migration: %w", err)
	}
	return nil
}
