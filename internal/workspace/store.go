// Package workspace manages CloudThreat Atlas' private local snapshot catalog.
package workspace

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/graph"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	_ "modernc.org/sqlite"
)

const (
	DatabaseFile     = "atlas.db"
	maxSnapshotBytes = 64 << 20
)

var (
	safeID                = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	subscriptionIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	environmentSlug       = regexp.MustCompile(`[^a-z0-9]+`)
)

// ErrSnapshotNotFound is returned when an identifier is absent from the catalog.
var ErrSnapshotNotFound = errors.New("snapshot not found")

// Store combines a SQLite catalog with portable gzip-compressed schema 1.0 files.
type Store struct {
	dir          string
	snapshotDir  string
	db           *sql.DB
	loadCache    snapshotLoadCache
	loadSnapshot func(context.Context, SnapshotMetadata) (model.Snapshot, snapshotFileSignature, error)
}

// snapshotLoadCache keeps one verified snapshot and permits only one
// decompression at a time. The one-entry policy bounds retained memory while
// coalescing the graph/findings/path requests that typically target the same
// snapshot.
type snapshotLoadCache struct {
	mutex   sync.Mutex
	entry   *snapshotCacheEntry
	loading *snapshotLoadCall
}

type snapshotCacheEntry struct {
	id        string
	sha256    string
	signature snapshotFileSignature
	snapshot  model.Snapshot
}

type snapshotLoadCall struct {
	id        string
	sha256    string
	signature snapshotFileSignature
	done      chan struct{}
	err       error
}

type snapshotFileSignature struct {
	size             int64
	modifiedUnixNano int64
	compressedSHA256 [sha256.Size]byte
}

// Environment identifies one cloud environment independently from a point-in-time snapshot.
type Environment struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Provider         string    `json:"provider"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
	SnapshotCount    int       `json:"snapshotCount"`
	LatestSnapshotID string    `json:"latestSnapshotId,omitempty"`
}

// SnapshotMetadata is the searchable catalog entry stored outside portable JSON.
type SnapshotMetadata struct {
	ID                string    `json:"id"`
	SourceSnapshotID  string    `json:"sourceSnapshotId"`
	EnvironmentID     string    `json:"environmentId"`
	Name              string    `json:"name"`
	Provider          string    `json:"provider"`
	GeneratedAt       time.Time `json:"generatedAt"`
	ImportedAt        time.Time `json:"importedAt"`
	RiskScore         int       `json:"riskScore"`
	ResourceCount     int       `json:"resourceCount"`
	RelationshipCount int       `json:"relationshipCount"`
	FindingCount      int       `json:"findingCount"`
	AttackPathCount   int       `json:"attackPathCount"`
	CompressedBytes   int64     `json:"compressedBytes"`
	SHA256            string    `json:"sha256"`
	fileName          string
}

// Catalog is the multi-snapshot workspace index.
type Catalog struct {
	Environments []Environment      `json:"environments"`
	Snapshots    []SnapshotMetadata `json:"snapshots"`
}

// Diagnostic is one actionable workspace health check.
type Diagnostic struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// DefaultDir returns the OS-appropriate private data directory.
func DefaultDir() (string, error) {
	if value := strings.TrimSpace(os.Getenv("CLOUDTHREAT_ATLAS_HOME")); value != "" {
		return filepath.Abs(value)
	}
	var base string
	switch runtime.GOOS {
	case "windows":
		base = strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
		if base == "" {
			var err error
			base, err = os.UserConfigDir()
			if err != nil {
				return "", fmt.Errorf("resolve local app data directory: %w", err)
			}
		}
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve user home directory: %w", err)
		}
		base = filepath.Join(home, "Library", "Application Support")
	default:
		base = strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("resolve user home directory: %w", err)
			}
			base = filepath.Join(home, ".local", "share")
		}
	}
	return filepath.Join(base, "cloudthreat-atlas"), nil
}

// Open initializes a private workspace and applies forward-only migrations.
func Open(ctx context.Context, dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		var err error
		dir, err = DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create workspace directory: %w", err)
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return nil, fmt.Errorf("protect workspace directory: %w", err)
	}
	snapshotDir := filepath.Join(abs, "snapshots")
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		return nil, fmt.Errorf("create snapshot directory: %w", err)
	}
	if err := os.Chmod(snapshotDir, 0o700); err != nil {
		return nil, fmt.Errorf("protect snapshot directory: %w", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(abs, DatabaseFile))
	if err != nil {
		return nil, fmt.Errorf("open workspace catalog: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{dir: abs, snapshotDir: snapshotDir, db: db}
	store.loadSnapshot = store.loadVerified
	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.backfillTriageMigration(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(filepath.Join(abs, DatabaseFile), 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("protect workspace catalog: %w", err)
	}
	return store, nil
}

// Dir returns the absolute workspace directory.
func (s *Store) Dir() string { return s.dir }

// Close closes the catalog.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	pragmas := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
	}
	for _, statement := range pragmas {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure workspace catalog: %w", err)
		}
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS environments (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, provider TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS snapshots (
            id TEXT PRIMARY KEY,
            source_snapshot_id TEXT NOT NULL,
            environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
            name TEXT NOT NULL, provider TEXT NOT NULL,
            generated_at TEXT NOT NULL, imported_at TEXT NOT NULL,
            risk_score INTEGER NOT NULL, resource_count INTEGER NOT NULL,
            relationship_count INTEGER NOT NULL, finding_count INTEGER NOT NULL,
            attack_path_count INTEGER NOT NULL, file_name TEXT NOT NULL UNIQUE,
            compressed_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS snapshots_environment_generated_idx ON snapshots(environment_id, generated_at DESC, id)`,
		`CREATE INDEX IF NOT EXISTS snapshots_imported_idx ON snapshots(imported_at DESC, id)`,
		`CREATE TABLE IF NOT EXISTS finding_triage (
            environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL, status TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT '', finding_id TEXT NOT NULL,
            first_seen_snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE RESTRICT,
            last_seen_snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE RESTRICT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(environment_id, fingerprint),
            CHECK(status IN ('open','acknowledged','accepted-risk','resolved'))
        )`,
		`CREATE INDEX IF NOT EXISTS finding_triage_snapshot_idx ON finding_triage(last_seen_snapshot_id, status)`,
		`CREATE TABLE IF NOT EXISTS scan_jobs (
            id TEXT PRIMARY KEY, provider TEXT NOT NULL,
            subscription_id TEXT NOT NULL, resource_group TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL, phase TEXT NOT NULL, error TEXT NOT NULL DEFAULT '',
            snapshot_id TEXT NOT NULL DEFAULT '', revision INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL, started_at TEXT, updated_at TEXT NOT NULL, completed_at TEXT,
            CHECK(status IN ('queued','running','completed','failed','cancelled','interrupted'))
        )`,
		`CREATE INDEX IF NOT EXISTS scan_jobs_created_idx ON scan_jobs(created_at DESC, id)`,
		`CREATE TABLE IF NOT EXISTS scan_job_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
            status TEXT NOT NULL, phase TEXT NOT NULL, message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS scan_job_events_job_idx ON scan_job_events(job_id, sequence)`,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin workspace migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply workspace migration: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("record workspace migration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2, ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("record workspace migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit workspace migration: %w", err)
	}
	return nil
}

// Import saves a complete schema 1.0 snapshot atomically. environmentID may be
// empty, in which case a stable provider/name-derived identifier is used.
func (s *Store) Import(ctx context.Context, snapshot model.Snapshot, environmentID string) (SnapshotMetadata, error) {
	if err := validateSnapshot(snapshot); err != nil {
		return SnapshotMetadata{}, err
	}
	sourceSnapshotID := snapshot.ID
	if environmentID == "" {
		environmentID = derivedEnvironmentID(snapshot)
	}
	if !safeID.MatchString(environmentID) {
		return SnapshotMetadata{}, fmt.Errorf("environment id must match %s", safeID.String())
	}
	persistedID, err := newSnapshotID()
	if err != nil {
		return SnapshotMetadata{}, err
	}
	snapshot.ID = persistedID
	data, err := json.Marshal(snapshot)
	if err != nil {
		return SnapshotMetadata{}, fmt.Errorf("encode snapshot: %w", err)
	}
	if len(data) > maxSnapshotBytes {
		return SnapshotMetadata{}, fmt.Errorf("snapshot exceeds %d byte limit", maxSnapshotBytes)
	}
	digest := sha256.Sum256(data)
	fileName := snapshotFileName(persistedID)
	finalPath := filepath.Join(s.snapshotDir, fileName)
	if _, err := os.Stat(finalPath); err == nil {
		return SnapshotMetadata{}, fmt.Errorf("snapshot %q already exists", persistedID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return SnapshotMetadata{}, fmt.Errorf("check snapshot file: %w", err)
	}
	temp, err := os.CreateTemp(s.snapshotDir, ".snapshot-*.tmp")
	if err != nil {
		return SnapshotMetadata{}, fmt.Errorf("create temporary snapshot: %w", err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return SnapshotMetadata{}, fmt.Errorf("protect temporary snapshot: %w", err)
	}
	zw, err := gzip.NewWriterLevel(temp, gzip.BestSpeed)
	if err != nil {
		return SnapshotMetadata{}, fmt.Errorf("create snapshot compressor: %w", err)
	}
	zw.Header.ModTime = time.Time{}
	zw.Header.Name = "snapshot.json"
	if _, err := zw.Write(data); err != nil {
		return SnapshotMetadata{}, fmt.Errorf("compress snapshot: %w", err)
	}
	if err := zw.Close(); err != nil {
		return SnapshotMetadata{}, fmt.Errorf("finish snapshot compression: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return SnapshotMetadata{}, fmt.Errorf("sync snapshot: %w", err)
	}
	if err := temp.Close(); err != nil {
		return SnapshotMetadata{}, fmt.Errorf("close snapshot: %w", err)
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		return SnapshotMetadata{}, fmt.Errorf("publish snapshot: %w", err)
	}
	committed = true
	info, err := os.Stat(finalPath)
	if err != nil {
		_ = os.Remove(finalPath)
		return SnapshotMetadata{}, fmt.Errorf("inspect snapshot: %w", err)
	}
	importedAt := time.Now().UTC()
	metadata := SnapshotMetadata{
		ID: persistedID, SourceSnapshotID: sourceSnapshotID, EnvironmentID: environmentID, Name: snapshot.Name, Provider: snapshot.Provider,
		GeneratedAt: snapshot.GeneratedAt.UTC(), ImportedAt: importedAt, RiskScore: snapshot.RiskScore,
		ResourceCount: len(snapshot.Resources), RelationshipCount: len(snapshot.Relationships),
		FindingCount: len(snapshot.Findings), AttackPathCount: len(snapshot.AttackPaths),
		CompressedBytes: info.Size(), SHA256: hex.EncodeToString(digest[:]), fileName: fileName,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		_ = os.Remove(finalPath)
		return SnapshotMetadata{}, fmt.Errorf("begin snapshot import: %w", err)
	}
	defer tx.Rollback()
	now := importedAt.Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO environments(id, name, provider, created_at, updated_at) VALUES(?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET name=excluded.name, provider=excluded.provider, updated_at=excluded.updated_at`,
		environmentID, snapshot.Name, snapshot.Provider, now, now)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO snapshots(
            id, source_snapshot_id, environment_id, name, provider, generated_at, imported_at, risk_score,
            resource_count, relationship_count, finding_count, attack_path_count,
            file_name, compressed_bytes, sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			metadata.ID, metadata.SourceSnapshotID, metadata.EnvironmentID, metadata.Name, metadata.Provider,
			metadata.GeneratedAt.Format(time.RFC3339Nano), metadata.ImportedAt.Format(time.RFC3339Nano),
			metadata.RiskScore, metadata.ResourceCount, metadata.RelationshipCount,
			metadata.FindingCount, metadata.AttackPathCount, metadata.fileName,
			metadata.CompressedBytes, metadata.SHA256)
	}
	if err == nil {
		err = upsertSnapshotTriage(ctx, tx, metadata.EnvironmentID, metadata.ID, snapshot.Findings, metadata.ImportedAt)
	}
	if err != nil {
		_ = os.Remove(finalPath)
		return SnapshotMetadata{}, fmt.Errorf("catalog snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		_ = os.Remove(finalPath)
		return SnapshotMetadata{}, fmt.Errorf("commit snapshot import: %w", err)
	}
	return metadata, nil
}

// Load reads and verifies one snapshot and returns a mutable deep copy. Use
// WithSnapshot for read-only work that can finish within a callback.
func (s *Store) Load(ctx context.Context, id string) (model.Snapshot, error) {
	var result model.Snapshot
	err := s.WithSnapshot(ctx, id, func(snapshot model.Snapshot) error {
		result = model.CloneSnapshot(snapshot)
		return nil
	})
	return result, err
}

// WithSnapshot invokes visit with a verified, cache-backed snapshot without
// cloning the full graph. The snapshot and every slice/map reachable from it
// are immutable views: visit must not mutate them, retain them after returning,
// or start asynchronous work that uses them. Calls may execute concurrently.
func (s *Store) WithSnapshot(ctx context.Context, id string, visit func(model.Snapshot) error) error {
	if visit == nil {
		return errors.New("snapshot visitor is required")
	}
	snapshot, err := s.loadReadOnly(ctx, id)
	if err != nil {
		return err
	}
	return visit(snapshot)
}

func (s *Store) loadReadOnly(ctx context.Context, id string) (model.Snapshot, error) {
	metadata, err := s.Metadata(ctx, id)
	if err != nil {
		return model.Snapshot{}, err
	}
	path := filepath.Join(s.snapshotDir, metadata.fileName)
	for {
		if err := ctx.Err(); err != nil {
			return model.Snapshot{}, err
		}
		signature, err := inspectSnapshotFile(path, metadata)
		if err != nil {
			return model.Snapshot{}, err
		}

		s.loadCache.mutex.Lock()
		if entry := s.loadCache.entry; entry != nil && entry.id == id && entry.sha256 == metadata.SHA256 && entry.signature == signature {
			cached := entry.snapshot
			s.loadCache.mutex.Unlock()
			return cached, nil
		}
		if call := s.loadCache.loading; call != nil {
			done := call.done
			s.loadCache.mutex.Unlock()
			select {
			case <-done:
				if call.id == id && call.sha256 == metadata.SHA256 && call.signature == signature && call.err != nil {
					return model.Snapshot{}, call.err
				}
				continue
			case <-ctx.Done():
				return model.Snapshot{}, ctx.Err()
			}
		}

		call := &snapshotLoadCall{id: id, sha256: metadata.SHA256, signature: signature, done: make(chan struct{})}
		s.loadCache.loading = call
		s.loadCache.mutex.Unlock()
		go s.completeSnapshotLoad(call, metadata)
		select {
		case <-call.done:
			if call.err != nil {
				return model.Snapshot{}, call.err
			}
			continue
		case <-ctx.Done():
			return model.Snapshot{}, ctx.Err()
		}
	}
}

func (s *Store) completeSnapshotLoad(call *snapshotLoadCall, metadata SnapshotMetadata) {
	// Snapshot files are local, size-bounded inputs. Their shared decode has an
	// independent lifecycle so one HTTP request cannot cancel work awaited by
	// other live requests.
	snapshot, verifiedSignature, loadErr := s.loadSnapshot(context.Background(), metadata)
	s.loadCache.mutex.Lock()
	call.err = loadErr
	if loadErr == nil {
		s.loadCache.entry = &snapshotCacheEntry{id: metadata.ID, sha256: metadata.SHA256, signature: verifiedSignature, snapshot: snapshot}
	}
	if s.loadCache.loading == call {
		s.loadCache.loading = nil
	}
	close(call.done)
	s.loadCache.mutex.Unlock()
}

func inspectSnapshotFile(path string, metadata SnapshotMetadata) (snapshotFileSignature, error) {
	file, err := os.Open(path)
	if err != nil {
		return snapshotFileSignature{}, fmt.Errorf("open snapshot %q: %w", metadata.ID, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return snapshotFileSignature{}, fmt.Errorf("inspect snapshot %q: %w", metadata.ID, err)
	}
	if info.Size() != metadata.CompressedBytes {
		return snapshotFileSignature{}, fmt.Errorf("snapshot %q compressed size mismatch", metadata.ID)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return snapshotFileSignature{}, fmt.Errorf("verify compressed snapshot %q: %w", metadata.ID, err)
	}
	var compressedDigest [sha256.Size]byte
	copy(compressedDigest[:], hasher.Sum(nil))
	return snapshotFileSignature{size: info.Size(), modifiedUnixNano: info.ModTime().UnixNano(), compressedSHA256: compressedDigest}, nil
}

func (s *Store) loadVerified(ctx context.Context, metadata SnapshotMetadata) (model.Snapshot, snapshotFileSignature, error) {
	if err := ctx.Err(); err != nil {
		return model.Snapshot{}, snapshotFileSignature{}, err
	}
	file, err := os.Open(filepath.Join(s.snapshotDir, metadata.fileName))
	if err != nil {
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("open snapshot %q: %w", metadata.ID, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("inspect snapshot %q: %w", metadata.ID, err)
	}
	if info.Size() != metadata.CompressedBytes {
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("snapshot %q compressed size mismatch", metadata.ID)
	}
	zr, err := gzip.NewReader(file)
	if err != nil {
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("decompress snapshot %q: %w", metadata.ID, err)
	}
	limited := &io.LimitedReader{R: zr, N: maxSnapshotBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		_ = zr.Close()
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("read snapshot %q: %w", metadata.ID, err)
	}
	if err := zr.Close(); err != nil {
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("finish decompressing snapshot %q: %w", metadata.ID, err)
	}
	if len(data) > maxSnapshotBytes {
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("snapshot %q exceeds decompressed size limit", metadata.ID)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != metadata.SHA256 {
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("snapshot %q checksum mismatch", metadata.ID)
	}
	var snapshot model.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("decode snapshot %q: %w", metadata.ID, err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("rewind snapshot %q: %w", metadata.ID, err)
	}
	compressedHasher := sha256.New()
	if _, err := io.Copy(compressedHasher, file); err != nil {
		return model.Snapshot{}, snapshotFileSignature{}, fmt.Errorf("verify compressed snapshot %q: %w", metadata.ID, err)
	}
	var compressedDigest [sha256.Size]byte
	copy(compressedDigest[:], compressedHasher.Sum(nil))
	signature := snapshotFileSignature{size: info.Size(), modifiedUnixNano: info.ModTime().UnixNano(), compressedSHA256: compressedDigest}
	return snapshot, signature, nil
}

// Metadata returns one catalog record.
func (s *Store) Metadata(ctx context.Context, id string) (SnapshotMetadata, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, source_snapshot_id, environment_id, name, provider, generated_at, imported_at,
        risk_score, resource_count, relationship_count, finding_count, attack_path_count,
        file_name, compressed_bytes, sha256 FROM snapshots WHERE id=?`, id)
	metadata, err := scanMetadata(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SnapshotMetadata{}, fmt.Errorf("%w: %q", ErrSnapshotNotFound, id)
	}
	return metadata, err
}

// Catalog returns environments and snapshots in stable newest-first order.
func (s *Store) Catalog(ctx context.Context) (Catalog, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, source_snapshot_id, environment_id, name, provider, generated_at, imported_at,
        risk_score, resource_count, relationship_count, finding_count, attack_path_count,
        file_name, compressed_bytes, sha256 FROM snapshots ORDER BY generated_at DESC, id`)
	if err != nil {
		return Catalog{}, fmt.Errorf("list snapshots: %w", err)
	}
	defer rows.Close()
	var catalog Catalog
	for rows.Next() {
		metadata, scanErr := scanMetadata(rows)
		if scanErr != nil {
			return Catalog{}, scanErr
		}
		catalog.Snapshots = append(catalog.Snapshots, metadata)
	}
	if err := rows.Err(); err != nil {
		return Catalog{}, fmt.Errorf("list snapshots: %w", err)
	}
	environmentRows, err := s.db.QueryContext(ctx, `SELECT e.id, e.name, e.provider, e.created_at, e.updated_at,
        COUNT(s.id), COALESCE((SELECT s2.id FROM snapshots s2 WHERE s2.environment_id=e.id ORDER BY s2.generated_at DESC, s2.id LIMIT 1),'')
        FROM environments e LEFT JOIN snapshots s ON s.environment_id=e.id
        GROUP BY e.id ORDER BY e.name, e.id`)
	if err != nil {
		return Catalog{}, fmt.Errorf("list environments: %w", err)
	}
	defer environmentRows.Close()
	for environmentRows.Next() {
		var environment Environment
		var createdAt, updatedAt string
		if err := environmentRows.Scan(&environment.ID, &environment.Name, &environment.Provider, &createdAt, &updatedAt, &environment.SnapshotCount, &environment.LatestSnapshotID); err != nil {
			return Catalog{}, fmt.Errorf("scan environment: %w", err)
		}
		environment.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return Catalog{}, fmt.Errorf("parse environment created time: %w", err)
		}
		environment.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
		if err != nil {
			return Catalog{}, fmt.Errorf("parse environment updated time: %w", err)
		}
		catalog.Environments = append(catalog.Environments, environment)
	}
	return catalog, environmentRows.Err()
}

// LatestID returns the newest snapshot identifier, or an empty string for a new workspace.
func (s *Store) LatestID(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM snapshots ORDER BY generated_at DESC, id LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// Diagnose checks the database and all cataloged compressed snapshots.
func (s *Store) Diagnose(ctx context.Context) []Diagnostic {
	checks := []Diagnostic{{Name: "private-directory", OK: true, Message: s.dir}}
	if info, err := os.Stat(s.dir); err != nil {
		checks[0] = Diagnostic{Name: "private-directory", Message: err.Error()}
	} else if info.Mode().Perm()&0o077 != 0 {
		checks[0] = Diagnostic{Name: "private-directory", Message: fmt.Sprintf("permissions are %04o; expected 0700", info.Mode().Perm())}
	}
	var integrity string
	if err := s.db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		message := integrity
		if err != nil {
			message = err.Error()
		}
		checks = append(checks, Diagnostic{Name: "sqlite-integrity", Message: message})
	} else {
		checks = append(checks, Diagnostic{Name: "sqlite-integrity", OK: true, Message: "ok"})
	}
	catalog, err := s.Catalog(ctx)
	if err != nil {
		checks = append(checks, Diagnostic{Name: "snapshot-files", Message: err.Error()})
		return checks
	}
	var failures []string
	for _, metadata := range catalog.Snapshots {
		// Diagnostics deliberately bypass the cache so every cataloged file is
		// re-read and checksum-verified at the time of the health check.
		if _, _, err := s.loadVerified(ctx, metadata); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) == 0 {
		checks = append(checks, Diagnostic{Name: "snapshot-files", OK: true, Message: fmt.Sprintf("%d verified", len(catalog.Snapshots))})
	} else {
		sort.Strings(failures)
		checks = append(checks, Diagnostic{Name: "snapshot-files", Message: strings.Join(failures, "; ")})
	}
	return checks
}

type rowScanner interface{ Scan(dest ...any) error }

func scanMetadata(row rowScanner) (SnapshotMetadata, error) {
	var metadata SnapshotMetadata
	var generatedAt, importedAt string
	err := row.Scan(&metadata.ID, &metadata.SourceSnapshotID, &metadata.EnvironmentID, &metadata.Name, &metadata.Provider,
		&generatedAt, &importedAt, &metadata.RiskScore, &metadata.ResourceCount,
		&metadata.RelationshipCount, &metadata.FindingCount, &metadata.AttackPathCount,
		&metadata.fileName, &metadata.CompressedBytes, &metadata.SHA256)
	if err != nil {
		return SnapshotMetadata{}, err
	}
	metadata.GeneratedAt, err = time.Parse(time.RFC3339Nano, generatedAt)
	if err != nil {
		return SnapshotMetadata{}, fmt.Errorf("parse snapshot generated time: %w", err)
	}
	metadata.ImportedAt, err = time.Parse(time.RFC3339Nano, importedAt)
	if err != nil {
		return SnapshotMetadata{}, fmt.Errorf("parse snapshot imported time: %w", err)
	}
	return metadata, nil
}

func validateSnapshot(snapshot model.Snapshot) error {
	if snapshot.SchemaVersion != "1.0" {
		return fmt.Errorf("unsupported schema version %q; expected 1.0", snapshot.SchemaVersion)
	}
	if !safeID.MatchString(snapshot.ID) {
		return fmt.Errorf("snapshot id must match %s", safeID.String())
	}
	if strings.TrimSpace(snapshot.Name) == "" {
		return errors.New("snapshot name must not be empty")
	}
	if strings.TrimSpace(snapshot.Provider) == "" {
		return errors.New("snapshot provider must not be empty")
	}
	if snapshot.Scope != nil && strings.TrimSpace(snapshot.Scope.SubscriptionID) == "" {
		return errors.New("snapshot scope subscriptionId must not be empty")
	}
	if snapshot.GeneratedAt.IsZero() {
		return errors.New("snapshot generatedAt must not be empty")
	}
	if snapshot.RiskScore < 0 || snapshot.RiskScore > 100 {
		return errors.New("snapshot riskScore must be between 0 and 100")
	}
	if _, err := graph.New(snapshot.Resources, snapshot.Relationships); err != nil {
		return fmt.Errorf("invalid snapshot graph: %w", err)
	}
	return nil
}

func derivedEnvironmentID(snapshot model.Snapshot) string {
	provider := strings.ToLower(strings.TrimSpace(snapshot.Provider))
	if provider == "azure" {
		if snapshot.Scope != nil && strings.TrimSpace(snapshot.Scope.SubscriptionID) != "" {
			subscriptionID := strings.ToLower(strings.TrimSpace(snapshot.Scope.SubscriptionID))
			if subscriptionIDPattern.MatchString(subscriptionID) {
				return AzureEnvironmentID(model.Scope{SubscriptionID: subscriptionID, ResourceGroup: strings.TrimSpace(snapshot.Scope.ResourceGroup)})
			}
			digest := sha256.Sum256([]byte(subscriptionID + "\x00" + strings.ToLower(strings.TrimSpace(snapshot.Scope.ResourceGroup))))
			return "azure-redacted-" + hex.EncodeToString(digest[:12])
		}
		subscriptions := make(map[string]struct{})
		for _, resource := range snapshot.Resources {
			if subscriptionID := strings.ToLower(strings.TrimSpace(resource.Properties["subscriptionId"])); subscriptionIDPattern.MatchString(subscriptionID) {
				subscriptions[subscriptionID] = struct{}{}
			}
		}
		if len(subscriptions) == 1 {
			for subscriptionID := range subscriptions {
				return "azure-" + strings.ReplaceAll(subscriptionID, "-", "")
			}
		}
		// Schema 1.0 Azure exports created before collection scope became
		// portable may have had subscriptionId properties removed by redaction.
		// The deterministically redacted subscription resource remains stable
		// across scans and prevents unrelated tenants from sharing one history.
		var subscriptionRoots []string
		for _, resource := range snapshot.Resources {
			if strings.EqualFold(resource.Type, "Microsoft.Resources/subscriptions") && strings.TrimSpace(resource.ID) != "" {
				subscriptionRoots = append(subscriptionRoots, strings.ToLower(strings.TrimSpace(resource.ID)))
			}
		}
		if len(subscriptionRoots) > 0 {
			sort.Strings(subscriptionRoots)
			digest := sha256.Sum256([]byte(strings.Join(subscriptionRoots, "\x00")))
			return "azure-legacy-" + hex.EncodeToString(digest[:12])
		}
		if strings.EqualFold(strings.TrimSpace(snapshot.Name), "Redacted Azure environment") {
			digest := sha256.Sum256([]byte(snapshot.ID))
			return "azure-legacy-" + hex.EncodeToString(digest[:12])
		}
	}
	base := strings.ToLower(provider + "-" + snapshot.Name)
	base = environmentSlug.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "environment"
	}
	if len(base) > 80 {
		base = base[:80]
	}
	digest := sha256.Sum256([]byte(provider + "\x00" + snapshot.Name))
	return base + "-" + hex.EncodeToString(digest[:6])
}

func newSnapshotID() (string, error) {
	return newOpaqueID("snap")
}

func newOpaqueID(prefix string) (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate %s id: %w", prefix, err)
	}
	return prefix + "-" + time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random), nil
}

func snapshotFileName(id string) string {
	digest := sha256.Sum256([]byte(id))
	return hex.EncodeToString(digest[:]) + ".json.gz"
}
