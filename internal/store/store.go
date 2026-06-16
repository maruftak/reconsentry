// Package store persists timestamped attack-surface snapshots in SQLite
// (pure-Go modernc driver, so the binary cross-compiles without cgo).
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/maruftak/reconsentry/internal/model"
)

// Store is a snapshot database handle.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS runs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scope TEXT NOT NULL,
	started_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
	run_id INTEGER NOT NULL,
	scope  TEXT NOT NULL,
	target TEXT NOT NULL,
	host   TEXT NOT NULL,
	ip     TEXT,
	alive  INTEGER NOT NULL DEFAULT 0,
	status INTEGER NOT NULL DEFAULT 0,
	tech   TEXT,
	title  TEXT,
	server TEXT
);
CREATE INDEX IF NOT EXISTS idx_assets_run ON assets(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_scope ON runs(scope, id);
CREATE TABLE IF NOT EXISTS endpoints (
	run_id INTEGER NOT NULL,
	scope  TEXT NOT NULL,
	target TEXT,
	host   TEXT NOT NULL,
	url    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoints_run ON endpoints(run_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_scope ON endpoints(scope, run_id);
CREATE TABLE IF NOT EXISTS dns_records (
	run_id INTEGER NOT NULL,
	scope  TEXT NOT NULL,
	host   TEXT NOT NULL,
	type   TEXT NOT NULL,
	value  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_run ON dns_records(run_id);
CREATE INDEX IF NOT EXISTS idx_dns_scope ON dns_records(scope, run_id);
CREATE TABLE IF NOT EXISTS content_fingerprints (
	run_id  INTEGER NOT NULL,
	scope   TEXT NOT NULL,
	target  TEXT,
	host    TEXT NOT NULL,
	status  INTEGER NOT NULL DEFAULT 0,
	favicon TEXT,
	simhash TEXT NOT NULL DEFAULT '0',
	title   TEXT
);
CREATE INDEX IF NOT EXISTS idx_content_run ON content_fingerprints(run_id);
CREATE INDEX IF NOT EXISTS idx_content_scope ON content_fingerprints(scope, run_id);
`

// Open opens (creating if needed) the snapshot database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

// OpenReadOnly opens an existing snapshot database at path read-only: it never
// creates the file, never writes the schema, and the connection is opened in
// SQLite read-only mode so a stray write fails loudly instead of mutating
// collected data. It is the entry point for read-only reporting surfaces (e.g.
// the MCP server). It errors if the database does not exist or is unreadable.
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("open store read-only: %w", err)
	}
	// modernc honours the SQLite "mode=ro" URI parameter, so any write attempt
	// returns an error instead of mutating the file.
	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open store read-only: %w", err)
	}
	// Force a connection so a missing/locked/corrupt db fails here, not mid-query.
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open store read-only: %w", err)
	}
	return &Store{db: db}, nil
}

// Scopes returns the distinct scope names present in the database, sorted, so a
// reporting client can enumerate what has been collected without prior
// knowledge of the config. An empty database yields a nil slice, not an error.
func (s *Store) Scopes() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT scope FROM runs ORDER BY scope`)
	if err != nil {
		return nil, fmt.Errorf("query scopes: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan scope: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// LatestAssets returns the assets from the most recent run for scope. It
// returns a nil slice (not an error) when no prior run exists.
func (s *Store) LatestAssets(scope string) ([]model.Asset, error) {
	var runID int64
	err := s.db.QueryRow(`SELECT id FROM runs WHERE scope = ? ORDER BY id DESC LIMIT 1`, scope).Scan(&runID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest run: %w", err)
	}
	return s.assetsForRun(runID)
}

// AssetsForRun returns the assets recorded by a specific run, so historical
// snapshots can be replayed (e.g. to reconstruct the surface changelog) rather
// than only the latest one.
func (s *Store) AssetsForRun(runID int64) ([]model.Asset, error) {
	return s.assetsForRun(runID)
}

func (s *Store) assetsForRun(runID int64) ([]model.Asset, error) {
	rows, err := s.db.Query(
		`SELECT target, host, ip, alive, status, tech, title, server FROM assets WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("query assets: %w", err)
	}
	defer rows.Close()

	var out []model.Asset
	for rows.Next() {
		var (
			a                       model.Asset
			ip, tech, title, server sql.NullString
			alive                   int
		)
		if err := rows.Scan(&a.Target, &a.Host, &ip, &alive, &a.Status, &tech, &title, &server); err != nil {
			return nil, fmt.Errorf("scan asset: %w", err)
		}
		a.IP = ip.String
		a.Alive = alive != 0
		a.Title = title.String
		a.Server = server.String
		if tech.String != "" {
			a.Tech = strings.Split(tech.String, ", ")
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RunInfo summarizes a single stored run.
type RunInfo struct {
	ID        int64     `json:"run_id"`
	StartedAt time.Time `json:"started_at"`
	Assets    int       `json:"asset_count"`
}

// Runs returns metadata for every run of scope, most recent first, so the
// monitoring history is queryable without re-probing.
func (s *Store) Runs(scope string) ([]RunInfo, error) {
	rows, err := s.db.Query(
		`SELECT r.id, r.started_at, COUNT(a.run_id)
		   FROM runs r LEFT JOIN assets a ON a.run_id = r.id
		  WHERE r.scope = ?
		  GROUP BY r.id, r.started_at
		  ORDER BY r.id DESC`, scope)
	if err != nil {
		return nil, fmt.Errorf("query runs: %w", err)
	}
	defer rows.Close()

	var out []RunInfo
	for rows.Next() {
		var ri RunInfo
		if err := rows.Scan(&ri.ID, &ri.StartedAt, &ri.Assets); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		out = append(out, ri)
	}
	return out, rows.Err()
}

// SaveRun persists a run and its assets atomically, returning the new run id.
func (s *Store) SaveRun(scope string, at time.Time, assets []model.Asset) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(`INSERT INTO runs(scope, started_at) VALUES(?, ?)`, scope, at)
	if err != nil {
		return 0, fmt.Errorf("insert run: %w", err)
	}
	runID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("run id: %w", err)
	}

	stmt, err := tx.Prepare(
		`INSERT INTO assets(run_id, scope, target, host, ip, alive, status, tech, title, server)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, a := range assets {
		alive := 0
		if a.Alive {
			alive = 1
		}
		if _, err := stmt.Exec(runID, scope, a.Target, a.Host, a.IP, alive, a.Status, a.TechString(), a.Title, a.Server); err != nil {
			return 0, fmt.Errorf("insert asset %s: %w", a.Host, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return runID, nil
}

// SaveEndpoints persists crawled endpoints for a run.
func (s *Store) SaveEndpoints(runID int64, scope string, eps []model.Endpoint) error {
	if len(eps) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoints: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT INTO endpoints(run_id, scope, target, host, url) VALUES(?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("prepare endpoints: %w", err)
	}
	defer stmt.Close()

	for _, e := range eps {
		if _, err := stmt.Exec(runID, scope, e.Target, e.Host, e.URL); err != nil {
			return fmt.Errorf("insert endpoint %s: %w", e.URL, err)
		}
	}
	return tx.Commit()
}

// LatestEndpoints returns the endpoints from the most recent run of scope that
// recorded any (so an intermittent crawl does not flag everything as new). It
// returns a nil slice when no crawl has happened yet.
func (s *Store) LatestEndpoints(scope string) ([]model.Endpoint, error) {
	var runID int64
	err := s.db.QueryRow(`SELECT run_id FROM endpoints WHERE scope = ? ORDER BY run_id DESC LIMIT 1`, scope).Scan(&runID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest endpoint run: %w", err)
	}
	rows, err := s.db.Query(`SELECT target, host, url FROM endpoints WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("query endpoints: %w", err)
	}
	defer rows.Close()

	var out []model.Endpoint
	for rows.Next() {
		var (
			e      model.Endpoint
			target sql.NullString
		)
		if err := rows.Scan(&target, &e.Host, &e.URL); err != nil {
			return nil, fmt.Errorf("scan endpoint: %w", err)
		}
		e.Target = target.String
		out = append(out, e)
	}
	return out, rows.Err()
}

// SaveDNSRecords persists the DNS records collected for a run.
func (s *Store) SaveDNSRecords(runID int64, scope string, recs []model.DNSRecord) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin dns: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT INTO dns_records(run_id, scope, host, type, value) VALUES(?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("prepare dns: %w", err)
	}
	defer stmt.Close()

	for _, r := range recs {
		if _, err := stmt.Exec(runID, scope, r.Host, r.Type, r.Value); err != nil {
			return fmt.Errorf("insert dns %s/%s: %w", r.Host, r.Type, err)
		}
	}
	return tx.Commit()
}

// LatestDNSRecords returns the DNS records from the most recent run of scope
// that recorded any (so an intermittent --dns run does not flag everything as
// changed). It returns a nil slice when no DNS collection has happened yet.
func (s *Store) LatestDNSRecords(scope string) ([]model.DNSRecord, error) {
	var runID int64
	err := s.db.QueryRow(`SELECT run_id FROM dns_records WHERE scope = ? ORDER BY run_id DESC LIMIT 1`, scope).Scan(&runID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest dns run: %w", err)
	}
	rows, err := s.db.Query(`SELECT host, type, value FROM dns_records WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("query dns: %w", err)
	}
	defer rows.Close()

	var out []model.DNSRecord
	for rows.Next() {
		var r model.DNSRecord
		if err := rows.Scan(&r.Host, &r.Type, &r.Value); err != nil {
			return nil, fmt.Errorf("scan dns: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveContentFingerprints persists the content fingerprints collected for a run.
// Only NON-FAILED fingerprints are stored — one with a status, a favicon hash,
// or a nonzero simhash. A failed/empty fetch (host only) is dropped so a
// transient outage never overwrites the baseline a later run diffs against. The
// 64-bit simhash is stored as TEXT (base-10) so the high bit round-trips without
// SQLite's signed-integer coercion.
func (s *Store) SaveContentFingerprints(runID int64, scope string, fps []model.ContentFingerprint) error {
	if len(fps) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin content: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(
		`INSERT INTO content_fingerprints(run_id, scope, target, host, status, favicon, simhash, title)
		 VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("prepare content: %w", err)
	}
	defer stmt.Close()

	saved := 0
	for _, f := range fps {
		if f.Status == 0 && f.SimHash == 0 && f.FaviconHash == "" {
			continue // failed/empty fetch: do not clobber the baseline
		}
		if _, err := stmt.Exec(runID, scope, f.Target, f.Host, f.Status, f.FaviconHash,
			strconv.FormatUint(f.SimHash, 10), f.TitleHash); err != nil {
			return fmt.Errorf("insert content %s: %w", f.Host, err)
		}
		saved++
	}
	if saved == 0 {
		// Nothing worth persisting (e.g. every host failed this run): roll back so
		// no empty content row shadows the previous baseline.
		return tx.Rollback()
	}
	return tx.Commit()
}

// LatestContentFingerprints returns the content fingerprints from the most
// recent run of scope that recorded any (so an intermittent --content run does
// not flag everything as changed). It returns a nil slice when no content
// collection has happened yet.
func (s *Store) LatestContentFingerprints(scope string) ([]model.ContentFingerprint, error) {
	var runID int64
	err := s.db.QueryRow(`SELECT run_id FROM content_fingerprints WHERE scope = ? ORDER BY run_id DESC LIMIT 1`, scope).Scan(&runID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest content run: %w", err)
	}
	rows, err := s.db.Query(`SELECT target, host, status, favicon, simhash, title FROM content_fingerprints WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("query content: %w", err)
	}
	defer rows.Close()

	var out []model.ContentFingerprint
	for rows.Next() {
		var (
			f                      model.ContentFingerprint
			target, favicon, title sql.NullString
			simhash                string
		)
		if err := rows.Scan(&target, &f.Host, &f.Status, &favicon, &simhash, &title); err != nil {
			return nil, fmt.Errorf("scan content: %w", err)
		}
		f.Target = target.String
		f.FaviconHash = favicon.String
		f.TitleHash = title.String
		// simhash is stored as base-10 TEXT; a malformed value degrades to 0,
		// which the diff treats as "no body fingerprint" rather than erroring.
		f.SimHash, _ = strconv.ParseUint(simhash, 10, 64)
		out = append(out, f)
	}
	return out, rows.Err()
}

// Prune keeps only the most recent keep runs for scope (and their assets),
// deleting older snapshots so the database stays bounded over long-running
// monitoring. keep <= 0 is a no-op (retain everything).
func (s *Store) Prune(scope string, keep int) error {
	if keep <= 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin prune: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(
		`DELETE FROM assets WHERE scope = ? AND run_id NOT IN (
			SELECT id FROM runs WHERE scope = ? ORDER BY id DESC LIMIT ?)`,
		scope, scope, keep); err != nil {
		return fmt.Errorf("prune assets: %w", err)
	}
	if _, err := tx.Exec(
		`DELETE FROM endpoints WHERE scope = ? AND run_id NOT IN (
			SELECT id FROM runs WHERE scope = ? ORDER BY id DESC LIMIT ?)`,
		scope, scope, keep); err != nil {
		return fmt.Errorf("prune endpoints: %w", err)
	}
	if _, err := tx.Exec(
		`DELETE FROM dns_records WHERE scope = ? AND run_id NOT IN (
			SELECT id FROM runs WHERE scope = ? ORDER BY id DESC LIMIT ?)`,
		scope, scope, keep); err != nil {
		return fmt.Errorf("prune dns: %w", err)
	}
	if _, err := tx.Exec(
		`DELETE FROM content_fingerprints WHERE scope = ? AND run_id NOT IN (
			SELECT id FROM runs WHERE scope = ? ORDER BY id DESC LIMIT ?)`,
		scope, scope, keep); err != nil {
		return fmt.Errorf("prune content: %w", err)
	}
	if _, err := tx.Exec(
		`DELETE FROM runs WHERE scope = ? AND id NOT IN (
			SELECT id FROM runs WHERE scope = ? ORDER BY id DESC LIMIT ?)`,
		scope, scope, keep); err != nil {
		return fmt.Errorf("prune runs: %w", err)
	}
	return tx.Commit()
}
