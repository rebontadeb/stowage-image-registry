package store

import (
	"database/sql"
	"errors"
	"time"
)

const securitySchema = `
CREATE TABLE IF NOT EXISTS scans (
	registry TEXT NOT NULL,
	repo     TEXT NOT NULL,
	digest   TEXT NOT NULL,
	kind     TEXT NOT NULL,            -- vuln | sbom | sig | oval
	status   TEXT NOT NULL,            -- queued | running | done | failed
	error    TEXT NOT NULL DEFAULT '',
	tool     TEXT NOT NULL DEFAULT '', -- tool and data versions, for the "scanned with" line
	summary  TEXT NOT NULL DEFAULT '{}',
	result   BLOB,                     -- gzip JSON
	extra    BLOB,                     -- gzip: second SBOM format / HTML report
	queued   INTEGER NOT NULL,
	started  INTEGER NOT NULL DEFAULT 0,
	finished INTEGER NOT NULL DEFAULT 0,
	by       TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (registry, repo, digest, kind)
);
CREATE TABLE IF NOT EXISTS signing_keys (
	registry     TEXT PRIMARY KEY,
	public_pem   TEXT NOT NULL,
	private_enc  BLOB NOT NULL,
	password_enc BLOB NOT NULL,
	created      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS trust_keys (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	registry    TEXT NOT NULL,
	label       TEXT NOT NULL,
	public_pem  TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	own         INTEGER NOT NULL DEFAULT 0,
	created     INTEGER NOT NULL,
	UNIQUE (registry, fingerprint)
);
CREATE TABLE IF NOT EXISTS scap_content (
	name     TEXT PRIMARY KEY,
	kind     TEXT NOT NULL,
	filename TEXT NOT NULL,
	sha256   TEXT NOT NULL,
	size     INTEGER NOT NULL,
	source   TEXT NOT NULL DEFAULT '',
	added_by TEXT NOT NULL DEFAULT '',
	added    INTEGER NOT NULL
);
`

const (
	ScanQueued  = "queued"
	ScanRunning = "running"
	ScanDone    = "done"
	ScanFailed  = "failed"
)

type Scan struct {
	Registry string    `json:"registry"`
	Repo     string    `json:"repo"`
	Digest   string    `json:"digest"`
	Kind     string    `json:"kind"`
	Status   string    `json:"status"`
	Error    string    `json:"error,omitempty"`
	Tool     string    `json:"tool,omitempty"`
	Summary  string    `json:"-"` // raw JSON
	Result   []byte    `json:"-"`
	Extra    []byte    `json:"-"`
	Queued   time.Time `json:"queued"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	By       string    `json:"by,omitempty"`
}

func ts(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// QueueScan creates or resets a scan row to "queued". Returns false when one is already queued or
// running for that image, so repeated clicks do not stack up work.
func (s *Store) QueueScan(registry, repo, digest, kind, by string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var status string
	err = tx.QueryRow(`SELECT status FROM scans WHERE registry=? AND repo=? AND digest=? AND kind=?`, registry, repo, digest, kind).Scan(&status)
	if err == nil && (status == ScanQueued || status == ScanRunning) {
		return false, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	_, err = tx.Exec(`INSERT INTO scans (registry,repo,digest,kind,status,queued,by) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(registry,repo,digest,kind) DO UPDATE SET status=?, error='', tool='', summary='{}', result=NULL, extra=NULL,
		queued=excluded.queued, started=0, finished=0, by=excluded.by`,
		registry, repo, digest, kind, ScanQueued, time.Now().Unix(), by, ScanQueued)
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *Store) StartScan(registry, repo, digest, kind string) error {
	_, err := s.db.Exec(`UPDATE scans SET status=?, started=? WHERE registry=? AND repo=? AND digest=? AND kind=?`,
		ScanRunning, time.Now().Unix(), registry, repo, digest, kind)
	return err
}

func (s *Store) FinishScan(sc Scan) error {
	_, err := s.db.Exec(`UPDATE scans SET status=?, error=?, tool=?, summary=?, result=?, extra=?, finished=? WHERE registry=? AND repo=? AND digest=? AND kind=?`,
		sc.Status, sc.Error, sc.Tool, orJSON(sc.Summary), sc.Result, sc.Extra, time.Now().Unix(), sc.Registry, sc.Repo, sc.Digest, sc.Kind)
	return err
}

func orJSON(s string) string {
	if s == "" {
		return "{}"
	}
	return s
}

const scanCols = `registry,repo,digest,kind,status,error,tool,summary,queued,started,finished,by`

func scanRow(sc scanner, withBlobs bool) (Scan, error) {
	var x Scan
	var q, st, f int64
	var err error
	if withBlobs {
		err = sc.Scan(&x.Registry, &x.Repo, &x.Digest, &x.Kind, &x.Status, &x.Error, &x.Tool, &x.Summary, &q, &st, &f, &x.By, &x.Result, &x.Extra)
	} else {
		err = sc.Scan(&x.Registry, &x.Repo, &x.Digest, &x.Kind, &x.Status, &x.Error, &x.Tool, &x.Summary, &q, &st, &f, &x.By)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return x, ErrNotFound
	}
	x.Queued, x.Started, x.Finished = ts(q), ts(st), ts(f)
	return x, err
}

// GetScan returns one scan including its result blobs.
func (s *Store) GetScan(registry, repo, digest, kind string) (Scan, error) {
	return scanRow(s.db.QueryRow(`SELECT `+scanCols+`,result,extra FROM scans WHERE registry=? AND repo=? AND digest=? AND kind=?`, registry, repo, digest, kind), true)
}

// ListScans returns scan metadata (no blobs) for a repository, or the whole registry when repo is "".
func (s *Store) ListScans(registry, repo string) ([]Scan, error) {
	q, args := `SELECT `+scanCols+` FROM scans WHERE registry=?`, []any{registry}
	if repo != "" {
		q += ` AND repo=?`
		args = append(args, repo)
	}
	rows, err := s.db.Query(q+` ORDER BY repo,digest,kind`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scan{}
	for rows.Next() {
		x, err := scanRow(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// ListScansOfKind returns finished scans of one kind for the given registries (no blobs).
func (s *Store) ListDoneScans(kind string) ([]Scan, error) {
	rows, err := s.db.Query(`SELECT `+scanCols+` FROM scans WHERE kind=? AND status=?`, kind, ScanDone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scan{}
	for rows.Next() {
		x, err := scanRow(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// PruneScans deletes scans of digests no longer present in a repository.
func (s *Store) PruneScans(registry, repo string, keep []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT DISTINCT digest FROM scans WHERE registry=? AND repo=?`, registry, repo)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, d := range keep {
		have[d] = true
	}
	var drop []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			rows.Close()
			return err
		}
		if !have[d] {
			drop = append(drop, d)
		}
	}
	rows.Close()
	for _, d := range drop {
		if _, err := tx.Exec(`DELETE FROM scans WHERE registry=? AND repo=? AND digest=? AND status NOT IN (?,?)`, registry, repo, d, ScanQueued, ScanRunning); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeleteScansOfRepo(registry, repo string) error {
	_, err := s.db.Exec(`DELETE FROM scans WHERE registry=? AND repo=?`, registry, repo)
	return err
}

func (s *Store) DeleteScansOfDigest(registry, repo, digest string) error {
	_, err := s.db.Exec(`DELETE FROM scans WHERE registry=? AND repo=? AND digest=?`, registry, repo, digest)
	return err
}

// FailInterruptedScans marks work that was in flight when the manager stopped.
func (s *Store) FailInterruptedScans() error {
	_, err := s.db.Exec(`UPDATE scans SET status=?, error='interrupted: the manager restarted', finished=? WHERE status IN (?,?)`,
		ScanFailed, time.Now().Unix(), ScanQueued, ScanRunning)
	return err
}

// ---- signing and trust keys ----

type SigningKey struct {
	Registry    string
	PublicPEM   string
	PrivateEnc  []byte
	PasswordEnc []byte
	Created     time.Time
}

func (s *Store) PutSigningKey(k SigningKey) error {
	_, err := s.db.Exec(`INSERT INTO signing_keys VALUES (?,?,?,?,?)`, k.Registry, k.PublicPEM, k.PrivateEnc, k.PasswordEnc, time.Now().Unix())
	if err != nil && isConstraint(err) {
		return ErrExists
	}
	return err
}

func (s *Store) GetSigningKey(registry string) (SigningKey, error) {
	var k SigningKey
	var c int64
	err := s.db.QueryRow(`SELECT registry,public_pem,private_enc,password_enc,created FROM signing_keys WHERE registry=?`, registry).
		Scan(&k.Registry, &k.PublicPEM, &k.PrivateEnc, &k.PasswordEnc, &c)
	if errors.Is(err, sql.ErrNoRows) {
		return k, ErrNotFound
	}
	k.Created = ts(c)
	return k, err
}

func (s *Store) DeleteSigningKey(registry string) error {
	res, err := s.db.Exec(`DELETE FROM signing_keys WHERE registry=?`, registry)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type TrustKey struct {
	ID          int64     `json:"id"`
	Registry    string    `json:"-"`
	Label       string    `json:"label"`
	PublicPEM   string    `json:"publicKey"`
	Fingerprint string    `json:"fingerprint"`
	Own         bool      `json:"own"` // the registry's own generated signing key
	Created     time.Time `json:"created"`
}

func (s *Store) AddTrustKey(k TrustKey) (TrustKey, error) {
	res, err := s.db.Exec(`INSERT INTO trust_keys (registry,label,public_pem,fingerprint,own,created) VALUES (?,?,?,?,?,?)`,
		k.Registry, k.Label, k.PublicPEM, k.Fingerprint, b2i(k.Own), time.Now().Unix())
	if err != nil {
		if isConstraint(err) {
			return k, ErrExists
		}
		return k, err
	}
	k.ID, _ = res.LastInsertId()
	return k, nil
}

func (s *Store) TrustKeys(registry string) ([]TrustKey, error) {
	rows, err := s.db.Query(`SELECT id,registry,label,public_pem,fingerprint,own,created FROM trust_keys WHERE registry=? ORDER BY id`, registry)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrustKey{}
	for rows.Next() {
		var k TrustKey
		var own int
		var c int64
		if err := rows.Scan(&k.ID, &k.Registry, &k.Label, &k.PublicPEM, &k.Fingerprint, &own, &c); err != nil {
			return nil, err
		}
		k.Own, k.Created = own != 0, ts(c)
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) DeleteTrustKey(registry string, id int64) error {
	res, err := s.db.Exec(`DELETE FROM trust_keys WHERE registry=? AND id=?`, registry, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- SCAP content library ----

type SCAPContent struct {
	Name     string    `json:"name"`
	Kind     string    `json:"kind"` // "oval"
	Filename string    `json:"filename"`
	SHA256   string    `json:"sha256"`
	Size     int64     `json:"size"`
	Source   string    `json:"source"`
	AddedBy  string    `json:"addedBy"`
	Added    time.Time `json:"added"`
}

func (s *Store) PutSCAPContent(c SCAPContent) error {
	_, err := s.db.Exec(`INSERT INTO scap_content VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, filename=excluded.filename, sha256=excluded.sha256, size=excluded.size, source=excluded.source, added_by=excluded.added_by, added=excluded.added`,
		c.Name, c.Kind, c.Filename, c.SHA256, c.Size, c.Source, c.AddedBy, time.Now().Unix())
	return err
}

func (s *Store) SCAPContentList() ([]SCAPContent, error) {
	rows, err := s.db.Query(`SELECT name,kind,filename,sha256,size,source,added_by,added FROM scap_content ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SCAPContent{}
	for rows.Next() {
		var c SCAPContent
		var a int64
		if err := rows.Scan(&c.Name, &c.Kind, &c.Filename, &c.SHA256, &c.Size, &c.Source, &c.AddedBy, &a); err != nil {
			return nil, err
		}
		c.Added = ts(a)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetSCAPContent(name string) (SCAPContent, error) {
	var c SCAPContent
	var a int64
	err := s.db.QueryRow(`SELECT name,kind,filename,sha256,size,source,added_by,added FROM scap_content WHERE name=?`, name).
		Scan(&c.Name, &c.Kind, &c.Filename, &c.SHA256, &c.Size, &c.Source, &c.AddedBy, &a)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	c.Added = ts(a)
	return c, err
}

func (s *Store) DeleteSCAPContent(name string) error {
	res, err := s.db.Exec(`DELETE FROM scap_content WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
