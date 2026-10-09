package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Account is a manager login (local or federated through OIDC).
type Account struct {
	ID            int64     `json:"id"`
	Username      string    `json:"username"`
	DisplayName   string    `json:"displayName"`
	Role          string    `json:"role"`
	Source        string    `json:"source"` // "local" or "oidc"
	OIDCSubject   string    `json:"-"`
	PasswordHash  string    `json:"-"`
	Disabled      bool      `json:"disabled"`
	MustChange    bool      `json:"mustChangePassword"`
	AllRegistries bool      `json:"allRegistries"`
	Registries    []string  `json:"registries"` // explicit assignments (ignored when AllRegistries)
	CreatedAt     time.Time `json:"createdAt"`
	LastLogin     time.Time `json:"lastLogin"`
}

type Session struct {
	AccountID int64
	CreatedAt time.Time
	ExpiresAt time.Time
	LastSeen  time.Time
}

type AuditEntry struct {
	ID        int64             `json:"id"`
	Time      time.Time         `json:"time"`
	Actor     string            `json:"actor"`
	ActorRole string            `json:"actorRole"`
	Action    string            `json:"action"`
	Target    string            `json:"target"`
	Detail    map[string]string `json:"detail,omitempty"`
	Outcome   string            `json:"outcome"` // "ok" or "denied"/"error"
	IP        string            `json:"ip"`
}

type AuditFilter struct {
	Actor, Action, Target, Outcome string // exact match on actor/outcome; prefix match on action/target
	Since, Until                   time.Time
	BeforeID                       int64 // cursor: only entries with id < BeforeID
	Limit                          int
}

const authSchema = `
CREATE TABLE IF NOT EXISTS accounts (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
	display_name   TEXT NOT NULL DEFAULT '',
	role           TEXT NOT NULL,
	source         TEXT NOT NULL,
	oidc_subject   TEXT,
	password_hash  TEXT NOT NULL DEFAULT '',
	disabled       INTEGER NOT NULL DEFAULT 0,
	must_change    INTEGER NOT NULL DEFAULT 0,
	all_registries INTEGER NOT NULL DEFAULT 0,
	created_at     INTEGER NOT NULL,
	last_login     INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS accounts_oidc ON accounts(oidc_subject) WHERE oidc_subject IS NOT NULL;
CREATE TABLE IF NOT EXISTS account_registries (
	account_id INTEGER NOT NULL,
	registry   TEXT NOT NULL,
	PRIMARY KEY (account_id, registry)
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	account_id INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_account ON sessions(account_id);
CREATE TABLE IF NOT EXISTS audit (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         INTEGER NOT NULL,
	actor      TEXT NOT NULL,
	actor_role TEXT NOT NULL DEFAULT '',
	action     TEXT NOT NULL,
	target     TEXT NOT NULL DEFAULT '',
	detail     TEXT NOT NULL DEFAULT '',
	outcome    TEXT NOT NULL,
	ip         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS audit_actor ON audit(actor);
CREATE INDEX IF NOT EXISTS audit_target ON audit(target);
`

const acctCols = `id,username,display_name,role,source,COALESCE(oidc_subject,''),password_hash,disabled,must_change,all_registries,created_at,last_login`

func scanAccount(sc scanner) (Account, error) {
	var a Account
	var created, last int64
	var dis, must, all int
	err := sc.Scan(&a.ID, &a.Username, &a.DisplayName, &a.Role, &a.Source, &a.OIDCSubject, &a.PasswordHash, &dis, &must, &all, &created, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	a.Disabled, a.MustChange, a.AllRegistries = dis != 0, must != 0, all != 0
	a.CreatedAt = time.Unix(created, 0).UTC()
	if last > 0 {
		a.LastLogin = time.Unix(last, 0).UTC()
	}
	a.Registries = []string{}
	return a, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) loadRegistries(a *Account) error {
	rows, err := s.db.Query(`SELECT registry FROM account_registries WHERE account_id=? ORDER BY registry`, a.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return err
		}
		a.Registries = append(a.Registries, r)
	}
	return rows.Err()
}

func (s *Store) getAccount(where string, arg any) (Account, error) {
	a, err := scanAccount(s.db.QueryRow(`SELECT `+acctCols+` FROM accounts WHERE `+where, arg))
	if err != nil {
		return a, err
	}
	return a, s.loadRegistries(&a)
}

func (s *Store) AccountByID(id int64) (Account, error)       { return s.getAccount("id=?", id) }
func (s *Store) AccountByUsername(u string) (Account, error) { return s.getAccount("username=?", u) }
func (s *Store) AccountByOIDCSubject(sub string) (Account, error) {
	return s.getAccount("oidc_subject=?", sub)
}

func (s *Store) CountAccounts() (int, error) {
	var n int
	return n, s.db.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&n)
}

// CountActiveAdmins counts enabled admins, optionally ignoring one account.
func (s *Store) CountActiveAdmins(except int64) (int, error) {
	var n int
	return n, s.db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE role='admin' AND disabled=0 AND id<>?`, except).Scan(&n)
}

func (s *Store) ListAccounts() ([]Account, error) {
	rows, err := s.db.Query(`SELECT ` + acctCols + ` FROM accounts ORDER BY username`)
	if err != nil {
		return nil, err
	}
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, a)
	}
	rows.Close()
	for i := range out {
		if err := s.loadRegistries(&out[i]); err != nil {
			return nil, err
		}
	}
	if out == nil {
		out = []Account{}
	}
	return out, nil
}

func (s *Store) CreateAccount(a Account) (Account, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return a, err
	}
	defer tx.Rollback()
	var sub any
	if a.OIDCSubject != "" {
		sub = a.OIDCSubject
	}
	res, err := tx.Exec(`INSERT INTO accounts (username,display_name,role,source,oidc_subject,password_hash,disabled,must_change,all_registries,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		a.Username, a.DisplayName, a.Role, a.Source, sub, a.PasswordHash, b2i(a.Disabled), b2i(a.MustChange), b2i(a.AllRegistries), time.Now().Unix())
	if err != nil {
		if isConstraint(err) {
			return a, ErrExists
		}
		return a, err
	}
	id, _ := res.LastInsertId()
	if err := setRegistries(tx, id, a.Registries); err != nil {
		return a, err
	}
	if err := tx.Commit(); err != nil {
		return a, err
	}
	return s.AccountByID(id)
}

// UpdateAccount writes the editable fields (not credentials; see SetPassword).
func (s *Store) UpdateAccount(a Account) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE accounts SET display_name=?,role=?,disabled=?,all_registries=?,must_change=? WHERE id=?`,
		a.DisplayName, a.Role, b2i(a.Disabled), b2i(a.AllRegistries), b2i(a.MustChange), a.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := setRegistries(tx, a.ID, a.Registries); err != nil {
		return err
	}
	return tx.Commit()
}

func setRegistries(tx *sql.Tx, id int64, regs []string) error {
	if _, err := tx.Exec(`DELETE FROM account_registries WHERE account_id=?`, id); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range regs {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		if _, err := tx.Exec(`INSERT INTO account_registries VALUES (?,?)`, id, r); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SetPassword(id int64, hash string, mustChange bool) error {
	res, err := s.db.Exec(`UPDATE accounts SET password_hash=?,must_change=? WHERE id=?`, hash, b2i(mustChange), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) TouchLogin(id int64) error {
	_, err := s.db.Exec(`UPDATE accounts SET last_login=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

func (s *Store) DeleteAccount(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM accounts WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	for _, q := range []string{`DELETE FROM account_registries WHERE account_id=?`, `DELETE FROM sessions WHERE account_id=?`} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- sessions ----

func (s *Store) CreateSession(tokenHash string, accountID int64, expires time.Time) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO sessions VALUES (?,?,?,?,?)`, tokenHash, accountID, now, expires.Unix(), now)
	return err
}

func (s *Store) GetSession(tokenHash string) (Session, error) {
	var se Session
	var created, exp, seen int64
	err := s.db.QueryRow(`SELECT account_id,created_at,expires_at,last_seen FROM sessions WHERE token_hash=?`, tokenHash).Scan(&se.AccountID, &created, &exp, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return se, ErrNotFound
	}
	se.CreatedAt, se.ExpiresAt, se.LastSeen = time.Unix(created, 0), time.Unix(exp, 0), time.Unix(seen, 0)
	return se, err
}

func (s *Store) TouchSession(tokenHash string, expires time.Time) error {
	_, err := s.db.Exec(`UPDATE sessions SET expires_at=?,last_seen=? WHERE token_hash=?`, expires.Unix(), time.Now().Unix(), tokenHash)
	return err
}

func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

// DeleteSessionsFor ends every session of an account, optionally keeping one.
func (s *Store) DeleteSessionsFor(id int64, keepHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE account_id=? AND token_hash<>?`, id, keepHash)
	return err
}

func (s *Store) PurgeSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at<?`, time.Now().Unix())
	return err
}

// RemoveRegistryAccess drops every assignment to a registry (called when it is deleted, so a
// later registry with the same name does not inherit access).
func (s *Store) RemoveRegistryAccess(name string) error {
	_, err := s.db.Exec(`DELETE FROM account_registries WHERE registry=?`, name)
	return err
}

// ---- audit ----

func (s *Store) AddAudit(e AuditEntry) error {
	detail := ""
	if len(e.Detail) > 0 {
		detail = mustJSON(e.Detail)
	}
	_, err := s.db.Exec(`INSERT INTO audit (ts,actor,actor_role,action,target,detail,outcome,ip) VALUES (?,?,?,?,?,?,?,?)`,
		time.Now().UnixMilli(), e.Actor, e.ActorRole, e.Action, e.Target, detail, e.Outcome, e.IP)
	return err
}

func (s *Store) QueryAudit(f AuditFilter) ([]AuditEntry, error) {
	var where []string
	var args []any
	add := func(cond string, v any) { where = append(where, cond); args = append(args, v) }
	if f.Actor != "" {
		add("actor=? COLLATE NOCASE", f.Actor)
	}
	if f.Outcome != "" {
		add("outcome=?", f.Outcome)
	}
	if f.Action != "" {
		add("action LIKE ? ESCAPE '\\'", likePrefix(f.Action))
	}
	if f.Target != "" {
		add("target LIKE ? ESCAPE '\\'", likePrefix(f.Target))
	}
	if !f.Since.IsZero() {
		add("ts>=?", f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		add("ts<?", f.Until.UnixMilli())
	}
	if f.BeforeID > 0 {
		add("id<?", f.BeforeID)
	}
	q := `SELECT id,ts,actor,actor_role,action,target,detail,outcome,ip FROM audit`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 50000 {
		limit = 100
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var ts int64
		var detail string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.ActorRole, &e.Action, &e.Target, &detail, &e.Outcome, &e.IP); err != nil {
			return nil, err
		}
		e.Time = time.UnixMilli(ts).UTC()
		e.Detail = parseDetail(detail)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) PurgeAudit(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit WHERE ts<?`, before.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func likePrefix(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(v) + "%"
}
