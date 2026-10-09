// Package store persists registry instance records in SQLite.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
)

// Registry is one tenant's registry (stored and served as "customer": the name predates "tenant"). Secret fields never serialise.
type Registry struct {
	Name        string    `json:"name"`
	Customer    string    `json:"customer"`
	Image       string    `json:"image"`
	HostPort    int       `json:"hostPort"`
	StorageSize string    `json:"storageSize"`
	CreatedAt   time.Time `json:"createdAt"`

	AdminPass  string            `json:"-"` // password of the internal _admin htpasswd user
	TLSCert    string            `json:"-"` // PEM; empty = plain HTTP
	TLSKey     string            `json:"-"` // PEM
	ConfigYAML string            `json:"-"` // custom config.yml; empty = image default
	Env        map[string]string `json:"-"` // extra REGISTRY_* overrides
}

// User is an htpasswd entry (bcrypt hash).
type User struct {
	Name string
	Hash string
}

type Store struct{ db *sql.DB }

const cols = `name,customer,image,host_port,storage_size,created_at,admin_pass,tls_cert,tls_key,config_yaml,env_json`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS registries (
		name         TEXT PRIMARY KEY,
		customer     TEXT NOT NULL,
		image        TEXT NOT NULL,
		host_port    INTEGER NOT NULL UNIQUE,
		storage_size TEXT NOT NULL,
		created_at   INTEGER NOT NULL,
		admin_pass   TEXT NOT NULL DEFAULT '',
		tls_cert     TEXT NOT NULL DEFAULT '',
		tls_key      TEXT NOT NULL DEFAULT '',
		config_yaml  TEXT NOT NULL DEFAULT '',
		env_json     TEXT NOT NULL DEFAULT '{}'
	);
	CREATE TABLE IF NOT EXISTS registry_users (
		registry TEXT NOT NULL,
		username TEXT NOT NULL,
		hash     TEXT NOT NULL,
		PRIMARY KEY (registry, username)
	);` + authSchema + securitySchema)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Create(r Registry, users []User) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	env, _ := json.Marshal(r.Env)
	_, err = tx.Exec(`INSERT INTO registries (`+cols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		r.Name, r.Customer, r.Image, r.HostPort, r.StorageSize, r.CreatedAt.Unix(),
		r.AdminPass, r.TLSCert, r.TLSKey, r.ConfigYAML, string(env))
	if err != nil {
		if isConstraint(err) {
			return ErrExists
		}
		return err
	}
	if err := replaceUsers(tx, r.Name, users); err != nil {
		return err
	}
	return tx.Commit()
}

// Save persists the mutable parts of a registry (TLS, config, env) and replaces its users atomically.
func (s *Store) Save(r Registry, users []User) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	env, _ := json.Marshal(r.Env)
	res, err := tx.Exec(`UPDATE registries SET tls_cert=?,tls_key=?,config_yaml=?,env_json=? WHERE name=?`,
		r.TLSCert, r.TLSKey, r.ConfigYAML, string(env), r.Name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := replaceUsers(tx, r.Name, users); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceUsers(tx *sql.Tx, reg string, users []User) error {
	if _, err := tx.Exec(`DELETE FROM registry_users WHERE registry=?`, reg); err != nil {
		return err
	}
	for _, u := range users {
		if _, err := tx.Exec(`INSERT INTO registry_users VALUES (?,?,?)`, reg, u.Name, u.Hash); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Users(reg string) ([]User, error) {
	rows, err := s.db.Query(`SELECT username,hash FROM registry_users WHERE registry=? ORDER BY username`, reg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Name, &u.Hash); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) Get(name string) (Registry, error) {
	return scan(s.db.QueryRow(`SELECT `+cols+` FROM registries WHERE name=?`, name))
}

func (s *Store) List() ([]Registry, error) {
	rows, err := s.db.Query(`SELECT ` + cols + ` FROM registries ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Registry{}
	for rows.Next() {
		r, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Delete(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM registries WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	for _, q := range []string{`DELETE FROM registry_users WHERE registry=?`, `DELETE FROM account_registries WHERE registry=?`, `DELETE FROM scans WHERE registry=?`, `DELETE FROM signing_keys WHERE registry=?`, `DELETE FROM trust_keys WHERE registry=?`} {
		if _, err := tx.Exec(q, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UsedPorts() (map[int]bool, error) {
	rows, err := s.db.Query(`SELECT host_port FROM registries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := map[int]bool{}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		used[p] = true
	}
	return used, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scan(sc scanner) (Registry, error) {
	var r Registry
	var ts int64
	var env string
	err := sc.Scan(&r.Name, &r.Customer, &r.Image, &r.HostPort, &r.StorageSize, &ts,
		&r.AdminPass, &r.TLSCert, &r.TLSKey, &r.ConfigYAML, &env)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.CreatedAt = time.Unix(ts, 0).UTC()
	if err := json.Unmarshal([]byte(env), &r.Env); err != nil {
		return r, err
	}
	return r, nil
}

func isConstraint(err error) bool {
	return strings.Contains(err.Error(), "constraint failed")
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func parseDetail(s string) map[string]string {
	if s == "" {
		return nil
	}
	var m map[string]string
	if json.Unmarshal([]byte(s), &m) != nil {
		return nil
	}
	return m
}
