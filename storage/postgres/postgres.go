// Package postgres has a storage provider that uses a PostgreSQL database table.
//
// The database table is expected to have the following structure:
//  create table <table_name>(
//    id character varying(255) primary key,
//    version integer null,
//    expires_at timestamp with time zone null,
//    format character varying null,
//    data bytea null
//  )
package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/jjeffery/errors"
	"github.com/jjeffery/sessions/storage"
)

// Provider provides storage for sessions using a PostgreSQL table.
// It implements the storage.Provider interface.
//
// The structure of the SQL table is described in the package comment.
type Provider struct {
	db        *sql.DB
	tableName string
}

var (
	// ensure Provider implements storage.Provider
	_ storage.Provider = (*Provider)(nil)
)

// New creates a new Provider given a database handle and the PostgreSQL table name.
func New(db *sql.DB, tableName string) *Provider {
	if tableName == "" {
		tableName = "http_sessions"
	}
	return &Provider{
		db:        db,
		tableName: tableName,
	}
}

// CreateTable creates the dynamodb table.
func (db *Provider) CreateTable() error {
	errors := errors.With("table", db.tableName)
	queryFmt := `create table if not exists %s(` +
		`id character varying(255) primary key,` +
		` version integer null,` +
		` expires_at timestamp with time zone null,` +
		` format character varying null,` +
		` data bytea null)`
	query := fmt.Sprintf(queryFmt, db.tableName)
	ctx := context.TODO()
	if _, err := db.db.ExecContext(ctx, query); err != nil {
		return errors.Wrap(err, "cannot create table")
	}

	return nil
}

// DropTable deletes the DynamoDB table.
func (db *Provider) DropTable() error {
	errors := errors.With("table", db.tableName)
	query := fmt.Sprintf(`drop table if exists %s`, db.tableName)
	ctx := context.TODO()
	if _, err := db.db.ExecContext(ctx, query); err != nil {
		return errors.Wrap(err, "cannot create table")
	}
	return nil
}

// Fetch implements the storage.Provider interface.
func (db *Provider) Fetch(ctx context.Context, id string) (*storage.Record, error) {
	errors := errors.With("id", id, "table", db.tableName)
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot begin tx")
	}
	defer tx.Rollback()

	var version sql.NullInt64
	var expires nullTime
	var format sql.NullString
	var data []byte

	query := fmt.Sprintf("select version, expires_at, format, data from %s where id = $1", db.tableName)
	err = db.db.QueryRowContext(ctx, query, id).Scan(
		&version,
		&expires,
		&format,
		&data,
	)
	if err == sql.ErrNoRows {
		// not found
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "cannot get record").With("query", query)
	}
	rec := &storage.Record{
		ID: id,
	}
	if version.Valid {
		rec.Version = version.Int64
	}
	if expires.Valid {
		rec.ExpiresAt = expires.Time
	}
	if format.Valid {
		rec.Format = format.String
	}
	rec.Data = data
	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "cannot commit tx")
	}

	return rec, nil
}

// Save implements the storage.Provider interface.
func (db *Provider) Save(ctx context.Context, rec *storage.Record, oldVersion int64) error {
	if oldVersion < 0 {
		return db.saveUnversioned(ctx, rec)
	}
	return db.saveVersioned(ctx, rec, oldVersion)
}

func (db *Provider) saveUnversioned(ctx context.Context, rec *storage.Record) error {
	errors := errors.With("id", rec.ID, "table", db.tableName)
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "cannot begin tx")
	}
	defer tx.Rollback()

	var format sql.NullString
	if rec.Format != "" {
		format.Valid = true
		format.String = rec.Format
	}

	var expires nullTime
	if !rec.ExpiresAt.IsZero() {
		expires.Valid = true
		expires.Time = rec.ExpiresAt
	}
	queryFmt := `insert into %s(id, expires_at, format, data) values($1, $2, $3, $4)` +
		` on conflict(id) do update set version = null, expires_at = $2, format = $3, data = $4`
	query := fmt.Sprintf(queryFmt, db.tableName)
	if _, err := tx.ExecContext(ctx, query, rec.ID, expires, format, rec.Data); err != nil {
		return errors.Wrap(err, "cannot update row")
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "cannot commit tx")
	}

	return nil
}

func (db *Provider) saveVersioned(ctx context.Context, rec *storage.Record, oldVersion int64) error {
	errors := errors.With("id", rec.ID, "table", db.tableName)
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "cannot begin tx")
	}
	defer tx.Rollback()

	var format sql.NullString
	if rec.Format != "" {
		format.Valid = true
		format.String = rec.Format
	}

	var expires nullTime
	if !rec.ExpiresAt.IsZero() {
		expires.Valid = true
		expires.Time = rec.ExpiresAt
	}

	var rowCount int64
	if oldVersion == 0 {
		queryFmt := `insert into %s(id, version, expires_at, format, data) values($1, $2, $3, $4, $5)` +
			` on conflict(id) do nothing`
		query := fmt.Sprintf(queryFmt, db.tableName)
		result, err := tx.ExecContext(ctx, query, rec.ID, rec.Version, expires, format, rec.Data)
		if err != nil {
			return errors.Wrap(err, "cannot insert row")
		}
		rowCount, err = result.RowsAffected()
		if err != nil {
			return errors.Wrap(err, "cannot get rows affected")
		}
	} else {
		queryFmt := `update %s set version = $1, expires_at = $2, format = $3, data = $4` +
			` where id = $5` +
			` and version = $6`
		query := fmt.Sprintf(queryFmt, db.tableName)
		result, err := tx.ExecContext(ctx, query, rec.Version, expires, format, rec.Data, rec.ID, oldVersion)
		if err != nil {
			return errors.Wrap(err, "cannot update row")
		}
		rowCount, err = result.RowsAffected()
		if err != nil {
			return errors.Wrap(err, "cannot get rows affected")
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "cannot commit tx")
	}

	if rowCount == 0 {
		// optimistic locking conflict
		return storage.ErrVersionConflict
	}
	return nil
}

// Delete implements the storage.Provider interface.
func (db *Provider) Delete(ctx context.Context, id string) error {
	errors := errors.With("id", id, "table", db.tableName)
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "cannot begin tx")
	}
	defer tx.Rollback()

	query := fmt.Sprintf("delete from %s where id = $1", db.tableName)
	if _, err := tx.ExecContext(ctx, query, id); err != nil {
		return errors.Wrap(err, "cannot delete row")
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "cannot commit tx")
	}

	return nil
}

// Purge deletes all expired records.
func (db *Provider) Purge(ctx context.Context) error {
	errors := errors.With("table", db.tableName)
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "cannot begin tx")
	}
	defer tx.Rollback()

	// TODO(jpj): would be more robust to have a limit
	query := fmt.Sprintf("delete from %s where expires_at < now()", db.tableName)
	if _, err := tx.ExecContext(ctx, query); err != nil {
		return errors.Wrap(err, "cannot delete row")
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "cannot commit tx")
	}

	return nil
}

type nullTime struct {
	Time  time.Time
	Valid bool // Valid is true if Time is not NULL
}

// Scan implements the Scanner interface.
func (nt *nullTime) Scan(value interface{}) error {
	nt.Time, nt.Valid = value.(time.Time)
	return nil
}

// Value implements the driver Valuer interface.
func (nt nullTime) Value() (driver.Value, error) {
	if !nt.Valid {
		return nil, nil
	}
	return nt.Time, nil
}
