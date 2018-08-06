package postgresstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jjeffery/errors"
	"github.com/jjeffery/sessions/sessionstore"
)

// DB provides storage for sessions using a PostgreSQL table.
// It implements the sessionstore.DB interface.
//
// The structure of the SQL table is described in the package comment.
type DB struct {
	db        *sql.DB
	tableName string
}

// NewDB creates a new DB given a database handle and the PostgreSQL table name.
func NewDB(db *sql.DB, tableName string) *DB {
	if tableName == "" {
		tableName = "http_sessions"
	}
	return &DB{
		db:        db,
		tableName: tableName,
	}
}

// CreateTable creates the dynamodb table.
func (db *DB) CreateTable() error {
	errors := errors.With("table", db.tableName)
	queryFmt := `create table if not exists %s(` +
		`id character varying(256) primary key,` +
		` version integer null,` +
		` expires_at timestamp with time zone null,` +
		` values_json jsonb null)`
	query := fmt.Sprintf(queryFmt, db.tableName)
	ctx := context.TODO()
	if _, err := db.db.ExecContext(ctx, query); err != nil {
		return errors.Wrap(err, "cannot create table")
	}

	return nil
}

// DropTable deletes the DynamoDB table.
func (db *DB) DropTable() error {
	errors := errors.With("table", db.tableName)
	query := fmt.Sprintf(`drop table if exists %s`, db.tableName)
	ctx := context.TODO()
	if _, err := db.db.ExecContext(ctx, query); err != nil {
		return errors.Wrap(err, "cannot create table")
	}
	return nil
}

// Get implements the sessionstore.DB interface.
func (db *DB) Get(ctx context.Context, id string) (*sessionstore.Record, error) {
	errors := errors.With("id", id, "table", db.tableName)
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot begin tx")
	}
	defer tx.Rollback()

	var version sql.NullInt64
	var expires nullTime
	var valuesJSON []byte

	query := fmt.Sprintf("select version, expires_at, values_json from %s where id = $1", db.tableName)
	err = db.db.QueryRowContext(ctx, query, id).Scan(
		&version,
		&expires,
		&valuesJSON,
	)
	if err == sql.ErrNoRows {
		// not found
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "cannot get record").With("query", query)
	}
	rec := &sessionstore.Record{
		ID: id,
	}
	if version.Valid {
		rec.Version = version.Int64
	}
	if expires.Valid {
		rec.Expires = expires.Time.Unix()
	}
	if valuesJSON == nil || len(valuesJSON) == 0 {
		rec.Values = make(map[string]interface{})
	} else {
		if err := json.Unmarshal(valuesJSON, &rec.Values); err != nil {
			return nil, errors.Wrap(err, "invalid JSON in values")
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "cannot commit tx")
	}

	return rec, nil
}

// PutUnversioned implements the sessionstore.DB interface.
func (db *DB) PutUnversioned(ctx context.Context, rec *sessionstore.Record) error {
	errors := errors.With("id", rec.ID, "table", db.tableName)
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "cannot begin tx")
	}
	defer tx.Rollback()

	valuesJSON, err := json.Marshal(rec.Values)
	if err != nil {
		return errors.Wrap(err, "cannot marshal to JSON")
	}
	var expires nullTime
	if rec.Expires > 0 {
		expires.Valid = true
		expires.Time = time.Unix(rec.Expires, 0)
	}
	queryFmt := `insert into %s(id, expires_at, values_json) values($1, $2, $3)` +
		` on conflict(id) do update set version = null, expires_at = $2, values_json = $3`
	query := fmt.Sprintf(queryFmt, db.tableName)
	if _, err := tx.ExecContext(ctx, query, rec.ID, expires, valuesJSON); err != nil {
		return errors.Wrap(err, "cannot update row")
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "cannot commit tx")
	}

	return nil
}

// PutVersioned implements the sessionstore.DB interface.
func (db *DB) PutVersioned(ctx context.Context, rec *sessionstore.Record, oldVersion int64) (ok bool, err error) {
	errors := errors.With("id", rec.ID, "table", db.tableName)
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return false, errors.Wrap(err, "cannot begin tx")
	}
	defer tx.Rollback()

	valuesJSON, err := json.Marshal(rec.Values)
	if err != nil {
		return false, errors.Wrap(err, "cannot marshal to JSON")
	}
	var expires nullTime
	if rec.Expires > 0 {
		expires.Valid = true
		expires.Time = time.Unix(rec.Expires, 0)
	}

	var rowCount int64
	if oldVersion == 0 {
		queryFmt := `insert into %s(id, version, expires_at, values_json) values($1, $2, $3, $4)` +
			` on conflict(id) do nothing`
		query := fmt.Sprintf(queryFmt, db.tableName)
		result, err := tx.ExecContext(ctx, query, rec.ID, rec.Version, expires, valuesJSON)
		if err != nil {
			return false, errors.Wrap(err, "cannot insert row")
		}
		rowCount, err = result.RowsAffected()
		if err != nil {
			return false, errors.Wrap(err, "cannot get rows affected")
		}
	} else {
		queryFmt := `update %s set version = $1, expires_at = $2, values_json = $3 where id = $4 and version = $5`
		query := fmt.Sprintf(queryFmt, db.tableName)
		result, err := tx.ExecContext(ctx, query, rec.Version, expires, valuesJSON, rec.ID, oldVersion)
		if err != nil {
			return false, errors.Wrap(err, "cannot update row")
		}
		rowCount, err = result.RowsAffected()
		if err != nil {
			return false, errors.Wrap(err, "cannot get rows affected")
		}
	}
	if err := tx.Commit(); err != nil {
		return false, errors.Wrap(err, "cannot commit tx")
	}

	if rowCount == 0 {
		// optimistic locking conflict
		return false, nil
	}
	return true, nil
}

// Delete implements the sessionstore.DB interface.
func (db *DB) Delete(ctx context.Context, id string) error {
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
func (db *DB) Purge(ctx context.Context) error {
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
