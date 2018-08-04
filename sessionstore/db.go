package sessionstore

import "context"

// Record contains information that is persisted to the DB.
type Record struct {
	ID      string
	Version int64
	Values  map[string]interface{}
	Expires int64
}

// DB is the interface used by the session store for persisting session information
// to a database.
type DB interface {
	// Get returns a record from the database given its unique ID. An unversioned
	// record can have any value in the Version field, as it will be ignored.
	Get(ctx context.Context, id string) (*Record, error)

	// PutUnversioned saves a record to the database. The record's version field
	// is ignored, and does not need to be saved in the database.
	PutUnversioned(ctx context.Context, rec *Record) error

	// PutVersioned saves a record to the database, ensuring that no other
	// party has modified the record since it was fetched.
	//
	// If oldVersion is zero, then a conflict occurs if a matching record already
	// exists in the database. If oldVersion is non-zero, then a conflict occurs
	// if the matching record in the database has a different version (or if there
	// is no matching record in the database).
	//
	// If a conflict occurs then ok is false. If there is no conflict then ok is
	// true.
	PutVersioned(ctx context.Context, rec *Record, oldVersion int64) (ok bool, err error)

	// Delete the record given its unique ID. No version check is performed. It
	// is not an error if the record does not exist.
	Delete(ctx context.Context, id string) error
}
