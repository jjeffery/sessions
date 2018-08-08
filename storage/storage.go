// Package storage defines a Provider interface for persistent record storage.
// The provider allows both versioned and unversioned records. Each
// record stored has a time when the record expires, and can be deleted.
package storage

import (
	"context"
	"errors"
	"time"
)

const (
	// MaxIDLength is the maximum allowed length of a Record.ID field.
	MaxIDLength = 255
)

var (
	// ErrVersionConflict is the error returned by Provider.Save when a
	// version conflict is detected.
	ErrVersionConflict = errors.New("version conflict")
)

// Record contains information that is persisted to the Provider.
type Record struct {
	ID      string    // unique identifer, maximum length 255 bytes
	Version int64     // optimistic locking version, must be > 0
	Expires time.Time // time that this record expires, and can be deleted
	Format  string    // arbitrary string that can be used to interpret the contents of Data
	Data    []byte    // opaque data to be stored
}

// Provider is the interface used by the session store for persisting session information
// to a database.
type Provider interface {
	// Fetch returns a record from the database given its unique ID. An unversioned
	// record can have any value in the Version field, as it will be ignored.
	Fetch(ctx context.Context, id string) (*Record, error)

	// Save saves a record to the database, optionally checking for any version conflicts.
	//
	// If expectVersion is greater than zero, then a version conflict occurs
	// if the matching record in the database has a different version, or if there
	// is no matching record in the database.
	//
	// If expectVersion is zero, then a version conflict error occurs if a matching
	// record already exists in the database.
	//
	// In both cases, if a version conflict occurs, then Save returns an error value
	// of ErrVersionConflict.
	//
	// If expectVersion is negative, then no version check is performed.
	// If there is no matching record in the database, a new record is created.
	// If there is a matching record in the database, it is completely replaced.
	// The record's version field is ignored, and does not need to be saved.
	Save(ctx context.Context, rec *Record, expectVersion int64) error

	// Delete the record given its unique ID. No version check is performed. It
	// is not an error if the record does not exist.
	Delete(ctx context.Context, id string) error
}
