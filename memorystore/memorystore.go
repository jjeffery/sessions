package memorystore

import (
	"context"
	"sync"

	"github.com/jjeffery/sessions/sessionstore"
)

// DB implements the sessionstore.DB interface and is intended for testing.
type DB struct {
	mutex sync.Mutex
	m     map[string]*sessionstore.Record
}

// NewDB creates a new memory DB.
func NewDB() *DB {
	return &DB{}
}

// Get implements the sessionstore.DB interface.
func (db *DB) Get(ctx context.Context, id string) (*sessionstore.Record, error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	return cloneRecord(db.m[id]), nil
}

// PutUnversioned implements the sessionstore.DB interface.
func (db *DB) PutUnversioned(ctx context.Context, rec *sessionstore.Record) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	if db.m == nil {
		db.m = make(map[string]*sessionstore.Record)
	}
	db.m[rec.ID] = cloneRecord(rec)
	return nil
}

// PutVersioned implements the sessionstore.DB interface.
func (db *DB) PutVersioned(ctx context.Context, rec *sessionstore.Record, oldVersion int64) (ok bool, err error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	if oldVersion == 0 {
		if _, ok := db.m[rec.ID]; ok {
			// record already exists
			return false, nil
		}
	} else {
		existing := db.m[rec.ID]
		if existing == nil {
			return false, nil
		}
		if existing.Version != oldVersion {
			return false, nil
		}
	}
	if db.m == nil {
		db.m = make(map[string]*sessionstore.Record)
	}
	db.m[rec.ID] = cloneRecord(rec)
	return true, nil
}

// Delete implements the sessionstore.DB interface.
func (db *DB) Delete(ctx context.Context, id string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	delete(db.m, id)
	return nil
}

// cloneRecord copies a record, but does not do a very good job
// with the Values field.
func cloneRecord(rec *sessionstore.Record) *sessionstore.Record {
	if rec == nil {
		return nil
	}
	cpy := *rec
	cpy.Values = make(map[string]interface{})
	for k, v := range rec.Values {
		cpy.Values[k] = v
	}
	return &cpy
}
