// Package memory has a memory-backed storage provider for testing purposes.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/jjeffery/sessions/storage"
)

// Provider implements the storage.Provider using memory. It is intended for testing.
type Provider struct {
	// TimeNow is used to obtain the current time.
	TimeNow func() time.Time

	mutex sync.RWMutex
	m     map[string]*storage.Record
}

// New creates a new memory-backed Provider.
func New() *Provider {
	return &Provider{
		TimeNow: time.Now,
	}
}

// WithTimeNow sets the TimeNow function. It returns db.
func (db *Provider) WithTimeNow(timeNow func() time.Time) *Provider {
	if timeNow == nil {
		timeNow = time.Now
	}
	db.TimeNow = timeNow
	return db
}

// Fetch implements the Provider interface.
func (db *Provider) Fetch(ctx context.Context, id string) (*storage.Record, error) {
	db.mutex.RLock()
	rec := cloneRecord(db.m[id])
	db.mutex.RUnlock()
	if rec != nil && rec.Expires.Before(db.TimeNow()) {
		db.Delete(ctx, rec.ID)
		rec = nil
	}
	return rec, nil
}

// Save implements the Provider interface.
func (db *Provider) Save(ctx context.Context, rec *storage.Record, oldVersion int64) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	if oldVersion >= 0 && rec.Version <= 0 {
		// should never happen, panic if this happens during testing
		panic("invalid rec.Version")
	}
	if oldVersion == 0 {
		if _, ok := db.m[rec.ID]; ok {
			// record already exists
			return storage.ErrVersionConflict
		}
	} else if oldVersion > 0 {
		existing := db.m[rec.ID]
		if existing == nil {
			return storage.ErrVersionConflict
		}
		if existing.Version != oldVersion {
			return storage.ErrVersionConflict
		}
	}
	if db.m == nil {
		db.m = make(map[string]*storage.Record)
	}
	db.m[rec.ID] = cloneRecord(rec)
	return nil
}

// Delete implements the Provider interface.
func (db *Provider) Delete(ctx context.Context, id string) error {
	db.mutex.Lock()
	delete(db.m, id)
	db.mutex.Unlock()
	return nil
}

// cloneRecord copies a record, but does not do a very good job
// with the Values field.
func cloneRecord(rec *storage.Record) *storage.Record {
	if rec == nil {
		return nil
	}
	cpy := *rec
	if rec.Data != nil {
		cpy.Data = make([]byte, len(rec.Data))
		copy(cpy.Data, rec.Data)
	}
	return &cpy
}
