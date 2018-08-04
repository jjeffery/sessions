package sessionstore

import (
	"context"
	"sync"
)

// clone copies a record, used for testing
func (rec *Record) clone() *Record {
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

// memoryDB implements the DB interface and is used for testing.
type memoryDB struct {
	mutex sync.Mutex
	m     map[string]*Record
}

func (mdb *memoryDB) Get(ctx context.Context, id string) (*Record, error) {
	mdb.mutex.Lock()
	defer mdb.mutex.Unlock()
	return mdb.m[id].clone(), nil
}

func (mdb *memoryDB) PutUnversioned(ctx context.Context, rec *Record) error {
	mdb.mutex.Lock()
	defer mdb.mutex.Unlock()
	if mdb.m == nil {
		mdb.m = make(map[string]*Record)
	}
	mdb.m[rec.ID] = rec.clone()
	return nil
}

func (mdb *memoryDB) PutVersioned(ctx context.Context, rec *Record, oldVersion int64) (ok bool, err error) {
	mdb.mutex.Lock()
	defer mdb.mutex.Unlock()
	if oldVersion == 0 {
		if _, ok := mdb.m[rec.ID]; ok {
			// record already exists
			return false, nil
		}
	} else {
		existing := mdb.m[rec.ID]
		if existing == nil {
			return false, nil
		}
		if existing.Version != oldVersion {
			return false, nil
		}
	}
	if mdb.m == nil {
		mdb.m = make(map[string]*Record)
	}
	mdb.m[rec.ID] = rec.clone()
	return true, nil
}

func (mdb *memoryDB) Delete(ctx context.Context, id string) error {
	mdb.mutex.Lock()
	defer mdb.mutex.Unlock()
	delete(mdb.m, id)
	return nil
}
