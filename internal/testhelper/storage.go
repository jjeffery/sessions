package testhelper

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jjeffery/sessions/storage"
)

// TestStorageProvider runs a set of common tests on a storage.Provider implementation.
func TestStorageProvider(t *testing.T, db storage.Provider) {
	conflictTest(t, db)
	raceTest(t, db)
}

func conflictTest(t *testing.T, db storage.Provider) {
	ctx := context.Background()
	const id = "conflict-test-id"
	defer db.Delete(ctx, id)

	var saveRec storage.Record

	saveRec = storage.Record{
		ID:      id,
		Format:  "anything",
		Data:    []byte{0},
		Expires: time.Now().Add(time.Hour * 12),
	}
	for oldVersion := int64(0); oldVersion < 3; oldVersion++ {
		saveRec.Version = oldVersion + 1
		if err := db.Save(ctx, &saveRec, oldVersion); err != nil {
			t.Fatalf("got=%v, want=nil", err)
		}
		if got, want := db.Save(ctx, &saveRec, oldVersion), storage.ErrVersionConflict; got != want {
			t.Fatalf("got=%v, want=%v", got, want)
		}
	}

	rec, err := db.Fetch(ctx, id)
	if err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}
	if got, want := rec.Version, saveRec.Version; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	// first delete
	if err := db.Delete(ctx, id); err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}

	// second delete should succeed, even though the record is gone
	if err := db.Delete(ctx, id); err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}

	rec, err = db.Fetch(ctx, id)
	if err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}
	if rec != nil {
		t.Fatalf("got=%v, want=nil", rec)
	}

	{
		oldVersion := saveRec.Version
		saveRec.Version++
		if got, want := db.Save(ctx, &saveRec, oldVersion), storage.ErrVersionConflict; got != want {
			t.Fatalf("got=%v, want=%v", got, want)
		}
	}
}

func raceTest(t *testing.T, db storage.Provider) {
	const loopCount = 20
	var wg sync.WaitGroup
	for i := 0; i < loopCount; i++ {
		wg.Add(1)
		go func(i int) {
			raceTest1(t, db, i)
			wg.Done()
		}(i)

		wg.Add(1)
		go func(i int) {
			raceTest2(t, db, i, true)
			wg.Done()
		}(i)

		wg.Add(1)
		go func(i int) {
			raceTest2(t, db, i, false)
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func raceTest1(t *testing.T, db storage.Provider, instance int) {
	const loopCount = 20
	ctx := context.Background()
	const id = "record-id-for-race-testing"
	const format = "testing"
	expires := time.Now().Add(time.Hour * 12)
	data := make([]byte, 256)

	for version := int64(0); version < loopCount; version++ {
		data[0] = byte(version % 256)
		rec := &storage.Record{
			ID:      id,
			Version: version + 1,
			Expires: expires,
			Format:  format,
			Data:    data,
		}
		err := db.Save(ctx, rec, version)
		if err == nil {
			t.Logf("%d: saved version %d", instance, version)
			continue
		}
		if err == storage.ErrVersionConflict {
			rec, err = db.Fetch(ctx, id)
			if err != nil {
				t.Errorf("%d: %v", instance, err)
			}
			if got, want := rec.Data[0], byte((rec.Version-1)%256); got != want {
				t.Errorf("%d: got=%v, want=%v", instance, got, want)
			}
			continue
		}
		t.Errorf("%d: %v", instance, err)
	}
}

func raceTest2(t *testing.T, db storage.Provider, instance int, add bool) {
	const loopCount = 20
	ctx := context.Background()
	for i := 0; i < loopCount; i++ {
		id := fmt.Sprintf("record-%d-%d", instance, i)
		if add {
			rec := storage.Record{
				ID:      id,
				Format:  "test",
				Expires: time.Now().Add(12 * time.Hour),
				Data:    []byte{byte(i % 256)},
			}
			if err := db.Save(ctx, &rec, -1); err != nil {
				t.Fatalf("%d: %d: %v", instance, i, err)
				continue
			}
		} else {
			for {
				rec, err := db.Fetch(ctx, id)
				if err != nil {
					t.Fatalf("%d: %d: %v", instance, i, err)
				}
				if rec != nil {
					if got, want := rec.Data[0], byte(i%256); got != want {
						t.Fatalf("%d: %d: got=%v, want=%v", instance, i, got, want)
					}
					if err := db.Delete(ctx, id); err != nil {
						t.Fatalf("%d: %d: %v", instance, i, err)
					}
					rec, err = db.Fetch(ctx, id)
					if err != nil {
						t.Fatalf("%d: %d: %v", instance, i, err)
					}
					if rec != nil {
						t.Fatalf("%d: %d: got=%v, want=nil", instance, i, rec)
					}
					break

				}
				time.Sleep(time.Millisecond * 250)
			}
		}
	}
}
