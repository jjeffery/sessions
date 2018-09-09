package memory

import (
	"context"
	"testing"
	"time"

	"github.com/jjeffery/sessions/internal/testhelper"
	"github.com/jjeffery/sessions/storage"
)

func TestMemoryDB(t *testing.T) {
	ctx := context.Background()
	db := New()
	testhelper.TestStorageProvider(t, db)

	// test that expires works for memorydb
	db = db.WithTimeNow(func() time.Time {
		return time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)
	})

	if err := db.Save(ctx, &storage.Record{ID: "XXX", ExpiresAt: time.Unix(0, 0)}, -1); err != nil {
		t.Fatal(err)
	}

	rec, err := db.Fetch(ctx, "XXX")
	if err != nil {
		t.Fatal(err)
	}
	if rec != nil {
		t.Fatalf("got=%v, want=nil", rec)
	}

	// test that setting the time func to nil works
	db = db.WithTimeNow(nil)
	if db.TimeNow == nil {
		t.Errorf("got=nil, want=non-nil")
	}

	// test panic when dodgy values are supplied
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected panic")
			}
		}()
		rec := storage.Record{
			ID: "YYY",
		}
		db.Save(ctx, &rec, 0)
	}()
}
