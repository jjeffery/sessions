package secret

import (
	"context"
	"testing"
	"time"
)

func TestRefresh(t *testing.T) {
	sr := newStubRestore()
	defer sr.restore()
	store := &memoryStore{}
	ctx := context.Background()
	safe := New(store, 0)

	now := time.Now()
	timeNowFunc = func() time.Time {
		return now
	}

	if got, want := safe.shouldRefreshNow(), true; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if err := safe.Refresh(ctx); err != nil {
		t.Fatalf("got=%v, want=nil", err)

	}

	if got, want := safe.shouldRefreshNow(), false; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if got, want := len(safe.codeBook.Secrets), 1; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	now = now.Add(safe.RotationPeriod() + time.Second)

	if got, want := safe.shouldRefreshNow(), true; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if err := safe.Refresh(ctx); err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}

	if got, want := safe.shouldRefreshNow(), false; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if got, want := len(safe.codeBook.Secrets), 2; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	now = now.Add(minimumRotationPeriod + 1)

	if got, want := safe.shouldRefreshNow(), true; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if err := safe.Refresh(ctx); err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}

	if got, want := safe.shouldRefreshNow(), false; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if got, want := len(safe.codeBook.Secrets), 2; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
}

type stubRestore struct {
	timeNow  func() time.Time
	randRead func(b []byte) (n int, err error)
}

func newStubRestore() stubRestore {
	return stubRestore{
		timeNow:  timeNowFunc,
		randRead: randReadFunc,
	}
}

func (sr stubRestore) restore() {
	timeNowFunc = sr.timeNow
	randReadFunc = sr.randRead
}

type memoryStore struct {
	rec    *Record
	getErr error
	putErr error
}

func (ms *memoryStore) GetSecret(ctx context.Context) (*Record, error) {
	if ms.getErr != nil {
		return nil, ms.getErr
	}
	if ms.rec == nil {
		return nil, nil
	}
	var rec = *ms.rec
	return &rec, nil
}

func (ms *memoryStore) PutSecret(ctx context.Context, rec *Record) (bool, error) {
	if ms.putErr != nil {
		return false, ms.putErr
	}
	if ms.rec == nil {
		if rec.Version != 0 {
			return false, nil
		}
	} else if ms.rec.Version != rec.Version {
		return false, nil
	}
	rec.Version++
	var copy = *rec
	ms.rec = &copy
	return true, nil
}

func (safe *Safe) shouldRefreshNow() bool {
	return safe.RefreshIn() <= 0
}
