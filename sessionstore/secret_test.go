package sessionstore

import (
	"context"
	"reflect"
	"testing"

	"github.com/jjeffery/sessions/internal/secret"
)

func TestSecret(t *testing.T) {
	TestingSecretHelper(t, &memoryDB{}, "")
	TestingSecretHelper(t, &memoryDB{}, "x")
}

func TestingSecretHelper(t *testing.T, db DB, appid string) {
	ctx := context.Background()
	ss := newSecretStore(db, appid)
	rec := secret.Record{
		Expires: 2000000,
		Format:  "test",
		Version: 1,
		Secret:  []byte{0, 1, 2, 3, 4, 5},
	}

	// should not work: record not exists
	ok, err := ss.PutSecret(ctx, &rec)
	wantNil(t, err)
	gotWant(t, ok, false)

	// should work: create new record
	rec.Version = 0
	ok, err = ss.PutSecret(ctx, &rec)
	wantNil(t, err)
	gotWant(t, ok, true)
	gotWant(t, rec.Version, int64(1))

	rec2, err := ss.GetSecret(ctx)
	wantNil(t, err)
	wantNonNil(t, rec2)
	wantDeepEqual(t, rec2, &rec)
}

func wantNil(t *testing.T, v interface{}) {
	t.Helper()
	if v != nil {
		t.Fatalf("got=%v, want=nil", v)
	}
}

func wantNonNil(t *testing.T, v interface{}) {
	t.Helper()
	if v == nil {
		t.Fatalf("got=nil, want=non-nil")
	}
}
func gotWant(t *testing.T, got, want interface{}) {
	t.Helper()
	if got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
}

func wantDeepEqual(t *testing.T, got, want *secret.Record) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%+v, want=%+v", got, want)
	}
}
