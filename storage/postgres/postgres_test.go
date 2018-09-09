package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jjeffery/sessions/internal/testhelper"
	"github.com/jjeffery/sessions/storage"
	_ "github.com/lib/pq"
)

func TestSessionStore(t *testing.T) {
	newDB := newDBFunc(t)

	testhelper.TestSessionStore(t, newDB)
	testhelper.TestStorageProvider(t, newDB())
}

func TestPurge(t *testing.T) {
	ctx := context.Background()
	db := postgresDB(t)
	stg := New(db, "")
	wantNoError(t, stg.DropTable())
	wantNoError(t, stg.CreateTable())
	rec := storage.Record{
		ID:        "xxx",
		ExpiresAt: time.Now().Add(-time.Second),
	}
	err := stg.Save(ctx, &rec, -1)
	wantNoError(t, err)
	rec.ID = "YYY"
	rec.ExpiresAt = time.Now().Add(time.Second * 10)
	err = stg.Save(ctx, &rec, -1)
	wantNoError(t, err)

	countRows := func() int {
		var count int
		err := db.QueryRowContext(ctx, "select count(*) from http_sessions").Scan(&count)
		wantNoError(t, err)
		return count
	}

	if got, want := countRows(), 2; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	err = stg.Purge(ctx)
	wantNoError(t, err)

	if got, want := countRows(), 1; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
}

func newDBFunc(t *testing.T) func() storage.Provider {
	db := postgresDB(t)
	const tableName = "http_sessions"

	return func() storage.Provider {
		pdb := New(db, tableName)
		if err := pdb.DropTable(); err != nil {
			t.Fatalf("cannot drop table %s: %v", tableName, err)
		}
		if err := pdb.CreateTable(); err != nil {
			t.Fatalf("cannot create table %s: %v", tableName, err)
		}
		return pdb
	}
}

// postgresDB returns a *sql.DB for accessing the test PostgreSQL database.
func postgresDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://postgresstore_test:postgresstore_test@localhost/postgresstore_test?sslmode=disable")
	if err != nil {
		t.Fatal("sql.Open:", err)
	}
	return db
}

func wantNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}
}
