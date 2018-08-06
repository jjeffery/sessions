package postgresstore

import (
	"database/sql"
	"testing"

	"github.com/jjeffery/sessions/internal/testhelper"
	"github.com/jjeffery/sessions/sessionstore"
	_ "github.com/lib/pq"
)

func TestSessionStore(t *testing.T) {
	newDB := newDBFunc(t)

	testhelper.SessionStoreTest(t, newDB)
}

func newDBFunc(t *testing.T) func() sessionstore.DB {
	db := postgresDB(t)
	const tableName = "http_sessions"

	return func() sessionstore.DB {
		pdb := NewDB(db, tableName)
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
