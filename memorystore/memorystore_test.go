package memorystore

import (
	"testing"

	"github.com/jjeffery/sessions/internal/testhelper"
	"github.com/jjeffery/sessions/sessionstore"
)

func TestMemoryDB(t *testing.T) {
	newDB := func() sessionstore.DB {
		return NewDB()
	}
	testhelper.SessionStoreTest(t, newDB)
}
