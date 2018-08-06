package sessionstore_test

import (
	"testing"

	"github.com/jjeffery/sessions/internal/testhelper"
	"github.com/jjeffery/sessions/memorystore"
	"github.com/jjeffery/sessions/sessionstore"
)

func TestMemoryDB(t *testing.T) {
	newDB := func() sessionstore.DB {
		return memorystore.NewDB()
	}
	testhelper.SessionStoreTest(t, newDB)
}
