package sessionstore_test

import (
	"testing"

	"github.com/jjeffery/sessions/internal/testhelper"
	"github.com/jjeffery/sessions/storage"
	"github.com/jjeffery/sessions/storage/memory"
)

func TestMemoryDB(t *testing.T) {
	newDB := func() storage.Provider {
		return memory.New()
	}
	testhelper.TestSessionStore(t, newDB)
}
