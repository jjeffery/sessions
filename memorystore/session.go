package memorystore

import (
	"github.com/gorilla/sessions"
	"github.com/jjeffery/sessions/sessionstore"
)

// NewSessionStore returns a new session store that uses the memory DB
// for storing both sessions and cookie secrets. If multiple applications use the same
// memory DB for storage, then each application should use a different id so that
// the applications each use different cookie secrets for signing and encrypting the
// secure cookies.
func (store *DB) NewSessionStore(options sessions.Options, appid string) sessions.Store {
	return sessionstore.New(store, options, appid)
}

// New creates a new session store backed by memory. Access to the
// Session options describe the session cookie. If multiple applications share the same
// memory DB, then each application should have a different appid so that they will
// use different secrets for signing and encrypting the secure cookies. Otherwise,
// appid can be left blank.
func New(options sessions.Options, appid string) sessions.Store {
	db := NewDB()
	return db.NewSessionStore(options, appid)
}
