package sessionstore

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/jjeffery/errors"
	"github.com/jjeffery/sessions/codecstore"
	"github.com/jjeffery/sessions/storage"
)

var (
	nowFunc           = time.Now
	randRead          = rand.Read
	errEmptySessionID = errors.New("empty session id")
)

type sessionID [16]byte

func newSessionID() (sessionID, error) {
	var sid sessionID
	if _, err := randRead(sid[:]); err != nil {
		return sid, err
	}
	return sid, nil
}

func (sid sessionID) String() string {
	str := hex.EncodeToString(sid[:])
	return str
}

func parseSessionID(str string) (sessionID, error) {
	var sid sessionID
	if str == "" {
		// empty session IDs are expected, so detect and error quickly
		return sid, errEmptySessionID
	}
	n, err := hex.Decode(sid[:], []byte(str))
	if err != nil {
		return sid, err
	}
	if n < len(sid) {
		return sid, fmt.Errorf("sessionID too small len=%d", n)
	}
	return sid, nil
}

// Store implements the Gorilla Sessions sessions.Store interface for persistence
// of HTTP session data.
//
// The Store automatically generates and persists random secret keying material
// that is used for generating the keys used to sign and encrypt the secure session
// cookies. The secret keying material is regularly rotated.
type Store struct {
	appid   string
	options sessions.Options
	db      storage.Provider
	codecs  *codecstore.Store
}

// New creates a new store suitable for persisting sessions. Session
// data is persisted using db and options provides information about
// the session cookies. If multiple web applications use the same
// provider (eg the same database table), then each web
// application should use a different appid so that they generate and
// rotate their own, independent secret keying material.
func New(db storage.Provider, options sessions.Options, appid string) *Store {
	return &Store{
		appid:   appid,
		options: options,
		db:      db,
		codecs:  codecstore.New(db, time.Duration(options.MaxAge)*time.Second, appid),
	}
}

// Get returns a cached session.
func (ss *Store) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(ss, name)
}

// New creates and returns a new session.
//
// Note that New should never return a nil session, even in the case of
// an error if using the Registry infrastructure to cache the session.
func (ss *Store) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(ss, name)
	// make a copy
	options := ss.options
	session.Options = &options
	session.IsNew = true
	c, err := r.Cookie(name)
	if err == http.ErrNoCookie {
		return session, nil
	}
	if err != nil {
		// this will not get exercised, as ErrNoCookie is the
		// only error returned by the http.Request.Cookie method
		err = errors.Wrap(err, "cannot obtain cookie")
		return session, err
	}
	codec, err := ss.codecs.Codec(r.Context())
	if err != nil {
		err = errors.Wrap(err, "cannot get codec")
		return session, err
	}
	var sid sessionID
	err = codec.Decode(name, c.Value, &sid)
	if err != nil {
		err = errors.Wrap(err, "cannot decode cookie")
		return session, err
	}
	session.ID = sid.String()
	rec, err := ss.db.Fetch(r.Context(), ss.recordID(session))
	if err == nil && rec != nil {
		session.IsNew = false //  session data exists, so not new
		if rec.Data != nil {
			decoder := gob.NewDecoder(bytes.NewReader(rec.Data))
			if err := decoder.Decode(&session.Values); err != nil {
				return session, err
			}
		}
	}
	return session, err
}

// Save persists session to the underlying store implementation.
func (ss *Store) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Marked for deletion.
	if session.Options.MaxAge < 0 {
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		if session.ID != "" {
			if err := ss.db.Delete(r.Context(), ss.recordID(session)); err != nil {
				return err
			}
		}
	} else {
		sid, err := parseSessionID(session.ID)
		if err != nil {
			sid, err = newSessionID()
			if err != nil {
				// this will only happen if the crypto RNG fails
				return errors.Wrap(err, "cannot generate random session id")
			}
			session.ID = sid.String()
		}

		expiresIn := time.Duration(session.Options.MaxAge) * time.Second
		if expiresIn <= 0 {
			expiresIn = time.Hour * 24
		}
		rec := storage.Record{
			ID:      ss.recordID(session),
			Format:  "gob",
			Expires: nowFunc().Add(expiresIn),
		}
		rec.Data, err = encodeSession(session)
		if err != nil {
			return err
		}
		if err := ss.db.Save(r.Context(), &rec, -1); err != nil {
			return err
		}
		codec, err := ss.codecs.Codec(r.Context())
		if err != nil {
			return err
		}
		encoded, err := codec.Encode(session.Name(), sid)
		if err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	}
	return nil
}

// recordID returns the unique ID for saving a session record to persistent storage
func (ss *Store) recordID(session *sessions.Session) string {
	if ss.appid == "" {
		return session.ID
	}
	return ss.appid + "-" + session.ID
}

func encodeSession(session *sessions.Session) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(session.Values); err != nil {
		return nil, errors.Wrap(err, "cannot encode session values")
	}
	return buf.Bytes(), nil
}
