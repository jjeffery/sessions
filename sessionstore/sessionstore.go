package sessionstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jjeffery/errors"
	"github.com/jjeffery/sessions/internal/secret"
)

var (
	nowFunc           = time.Now
	randRead          = rand.Read
	errEmptySessionID = errors.New("empty session id")
)

type sessionID [16]byte

func newSessionID() (sessionID, error) {
	var sid sessionID
	if _, err := io.ReadFull(rand.Reader, sid[:]); err != nil {
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

type sessionStore struct {
	appid   string
	options sessions.Options
	store   DB
	safe    *secret.Safe

	rw struct {
		mutex  sync.RWMutex
		encode []securecookie.Codec // contains current codecs only
		decode []securecookie.Codec // contains current and future codecs
	}
}

// New creates a new store suitable for persisting sessions. Session
// data is persisted using db and options provides information about
// the session cookies. If multiple web applications use the same
// database persistence (eg the same database table), then each web
// application should use a different appid so that they generate and
// rotate their own, independent secret keying material.
func New(db DB, options sessions.Options, appid string) sessions.Store {
	return &sessionStore{
		appid:   appid,
		options: options,
		store:   db,
		safe:    secret.New(newSecretStore(db, appid), time.Duration(options.MaxAge)*time.Second),
	}
}

// Get returns a cached session.
func (ss *sessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(ss, name)
}

// New creates and return a new session.
//
// Note that New should never return a nil session, even in the case of
// an error if using the Registry infrastructure to cache the session.
func (ss *sessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
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
		err = errors.Wrap(err, "cannot obtain cookie")
		return session, err
	}
	_, decode, err := ss.codecs(r.Context())
	if err != nil {
		err = errors.Wrap(err, "cannot get codecs")
		return session, err
	}
	var sid sessionID
	err = securecookie.DecodeMulti(name, c.Value, &sid, decode...)
	if err != nil {
		err = errors.Wrap(err, "cannot decode cookie")
		return session, err
	}
	session.ID = sid.String()
	rec, err := ss.store.Get(r.Context(), ss.recordID(session))
	if err == nil && rec != nil {
		session.IsNew = false //  session data exists, so not new
		for k, v := range rec.Values {
			session.Values[k] = v
		}
	}
	return session, err
}

// Save persists session to the underlying store implementation.
func (ss *sessionStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Marked for deletion.
	if session.Options.MaxAge < 0 {
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		if session.ID != "" {
			if err := ss.store.Delete(r.Context(), ss.recordID(session)); err != nil {
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

		expireSeconds := int64(session.Options.MaxAge)
		if expireSeconds <= 0 {
			expireSeconds = 86400 * 30
		}
		rec := Record{
			ID:      ss.recordID(session),
			Values:  make(map[string]interface{}),
			Expires: nowFunc().Unix() + expireSeconds,
		}
		for k, v := range session.Values {
			if ks, ok := k.(string); ok {
				rec.Values[ks] = v
			}
		}
		if err := ss.store.PutUnversioned(r.Context(), &rec); err != nil {
			return err
		}
		encode, _, err := ss.codecs(r.Context())
		if err != nil {
			return err
		}
		encoded, err := securecookie.EncodeMulti(session.Name(), sid, encode...)
		if err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	}
	return nil
}

func (ss *sessionStore) codecs(ctx context.Context) (encode, decode []securecookie.Codec, err error) {
	if ss.safe.RefreshIn() <= 0 {
		if err := ss.safe.Refresh(ctx); err != nil {
			return nil, nil, err
		}
		encode, decode = ss.safe.Codecs()
		ss.rw.mutex.Lock()
		ss.rw.encode = encode
		ss.rw.decode = decode
		ss.rw.mutex.Unlock()
	} else {
		ss.rw.mutex.RLock()
		encode = ss.rw.encode
		decode = ss.rw.decode
		ss.rw.mutex.RUnlock()
	}
	return encode, decode, nil
}

// recordID returns the unique ID for saving a session record to persistent storage
func (ss *sessionStore) recordID(session *sessions.Session) string {
	if ss.appid == "" {
		return session.ID
	}
	return ss.appid + "-" + session.ID
}
