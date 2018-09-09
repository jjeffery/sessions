// Package codecstore provides a codec for encrypting and decrypting secure cookies.
// The secret keying material used for creating the codec hash and encryption keys
// is randomly generated, persisted to storage, and rotated regularly.
//
// The codec storage and rotation mechanism is designed to be shared across multiple
// processes running on multiple hosts.
package codecstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/jjeffery/errors"
	"github.com/jjeffery/sessions/storage"
	"golang.org/x/crypto/hkdf"
)

const (
	// defaultRotationPeriod is the default time period for rotation
	// of secrets, and is used if zero is provided as the rotation period.
	defaultRotationPeriod = 30 * 24 * time.Hour

	// minimumRotationPeriod is the minimum time duration between rotating secrets.
	// Secret keying material is regularly read from persistent storage by all hosts
	// as often as this period.
	minimumRotationPeriod = 15 * time.Minute

	// gobFormat is used to identify the format used for marshalling/unmarshalling secrets,
	// included to provide backwards-compatibility in case future versions of this package
	// change the format
	gobFormat = "gob"
)

var (
	// timeNowFunc returns the current time, and can be replaced during testing
	timeNowFunc = time.Now

	// randReadFunc populates a byte array with random data, and can be
	// replaced during testing
	randReadFunc = rand.Read
)

// Codec is used to encode and decode cookie values. It implements the
// securecookie.Codec interface.
type Codec struct {
	encoders []securecookie.Codec
	decoders []securecookie.Codec
	expires  time.Time
}

// Encode implements the securecookie.Codec interface.
func (c *Codec) Encode(name string, value interface{}) (string, error) {
	return securecookie.EncodeMulti(name, value, c.encoders...)
}

// Decode implements the securecookie.Codec interface.
func (c *Codec) Decode(name, value string, dst interface{}) error {
	return securecookie.DecodeMulti(name, value, dst, c.decoders...)
}

// ExpiresAt returns the time at which this codec expires and will need
// to be refreshed.
func (c *Codec) ExpiresAt() time.Time {
	return c.expires
}

func newCodec(cb *codeBookT, rotationPeriod time.Duration) *Codec {
	now := timeNowFunc()
	nowUnix := now.Unix()

	encodeKeyPairs := make([][]byte, 0, len(cb.Secrets)*2)
	decodeKeyPairs := make([][]byte, 0, len(cb.Secrets)*2)
	for _, secret := range cb.Secrets {
		k1, k2 := newKeyPair(secret.KeyingMaterial[:])
		decodeKeyPairs = append(decodeKeyPairs, k1, k2)
		if secret.StartAt <= nowUnix {
			// only use current secrets for encode codecs
			// because other hosts may not have downloaded
			// the new secrets yet
			encodeKeyPairs = append(encodeKeyPairs, k1, k2)
		}
	}
	encoders := securecookie.CodecsFromPairs(encodeKeyPairs...)
	decoders := securecookie.CodecsFromPairs(decodeKeyPairs...)

	// nextRotation is the time to rotate the secret keying material
	nextRotation := time.Unix(cb.Secrets[0].StartAt, 0).Add(rotationPeriod)

	// nextRefresh is the time to perform a regular check
	nextRefresh := now.Add(minimumRotationPeriod)

	// choose the earliest time of next rotation or next refresh
	next := nextRotation
	if next.After(nextRefresh) {
		next = nextRefresh
	}

	return &Codec{
		encoders: encoders,
		decoders: decoders,
		expires:  next,
	}
}

// newKeyPair takes a secret and prepares two keys using
// the HKDF key derivation function.
func newKeyPair(secret []byte) ([]byte, []byte) {
	hash := sha256.New
	kdf := hkdf.New(hash, secret, nil, nil)

	hashKey := make([]byte, 32)
	encryptKey := make([]byte, 32)
	kdf.Read(hashKey[:])
	kdf.Read(encryptKey[:])

	return hashKey, encryptKey
}

// Store is responsble for generating, rotating and persisting secret keying
// material that is used to create hash and encryption keys for secure cookies.
type Store struct {
	rotationPeriod time.Duration
	db             storage.Provider
	secretID       string

	mutex sync.RWMutex
	codec *Codec
}

// New returns a new store which generates, rotates and persists secret keying material.
//
// The rotation period is the time duration between key rotation, and should be set to be
// at least the max-age of the cookie. If zero is passed as the rotation period, then the
// default rotation period value is used.
//
// The secret ID is used as the key for persisting the secret keying material to the
// db storage. If a blank string is supplied then a default value ("secret") is used.
func New(db storage.Provider, rotationPeriod time.Duration, secretID string) *Store {
	if rotationPeriod <= 0 {
		rotationPeriod = defaultRotationPeriod
	}
	if rotationPeriod < minimumRotationPeriod {
		rotationPeriod = minimumRotationPeriod
	}
	if secretID == "" {
		secretID = "secret"
	}

	return &Store{
		db:             db,
		rotationPeriod: rotationPeriod,
		secretID:       secretID,
	}
}

// RotationPeriod is the time duration between key rotation.
// It should be equal to or greater than the max-age of the associated
// secure cookie.
func (store *Store) RotationPeriod() time.Duration {
	return store.rotationPeriod
}

// Codec returns a codec that can be used to encrypt and decrypt
// secure cookies. The codec has an expiration time. The codec
// is cached, so this function does not access the persistent
// storage if an unexpired codec is available.
func (store *Store) Codec(ctx context.Context) (*Codec, error) {
	now := timeNowFunc()
	store.mutex.RLock()
	codec := store.codec
	store.mutex.RUnlock()

	if codec == nil || codec.expires.Before(now) {
		cb, err := store.refresh(ctx)
		if err != nil {
			return nil, err
		}
		codec = newCodec(cb, store.rotationPeriod)
		store.mutex.Lock()
		store.codec = codec
		store.mutex.Unlock()
	}

	return codec, nil
}

// refresh and, if necessary, rotate the secrets from  the secret store.
func (store *Store) refresh(ctx context.Context) (*codeBookT, error) {
	rec, err := store.db.Fetch(ctx, store.secretID)
	if err != nil {
		return nil, err
	}
	var cb codeBookT
	if rec != nil {
		if err = cb.unmarshal(rec.Format, rec.Data); err != nil {
			return nil, err
		}
	}
	modified, err := cb.rotate(store.rotationPeriod)
	if err != nil {
		return nil, err
	}
	if modified {
		if rec == nil {
			rec = &storage.Record{}
		}
		oldVersion := rec.Version
		rec.Version++
		rec.Format, rec.Data, err = cb.marshal()
		if err != nil {
			return nil, err
		}
		rec.Expires = timeNowFunc().Add(store.rotationPeriod * 4)
		rec.ID = store.secretID
		err := store.db.Save(ctx, rec, oldVersion)
		if err == storage.ErrVersionConflict {
			// another station beat us to the update, so retrieve again
			rec, err = store.db.Fetch(ctx, store.secretID)
			if err != nil {
				return nil, err
			}
			if err = cb.unmarshal(rec.Format, rec.Data); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}

	return &cb, nil
}

// secretT contains secret keying material that can be used by a key
// derivation function (eg HKDF) to build symmetric encryption keys.
// In order to support an orderly secret rotation, each keying material has
// a time before which it should not be used. This gives each node time to
// refresh all current secrets before they start being used.
type secretT struct {
	KeyingMaterial [32]byte // secret, random bytes
	StartAt        int64    // unix time that secret becomes/became active
}

// codeBookT contains a list of secrets that can be used for generating
// symmetric encryption keys. The most recently generated key is first
// in the list and the oldest key is last in the list.
type codeBookT struct {
	Secrets []*secretT // Most recent first
}

func (cb *codeBookT) marshal() (format string, data []byte, err error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(cb.Secrets); err != nil {
		return "", nil, err
	}
	return gobFormat, buf.Bytes(), nil
}

func (cb *codeBookT) unmarshal(format string, data []byte) error {
	if format != gobFormat {
		return fmt.Errorf("unsupported secret record format: %s", format)
	}

	var secrets []*secretT
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&secrets); err != nil {
		return errors.Wrap(err, "cannot unmarshal secret")
	}
	cb.Secrets = secrets
	return nil
}

// rotate adds a new secret to the code book, and removes any obsolete secrets.
func (cb *codeBookT) rotate(rotationPeriod time.Duration) (modified bool, err error) {
	now := timeNowFunc()
	rpSecs := int64(rotationPeriod.Seconds())

	// Remove any obsolete secrets, leaving at least one.
	// A secret is obsolete if it is older than the first secret older
	// than the rotation period. (Read that again, slowly).
	{
		before := now.Unix() - rpSecs
		for i := 0; i < len(cb.Secrets); i++ {
			secret := cb.Secrets[i]
			if secret.StartAt < before {
				if i+1 < len(cb.Secrets) {
					cb.Secrets = cb.Secrets[:i+1]
					modified = true
				}
				break
			}
		}
	}

	var keyRequired bool

	if len(cb.Secrets) == 0 {
		keyRequired = true
	} else {
		// there is at least one secret, only need another if
		// it is older than the rotation period
		before := now.Unix() - rpSecs
		keyRequired = cb.Secrets[0].StartAt < before
	}

	if keyRequired {
		var keyingMaterial [32]byte
		if _, err := randReadFunc(keyingMaterial[:]); err != nil {
			return modified, errors.Wrap(err, "cannot read random bytes")
		}

		startAt := now.Unix()

		if len(cb.Secrets) > 0 {
			// If a secret already exists, start in the future.
			// This provides time for other stations to refresh and
			// receive the new secret.
			startAt += int64(minimumRotationPeriod.Seconds())
		}

		secret := &secretT{
			KeyingMaterial: keyingMaterial,
			StartAt:        startAt,
		}

		// prepend the new secret to the secrets list
		secrets := make([]*secretT, 0, len(cb.Secrets)+1)
		secrets = append(secrets, secret)
		secrets = append(secrets, cb.Secrets...)
		cb.Secrets = secrets
		modified = true
	}

	return modified, nil
}
