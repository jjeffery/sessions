// Package secret is for creating, storing and rotating secrets used for encrypting session cookies.
package secret

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
	"golang.org/x/crypto/hkdf"
)

const (
	// defaultRotationPeriod is the default number of seconds between rotation
	// of secrets, used if zero is provided as the rotation period
	defaultRotationPeriod = 86400 * time.Second

	// minimumRotationPeriod is the minimum number of seconds between rotating secrets,
	// it is the period between refreshing secret data from the store
	minimumRotationPeriod = 900 * time.Second

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

// Safe contains one or more secrets that are persisted from and to the store.
// Secrets are rotated regularly, the rotation period specifies how often.
type Safe struct {
	rotationPeriod time.Duration
	mutex          sync.RWMutex
	codeBook       *codeBookT
	store          Store
}

// New returns a new safe which persists secrets using the store.
// The rotation period is the number of seconds between key rotation,
// and should be set to be at least the max-age of the cookie. If
// zero is passed, then a large default value is used.
func New(store Store, rotationPeriod time.Duration) *Safe {
	if rotationPeriod <= 0 {
		rotationPeriod = defaultRotationPeriod
	}
	if rotationPeriod < minimumRotationPeriod {
		rotationPeriod = minimumRotationPeriod
	}

	return &Safe{
		store:          store,
		rotationPeriod: rotationPeriod,
	}
}

// RotationPeriod is the number of seconds between key rotation.
// It should be equal to or greater than the max-age of the associated
// secure cookie.
func (safe *Safe) RotationPeriod() time.Duration {
	return safe.rotationPeriod
}

// Codecs returns lists of codecs suitable for signing and encrypting
// secure cookies. Two sets of codecs are returned: encode should be
// used for encoding cookies. It only makes use of secrets whose start
// time is in the past. The decode codecs make use of all secrets, including
// those whose start time is in the future.
func (safe *Safe) Codecs() (encode []securecookie.Codec, decode []securecookie.Codec) {
	cb := safe.cb()
	now := timeNowFunc().Unix()

	encodeKeyPairs := make([][]byte, 0, len(cb.Secrets)*2)
	decodeKeyPairs := make([][]byte, 0, len(cb.Secrets)*2)
	for _, secret := range cb.Secrets {
		k1, k2 := newKeyPair(secret.KeyingMaterial[:])
		decodeKeyPairs = append(decodeKeyPairs, k1, k2)
		if secret.StartAt <= now {
			// only use current secrets for encode codecs
			// because other hosts may not have downloaded
			// the new secrets yet
			encodeKeyPairs = append(encodeKeyPairs, k1, k2)
		}
	}
	encode = securecookie.CodecsFromPairs(encodeKeyPairs...)
	decode = securecookie.CodecsFromPairs(decodeKeyPairs...)
	return encode, decode
}

func (safe *Safe) cb() *codeBookT {
	var cb *codeBookT
	safe.mutex.RLock()
	cb = safe.codeBook
	safe.mutex.RUnlock()
	return cb
}

// newKeyPair takes a secret and prepares two keys using
// the HKDF key derivation function.
func newKeyPair(secret []byte) ([]byte, []byte) {
	hash := sha256.New
	kdf := hkdf.New(hash, secret, nil, nil)

	var hashKey [32]byte
	var encryptKey [32]byte
	kdf.Read(hashKey[:])
	kdf.Read(encryptKey[:])

	return hashKey[:], encryptKey[:]
}

// RefreshIn returns the number of seconds to wait before it is time to
// refresh the secret store. If zero is returned, it is time to refresh now.
func (safe *Safe) RefreshIn() time.Duration {
	cb := safe.cb()

	if cb == nil {
		return 0
	}
	if len(cb.Secrets) == 0 {
		return 0
	}
	next := cb.refreshed.Add(minimumRotationPeriod)
	now := timeNowFunc()
	if now.After(next) {
		return 0
	}

	return next.Sub(now)
}

// Refresh the secrets from  the secret store.
func (safe *Safe) Refresh(ctx context.Context) error {
	rec, err := safe.store.GetSecret(ctx)
	if err != nil {
		return err
	}
	cb, err := newCodeBook(rec)
	if err != nil {
		return err
	}
	if err := cb.rotate(safe.rotationPeriod); err != nil {
		return err
	}
	if cb.modified {
		rec, err = cb.toRecord()
		if err != nil {
			return err
		}
		rec.Expires = timeNowFunc().Add(safe.rotationPeriod * 2).Unix()
		ok, err := safe.store.PutSecret(ctx, rec)
		if err != nil {
			return err
		}
		if !ok {
			// another station beat us to the update, so retrieve again
			rec, err = safe.store.GetSecret(ctx)
		}
		cb, err = newCodeBook(rec)
		if err != nil {
			return err
		}
	}
	cb.refreshed = timeNowFunc()

	safe.mutex.Lock()
	safe.codeBook = cb
	safe.mutex.Unlock()
	return nil
}

// secretT contains secret keying material that can be use by a key
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
	Version   int64      // Optimistic locking version
	Secrets   []*secretT // Most recent first
	modified  bool       // if modified after
	refreshed time.Time  // time of last refresh
}

func (cb *codeBookT) toRecord() (*Record, error) {
	data, err := cb.marshal()
	if err != nil {
		return nil, err
	}
	return &Record{
		Version: cb.Version,
		Format:  gobFormat,
		Secret:  data,
	}, nil
}

func newCodeBook(rec *Record) (*codeBookT, error) {
	cb := &codeBookT{}
	if rec != nil {
		cb.Version = rec.Version
		if rec.Format != gobFormat {
			return nil, fmt.Errorf("unsupported secret record format: %s", rec.Format)
		}
		if err := cb.unmarshal(rec.Secret); err != nil {
			return nil, err
		}
	}
	return cb, nil
}

func (cb *codeBookT) marshal() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(cb.Secrets); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (cb *codeBookT) unmarshal(data []byte) error {
	var secrets []*secretT
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&secrets); err != nil {
		return errors.Wrap(err, "cannot unmarshal secret")
	}
	cb.Secrets = secrets
	return nil
}

// rotate adds a new secret to the code book, and removes any obsolete secrets.
func (cb *codeBookT) rotate(rotationPeriod time.Duration) error {
	now := timeNowFunc()
	rpSecs := int64(rotationPeriod.Seconds())

	// remove any obsolete secrets, leaving at least one
	// a secret is obsolete if it is older than twice the
	// rotation period
	{
		before := now.Unix() - rpSecs*2
		for i := 0; i < len(cb.Secrets); i++ {
			secret := cb.Secrets[i]
			if secret.StartAt < before {
				cb.Secrets = cb.Secrets[:i+1]
				cb.modified = true
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
			return errors.Wrap(err, "cannot read random bytes")
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
		cb.modified = true
	}

	return nil
}

// Record contains the secret to be persisted to the store.
type Record struct {
	Version int64  // optimistic locking version
	Secret  []byte // opaque secret data
	Format  string // storage format
	Expires int64  // expiry in unix time
}

// Store represents a persistent store of secrets
type Store interface {
	// Get the secret from the store.
	GetSecret(context.Context) (*Record, error)

	// Save the data to the store. 	If the store is updated successfully
	// then ok will be true and the record's Version field will be updated
	// to contain the new version stored.
	//
	// If the store has a different version because another station has
	// updated the store prior, then ok will be false and the record will
	// be unchanged. In this instance, call GetSecret to obtain the most
	// recent secret.
	PutSecret(context.Context, *Record) (ok bool, err error)
}
