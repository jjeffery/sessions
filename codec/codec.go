// Package codec provides a codec for encrypting and decrypting secure cookies.
// The secret keying material used for creating the codec hash and encryption keys
// is randomly generated, persisted to storage, and rotated regularly.
//
// The codec storage and rotation mechanism is designed to be shared across multiple
// processes running on multiple hosts.
package codec

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
	// DefaultRotationPeriod is the default time period for rotation
	// of secrets, and is used if zero is provided as the rotation period.
	DefaultRotationPeriod = 30 * 24 * time.Hour

	// MinimumRotationPeriod is the minimum time duration between rotating secrets.
	MinimumRotationPeriod = 15 * time.Minute

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

// Codec implements the securecookie.Codec interface and can encrypt and decrypt
// secure cookies.
//
// It also is responsble for generating, persisting and rotating the secret keys
// used for verifying and encrypting the secure cookies.
type Codec struct {
	DB             storage.Provider
	RotationPeriod time.Duration
	SecretID       string

	mutex sync.RWMutex
	codec *immutableCodec
}

// New returns a new codec which encrypts and decrypts secure cookies. It also generates,
// persists and rotates secret keying material.
//
// The rotation period is the time duration between key rotation, and should be set to be
// at least the max-age of the cookie. If zero is passed as the rotation period, then the
// default rotation period value is used.
//
// The secret ID is used as the primary key for persisting the secret keying material to
// the db storage. If a blank string is supplied then a default value ("secret") is used.
func New(db storage.Provider, rotationPeriod time.Duration, secretID string) *Codec {
	if rotationPeriod <= 0 {
		rotationPeriod = DefaultRotationPeriod
	}
	if rotationPeriod < MinimumRotationPeriod {
		rotationPeriod = MinimumRotationPeriod
	}
	if secretID == "" {
		secretID = "secret"
	}

	return &Codec{
		DB:             db,
		RotationPeriod: rotationPeriod,
		SecretID:       secretID,
	}
}

// Encode implements the securecookie.Codec interface.
func (c *Codec) Encode(name string, value interface{}) (string, error) {
	codec, err := c.immutableCodec(context.TODO())
	if err != nil {
		return "", err
	}
	return codec.Encode(name, value)
}

// Decode implements the securecookie.Codec interface.
func (c *Codec) Decode(name, value string, dst interface{}) error {
	codec, err := c.immutableCodec(context.TODO())
	if err != nil {
		return err
	}
	return codec.Decode(name, value, dst)
}

// Refresh ensures that the hash and encryption keys are up to date, rotating
// if necessary.
//
// It is not mandatory to call Refresh, as the codec will update itself if
// necessary during each call to Encode or Decode. The difference is Request
// accepts a context and will return immediately if the context is canceled.
func (c *Codec) Refresh(ctx context.Context) error {
	_, err := c.immutableCodec(ctx)
	return err
}

func (c *Codec) rotationPeriod() time.Duration {
	rotationPeriod := c.RotationPeriod
	if rotationPeriod <= 0 {
		rotationPeriod = DefaultRotationPeriod
	}
	if rotationPeriod < MinimumRotationPeriod {
		rotationPeriod = MinimumRotationPeriod
	}
	return rotationPeriod
}

// immutableCodec retrieves the immutable codec, creating a new one if
// necessary. This function is safe to call concurrently from multiple
// goroutines.
func (c *Codec) immutableCodec(ctx context.Context) (*immutableCodec, error) {
	var codec *immutableCodec
	c.mutex.RLock()
	codec = c.codec
	c.mutex.RUnlock()

	if codec.isExpired() {
		var err error
		codec, err = c.newImmutableCodec(ctx)
		if err != nil {
			return nil, err
		}
		c.mutex.Lock()
		c.codec = codec
		c.mutex.Unlock()
	}
	return codec, nil
}

// newImmutableCodec creates a new immutable codec based on the secret
// keying material in the store. Secret keying material is rotated if
// necessary.
func (c *Codec) newImmutableCodec(ctx context.Context) (*immutableCodec, error) {
	now := timeNowFunc()

	cb, err := c.fetchSecrets(ctx)
	if err != nil {
		return nil, err
	}

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
	nextRotation := time.Unix(cb.Secrets[0].StartAt, 0).Add(c.RotationPeriod)

	// nextRefresh is the time to perform a regular check
	nextRefresh := now.Add(MinimumRotationPeriod)

	// choose the earliest time of next rotation or next refresh
	expiresAt := nextRotation
	if expiresAt.After(nextRefresh) {
		expiresAt = nextRefresh
	}

	codec := &immutableCodec{
		encoders:  encoders,
		decoders:  decoders,
		expiresAt: expiresAt,
	}

	return codec, nil
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

// fetchSecrets and, if necessary, rotate the secrets from  the secret store.
func (c *Codec) fetchSecrets(ctx context.Context) (*secretsT, error) {
	if c.DB == nil {
		return nil, errors.New("Codec.DB cannot be nil")
	}
	secretID := c.SecretID
	if secretID == "" {
		secretID = "secret"
	}
	rec, err := c.DB.Fetch(ctx, secretID)
	if err != nil {
		return nil, err
	}
	var cb secretsT
	if rec != nil {
		if err = cb.unmarshal(rec.Format, rec.Data); err != nil {
			return nil, err
		}
	}
	modified, err := cb.rotate(c.rotationPeriod())
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
		rec.ExpiresAt = timeNowFunc().Add(c.rotationPeriod() * 4)
		rec.ID = secretID
		err := c.DB.Save(ctx, rec, oldVersion)
		if err == storage.ErrVersionConflict {
			// another station beat us to the update, so retrieve again
			rec, err = c.DB.Fetch(ctx, secretID)
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

// secretsT contains a list of secrets that can be used for generating
// symmetric encryption keys. The most recently generated key is first
// in the list and the oldest key is last in the list.
type secretsT struct {
	Secrets []*secretT // Most recent first
}

func (ss *secretsT) marshal() (format string, data []byte, err error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(ss.Secrets); err != nil {
		return "", nil, err
	}
	return gobFormat, buf.Bytes(), nil
}

func (ss *secretsT) unmarshal(format string, data []byte) error {
	if format != gobFormat {
		return fmt.Errorf("unsupported secret record format: %s", format)
	}

	var secrets []*secretT
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&secrets); err != nil {
		return errors.Wrap(err, "cannot unmarshal secret")
	}
	ss.Secrets = secrets
	return nil
}

// rotate adds a new secret to the list, and removes any obsolete secrets.
func (ss *secretsT) rotate(rotationPeriod time.Duration) (modified bool, err error) {
	now := timeNowFunc()
	rpSecs := int64(rotationPeriod.Seconds())

	// Remove any obsolete secrets, leaving at least one.
	// A secret is obsolete if it is older than the first secret older
	// than the rotation period. (Read that again, slowly).
	{
		before := now.Unix() - rpSecs
		for i := 0; i < len(ss.Secrets); i++ {
			secret := ss.Secrets[i]
			if secret.StartAt < before {
				if i+1 < len(ss.Secrets) {
					ss.Secrets = ss.Secrets[:i+1]
					modified = true
				}
				break
			}
		}
	}

	var keyRequired bool

	if len(ss.Secrets) == 0 {
		keyRequired = true
	} else {
		// there is at least one secret, only need another if
		// it is older than the rotation period
		before := now.Unix() - rpSecs
		keyRequired = ss.Secrets[0].StartAt < before
	}

	if keyRequired {
		var keyingMaterial [32]byte
		if _, err := randReadFunc(keyingMaterial[:]); err != nil {
			return modified, errors.Wrap(err, "cannot read random bytes")
		}

		startAt := now.Unix()

		if len(ss.Secrets) > 0 {
			// If a secret already exists, start in the future.
			// This provides time for other stations to refresh and
			// receive the new secret.
			startAt += int64(MinimumRotationPeriod.Seconds())
		}

		secret := &secretT{
			KeyingMaterial: keyingMaterial,
			StartAt:        startAt,
		}

		// prepend the new secret to the secrets list
		secrets := make([]*secretT, 0, len(ss.Secrets)+1)
		secrets = append(secrets, secret)
		secrets = append(secrets, ss.Secrets...)
		ss.Secrets = secrets
		modified = true
	}

	return modified, nil
}

// immutableCodec is not changed once it is created, and can
// be called concurrently by different goroutines. It implements
// the securecookie.Codec interface.
type immutableCodec struct {
	encoders  []securecookie.Codec
	decoders  []securecookie.Codec
	expiresAt time.Time
}

// Encode implements the securecookie.Codec interface.
func (ic *immutableCodec) Encode(name string, value interface{}) (string, error) {
	return securecookie.EncodeMulti(name, value, ic.encoders...)
}

// Decode implements the securecookie.Codec interface.
func (ic *immutableCodec) Decode(name, value string, dst interface{}) error {
	return securecookie.DecodeMulti(name, value, dst, ic.decoders...)
}

func (ic *immutableCodec) isExpired() bool {
	return ic == nil || ic.expiresAt.Before(timeNowFunc())
}
