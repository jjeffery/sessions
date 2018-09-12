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
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/jjeffery/errors"
	"github.com/jjeffery/sessions/storage"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// DefaultMaxAge is the default maximum age for cookies, and is used
	// if zero is provided as the maximum age.
	DefaultMaxAge = 30 * 24 * time.Hour

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

	// defaultSerializer is the serializer used for encoding cookie values if
	// Codec.Serializer is nil.
	defaultSerializer = &securecookie.GobEncoder{}
)

// Codec implements the securecookie.Codec interface and can encrypt and decrypt
// secure cookies.
//
// It also generates, persists and rotates the secret key material used for
// verifying and encrypting the secure cookies. For this reason, the storage provider
// (DB) field must be set.
//
// The MaxAge field specifies the maximum age for a cookie. Any cookie older than this
// is invalid. If zero is passed as the maximum age, then the default maximum age is
// used.
//
// The rotation period is the time duration between key rotation. If zero is passed
// as the rotation period, then the rotation period is deemed to be the same as the
// maximum age. If the rotation period is significantly smaller than the maximum age,
// there will be more overhead decrypting cookies, so unless there is good reason
// to do so, leave the rotation period at its default value.
//
// The serializer is used to serialize the cookie contents. If not specified then
// the default (GOB) encoder is used.
//
// The secret ID is used as the primary key for persisting the secret keying material to
// the db storage. If a blank string is supplied then a default value ("secret") is used.
type Codec struct {
	DB             storage.Provider
	MaxAge         time.Duration
	RotationPeriod time.Duration
	Serializer     Serializer
	SecretID       string

	mutex sync.RWMutex
	codec *immutableCodec
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
// necessary during each call to Encode or Decode. The difference is Refresh
// accepts a context and will return immediately if the context is canceled.
func (c *Codec) Refresh(ctx context.Context) error {
	_, err := c.immutableCodec(ctx)
	return err
}

func (c *Codec) maxAge() time.Duration {
	maxAge := c.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	return maxAge
}

func (c *Codec) rotationPeriod() time.Duration {
	rotationPeriod := c.RotationPeriod
	if rotationPeriod <= 0 {
		rotationPeriod = c.maxAge()
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

	cb, err := c.fetchSecrets(ctx, now)
	if err != nil {
		return nil, err
	}

	nowUnix := now.Unix()

	encoders := make([]securecookie.Codec, 0, len(cb.Secrets)*2)
	decoders := make([]securecookie.Codec, 0, len(cb.Secrets)*2)
	for _, secret := range cb.Secrets {
		codec := &naclCodec{
			KeyingMaterial: secret.KeyingMaterial,
			Serializer:     c.Serializer,
		}
		decoders = append(decoders, codec)
		if secret.StartAt <= nowUnix {
			// only use current secrets for encode codecs
			// because other hosts may not have downloaded
			// the new secrets yet
			encoders = append(encoders, codec)
		}
	}

	// nextRotation is the time to rotate the secret keying material
	nextRotation := time.Unix(cb.Secrets[0].StartAt, 0).Add(c.rotationPeriod())

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

// fetchSecrets and, if necessary, rotate the secrets from  the secret store.
func (c *Codec) fetchSecrets(ctx context.Context, now time.Time) (*secretsT, error) {
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
	modified, err := cb.rotate(now, c.rotationPeriod(), c.maxAge())
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
		rec.ExpiresAt = now.Add(c.rotationPeriod() * 4)
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
func (ss *secretsT) rotate(now time.Time, rotationPeriod time.Duration, maxAge time.Duration) (modified bool, err error) {
	rpSecs := int64(rotationPeriod.Seconds())
	maxAgeSecs := int64(maxAge.Seconds())

	// Remove any obsolete secrets, leaving at least one.
	// A secret is obsolete if it is older than the first secret older
	// than the maximum age. (Read that again, slowly).
	{
		before := now.Unix() - maxAgeSecs
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

// Serializer provides an interface for providing custom serializers for cookie values.
// It is compatible with the securecookie.Serializer interface.
type Serializer interface {
	Serialize(src interface{}) ([]byte, error)
	Deserialize(src []byte, dst interface{}) error
}

// naclCodec is a codec that encodes/decodes using NaCl secretbox.
// https://nacl.cr.yp.to/secretbox.html.
//
// The reason we use our own encryption/decryption is mainly to have
// smaller cookies. The securecookie implementation uses AES CTR/HMAC SHA256.
// It base64-encodes the payload twice, and includes the cookie name and the
// timestamp as text. All this amounts to a bloated cookie. Call me a pedant
// but I don't like long cookies, especially for endpoints that are called
// often with small payloads. Using the fast and modern NaCl, which both
// encrypts and authenticates small messages also has some appeal.
//
// This implementation adds an overhead of 64 bytes to the serialized value
// and base64 encodes one time only.
type naclCodec struct {
	KeyingMaterial [32]byte
	Serializer     Serializer
	MaxAge         time.Duration
}

func (sc *naclCodec) Encode(name string, value interface{}) (string, error) {
	serializer := sc.Serializer
	if serializer == nil {
		serializer = defaultSerializer
	}
	serialized, err := serializer.Serialize(value)
	if err != nil {
		return "", err
	}

	// message is 8 bytes of unix timestamp followed by the serialized value
	message := make([]byte, 8+len(serialized))
	binary.BigEndian.PutUint64(message, uint64(timeNowFunc().Unix()))
	copy(message[8:], serialized)

	var nonce [24]byte
	if _, err = randReadFunc(nonce[:]); err != nil {
		return "", err
	}

	// Use hkdf to build the key from the keying material and the cookie name.
	// This prevents cookie swapping without the overhead of including the name
	// in the clear text.
	hash := sha256.New
	kdf := hkdf.New(hash, sc.KeyingMaterial[:], []byte(name), nil)
	var key [32]byte
	if _, err = kdf.Read(key[:]); err != nil {
		return "", err
	}
	sealed := secretbox.Seal(nonce[:], message, &nonce, &key)
	text := base64.RawURLEncoding.EncodeToString(sealed)
	return text, nil
}

func (sc *naclCodec) Decode(name, value string, dst interface{}) error {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return decodeError("invalid cookie characters")
	}
	if len(sealed) <= 24+secretbox.Overhead {
		return decodeError("cookie has been cut")
	}
	var nonce [24]byte
	copy(nonce[:], sealed[:24])
	box := sealed[24:]
	hash := sha256.New
	kdf := hkdf.New(hash, sc.KeyingMaterial[:], []byte(name), nil)
	var key [32]byte
	if _, err = kdf.Read(key[:]); err != nil {
		return err
	}
	message, ok := secretbox.Open(nil, box, &nonce, &key)
	if !ok {
		return decodeError("invalid cookie")
	}

	unixTimestamp := int64(binary.BigEndian.Uint64(message))
	message = message[8:]
	timestamp := time.Unix(unixTimestamp, 0)
	maxAge := sc.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if timestamp.Add(maxAge).Before(timeNowFunc()) {
		return decodeError("cookie expired")
	}
	serializer := sc.Serializer
	if serializer == nil {
		serializer = defaultSerializer
	}
	return serializer.Deserialize(message, dst)
}

// decodeError provides some level of compatibility with securecookie by
// providing the IsDecode method.
type decodeError string

func (e decodeError) IsDecode() bool {
	return true
}

func (e decodeError) Error() string {
	return string(e)
}
