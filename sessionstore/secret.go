package sessionstore

import (
	"context"
	"fmt"

	"github.com/jjeffery/sessions/internal/secret"
)

type secretStore struct {
	store DB
	id    string
}

// newSecretStore implements secret.Store for persisting
// information used to create secure cookie signing and
// encryption keys.
func newSecretStore(db DB, name string) secret.Store {
	ss := &secretStore{
		store: db,
	}
	if name == "" {
		ss.id = "secret"
	} else {
		ss.id = fmt.Sprintf("%s-secret", name)
	}
	return ss
}

func (ss *secretStore) PutSecret(ctx context.Context, srec *secret.Record) (ok bool, err error) {
	rec := Record{
		ID:      ss.id,
		Version: srec.Version + 1,
		Expires: srec.Expires,
		Values: map[string]interface{}{
			"format": srec.Format,
			"secret": srec.Secret,
		},
	}
	ok, err = ss.store.PutVersioned(ctx, &rec, srec.Version)
	if ok && err == nil {
		// success, so increment the version
		srec.Version = rec.Version
	}
	return ok, err
}

func (ss *secretStore) GetSecret(ctx context.Context) (*secret.Record, error) {
	rec, err := ss.store.Get(ctx, ss.id)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	srec := &secret.Record{
		Version: rec.Version,
		Expires: rec.Expires,
	}

	if format, ok := rec.Values["format"].(string); ok {
		srec.Format = format
	}
	if secret, ok := rec.Values["secret"].([]byte); ok {
		srec.Secret = secret
	}

	return srec, nil
}
