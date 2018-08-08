package secret

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/jjeffery/sessions/storage/memory"
)

func TestRefresh(t *testing.T) {
	defer restoreStubs()
	ctx := context.Background()

	now := time.Now()
	timeNowFunc = func() time.Time {
		return now
	}
	store := memory.New().WithTimeNow(timeNowFunc)
	safe := New(store, 0, "")

	if got, want := safe.shouldRefreshNow(), true; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if err := safe.Refresh(ctx); err != nil {
		t.Fatalf("got=%v, want=nil", err)

	}

	if got, want := safe.shouldRefreshNow(), false; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if got, want := len(safe.codeBook.Secrets), 1; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	now = now.Add(safe.RotationPeriod() + time.Second)

	if got, want := safe.shouldRefreshNow(), true; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if err := safe.Refresh(ctx); err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}

	if got, want := safe.shouldRefreshNow(), false; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if got, want := len(safe.codeBook.Secrets), 2; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	now = now.Add(minimumRotationPeriod + 1)

	if got, want := safe.shouldRefreshNow(), true; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if err := safe.Refresh(ctx); err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}

	if got, want := safe.shouldRefreshNow(), false; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if got, want := len(safe.codeBook.Secrets), 2; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
}

func TestRotatePeriod(t *testing.T) {
	safe := New(memory.New(), 0, "")
	if got, want := safe.RotationPeriod(), defaultRotationPeriod; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
	safe = New(memory.New(), time.Second*30, "")
	if got, want := safe.RotationPeriod(), minimumRotationPeriod; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
}

func TestCodecs(t *testing.T) {
	defer restoreStubs()
	{
		// stub out randRead function so our secrets are predictable
		var nextByte byte
		randReadFunc = func(data []byte) (n int, err error) {
			for i := 0; i < len(data); i++ {
				data[i] = nextByte
				nextByte++
				n++
			}
			return n, err
		}
	}

	var fakeNow = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	timeNowFunc = func() time.Time {
		return fakeNow
	}
	db := memory.New().WithTimeNow(timeNowFunc)

	ctx := context.Background()
	safe := New(db, 0, "")

	encode, decode := safe.Codecs()
	wantNilCodecs(t, encode)
	wantNilCodecs(t, decode)

	err := safe.Refresh(ctx)
	wantNilError(t, err)

	if got, want := len(safe.codeBook.Secrets), 1; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	if got, want := safe.codeBook.Secrets[0].KeyingMaterial, [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
	// because this is the first secret in the code book, it should start immediately, not
	// in the future
	if got, want := safe.codeBook.Secrets[0].StartAt, fakeNow.Unix(); got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	encode, decode = safe.Codecs()
	wantNonNilCodecs(t, encode)
	wantNonNilCodecs(t, decode)
	wantCodeBookLength(t, encode, 1)
	wantCodeBookLength(t, decode, 1)

	const cookieName = "test-cookie"

	encoded1, err := securecookie.EncodeMulti(cookieName, "content", encode...)
	wantNilError(t, err)
	t.Log("encoded1:", encoded1)

	// move into the future
	fakeNow = fakeNow.Add(safe.RotationPeriod() + time.Second)
	wantNilError(t, safe.Refresh(ctx))

	// should have 2 secrets now
	if got, want := len(safe.codeBook.Secrets), 2; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}

	// but encode should still be using the old secret, and
	// decode will use both
	encode, decode = safe.Codecs()
	wantCodeBookLength(t, encode, 1)
	wantCodeBookLength(t, decode, 2)

	// should be able to decode using both the encode codecs and the decode codecs
	var value string
	wantNilError(t, securecookie.DecodeMulti(cookieName, encoded1, &value, encode...))
	wantNilError(t, securecookie.DecodeMulti(cookieName, encoded1, &value, decode...))

	// move far enough into the future so that the lastest key will be encoded
	fakeNow = fakeNow.Add(minimumRotationPeriod + time.Second)

	// encode should be using the new secret now
	// decode will use both
	encode, decode = safe.Codecs()
	wantCodeBookLength(t, encode, 2)
	wantCodeBookLength(t, decode, 2)

	// encoded2 should be using a different key to encoded1s
	encoded2, err := securecookie.EncodeMulti(cookieName, "content", encode...)
	wantNilError(t, err)
	t.Log("encoded2:", encoded2)

	// at this point, both encoded1 and encoded2 can be decoded
	wantNilError(t, securecookie.DecodeMulti(cookieName, encoded1, &value, decode...))
	wantNilError(t, securecookie.DecodeMulti(cookieName, encoded2, &value, decode...))

	// move far enough into the future so that the oldest key will be removed
	fakeNow = fakeNow.Add(safe.RotationPeriod() + time.Second)
	wantNilError(t, safe.Refresh(ctx))

	encode, decode = safe.Codecs()
	wantCodeBookLength(t, encode, 1)
	wantCodeBookLength(t, decode, 2)

	// at this point, encoded1 is obsolete and encoded2 can be decoded
	wantError(t, securecookie.DecodeMulti(cookieName, encoded1, &value, decode...))
	wantNilError(t, securecookie.DecodeMulti(cookieName, encoded2, &value, decode...))
}

func wantNilError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}
}

func wantError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("got=nil, want=non-nil")
	}
	t.Logf("expected error: %v", err)
}

func wantNilCodecs(t *testing.T, codecs []securecookie.Codec) {
	t.Helper()
	if codecs != nil {
		t.Fatalf("got=%v, want=nil", codecs)
	}
}

func wantCodeBookLength(t *testing.T, codecs []securecookie.Codec, want int) {
	t.Helper()
	if got := len(codecs); got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
}

func wantNonNilCodecs(t *testing.T, codecs []securecookie.Codec) {
	t.Helper()
	if codecs == nil {
		t.Fatalf("got=nil, want=non-nil")
	}
}

func restoreStubs() {
	timeNowFunc = time.Now
	randReadFunc = rand.Read
}

/*
type memoryStore struct {
	rec    *Record
	getErr error
	putErr error
}

func (ms *memoryStore) GetSecret(ctx context.Context) (*Record, error) {
	if ms.getErr != nil {
		return nil, ms.getErr
	}
	if ms.rec == nil {
		return nil, nil
	}
	var rec = *ms.rec
	return &rec, nil
}

func (ms *memoryStore) PutSecret(ctx context.Context, rec *Record) (bool, error) {
	if ms.putErr != nil {
		return false, ms.putErr
	}
	if ms.rec == nil {
		if rec.Version != 0 {
			return false, nil
		}
	} else if ms.rec.Version != rec.Version {
		return false, nil
	}
	rec.Version++
	var copy = *rec
	ms.rec = &copy
	return true, nil
}
*/

func (safe *Safe) shouldRefreshNow() bool {
	return safe.RefreshIn() <= 0
}
