package codecstore

import (
	"context"
	"crypto/rand"
	mrand "math/rand"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/jjeffery/sessions/storage/memory"
)

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

func TestEncodeDecode(t *testing.T) {
	var fakeNow = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	timeNowFunc = func() time.Time {
		return fakeNow
	}
	db := memory.New().WithTimeNow(timeNowFunc)
	ctx := context.Background()
	store := New(db, time.Hour, "")

	cookies := make(map[string]time.Time)

	for i := 0; i < 720; i++ {
		codec, err := store.Codec(ctx)
		wantNilError(t, err)
		cookie, err := codec.Encode("cookie", "some value")
		wantNilError(t, err)
		cookies[cookie] = timeNowFunc()
		old := timeNowFunc().Add(-time.Hour)

		for c, tm := range cookies {
			if tm.Before(old) {
				delete(cookies, c)
				continue
			}
			var someValue string
			err = codec.Decode("cookie", c, &someValue)
			wantNilError(t, err)
		}

		fakeNow = fakeNow.Add(time.Millisecond * time.Duration(mrand.Intn(60000)))
	}
}

func TestRace(t *testing.T) {
	var mutex sync.RWMutex
	var fakeNow = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	timeNowFunc = func() time.Time {
		var result time.Time
		mutex.RLock()
		result = fakeNow
		mutex.RUnlock()
		return result
	}
	advanceTime := func() {
		mutex.Lock()
		fakeNow = fakeNow.Add(time.Millisecond * 1017)
		mutex.Unlock()
	}
	db := memory.New().WithTimeNow(timeNowFunc)
	ctx := context.Background()
	store := New(db, time.Hour, "")

	var wg sync.WaitGroup

	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			for i := 0; i < 7200; i++ {
				_, err := store.Codec(ctx)
				wantNilError(t, err)
				advanceTime()
			}
			wg.Done()
		}()
	}

	wg.Wait()
}

func TestCodec(t *testing.T) {
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

	codec1, err := safe.Codec(ctx)
	wantNilError(t, err)
	wantCodecLength(t, codec1.encoders, 1)
	wantCodecLength(t, codec1.decoders, 1)

	fakeNow = fakeNow.Add(minimumRotationPeriod - 10*time.Millisecond)
	codec2, err := safe.Codec(ctx)
	wantNilError(t, err)
	wantSameCodecs(t, codec1, codec2)

	fakeNow = fakeNow.Add(11 * time.Millisecond)
	codec2, err = safe.Codec(ctx)
	wantNilError(t, err)
	wantDifferentCodecs(t, codec1, codec2)
	wantCodecLength(t, codec2.encoders, 1)
	wantCodecLength(t, codec2.decoders, 1)

	fakeNow = fakeNow.Add(safe.RotationPeriod())
	codec1, err = safe.Codec(ctx)
	wantNilError(t, err)
	wantCodecLength(t, codec1.encoders, 1)
	wantCodecLength(t, codec1.decoders, 2)

	fakeNow = fakeNow.Add(minimumRotationPeriod + time.Millisecond)
	codec2, err = safe.Codec(ctx)
	wantNilError(t, err)
	wantDifferentCodecs(t, codec1, codec2)
	wantCodecLength(t, codec2.encoders, 2)
	wantCodecLength(t, codec2.decoders, 2)

	fakeNow = fakeNow.Add(safe.RotationPeriod() + time.Millisecond)
	codec1, err = safe.Codec(ctx)
	wantNilError(t, err)
	wantCodecLength(t, codec1.encoders, 2)
	wantCodecLength(t, codec1.decoders, 2)

	fakeNow = fakeNow.Add(minimumRotationPeriod + time.Millisecond)
	codec1, err = safe.Codec(ctx)
	wantNilError(t, err)
	wantCodecLength(t, codec1.encoders, 1)
	wantCodecLength(t, codec1.decoders, 2)
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

func wantCodecLength(t *testing.T, codecs []securecookie.Codec, want int) {
	t.Helper()
	if got := len(codecs); got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
}

func wantSameCodecs(t *testing.T, c1, c2 securecookie.Codec) {
	t.Helper()
	if c1 != c2 {
		t.Fatalf("want same codecs")
	}
}

func wantDifferentCodecs(t *testing.T, c1, c2 securecookie.Codec) {
	t.Helper()
	if c1 == c2 {
		t.Fatalf("want different codecs")
	}
}

func restoreStubs() {
	timeNowFunc = time.Now
	randReadFunc = rand.Read
}
