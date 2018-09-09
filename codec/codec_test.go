package codec

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
	codec := New(memory.New(), 0, "")
	if got, want := codec.RotationPeriod, DefaultRotationPeriod; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
	codec = New(memory.New(), time.Second*30, "")
	if got, want := codec.RotationPeriod, MinimumRotationPeriod; got != want {
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
	codec := New(db, time.Hour, "")

	cookies := make(map[string]time.Time)

	for i := 0; i < 720; i++ {
		err := codec.Refresh(ctx)
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
	codec := New(db, time.Hour, "")

	var wg sync.WaitGroup

	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			for i := 0; i < 7200; i++ {
				err := codec.Refresh(ctx)
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
	codec := New(db, 0, "")

	err := codec.Refresh(ctx)
	wantNilError(t, err)
	wantCodecLength(t, codec.codec.encoders, 1)
	wantCodecLength(t, codec.codec.decoders, 1)
	comp := newComparer(codec)

	fakeNow = fakeNow.Add(MinimumRotationPeriod - 10*time.Millisecond)
	err = codec.Refresh(ctx)
	wantNilError(t, err)
	comp.wantSame(t, codec)

	fakeNow = fakeNow.Add(11 * time.Millisecond)
	err = codec.Refresh(ctx)
	wantNilError(t, err)
	comp.wantDifferent(t, codec)
	wantCodecLength(t, codec.codec.encoders, 1)
	wantCodecLength(t, codec.codec.decoders, 1)

	fakeNow = fakeNow.Add(codec.RotationPeriod)
	err = codec.Refresh(ctx)
	wantNilError(t, err)
	wantCodecLength(t, codec.codec.encoders, 1)
	wantCodecLength(t, codec.codec.decoders, 2)
	comp = newComparer(codec)

	fakeNow = fakeNow.Add(MinimumRotationPeriod + time.Millisecond)
	err = codec.Refresh(ctx)
	wantNilError(t, err)
	comp.wantDifferent(t, codec)
	wantCodecLength(t, codec.codec.encoders, 2)
	wantCodecLength(t, codec.codec.decoders, 2)

	fakeNow = fakeNow.Add(codec.RotationPeriod + time.Millisecond)
	err = codec.Refresh(ctx)
	wantNilError(t, err)
	wantCodecLength(t, codec.codec.encoders, 2)
	wantCodecLength(t, codec.codec.decoders, 2)

	fakeNow = fakeNow.Add(MinimumRotationPeriod + time.Millisecond)
	err = codec.Refresh(ctx)
	wantNilError(t, err)
	wantCodecLength(t, codec.codec.encoders, 1)
	wantCodecLength(t, codec.codec.decoders, 2)
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

type codecComparer struct {
	ic *immutableCodec
}

func newComparer(codec *Codec) codecComparer {
	return codecComparer{
		ic: codec.codec,
	}
}

func (c codecComparer) wantSame(t *testing.T, codec *Codec) {
	t.Helper()
	if c.ic != codec.codec {
		t.Fatal("want same codec details")
	}
}

func (c codecComparer) wantDifferent(t *testing.T, codec *Codec) {
	t.Helper()
	if c.ic == codec.codec {
		t.Fatal("want different codec details")
	}
}
