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
	codec := Codec{
		DB: memory.New(),
	}
	if got, want := codec.rotationPeriod(), DefaultMaxAge; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
	codec = Codec{
		DB:             memory.New(),
		RotationPeriod: time.Second * 30,
	}
	if got, want := codec.rotationPeriod(), MinimumRotationPeriod; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
}

func TestLength(t *testing.T) {
	codec := &Codec{
		DB:     memory.New(),
		MaxAge: time.Hour,
	}

	message := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	cipherText, err := codec.Encode("really-long-cookie-name", message)
	wantNilError(t, err)
	t.Logf("%d bytes: %s", len(cipherText), cipherText)
}

func TestEncodeDecode(t *testing.T) {
	var fakeNow = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	timeNowFunc = func() time.Time {
		return fakeNow
	}
	db := memory.New().WithTimeNow(timeNowFunc)
	ctx := context.Background()
	codec := Codec{
		DB:     db,
		MaxAge: time.Hour,
	}

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
	codec := Codec{
		DB:     db,
		MaxAge: time.Hour,
	}

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
	codec := &Codec{DB: db}

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

	fakeNow = fakeNow.Add(codec.rotationPeriod())
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

	fakeNow = fakeNow.Add(codec.rotationPeriod() + time.Millisecond - MinimumRotationPeriod)
	err = codec.Refresh(ctx)
	wantNilError(t, err)
	wantCodecLength(t, codec.codec.encoders, 2)
	wantCodecLength(t, codec.codec.decoders, 2)

	fakeNow = fakeNow.Add(MinimumRotationPeriod + time.Millisecond)
	err = codec.Refresh(ctx)
	wantNilError(t, err)
	wantCodecLength(t, codec.codec.encoders, 2)
	wantCodecLength(t, codec.codec.decoders, 3)
}

func TestExpired(t *testing.T) {
	defer restoreStubs()
	var fakeNow = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	timeNowFunc = func() time.Time {
		return fakeNow
	}

	codec := &Codec{
		DB: memory.New().WithTimeNow(timeNowFunc),
	}

	text, err := codec.Encode("cookie", "data")
	wantNilError(t, err)

	fakeNow = fakeNow.Add(codec.maxAge() - time.Microsecond)

	var value string
	err = codec.Decode("cookie", text, &value)
	wantNilError(t, err)

	fakeNow = fakeNow.Add(2 * time.Microsecond)
	err = codec.Decode("cookie", text, &value)
	wantError(t, err)

	if decode, ok := err.(securecookie.Error); !ok {
		t.Fatalf("want decode error got %v", err)
	} else {
		if got, want := decode.IsDecode(), true; got != want {
			t.Errorf("got=%v, want=%v", got, want)
		}
		if got, want := decode.IsInternal(), false; got != want {
			t.Errorf("got=%v, want=%v", got, want)
		}
		if got, want := decode.IsUsage(), false; got != want {
			t.Errorf("got=%v, want=%v", got, want)
		}
		wantNilError(t, decode.Cause())
	}
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
