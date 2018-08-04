package sessionstore

import (
	"crypto/rand"
	"io"
	"testing"
	"time"
)

func TestSessionID(t *testing.T) {
	var nextByte byte
	randRead = func(data []byte) (n int, err error) {
		for i := 0; i < len(data); i++ {
			data[i] = nextByte
			nextByte++
			n++
		}
		return n, err
	}
	defer restoreStubs()

	sid, err := newSessionID()
	if err != nil {
		t.Fatalf("got=%v, want=nil", err)
	}
	if got, want := sid, sessionID([16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}); got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
	if got, want := sid.String(), "000102030405060708090a0b0c0d0e0f"; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
	randRead = func(data []byte) (n int, err error) {
		return 0, io.EOF
	}
	sid, err = newSessionID()
	if got, want := err, io.EOF; got != want {
		t.Fatalf("got=%v, want=%v", got, want)
	}
}

func TestParseSessionID(t *testing.T) {
	tests := []struct {
		str     string
		errText string
		sid     sessionID
	}{
		{
			str:     "",
			errText: "empty session id",
		},
		{
			str:     "abcf4",
			errText: "encoding/hex: odd length hex string",
		},
		{
			str:     "abcf45",
			errText: "sessionID too small len=3",
		},
		{
			str: "000102030405060708090a0b0c0d0e0f",
			sid: sessionID([16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}),
		},
	}
	for tn, tt := range tests {
		sid, err := parseSessionID(tt.str)
		if tt.errText != "" {
			// expecting error
			if err == nil {
				t.Errorf("%d: got=nil, want=%q", tn, tt.errText)
				continue
			}
			if got, want := err.Error(), tt.errText; got != want {
				t.Errorf("%d: got=%q, want=%q", tn, got, want)
				continue
			}
		} else {
			if err != nil {
				t.Errorf("%d: got=%v, want=nil", tn, err)
				continue
			}
			if got, want := sid, tt.sid; got != want {
				t.Errorf("%d: got=%v, want=%v", tn, got, want)
				continue
			}
		}
	}
}

func restoreStubs() {
	nowFunc = time.Now
	randRead = rand.Read
}
