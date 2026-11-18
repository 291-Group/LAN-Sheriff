package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func healthServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var se silentExit
	if errors.As(err, &se) {
		return se.code
	}
	return -1
}

func TestHealthExitCodes(t *testing.T) {
	cases := []struct {
		name, body string
		want       int
	}{
		{"healthy", `{"tracked":true,"ingest":{"consecutive_failures":0},"storage":{"ok":true}}`, 0},
		// A stall is reported but does not fail the check; see health.go.
		{"writes stalled", `{"tracked":true,"ingest":{"consecutive_failures":4,"last_error":"database is locked (5)"},"storage":{"ok":true}}`, 0},
		{"damaged", `{"tracked":true,"ingest":{"consecutive_failures":0},"storage":{"ok":false,` +
			`"damage":{"error":"database disk image is malformed (11)","source":"integrity check","since":"2026-11-15T03:25:42-05:00","file":"sheriff.db"},` +
			`"remedy":"stop LAN Sheriff, move sheriff.db..."}}`, 1},
		// An older server that does not report storage is not called damaged.
		{"older server", `{"tracked":true,"ingest":{"consecutive_failures":0}}`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := healthServer(c.body)
			defer srv.Close()
			got := exitCode(runHealth(context.Background(), srv.URL, 2*time.Second))
			if got != c.want {
				t.Errorf("exit %d, want %d", got, c.want)
			}
		})
	}
}
