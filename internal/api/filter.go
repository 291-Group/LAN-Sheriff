package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/store"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// filterFrom builds the shared filter from query parameters, so every endpoint
// accepts the same vocabulary and the UI can carry one filter set across views.
//
// Supported: range, from, to, device, process, country, org, proto, port,
// direction, active, q, limit.
func filterFrom(r *http.Request, defaultDirection types.Direction) store.Filter {
	q := r.URL.Query()

	f := store.Filter{
		Device:     q.Get("device"),
		Process:    q.Get("process"),
		Country:    q.Get("country"),
		Org:        q.Get("org"),
		Search:     q.Get("q"),
		ActiveOnly: q.Get("active") == "1",
		Limit:      intParam(r, "limit", 0),
	}

	if p := q.Get("proto"); p != "" {
		f.Proto = types.Proto(strings.ToLower(p))
	}
	if n, err := strconv.Atoi(q.Get("port")); err == nil && n > 0 {
		f.Port = n
	}

	switch d := types.Direction(q.Get("direction")); d {
	case types.DirOut, types.DirIn, types.DirInternal:
		f.Direction = d
	case "any":
		f.Direction = ""
	default:
		f.Direction = defaultDirection
	}

	f.Since, f.Until = timeRange(r)
	return f
}

// timeRange resolves the window being asked for.
//
// Either an explicit from/to pair of unix seconds, which is what the scrub
// control sends, or a relative range like "15m", "24h" or "7d". Relative is the
// default because the live view always wants "recently", not a fixed window.
func timeRange(r *http.Request) (since, until time.Time) {
	q := r.URL.Query()

	if from := q.Get("from"); from != "" {
		if n, err := strconv.ParseInt(from, 10, 64); err == nil {
			since = time.Unix(n, 0)
		}
	}
	if to := q.Get("to"); to != "" {
		if n, err := strconv.ParseInt(to, 10, 64); err == nil {
			until = time.Unix(n, 0)
		}
	}
	if !since.IsZero() {
		return since, until
	}
	return time.Now().Add(-parseRange(q.Get("range"))), until
}

// parseRange understands Go durations plus a day unit, which Go's parser has
// no notion of but every time-range control needs.
func parseRange(v string) time.Duration {
	const fallback = time.Hour
	if v == "" {
		return fallback
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	if strings.HasSuffix(v, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(v, "d")); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour
		}
	}
	return fallback
}
