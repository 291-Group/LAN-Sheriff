package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/auth"
	"github.com/291-Group/LAN-Sheriff/internal/capture"
	"github.com/291-Group/LAN-Sheriff/internal/dispatch"
	"github.com/291-Group/LAN-Sheriff/internal/pipeline"
	"github.com/291-Group/LAN-Sheriff/internal/store"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

const testPassword = "correct-horse-battery-staple"

// newServer builds a server over a real store, because the handlers are thin
// and the queries underneath them are the part worth exercising.
func newServer(t *testing.T, password string) (*Server, http.Handler) {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	authn, err := auth.New(password, time.Hour)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}

	s := &Server{
		Store:   st,
		Bus:     pipeline.NewBus(16),
		Probe:   capture.Probe{Active: "deputy"},
		Auth:    authn,
		Version: "test",
	}
	s.SetRetention(store.DefaultRetention())
	return s, s.RequireAuth(s.Routes())
}

func seed(t *testing.T, s *Server) {
	t.Helper()
	ctx := t.Context()
	now := time.Now()

	if err := s.Store.TouchEndpoints(ctx, map[string]store.EndpointSighting{
		"93.184.216.34": store.Sighting(false, now),
		"192.168.1.10":  store.Sighting(true, now),
	}); err != nil {
		t.Fatalf("touch: %v", err)
	}
	s.Store.SaveEnrichment(ctx, types.Endpoint{
		IP: "93.184.216.34", Country: "US", CountryName: "United States",
		City: "Boston", Org: "Edgecast", ASN: 15133, Lat: 42.36, Lon: -71.06,
	})

	out := types.Flow{
		TSStart: now, TSLast: now, DeviceID: "self-test", Process: "Firefox",
		SrcIP: "192.168.1.5", SrcPort: 5000, DstIP: "93.184.216.34", DstPort: 443,
		Proto: types.ProtoTCP, Direction: types.DirOut, Active: true,
	}
	in := out
	in.SrcPort, in.DstPort, in.Direction = 22, 51234, types.DirIn
	in.Process = "sshd"

	if err := s.Store.WriteFlows(ctx, []types.Flow{out, in}); err != nil {
		t.Fatalf("write flows: %v", err)
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	return v
}

// ---------- the authentication boundary ----------

func TestDataIsRefusedWithoutASession(t *testing.T) {
	s, h := newServer(t, testPassword)
	seed(t, s)

	// Every endpoint that can reveal anything about the network.
	for _, path := range []string{
		"/api/summary", "/api/egress", "/api/inbound", "/api/devices",
		"/api/flows", "/api/timeline", "/api/search?q=edge", "/api/settings",
		"/api/endpoints/93.184.216.34", "/api/export?view=egress",
		"/api/capabilities", "/api/stream", "/api/dispatch",
		"/api/dispatch/destinations",
	} {
		t.Run(path, func(t *testing.T) {
			if code := get(t, h, path).Code; code != http.StatusUnauthorized {
				t.Errorf("%s returned %d without a session, want 401", path, code)
			}
		})
	}

	// State-changing peering endpoints. An unauthenticated caller must not be
	// able to open a pairing window: that would admit an unpinned key to the
	// listener, which is the one thing the whole design refuses.
	for _, path := range []string{
		"/api/dispatch/pair", "/api/dispatch/join",
		"/api/dispatch/peers/ABCDE/trust",
	} {
		t.Run("POST "+path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("POST %s returned %d without a session, want 401", path, rec.Code)
			}
		})
	}
}

func TestAuthEndpointsStayReachableWhileSignedOut(t *testing.T) {
	// Otherwise there is no way to ever sign in.
	_, h := newServer(t, testPassword)
	if code := get(t, h, "/api/auth/status").Code; code != http.StatusOK {
		t.Errorf("auth status returned %d, want 200", code)
	}
}

func TestNoPasswordMeansOpenAccess(t *testing.T) {
	// A loopback-only install sets no password, and must not be gated.
	s, h := newServer(t, "")
	seed(t, s)

	if code := get(t, h, "/api/summary").Code; code != http.StatusOK {
		t.Errorf("summary returned %d with no password configured, want 200", code)
	}
}

func TestSetupRequiredBlocksEverything(t *testing.T) {
	s, h := newServer(t, "")
	s.Auth.SetSetupRequired(true)
	seed(t, s)

	if code := get(t, h, "/api/summary").Code; code != http.StatusUnauthorized {
		t.Error("data must not be served before a password has been created")
	}

	status := decode[AuthStatus](t, get(t, h, "/api/auth/status"))
	if !status.NeedsSetup || status.Authenticated {
		t.Errorf("status should report setup pending and not authenticated, got %+v", status)
	}
}

func TestLoginGrantsAccessAndLogoutRevokesIt(t *testing.T) {
	s, h := newServer(t, testPassword)
	seed(t, s)

	body := strings.NewReader(`{"password":"` + testPassword + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login returned %d: %s", rec.Code, rec.Body)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login should set a session cookie")
	}
	session := cookies[0]
	if !session.HttpOnly {
		t.Error("the session cookie must be HttpOnly so scripts cannot read it")
	}
	if session.SameSite != http.SameSiteStrictMode {
		t.Error("the session cookie must be SameSite=Strict to blunt cross-site request forgery")
	}

	authed := func() int {
		r := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
		r.AddCookie(session)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if authed() != http.StatusOK {
		t.Error("a valid session should reach the data")
	}

	out := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	out.AddCookie(session)
	h.ServeHTTP(httptest.NewRecorder(), out)

	if authed() != http.StatusUnauthorized {
		t.Error("the session must not survive signing out")
	}
}

func TestWrongPasswordIsRejectedVaguely(t *testing.T) {
	_, h := newServer(t, testPassword)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
		strings.NewReader(`{"password":"wrong"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
	// The message must not distinguish "no such user" from "bad password", or
	// hint at the password's shape.
	if msg := rec.Body.String(); strings.Contains(strings.ToLower(msg), testPassword) {
		t.Error("the error must not echo the attempted password")
	}
}

// ---------- filters and views ----------

func TestEgressDefaultsToOutboundOnly(t *testing.T) {
	s, h := newServer(t, "")
	seed(t, s)

	type resp struct {
		Endpoints []store.EgressRow `json:"endpoints"`
	}

	// Egress means egress: an inbound connection must not be drawn as an arc
	// leaving this machine.
	got := decode[resp](t, get(t, h, "/api/egress?range=24h"))
	for _, e := range got.Endpoints {
		for _, p := range e.Processes {
			if p == "sshd" {
				t.Error("the inbound connection leaked into the egress view")
			}
		}
	}

	inbound := decode[resp](t, get(t, h, "/api/inbound?range=24h"))
	if len(inbound.Endpoints) == 0 {
		t.Error("the inbound view should report the connection opened to us")
	}
}

func TestFiltersNarrowTheView(t *testing.T) {
	s, h := newServer(t, "")
	seed(t, s)

	type resp struct {
		Endpoints []store.EgressRow `json:"endpoints"`
	}
	all := decode[resp](t, get(t, h, "/api/egress?range=24h"))
	if len(all.Endpoints) == 0 {
		t.Fatal("expected at least one destination to start from")
	}

	for _, q := range []string{"process=Firefox", "country=US", "org=Edgecast", "q=edgecast"} {
		t.Run(q, func(t *testing.T) {
			if got := decode[resp](t, get(t, h, "/api/egress?range=24h&"+q)); len(got.Endpoints) == 0 {
				t.Errorf("filter %q matched nothing, but should match the seeded flow", q)
			}
		})
	}
	if got := decode[resp](t, get(t, h, "/api/egress?range=24h&process=NoSuchApp")); len(got.Endpoints) != 0 {
		t.Error("a filter matching nothing should return nothing")
	}
}

func TestInternalDestinationsAreNeverEgress(t *testing.T) {
	s, h := newServer(t, "")
	seed(t, s)

	type resp struct {
		Endpoints []store.EgressRow `json:"endpoints"`
	}
	got := decode[resp](t, get(t, h, "/api/egress?range=24h"))
	for _, e := range got.Endpoints {
		if e.IsInternal {
			t.Errorf("%s is a private address and must not appear on the map", e.IP)
		}
	}
}

func TestParseRange(t *testing.T) {
	cases := map[string]time.Duration{
		"15m":      15 * time.Minute,
		"1h":       time.Hour,
		"24h":      24 * time.Hour,
		"7d":       7 * 24 * time.Hour,
		"30d":      30 * 24 * time.Hour,
		"":         time.Hour, // default
		"nonsense": time.Hour,
		"-5h":      time.Hour, // a negative window is meaningless
	}
	for in, want := range cases {
		if got := parseRange(in); got != want {
			t.Errorf("parseRange(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestExportCarriesTheFilterAndADownloadName(t *testing.T) {
	s, h := newServer(t, "")
	seed(t, s)

	rec := get(t, h, "/api/export?view=egress&format=csv&range=24h")
	if rec.Code != http.StatusOK {
		t.Fatalf("export returned %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("export should download rather than render, got %q", cd)
	}

	body := rec.Body.String()
	if !strings.HasPrefix(body, "ip,rdns,asn,org,country") {
		t.Errorf("unexpected CSV header: %q", strings.SplitN(body, "\n", 2)[0])
	}
	if !strings.Contains(body, "93.184.216.34") {
		t.Error("the seeded destination should be present in the export")
	}
	// Export honours the same filter as the screen it came from.
	filtered := get(t, h, "/api/export?view=egress&format=csv&range=24h&process=NoSuchApp")
	if strings.Contains(filtered.Body.String(), "93.184.216.34") {
		t.Error("export ignored the filter")
	}
}

func TestExportRejectsAnUnknownView(t *testing.T) {
	_, h := newServer(t, "")
	if code := get(t, h, "/api/export?view=../../etc/passwd").Code; code != http.StatusBadRequest {
		t.Errorf("an unknown view should be refused, got %d", code)
	}
}

func TestSummaryReportsModeAndCapabilities(t *testing.T) {
	s, h := newServer(t, "")
	seed(t, s)

	sum := decode[SummaryResponse](t, get(t, h, "/api/summary?range=24h"))
	if sum.Mode != "deputy" {
		t.Errorf("mode = %q, want deputy", sum.Mode)
	}
	if sum.Version != "test" {
		t.Errorf("version = %q, want the injected build string", sum.Version)
	}
	if sum.Inbound == 0 {
		t.Error("the seeded inbound connection should be counted")
	}
}

func TestSettingsRejectAbsurdRetention(t *testing.T) {
	_, h := newServer(t, "")

	for _, body := range []string{
		`{"retention_raw_hours":0,"retention_rollup_days":1,"storage_max_mb":64}`,
		`{"retention_raw_hours":1,"retention_rollup_days":0,"storage_max_mb":64}`,
		`{"retention_raw_hours":1,"retention_rollup_days":1,"storage_max_mb":1}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("settings %s returned %d, want 400", body, rec.Code)
		}
	}
}

func TestWipeRemovesObservations(t *testing.T) {
	s, h := newServer(t, "")
	seed(t, s)

	req := httptest.NewRequest(http.MethodPost, "/api/wipe", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("wipe returned %d", rec.Code)
	}

	type resp struct {
		Endpoints []store.EgressRow `json:"endpoints"`
	}
	if got := decode[resp](t, get(t, h, "/api/egress?range=24h")); len(got.Endpoints) != 0 {
		t.Error("data survived the wipe")
	}
}

func TestUnknownEndpointIsNotFound(t *testing.T) {
	_, h := newServer(t, "")
	if code := get(t, h, "/api/endpoints/203.0.113.99").Code; code != http.StatusNotFound {
		t.Errorf("got %d, want 404", code)
	}
}

// Peer sharing can be switched on from the dashboard, and switching it on is
// recorded where somebody looking later will find it.
//
// The endpoint exists because peering was the only setting in the application
// that required quitting, editing a command line and starting again, on the
// machine most likely to be a Pi reached over SSH. It is guarded by the same
// authentication as every other mutating endpoint, and by the same
// SameSite=Strict session cookie; a caller who can reach it can already export
// every connection this instance has recorded.
func TestPeeringCanBeEnabledFromTheDashboard(t *testing.T) {
	s, h := newServer(t, "")

	// A host that cannot start peering says so rather than pretending.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, jsonReq(t, http.MethodPost, "/api/dispatch/enabled", `{"enabled":true}`))
	if rec.Code != http.StatusConflict {
		t.Fatalf("without a StartPeering hook: status %d, want 409", rec.Code)
	}

	// With one, it starts and is reported as on.
	var started int
	s.StartPeering = func(context.Context) (*dispatch.Service, error) {
		started++
		return &dispatch.Service{}, nil
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, jsonReq(t, http.MethodPost, "/api/dispatch/enabled", `{"enabled":true}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("enabling: status %d body %s", rec.Code, rec.Body)
	}
	if started != 1 {
		t.Errorf("StartPeering called %d times, want 1", started)
	}
	if s.Peering() == nil {
		t.Error("peering is still nil after being enabled")
	}

	// Enabling twice must not start a second service.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, jsonReq(t, http.MethodPost, "/api/dispatch/enabled", `{"enabled":true}`))
	if started != 1 {
		t.Errorf("a second enable started another service (%d)", started)
	}

	// The choice is remembered, so a restart keeps it.
	if v, ok, _ := s.Store.Setting(context.Background(), "dispatch_enabled"); !ok || v != "on" {
		t.Errorf("setting = %q ok=%v, want \"on\"", v, ok)
	}

	// And it is in the ledger, which is the record that answers "was this
	// machine ever sharing" after everything has been turned off again.
	hist, err := s.Store.PairingHistory(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].Event != "sharing_on" {
		t.Errorf("ledger = %+v, want one sharing_on entry", hist)
	}
}

func jsonReq(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// Exactly one of many simultaneous setup requests may establish the password.
//
// This is a regression test for a real race, found by pointing twelve
// concurrent requests at a server bound to a LAN address. Every one of the
// twelve was answered `{"ok":true}`, and the password that survived belonged to
// whichever request finished last. The handler checked NeedsSetup and then
// called SetPassword, and between those two lock acquisitions any number of
// other requests could pass the same check.
//
// What it cost was not theoretical. The person setting the machine up got a
// success and a working session cookie, so they had no reason to look again,
// while a stranger holding requests open owned the password and would still own
// it after that session expired. Being first is supposed to be how you win a
// first-run setup; being last to finish is not.
//
// The assertion is deliberately about the *count*, not about who won. Which
// racer wins is a scheduling detail and testing for it would be testing the Go
// runtime. That only one can win is the property that matters.
func TestOnlyOneConcurrentSetupCanWin(t *testing.T) {
	const racers = 12

	s, h := newServer(t, "")
	s.Auth.SetSetupRequired(true)

	var saved atomic.Int32
	s.SaveHash = func(string) error {
		saved.Add(1)
		return nil
	}

	// A barrier, so the requests are genuinely inside the handler together.
	// Starting twelve goroutines and hoping they overlap would pass against the
	// broken code often enough to be worthless.
	release := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, racers)

	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := strings.NewReader(
				fmt.Sprintf(`{"password":"password-from-racer-%02d"}`, i))
			req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", body)
			rec := httptest.NewRecorder()
			<-release
			h.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}()
	}
	close(release)
	wg.Wait()

	var won, refused int
	for i, code := range codes {
		switch code {
		case http.StatusOK:
			won++
		case http.StatusConflict:
			refused++
		default:
			t.Errorf("racer %d: unexpected status %d", i, code)
		}
	}
	if won != 1 {
		t.Errorf("exactly one setup may succeed, %d did", won)
	}
	if refused != racers-1 {
		t.Errorf("the other %d must be refused, %d were", racers-1, refused)
	}

	// The password is only persisted by the racer that actually set it, so a
	// loser cannot overwrite the winner's hash on disk after the fact.
	if n := saved.Load(); n != 1 {
		t.Errorf("the hash must be written once, it was written %d times", n)
	}

	// And the install is now genuinely closed: setup is over, and a further
	// attempt cannot reopen it.
	if s.Auth.NeedsSetup() {
		t.Error("setup should be complete")
	}
	body := strings.NewReader(`{"password":"a-latecomers-password"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("a later setup attempt must be refused, got %d", rec.Code)
	}
}

// A fresh install must not hand the dashboard `null` where it expects a list.
//
// Go marshals a nil slice as `null`. The Roster reads devices as an array, so on
// a database with nothing discovered yet it evaluated null.length, threw
// "Cannot read properties of null", and rendered a blank panel: a fresh install
// looking broken at the one moment it must not.
//
// The assertion is on the JSON rather than on the Go value, because the defect
// only exists once it has been marshalled.
func TestEmptyInstallNeverSerialisesNullCollections(t *testing.T) {
	_, h := newServer(t, "") // no seed: this is a first run

	for _, tc := range []struct {
		path   string
		fields []string
	}{
		{"/api/devices", []string{"devices"}},
		{"/api/summary", []string{"top_orgs", "top_countries", "top_processes"}},
	} {
		rec := get(t, h, tc.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", tc.path, rec.Code)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		for _, f := range tc.fields {
			raw, ok := body[f]
			if !ok {
				t.Errorf("%s: no %q field at all", tc.path, f)
				continue
			}
			if string(raw) == "null" {
				t.Errorf("%s: %q is null; the dashboard treats it as an array and crashes", tc.path, f)
			}
			var arr []any
			if err := json.Unmarshal(raw, &arr); err != nil {
				t.Errorf("%s: %q is not an array: %s", tc.path, f, raw)
			}
		}
	}
}
