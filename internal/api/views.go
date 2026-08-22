package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/store"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// handleTimeline backs the scrub control: hourly activity across a window,
// served from raw flows where they still exist and from rollups where they do
// not.
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	since, until := timeRange(r)
	if until.IsZero() {
		until = time.Now()
	}
	points, err := s.Store.Timeline(r.Context(), since, until)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	if points == nil {
		points = []store.TimePoint{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from":   since.Unix(),
		"to":     until.Unix(),
		"points": points,
	})
}

// handleSearch answers for the chosen layer.
//
// Peer hits are appended and carry the reporting peer's name, so a result from
// another machine is never mistaken for one of this machine's own. They are
// organizations and applications only: a peer sends no address, so there is
// nothing endpoint-shaped to match against.
//
// Searching used to read this machine's tables whatever the layer, which meant
// a paired household could watch a peer's traffic to an organization on the map
// and then get nothing at all by typing that organization's name.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	limit := intParam(r, "limit", 20)
	layer, wantsPeers := layerParam(r)

	results := []store.SearchResult{}
	if layer != layerAll && wantsPeers {
		// One peer's layer asks about that peer, not about this machine.
	} else {
		found, err := s.Store.Search(r.Context(), q, limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
			return
		}
		results = append(results, found...)
	}

	if wantsPeers && s.Peering() != nil {
		found, err := s.Store.PeerSearch(r.Context(), q, rangeParam(r), limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
			return
		}
		results = append(results, found...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	flows, err := s.Store.Flows(r.Context(), filterFrom(r, ""))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	if flows == nil {
		flows = []types.Flow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"flows": flows})
}

// handleExport writes the current view out as CSV or JSON.
//
// Export honours the same filter as the screen it was launched from, so what
// lands in the file is what the user was looking at, not the whole database.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	view := r.URL.Query().Get("view")
	if view == "" {
		view = "egress"
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}

	f := filterFrom(r, "")
	// An export is a deliberate action and may reasonably be large.
	if f.Limit == 0 {
		f.Limit = store.ExportCeiling
	}
	f.Export = true

	stamp := time.Now().Format("2006-01-02-1504")
	// **The name says when the file is not the whole answer.**
	//
	// A day of this network is 152957 connections and 48981 lookups; the
	// exports returned 5000 and 2000 of them, in files named as though they
	// were complete, with nothing anywhere saying otherwise. A CSV cannot carry
	// a footnote without ceasing to be a CSV, and the download is a plain link
	// so a response header would never be seen. The filename is the one piece
	// of writing that reaches the reader either way.
	name := func(n int) string {
		if n >= f.Limit {
			return fmt.Sprintf("lan-sheriff-%s-%s-first-%d.%s", view, stamp, n, format)
		}
		return fmt.Sprintf("lan-sheriff-%s-%s.%s", view, stamp, format)
	}

	switch view {
	case "egress", "inbound":
		if view == "inbound" {
			f.Direction = types.DirIn
		} else if f.Direction == "" {
			f.Direction = types.DirOut
		}
		rows, err := s.Store.Egress(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
			return
		}
		if format == "json" {
			writeDownloadJSON(w, name(len(rows)), rows)
			return
		}
		writeCSV(w, name(len(rows)),
			[]string{"ip", "rdns", "asn", "org", "country", "city", "lat", "lon",
				"connections", "bytes_out", "bytes_in", "apps", "ports", "first_seen", "last_seen"},
			func(add func(...string)) {
				for _, e := range rows {
					add(e.IP, e.RDNS, strconv.Itoa(e.ASN), e.Org, e.Country, e.City,
						formatFloat(e.Lat), formatFloat(e.Lon),
						strconv.Itoa(e.Conns), strconv.FormatUint(e.BytesOut, 10),
						strconv.FormatUint(e.BytesIn, 10),
						join(e.Processes), joinInts(e.Ports),
						e.FirstSeen.Format(time.RFC3339), e.LastSeen.Format(time.RFC3339))
				}
			})

	case "flows":
		flows, err := s.Store.Flows(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
			return
		}
		if format == "json" {
			writeDownloadJSON(w, name(len(flows)), flows)
			return
		}
		writeCSV(w, name(len(flows)),
			[]string{"ts_start", "ts_last", "direction", "device", "app", "pid",
				"src_ip", "src_port", "dst_ip", "dst_port", "proto", "bytes_out", "bytes_in", "active"},
			func(add func(...string)) {
				for _, fl := range flows {
					add(fl.TSStart.Format(time.RFC3339), fl.TSLast.Format(time.RFC3339),
						string(fl.Direction), fl.DeviceID, fl.Process, strconv.Itoa(int(fl.PID)),
						fl.SrcIP, strconv.Itoa(int(fl.SrcPort)),
						fl.DstIP, strconv.Itoa(int(fl.DstPort)), string(fl.Proto),
						strconv.FormatUint(fl.BytesOut, 10), strconv.FormatUint(fl.BytesIn, 10),
						strconv.FormatBool(fl.Active))
				}
			})

	// Radio Chatter's own contents. Without this the export buttons on that
	// screen handed the reader a file of destinations, which is a different
	// question than the one they were looking at, and this function's own
	// comment promises otherwise. It failed quietly: a valid CSV of the wrong
	// subject is not an error anybody notices until they open it.
	case "dns":
		events, err := s.Store.DNSEvents(r.Context(), store.DNSOptions{
			Since:  f.Since,
			Until:  f.Until,
			Device: f.Device,
			Domain: f.Search,
			Limit:  f.Limit,
			Export: true,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
			return
		}
		if format == "json" {
			writeDownloadJSON(w, name(len(events)), events)
			return
		}
		writeCSV(w, name(len(events)),
			[]string{"ts", "device", "app", "qname", "qtype", "answers", "resp_ms", "flagged"},
			func(add func(...string)) {
				for _, e := range events {
					add(e.TS.Format(time.RFC3339), e.DeviceID, e.Process, e.QName, e.QType,
						join(e.Answers), strconv.Itoa(e.RespMS), e.Flagged)
				}
			})

	default:
		writeErr(w, http.StatusBadRequest, types.ErrUnknownView, "unknown view: "+view)
	}
}

func writeCSV(w http.ResponseWriter, name string, header []string, rows func(add func(...string))) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(name))

	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write(header); err != nil {
		return
	}
	rows(func(fields ...string) { cw.Write(fields) })
}

func writeDownloadJSON(w http.ResponseWriter, name string, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(name))
	json.NewEncoder(w).Encode(v)
}

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'f', 4, 64) }

// CSV cells hold multiple values separated by "; " rather than "," so a
// spreadsheet does not split them into columns.
func join(v []string) string { return strings.Join(v, "; ") }

func joinInts(v []int) string {
	out := make([]string, len(v))
	for i, n := range v {
		out[i] = strconv.Itoa(n)
	}
	return strings.Join(out, "; ")
}

// Settings the user may change from the dashboard. Deliberately few: anything
// that needs configuring before the tool is useful does not belong here.
type Settings struct {
	RetentionRawHours   int    `json:"retention_raw_hours"`
	RetentionRollupDays int    `json:"retention_rollup_days"`
	StorageMaxMB        int64  `json:"storage_max_mb"`
	DBBytes             int64  `json:"db_bytes"`
	DataDir             string `json:"data_dir"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	ret := s.RetentionRef()
	out := Settings{
		RetentionRawHours:   int(ret.Raw.Hours()),
		RetentionRollupDays: int(ret.Rollup.Hours() / 24),
		StorageMaxMB:        ret.MaxBytes >> 20,
		DataDir:             s.DataDir,
	}
	if sum, err := s.Store.Summary(r.Context(), time.Now().Add(-time.Hour)); err == nil {
		out.DBBytes = sum.DBBytes
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSetSettings updates the retention policy. The change takes effect on
// the pruner's next pass rather than immediately, which avoids a settings save
// turning into a long blocking delete.
func (s *Server) handleSetSettings(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "could not read the request")
		return
	}
	if in.RetentionRawHours < 1 || in.RetentionRollupDays < 1 || in.StorageMaxMB < 16 {
		writeErr(w, http.StatusBadRequest, types.ErrRetentionInvalid,
			"retention must be at least 1 hour of detail, 1 day of history, and 16 MB of storage")
		return
	}

	s.SetRetention(store.Retention{
		Raw:      time.Duration(in.RetentionRawHours) * time.Hour,
		Rollup:   time.Duration(in.RetentionRollupDays) * 24 * time.Hour,
		MaxBytes: in.StorageMaxMB << 20,
		Interval: s.RetentionRef().Interval,
	})
	s.handleGetSettings(w, r)
}

// handleWipe deletes every observation. This is the one-click wipe the privacy
// posture promises: the data is a detailed record of a network, and the user
// must be able to destroy it without hunting for a file.
func (s *Server) handleWipe(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.Wipe(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
