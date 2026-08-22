package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Filter is the one filter model every view shares.
//
// Having a single struct rather than per-endpoint options means a filter set in
// the Watchtower carries into Radio Chatter and the Roster unchanged, which is
// the whole point of "one engine, many views": the user narrows once.
type Filter struct {
	Since time.Time
	Until time.Time

	Device  string
	Process string
	Country string
	Org     string
	Proto   types.Proto
	Port    int

	// Direction filters by who opened the connection. Empty means any.
	Direction types.Direction

	// ActiveOnly restricts results to flows still open.
	ActiveOnly bool

	// Search is free text matched against address, hostname, organization and
	// owning application.
	Search string

	Limit int

	// Export lifts the screen ceiling. Set only by the export handler.
	Export bool
}

// ExportCeiling is the most rows any export returns. Large enough that a normal
// day of a normal network comes out whole, bounded so that one request cannot
// read an entire year into memory. When a result reaches it the file says so in
// its own name, because a truncated export that looks complete is the kind of
// wrong answer nobody checks.
const ExportCeiling = 50000

// DefaultLimit caps a query that did not ask for one, so a filter that matches
// everything cannot pull the whole database into memory.
const DefaultLimit = 500

// ScreenCeiling is the most rows a screen will be given however large a limit is
// asked for, so one request cannot read the whole database into memory.
const ScreenCeiling = 5000

func (f Filter) limit() int {
	if f.Limit <= 0 {
		return DefaultLimit
	}
	// An export asks for ExportCeiling and means it. Held to the screen's
	// ceiling, a day of connections came out as 5000 of 152957 in a file named
	// as though it were all of them: the number was not wrong, it was answering
	// a question nobody asked.
	ceiling := ScreenCeiling
	if f.Export {
		ceiling = ExportCeiling
	}
	if f.Limit > ceiling {
		return ceiling
	}
	return f.Limit
}

// where builds the SQL predicate and its arguments.
//
// Column names are fixed strings and every value is bound as a parameter, so
// nothing a user types reaches the query text.
func (f Filter) where(flowAlias, endpointAlias string) ([]string, []any) {
	var (
		clauses []string
		args    []any
	)
	fa, ea := flowAlias, endpointAlias

	if !f.Since.IsZero() {
		clauses = append(clauses, fa+".ts_last >= ?")
		args = append(args, f.Since.Unix())
	}
	if !f.Until.IsZero() {
		clauses = append(clauses, fa+".ts_start <= ?")
		args = append(args, f.Until.Unix())
	}
	if f.ActiveOnly {
		clauses = append(clauses, fa+".active = 1")
	}
	if f.Direction != "" {
		clauses = append(clauses, fa+".direction = ?")
		args = append(args, string(f.Direction))
	}
	if f.Device != "" {
		// A flow's own device_id is not enough.
		//
		// Deputy Mode tags every flow with this host's identifier, so matching on
		// it directly worked. **Patrol Mode does not**: it sees a packet from an
		// address before anything has established which machine holds that
		// address, so it tags the flow `lan-<ip>`, a placeholder, not a device.
		// The real identity arrives later, from a MAC in the neighbour table or a
		// name over mDNS, and lands in `device_addresses`.
		//
		// Matching only on device_id therefore returned **nothing** for every
		// device except this one: the Roster listed a printer with 167 captured
		// flows and asking to see them showed an empty screen. The suspicion
		// rules already resolved through `device_addresses` for exactly this
		// reason; the filter did not.
		clauses = append(clauses, "("+fa+".device_id = ? OR "+fa+
			".src_ip IN (SELECT ip FROM device_addresses WHERE device_id = ?))")
		args = append(args, f.Device, f.Device)
	}
	if f.Process != "" {
		clauses = append(clauses, fa+".process = ?")
		args = append(args, f.Process)
	}
	if f.Proto != "" {
		clauses = append(clauses, fa+".proto = ?")
		args = append(args, string(f.Proto))
	}
	if f.Port > 0 {
		clauses = append(clauses, fa+".dst_port = ?")
		args = append(args, f.Port)
	}
	if f.Country != "" {
		clauses = append(clauses, ea+".country = ?")
		args = append(args, strings.ToUpper(f.Country))
	}
	if f.Org != "" {
		clauses = append(clauses, ea+".org = ?")
		args = append(args, f.Org)
	}
	if s := strings.TrimSpace(f.Search); s != "" {
		like := "%" + s + "%"
		clauses = append(clauses, fmt.Sprintf(
			"(%[1]s.ip LIKE ? OR %[1]s.rdns LIKE ? OR %[1]s.org LIKE ? OR %[2]s.process LIKE ?)", ea, fa))
		args = append(args, like, like, like, like)
	}
	return clauses, args
}

// SearchResult is one hit from the global search.
type SearchResult struct {
	Kind   string `json:"kind"` // endpoint | org | process | country
	Key    string `json:"key"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
	Count  int64  `json:"count"`
	// Peer names the machine that reported this hit, and is empty for anything
	// observed here. Searching found only this machine's traffic, so a paired
	// household could watch a peer's connections on the map and then fail to
	// find the same organization by typing its name.
	Peer string `json:"peer,omitempty"`
}
