//go:build windows

package deputy

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"
)

// The byte-order conversions are where a Windows socket-table reader usually
// goes wrong, and they are testable without a live machine. The API returns
// addresses and ports in network byte order inside little-endian DWORDs, so
// getting either wrong produces plausible-looking nonsense rather than an error.

func TestPortDecoding(t *testing.T) {
	cases := []struct {
		name  string
		dword uint32
		want  uint16
	}{
		// The API puts the port in network byte order in the low two bytes, so
		// port 80 (0x0050) arrives as 0x5000.
		{"http", 0x5000, 80},
		{"https", 0xBB01, 443},
		{"ssh", 0x1600, 22},
		{"dns", 0x3500, 53},
		{"ephemeral 51234", 0x22C8, 51234},
		{"unbound", 0x0000, 0},
		// Upper bytes carry nothing and must be ignored.
		{"upper bytes ignored", 0xFFFF5000, 80},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := port(c.dword); got != c.want {
				t.Errorf("port(%#x) = %d, want %d", c.dword, got, c.want)
			}
		})
	}
}

func TestAddr4Decoding(t *testing.T) {
	// dwLocalAddr is already in network byte order, so its little-endian bytes
	// are the address octets in order.
	cases := []struct {
		dword uint32
		want  string
	}{
		{0x0100007F, "127.0.0.1"},
		{0x0101A8C0, "192.168.1.1"},
		{0x08080808, "8.8.8.8"},
		{0x00000000, "0.0.0.0"},
	}
	for _, c := range cases {
		if got := addr4(c.dword); got.String() != c.want {
			t.Errorf("addr4(%#x) = %s, want %s", c.dword, got, c.want)
		}
	}
}

func TestAddr16UnmapsIPv4MappedAddresses(t *testing.T) {
	// A dual-stack socket reports IPv4 peers as ::ffff:a.b.c.d. Leaving them
	// mapped would split one destination across two representations.
	var mapped [16]byte
	mapped[10], mapped[11] = 0xff, 0xff
	mapped[12], mapped[13], mapped[14], mapped[15] = 93, 184, 216, 34

	got := addr16(mapped)
	if !got.Is4() {
		t.Errorf("addr16 should unmap IPv4-mapped addresses, got %s", got)
	}
	if got.String() != "93.184.216.34" {
		t.Errorf("addr16 = %s, want 93.184.216.34", got)
	}

	// A genuine IPv6 address must be left alone.
	real := netip.MustParseAddr("2606:4700::6812:7e76").As16()
	if addr16(real).String() != "2606:4700::6812:7e76" {
		t.Errorf("a real IPv6 address should pass through unchanged, got %s", addr16(real))
	}
}

func TestWindowsTCPState(t *testing.T) {
	cases := map[uint32]string{
		1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD",
		5: "ESTABLISHED", 8: "CLOSE_WAIT", 11: "TIME_WAIT", 12: "DELETE_TCB",
		0: "", 99: "", // out of range must not panic
	}
	for in, want := range cases {
		if got := windowsTCPState(in); got != want {
			t.Errorf("windowsTCPState(%d) = %q, want %q", in, got, want)
		}
	}
}

// rows reinterprets a raw API buffer. A miscount here would read past the end
// of the buffer, so the guard matters more than the happy path.
func TestRowsRespectsTheBufferOverTheCount(t *testing.T) {
	stride := int(unsafe.Sizeof(mibTCPRowOwnerPID{}))

	// A well-formed buffer holding two records.
	buf := make([]byte, 4+2*stride)
	binary.LittleEndian.PutUint32(buf[:4], 2)
	if got := len(rows[mibTCPRowOwnerPID](buf)); got != 2 {
		t.Errorf("got %d rows, want 2", got)
	}

	// A count that lies about holding more than the buffer can carry must be
	// clamped, not trusted.
	lying := make([]byte, 4+stride)
	binary.LittleEndian.PutUint32(lying[:4], 999)
	if got := len(rows[mibTCPRowOwnerPID](lying)); got != 1 {
		t.Errorf("an overstated count should clamp to what fits, got %d rows", got)
	}

	// Degenerate inputs.
	if rows[mibTCPRowOwnerPID](nil) != nil {
		t.Error("a nil buffer should yield no rows")
	}
	if rows[mibTCPRowOwnerPID]([]byte{1, 2}) != nil {
		t.Error("a buffer too short to hold the count should yield no rows")
	}
	zero := make([]byte, 4+stride)
	if rows[mibTCPRowOwnerPID](zero) != nil {
		t.Error("a zero count should yield no rows")
	}
}

func TestTrimExe(t *testing.T) {
	cases := map[string]string{
		`C:\Program Files\Mozilla Firefox\firefox.exe`: `C:\Program Files\Mozilla Firefox\firefox`,
		`C:\Windows\System32\svchost.EXE`:              `C:\Windows\System32\svchost`,
		`C:\tools\noextension`:                         `C:\tools\noextension`,
		``:                                             ``,
	}
	for in, want := range cases {
		if got := trimExe(in); got != want {
			t.Errorf("trimExe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSamplerConstructs(t *testing.T) {
	// iphlpapi.dll is present on every supported Windows version; failing here
	// means the lazy-load or symbol lookup is wrong.
	s, err := newSampler()
	if err != nil {
		t.Fatalf("newSampler: %v", err)
	}
	defer s.close()

	if s.byteCounts() {
		t.Error("the IP Helper tables carry no byte counters")
	}
	conns, err := s.sample()
	if err != nil {
		t.Fatalf("sample: %v", err)
	}
	// Any Windows machine has listening sockets, so an empty result means the
	// table read silently failed.
	if len(conns) == 0 {
		t.Error("expected at least one socket on a running Windows machine")
	}
	for _, c := range conns {
		if !c.Src.IsValid() {
			t.Errorf("a sampled socket has no valid local address: %+v", c)
		}
	}
}

// Windows hands out owning PID 0 for a socket whose owner is unknown or has
// exited, which is the normal state of one in TIME_WAIT. It used to be resolved
// to "System Idle Process", so the dashboard showed the idle process as the
// application responsible for real outbound traffic, beside OneDrive and Chrome.
//
// The idle process has no handle table and cannot hold a socket. An answer that
// cannot be true is worse than no answer, so this must stay unattributed.
func TestPidZeroIsNotAttributedToTheIdleProcess(t *testing.T) {
	got := processInfo(0)
	if got.name != "" {
		t.Errorf("processInfo(0).name = %q, want empty: PID 0 means the owner is "+
			"unknown or gone, not that the idle process opened a socket", got.name)
	}
	if got.path != "" {
		t.Errorf("processInfo(0).path = %q, want empty", got.path)
	}
}
