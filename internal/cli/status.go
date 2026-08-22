package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/291-Group/LAN-Sheriff/internal/config"
	"github.com/291-Group/LAN-Sheriff/internal/dispatch"
	"github.com/291-Group/LAN-Sheriff/internal/store"
)

// `lan-sheriff status` answers one question: is this machine sharing anything,
// and with whom.
//
// # Why it is a command and not a dashboard page
//
// The dashboard already says so, in a line at the foot of every view. But it
// requires knowing the dashboard exists, knowing which port it is on, and
// having whatever password protects it. The person with the strongest reason
// to ask this question is the one who did not install the software, somebody
// who found it running on their own computer and wants to know what it has
// been doing.
//
// That person has a terminal. This is for them, and it is why the command needs
// no privilege, no running instance, and no password: it reads the database and
// prints what it finds.
//
// LAN Sheriff cannot prevent somebody with physical access from pairing a
// machine with their own. Nothing running on that machine can. What it can do
// is answer honestly when asked, and refuse to forget, see migration 17.
func statusCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "status",
		Short: "Report whether this machine is sharing anything, and with whom",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, _ := cmd.Flags().GetString("data-dir")
			if dir == "" {
				dir = config.DefaultDataDir()
			}
			return runStatus(cmd.Context(), dir)
		},
	}
	c.Flags().String("data-dir", "", "where the database lives (default: the standard location)")
	return c
}

func runStatus(ctx context.Context, dir string) error {
	path := filepath.Join(dir, "sheriff.db")
	st, err := store.Open(path)
	if err != nil {
		return fmt.Errorf("no readable database at %s: %w", path, err)
	}
	defer st.Close()

	fmt.Printf("LAN Sheriff %s\n", Version)
	fmt.Printf("database  %s\n\n", path)

	peers, err := st.Peers(ctx)
	if err != nil {
		return err
	}

	if len(peers) == 0 {
		fmt.Println("SHARING   nothing. No machines are paired with this one.")
	} else {
		fmt.Printf("SHARING   with %s:\n", plural(len(peers), "paired machine", "paired machines"))
		for _, p := range peers {
			label := p.Label
			if label == "" {
				label = "(unnamed)"
			}
			last := "never connected"
			if !p.LastSeen.IsZero() {
				last = "last seen " + p.LastSeen.Local().Format("2006-01-02 15:04")
			}
			fmt.Printf("          %-24s %s  paired %s, %s\n",
				label, dispatch.Fingerprint(p.PeerID),
				p.PairedAt.Local().Format("2006-01-02"), last)
		}
		fmt.Println("\n          Paired machines receive hourly summaries: a device, an")
		fmt.Println("          organization, a country and counts. Never addresses, the")
		fmt.Println("          domains looked up, or individual connections.")
	}

	// The ledger, which outlives unpairing. A machine showing nothing paired
	// today may still have been paired last week, and that is exactly the thing
	// somebody checking their own computer wants to know.
	history, err := st.PairingHistory(ctx, 20)
	if err != nil {
		return err
	}
	if len(history) > 0 {
		fmt.Println("\nPAIRING HISTORY")
		for _, e := range history {
			label := e.Label
			if label == "" {
				label = "(unnamed)"
			}
			fmt.Printf("  %s  %-11s %-24s %s\n",
				e.At.Local().Format("2006-01-02 15:04"), eventLabel(e.Event), label,
				dispatch.Fingerprint(e.Peer))
		}
	}

	if len(peers) == 0 && len(history) == 0 {
		fmt.Println("\nThis machine has never been paired with another.")
	}

	// Unix seconds, which is how the setting is written. Parsing it as RFC 3339
	// failed silently and the line simply never appeared, the kind of bug that
	// survives because its only symptom is absence.
	if v, ok, _ := st.Setting(ctx, "roster_baseline_at"); ok {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil && secs > 0 {
			fmt.Printf("\nObserving since %s\n",
				time.Unix(secs, 0).Local().Format("2006-01-02"))
		}
	}
	return nil
}

// eventLabel turns the stored event code into something written for a reader.
//
// The codes are the right thing in the database, where they are compared and
// never read aloud. Printed straight out they gave a column of "sharing_on"
// and "sharing_off" among ordinary words, which looks like a leaked internal
// identifier because that is exactly what it is.
func eventLabel(event string) string {
	switch event {
	case "sharing_on":
		return "sharing on"
	case "sharing_off":
		return "sharing off"
	default:
		return event
	}
}

// plural picks a form rather than printing "machine(s)". There is one place
// this matters and it is the first line of the section, which is the line most
// likely to be pasted into a bug report.
func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
