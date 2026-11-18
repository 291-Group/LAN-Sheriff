package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/291-Group/LAN-Sheriff/internal/config"
)

// `lan-sheriff health` asks a running instance whether it is alive, over the
// same API the dashboard uses, and exits 0 if it answered.
//
// # Why a command, when the endpoint exists
//
// It exists for the Docker health check, and for anything else that wants a
// yes or no from a process it is supervising. The image carries no curl, by
// design: a network monitor's container should contain the monitor. It
// touches nothing but a socket; the check it replaces opened the database
// from a second process, and store.OpenReadOnly says what that cost.
//
// Exit 0 means the API answered and the database is not known to be damaged.
// Writes failing is reported, in the output, but is not a reason to fail: a
// restart during a storage stall throws away the observations the pipeline is
// holding until the storage comes back, which is the one thing a stall should
// not cost.
//
// A damaged database is the exception, and exits 1. It does not recover by
// itself, a restart neither helps nor costs anything more, and a container
// that stays "healthy" over a malformed database is how the Pi soak rig ran
// for three days with no working rules. See store/integrity.go.
func healthCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "health",
		Short: "Ask a running LAN Sheriff whether it is alive (exit 0 if so)",
		Long: `Ask a running LAN Sheriff whether it is alive, over its own API, and exit 0 if
it answered. Writes that are failing are reported but do not fail the check:
observations are held in memory until storage recovers, and restarting the
process during a stall would throw them away.

A damaged database does fail the check (exit 1), with what to do about it:
that does not recover by waiting.

To see what this machine shares with paired instances, use "lan-sheriff status".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			url, _ := cmd.Flags().GetString("url")
			timeout, _ := cmd.Flags().GetDuration("timeout")
			return runHealth(cmd.Context(), url, timeout)
		},
	}
	c.Flags().String("url", fmt.Sprintf("http://127.0.0.1:%d/api/health", config.DefaultPort),
		"the health endpoint of the instance to ask")
	c.Flags().Duration("timeout", 5*time.Second, "how long to wait for an answer")
	return c
}

func runHealth(ctx context.Context, url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "not answering: %v\n", err)
		return silentExit{code: 1}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "not healthy: HTTP %d from %s\n", resp.StatusCode, url)
		return silentExit{code: 1}
	}

	var body struct {
		Tracked bool `json:"tracked"`
		Ingest  *struct {
			Consecutive int64  `json:"consecutive_failures"`
			LastError   string `json:"last_error"`
		} `json:"ingest"`
		Storage *struct {
			OK     bool `json:"ok"`
			Damage *struct {
				Error  string    `json:"error"`
				Source string    `json:"source"`
				Since  time.Time `json:"since"`
			} `json:"damage"`
			Remedy string `json:"remedy"`
		} `json:"storage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		fmt.Fprintf(os.Stderr, "not healthy: unreadable answer from %s: %v\n", url, err)
		return silentExit{code: 1}
	}
	switch {
	case body.Storage != nil && !body.Storage.OK:
		fmt.Fprintln(os.Stderr, "not healthy: the database is damaged")
		if d := body.Storage.Damage; d != nil {
			fmt.Fprintf(os.Stderr, "  found by %s at %s: %s\n",
				d.Source, d.Since.Local().Format("2006-01-02 15:04:05"), d.Error)
		}
		if body.Storage.Remedy != "" {
			fmt.Fprintf(os.Stderr, "  to fix it: %s\n", body.Storage.Remedy)
		}
		return silentExit{code: 1}
	case body.Ingest != nil && body.Ingest.Consecutive > 0:
		fmt.Printf("alive; writes failing (%d in a row): %s\n",
			body.Ingest.Consecutive, body.Ingest.LastError)
	default:
		fmt.Println("alive")
	}
	return nil
}
