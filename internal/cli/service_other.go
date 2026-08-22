//go:build !windows

package cli

import "github.com/spf13/cobra"

// systemd and launchd both stop a service by sending SIGTERM, which serve.go
// already handles, so there is nothing to hook here. serviceStop stays nil and
// the extra shutdown path in runServe is compiled in but never armed.
var serviceStop chan struct{}

func runAsService(*cobra.Command) bool { return false }
