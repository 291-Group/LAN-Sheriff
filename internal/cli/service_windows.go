package cli

import (
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
)

// Running under the Windows service control manager.
//
// # Why this is more than registering the exe
//
// Windows does not start a service and leave it alone. It expects the process
// to connect back to the service control manager within about thirty seconds,
// report that it is running, and then answer Stop and Shutdown requests. A
// program that ignores all of that starts, works, and is then reported as
// "did not respond in a timely fashion" and killed. It also means a machine
// shutting down kills the process outright instead of asking it to stop, so
// the database is torn away mid-write on every single reboot.
//
// That is why `install` on Windows registers a real service rather than a
// scheduled task. A scheduled task would have been a third of the code and
// would have started at boot perfectly well, but nothing would ever tell it
// that the machine was going down.

// serviceStop is closed when the control manager asks the service to stop.
// serve.go watches it alongside the usual signals.
var serviceStop chan struct{}

const serviceName = "LANSheriff"

// runAsService reports whether this process was started by the service control
// manager, and if so runs the whole command under it. The caller returns
// immediately afterwards: in a service there is no terminal to return to.
func runAsService(root *cobra.Command) bool {
	inService, err := svc.IsWindowsService()
	if err != nil || !inService {
		return false
	}
	serviceStop = make(chan struct{})
	// An error here has nowhere useful to go: there is no console attached.
	// The service's own log file, which the installer configures, is where
	// anything worth reading ends up.
	_ = svc.Run(serviceName, &handler{root: root})
	return true
}

type handler struct{ root *cobra.Command }

func (h *handler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	s <- svc.Status{State: svc.StartPending}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The service was registered with its arguments in the binary path, so
		// os.Args already carries them and cobra parses them exactly as it
		// would from a terminal. Nothing here needs to know what they are.
		_ = h.root.Execute()
	}()

	s <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case <-done:
			// Exited on its own, which for a service means something went
			// wrong. Reporting stopped is what lets the control manager apply
			// its restart policy rather than believing it is still running.
			s <- svc.Status{State: svc.Stopped}
			return false, 1

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				close(serviceStop)
				// Wait for the real shutdown: flushing and closing the
				// database is the entire reason for answering this request at
				// all, and returning before it finishes would waste the
				// answer.
				<-done
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		}
	}
}
