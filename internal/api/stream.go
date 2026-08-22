package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// streamWriteTimeout bounds how long a single push may take. A client that
// cannot accept a small JSON message within this window is not keeping up, and
// is disconnected rather than allowed to accumulate.
const streamWriteTimeout = 5 * time.Second

// handleStream upgrades to a WebSocket and forwards live events.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	// The live feed is data like any other endpoint, so it is gated the same
	// way. Doing this before the upgrade means an unauthenticated client gets a
	// plain 401 rather than a socket that closes for no stated reason.
	if !s.authed(r) {
		writeErr(w, http.StatusUnauthorized, types.ErrAuthRequired, "authentication required")
		return
	}

	// The dashboard is served from this same origin. Cross-origin sockets are
	// refused: nothing on another site has any business reading this feed.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		slog.Debug("websocket upgrade failed", "err", err)
		return
	}
	defer c.CloseNow()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	events, unsubscribe := s.Bus.Subscribe()
	defer unsubscribe()

	// A read pump we never consume from: its only job is to notice the client
	// going away, and to absorb pings so the connection stays honest.
	go func() {
		defer cancel()
		for {
			if _, _, err := c.Read(ctx); err != nil {
				return
			}
		}
	}()

	// Say hello immediately so the UI can distinguish "connected, quiet
	// network" from "not connected".
	if err := s.push(ctx, c, map[string]any{
		"type": "status",
		"data": map[string]any{
			"connected": true,
			"mode":      s.Probe.Active,
			"origin":    s.Origin(),
		},
	}); err != nil {
		return
	}

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case m, ok := <-events:
			if !ok {
				return
			}
			if err := s.push(ctx, c, m); err != nil {
				return
			}
		case <-ping.C:
			pctx, pcancel := context.WithTimeout(ctx, streamWriteTimeout)
			err := c.Ping(pctx)
			pcancel()
			if err != nil {
				return
			}
		}
	}
}

func (s *Server) push(ctx context.Context, c *websocket.Conn, v any) error {
	ctx, cancel := context.WithTimeout(ctx, streamWriteTimeout)
	defer cancel()
	return wsjson.Write(ctx, c, v)
}
