// Package pty runs an agent command inside a pseudo-terminal and feeds
// its output into the ledger as terminal_output events, alongside the
// boundary's tool-call events. Same session id, one timeline.
//
// This is the co-capture plane: the boundary gateway sees tool calls,
// the PTY sees everything the terminal sees. The technique mirrors
// Backseat's capture; here it feeds the trust ledger instead of a relay.
package pty

import (
	"encoding/json"
	"os"
	"os/exec"
	"sync"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/creack/pty"
)

// Session runs one command inside a PTY, witnessing its output.
type Session struct {
	cmd       *exec.Cmd
	ptmx      *os.File
	store     ledger.Store
	sessionID string

	mu       sync.Mutex
	onOutput func([]byte)

	done chan struct{}
	once sync.Once
}

// Start launches command inside a new PTY and begins witnessing.
// Output flows to the ledger; call OnOutput to also mirror it (e.g. to
// the local terminal).
func Start(store ledger.Store, sessionID, command string, args ...string) (*Session, error) {
	cmd := exec.Command(command, args...)
	// Inherit a sane terminal size; resizing is a v1 gap, noted in docs.
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	s := &Session{
		cmd: cmd, ptmx: ptmx, store: store, sessionID: sessionID,
		done: make(chan struct{}),
	}
	store.Append(sessionID, "terminal_start", "pty", mustJSON(map[string]string{"command": command}), "", "")
	go s.readLoop()
	return s, nil
}

// OnOutput sets a callback invoked with every output chunk.
func (s *Session) OnOutput(fn func([]byte)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onOutput = fn
}

// Write sends input to the terminal (stdin of the command).
func (s *Session) Write(p []byte) (int, error) { return s.ptmx.Write(p) }

// Wait blocks until the command exits and records the exit.
func (s *Session) Wait() error {
	err := s.cmd.Wait()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	s.store.Append(s.sessionID, "terminal_exit", "pty",
		mustJSON(map[string]int{"exit_code": code}), "", "")
	s.once.Do(func() { close(s.done) })
	return err
}

// Close releases the PTY.
func (s *Session) Close() error {
	s.once.Do(func() { close(s.done) })
	return s.ptmx.Close()
}

func (s *Session) readLoop() {
	defer s.once.Do(func() { close(s.done) })
	buf := make([]byte, 4096)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			s.store.Append(s.sessionID, "terminal_output", "pty",
				mustJSON(map[string]string{"text": string(chunk)}), "", "")
			s.mu.Lock()
			fn := s.onOutput
			s.mu.Unlock()
			if fn != nil {
				fn(chunk)
			}
		}
		if err != nil {
			return // EIO on child exit is normal
		}
	}
}

// Done closes when the session ends.
func (s *Session) Done() <-chan struct{} { return s.done }

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
