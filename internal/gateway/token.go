package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/AllaniAnirudh/ledgerline/internal/token"
)

// agentTokenHeader carries the gateway-issued identity token on
// proxy-path requests. It never reaches upstream.
const agentTokenHeader = "X-Ledgerline-Agent-Token"

// agentIDKey is the request context key for the validated agent
// id. Only the proxy path sets it. The control plane never sets
// it. A handler reads it with agentIDOf.
type agentIDKey struct{}

func withAgentID(r *http.Request, id string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), agentIDKey{}, id))
}

func agentIDOf(r *http.Request) string {
	if r == nil {
		return ""
	}
	id, _ := r.Context().Value(agentIDKey{}).(string)
	return id
}

// SetTokenKey installs the HMAC key that signs and checks agent
// tokens, plus the file that holds revoked token ids. It loads
// the revocation file when it exists. A missing file means no
// revocations yet. A corrupt file refuses to start.
func (px *Proxy) SetTokenKey(key []byte, revokeFile string) error {
	px.tokenKey = key
	px.revokeFile = revokeFile
	if revokeFile == "" {
		return nil
	}
	return px.loadRevocations()
}

// SetRequireAgentToken turns proxy-path token checks on or off.
// When on, every proxy-path request must carry a valid token.
func (px *Proxy) SetRequireAgentToken(on bool) { px.requireAgentToken = on }

// RequireAgentToken reports whether proxy-path checks are on.
func (px *Proxy) RequireAgentToken() bool { return px.requireAgentToken }

// validateAgentToken checks the token on one proxy-path request.
// It returns the claims when the token is valid and not revoked.
// A missing, invalid, expired, or revoked token is an error.
// The caller answers with 401 and writes no ledger event. There
// is no agent id to attribute, so there is nothing to witness.
func (px *Proxy) validateAgentToken(r *http.Request) (*token.Claims, error) {
	tok := r.Header.Get(agentTokenHeader)
	if tok == "" {
		return nil, errors.New("no agent token")
	}
	claims, err := token.Validate(px.tokenKey, tok)
	if err != nil {
		return nil, err
	}
	if px.isRevoked(claims.ID) {
		return nil, errors.New("token is revoked")
	}
	return claims, nil
}

// isRevoked reports whether a token id is revoked.
func (px *Proxy) isRevoked(jti string) bool {
	px.revokedMu.Lock()
	defer px.revokedMu.Unlock()
	return px.revoked != nil && px.revoked[jti]
}

// RevokeToken marks one token id revoked and persists it. The
// revocation survives a gateway restart through the file. It
// returns an error when the file cannot be written. The in-memory
// mark still stands in that case.
func (px *Proxy) RevokeToken(jti string) error {
	px.revokedMu.Lock()
	if px.revoked == nil {
		px.revoked = map[string]bool{}
	}
	px.revoked[jti] = true
	err := px.saveRevocationsLocked()
	px.revokedMu.Unlock()
	return err
}

// loadRevocations reads the revocation file into memory. A file
// that does not exist means no revocations yet.
func (px *Proxy) loadRevocations() error {
	raw, err := os.ReadFile(px.revokeFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return fmt.Errorf("revocation file %s is corrupt: %w", px.revokeFile, err)
	}
	px.revokedMu.Lock()
	defer px.revokedMu.Unlock()
	px.revoked = map[string]bool{}
	for _, id := range ids {
		px.revoked[id] = true
	}
	return nil
}

// saveRevocationsLocked writes the revoked ids to the file. The
// caller holds revokedMu. The write is atomic: temp file plus
// rename. A partial write never leaves a corrupt file behind.
func (px *Proxy) saveRevocationsLocked() error {
	if px.revokeFile == "" {
		return nil
	}
	ids := make([]string, 0, len(px.revoked))
	for id := range px.revoked {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	raw, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	dir := filepath.Dir(px.revokeFile)
	tmp, err := os.CreateTemp(dir, ".revoked-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, px.revokeFile); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// rejectAgentAuth answers a proxy-path request that failed the
// agent token check. It logs the rejection to stderr. It writes
// no ledger event. It sets HTTP 401 with a JSON-RPC error body.
func (px *Proxy) rejectAgentAuth(w http.ResponseWriter, body []byte, err error) {
	log.Printf("ledgerline: proxy auth rejected: %v", err)
	writeJSONRPCErrorStatus(w, body, "ledgerline: missing or invalid agent token", http.StatusUnauthorized)
}
