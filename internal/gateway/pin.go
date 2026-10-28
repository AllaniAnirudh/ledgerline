package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// UpstreamPin identifies a configured upstream MCP server: the SHA-256
// of its base URL after the same trailing-slash normalization New
// applies. The pin file holds only this hash, never credentials, so
// an upstream URL carrying embedded credentials stays hidden.
func UpstreamPin(upstream string) string {
	sum := sha256.Sum256([]byte(strings.TrimSuffix(upstream, "/")))
	return hex.EncodeToString(sum[:])
}

// CheckUpstreamPin enforces the pin for one gateway start. It returns
// one of "ok", "created", or "reapproved":
//
//   - No pin file yet: the current upstream becomes the pin, and the
//     file is written. First run establishes the pin.
//   - Pin matches: nothing changes.
//   - Pin mismatches without reapprove: an error, and the gateway
//     must refuse to start. A changed upstream is a changed trust
//     root, and it needs a human to say so.
//   - Pin mismatches with reapprove: the pin file is overwritten
//     with the new upstream's pin. The caller witnesses the
//     re-approval in the ledger.
func CheckUpstreamPin(pinFile, upstream string, reapprove bool) (string, error) {
	want := UpstreamPin(upstream)
	raw, err := os.ReadFile(pinFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		if err := os.WriteFile(pinFile, []byte(want+"\n"), 0644); err != nil {
			return "", err
		}
		return "created", nil
	}
	if strings.TrimSpace(string(raw)) == want {
		return "ok", nil
	}
	if !reapprove {
		return "", fmt.Errorf("upstream pin mismatch: configured upstream %q does not match the pinned upstream; refusing to start (pass --reapprove-upstream to accept the new upstream)", upstream)
	}
	if err := os.WriteFile(pinFile, []byte(want+"\n"), 0644); err != nil {
		return "", err
	}
	return "reapproved", nil
}
