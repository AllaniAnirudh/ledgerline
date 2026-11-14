package token

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestIssueAndValidate(t *testing.T) {
	tok, claims, err := Issue(testKey, "agent-1", "buppy", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tok == "" || strings.Count(tok, ".") != 1 {
		t.Fatalf("token has the wrong shape: %q", tok)
	}
	if claims.AgentID != "agent-1" || claims.Owner != "buppy" {
		t.Fatalf("claims are wrong: %+v", claims)
	}
	if claims.ID == "" {
		t.Fatal("claims have no jti")
	}
	if got := time.Until(claims.ExpiresAt()); got < 50*time.Minute || got > time.Hour {
		t.Fatalf("expiry is wrong: %v", got)
	}
	back, err := Validate(testKey, tok)
	if err != nil {
		t.Fatal(err)
	}
	if back.AgentID != "agent-1" || back.ID != claims.ID {
		t.Fatalf("validated claims differ: %+v", back)
	}
}

func TestValidateExpired(t *testing.T) {
	tok, _, err := Issue(testKey, "agent-1", "buppy", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := Validate(testKey, tok); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token should fail as expired, got %v", err)
	}
}

func TestValidateWrongKey(t *testing.T) {
	tok, _, err := Issue(testKey, "agent-1", "buppy", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other := []byte("fedcba9876543210fedcba9876543210")
	if _, err := Validate(other, tok); err == nil {
		t.Fatal("token from another key should fail")
	}
}

func TestValidateTamperedPayload(t *testing.T) {
	tok, _, err := Issue(testKey, "agent-1", "buppy", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	payload := parts[0]
	// Flip the first payload char to a different base64url char.
	// The signature no longer matches.
	first := payload[0]
	replacement := byte('A')
	if first == 'A' {
		replacement = 'B'
	}
	tampered := string(replacement) + payload[1:] + "." + parts[1]
	if _, err := Validate(testKey, tampered); err == nil {
		t.Fatal("tampered payload should fail")
	}
}

func TestValidateTamperedSignature(t *testing.T) {
	tok, _, err := Issue(testKey, "agent-1", "buppy", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	sig := parts[1]
	// Tamper the first signature char, not the last. A 32-byte
	// HMAC ends in a char whose low two bits are padding. A
	// swap there can change only ignored bits, so validation
	// would still pass. The first char carries the top six
	// bits of the first byte. A swap there always changes
	// the decoded bytes.
	first := sig[0]
	replacement := byte('A')
	if first == 'A' {
		replacement = 'B'
	}
	tampered := parts[0] + "." + string(replacement) + sig[1:]
	if _, err := Validate(testKey, tampered); err == nil {
		t.Fatal("tampered signature should fail")
	}
}

func TestValidateMalformed(t *testing.T) {
	for _, bad := range []string{"", "abc", "a.b.c", ".sig", "payload."} {
		if _, err := Validate(testKey, bad); err == nil {
			t.Fatalf("malformed token %q should fail", bad)
		}
	}
}

func TestIssueRejectsLongTTL(t *testing.T) {
	if _, _, err := Issue(testKey, "agent-1", "buppy", 8*24*time.Hour); err == nil {
		t.Fatal("ttl over 7 days should fail")
	}
	if _, _, err := Issue(testKey, "agent-1", "buppy", MaxTTL); err != nil {
		t.Fatalf("ttl of exactly 7 days should pass, got %v", err)
	}
}

func TestIssueRejectsEmptyFields(t *testing.T) {
	if _, _, err := Issue(testKey, "", "buppy", time.Hour); err == nil {
		t.Fatal("empty agent id should fail")
	}
	if _, _, err := Issue(testKey, "agent-1", "", time.Hour); err == nil {
		t.Fatal("empty owner should fail")
	}
	if _, _, err := Issue([]byte("short"), "agent-1", "buppy", time.Hour); err == nil {
		t.Fatal("short key should fail")
	}
}

func TestParseKey(t *testing.T) {
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if b, err := ParseKey(hexKey); err != nil || len(b) != 32 {
		t.Fatalf("hex key should parse to 32 bytes, got %d, %v", len(b), err)
	}
	if b, err := ParseKey("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh4="); err != nil || len(b) != 32 {
		t.Fatalf("base64 key should parse to 32 bytes, got %d, %v", len(b), err)
	}
	if _, err := ParseKey("abcd"); err == nil {
		t.Fatal("short key should fail")
	}
	if _, err := ParseKey("not a key at all!!!"); err == nil {
		t.Fatal("garbage key should fail")
	}
}

// mintClaims signs one claims value by hand. Tests use it to
// build tokens Issue never mints, such as a future issue time
// or an expiry that sits before the issue time.
func mintClaims(t *testing.T, claims Claims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	part := base64.RawURLEncoding.EncodeToString(payload)
	return part + "." + sign(testKey, part)
}

func TestAudienceBindsTokenToGateway(t *testing.T) {
	tok, claims, err := IssueWithAudience(testKey, "agent-1", "buppy", time.Hour, "http://gateway-a:8080")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Audience != "http://gateway-a:8080" {
		t.Fatalf("audience is wrong: %q", claims.Audience)
	}
	// The matching gateway accepts it.
	if _, err := ValidateWithAudience(testKey, tok, "http://gateway-a:8080"); err != nil {
		t.Fatalf("matching audience should pass, got %v", err)
	}
	// A gateway with a different audience refuses it.
	if _, err := ValidateWithAudience(testKey, tok, "http://gateway-b:8080"); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("other audience should fail as audience, got %v", err)
	}
	// A gateway with no audience configured refuses it too.
	// It cannot prove the token names this gateway.
	if _, err := Validate(testKey, tok); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("no audience should fail as audience, got %v", err)
	}
}

func TestLegacyTokenWithoutAudienceStillWorks(t *testing.T) {
	tok, claims, err := Issue(testKey, "agent-1", "buppy", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Audience != "" {
		t.Fatalf("legacy token should carry no audience, got %q", claims.Audience)
	}
	// A gateway with an audience configured still accepts a
	// legacy token. Legacy tokens live at most 7 days. This
	// keeps existing tokens working across the upgrade.
	if _, err := ValidateWithAudience(testKey, tok, "http://gateway-a:8080"); err != nil {
		t.Fatalf("legacy token should pass, got %v", err)
	}
	if _, err := Validate(testKey, tok); err != nil {
		t.Fatalf("legacy token should pass plain validation, got %v", err)
	}
}

func TestValidateFutureIat(t *testing.T) {
	now := time.Now().UTC().Unix()
	// Two minutes in the future: past the 60 second skew.
	future := mintClaims(t, Claims{
		AgentID: "agent-1", Owner: "buppy",
		Issued: now + 120, Expires: now + 3600, ID: "future-1",
	})
	if _, err := Validate(testKey, future); err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("future issue time should fail as future, got %v", err)
	}
	// Thirty seconds in the future: inside the skew. It passes.
	skewed := mintClaims(t, Claims{
		AgentID: "agent-1", Owner: "buppy",
		Issued: now + 30, Expires: now + 3600, ID: "skew-1",
	})
	if _, err := Validate(testKey, skewed); err != nil {
		t.Fatalf("issue time inside the skew should pass, got %v", err)
	}
}

func TestValidateExpiryMustFollowIssue(t *testing.T) {
	now := time.Now().UTC().Unix()
	// Issue time inside the skew, expiry at the issue time.
	// The token is not expired yet, so the ordering check
	// is the one that must refuse it.
	backwards := mintClaims(t, Claims{
		AgentID: "agent-1", Owner: "buppy",
		Issued: now + 30, Expires: now + 30, ID: "back-1",
	})
	if _, err := Validate(testKey, backwards); err == nil || !strings.Contains(err.Error(), "not after its issue time") {
		t.Fatalf("expiry at issue time should fail, got %v", err)
	}
	earlier := mintClaims(t, Claims{
		AgentID: "agent-1", Owner: "buppy",
		Issued: now + 30, Expires: now + 10, ID: "back-2",
	})
	if _, err := Validate(testKey, earlier); err == nil || !strings.Contains(err.Error(), "not after its issue time") {
		t.Fatalf("expiry before issue time should fail, got %v", err)
	}
}
