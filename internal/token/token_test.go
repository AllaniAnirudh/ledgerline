package token

import (
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
	last := sig[len(sig)-1]
	replacement := byte('A')
	if last == 'A' {
		replacement = 'B'
	}
	tampered := parts[0] + "." + sig[:len(sig)-1] + string(replacement)
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
