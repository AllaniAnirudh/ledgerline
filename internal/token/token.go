// Package token mints and checks gateway-issued identity tokens.
//
// A token binds one agent id to one owner. The owner is the human
// or job that started the session. The gateway signs the token
// with HMAC-SHA256. The gateway checks it on every proxy request.
//
// Form: base64url(payload) + "." + base64url(signature). The
// payload is JSON with agent_id, owner, aud, iat, exp, and jti.
// The signature covers the payload part only. A token carries no
// secret. Anyone can read it. Only the key holder can mint one.
//
// The aud claim binds a token to one gateway. The audience is
// the gateway upstream URL. A token with an audience is valid
// only on a gateway that fronts that upstream. A token with no
// audience is a legacy token. It stays valid on every gateway
// until it expires. Its life is at most 7 days. Mint new tokens
// with an audience. A future release may refuse legacy tokens.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// DefaultTTL is the minting default. MaxTTL is the longest life
// a token may have. Both are in the CLI help and the README.
const (
	DefaultTTL = 8 * time.Hour
	MaxTTL     = 7 * 24 * time.Hour
)

// MinKeyBytes is the shortest key the parser accepts. A shorter
// key is too weak for HMAC use here.
const MinKeyBytes = 16

// MaxClockSkew is the largest future issue time a token may
// carry. Clocks differ. A token issued more than this far in
// the future is refused. See Validate.
const MaxClockSkew = 60 * time.Second

// Claims is the signed payload of one token.
type Claims struct {
	AgentID  string `json:"agent_id"`
	Owner    string `json:"owner"`
	Audience string `json:"aud,omitempty"`
	Issued   int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	ID       string `json:"jti"`
}

// ExpiresAt returns the expiry as a time.
func (c *Claims) ExpiresAt() time.Time { return time.Unix(c.Expires, 0).UTC() }

// Issue mints one token for an agent id and an owner. The ttl
// must be over zero and at most MaxTTL. Issue assigns a fresh
// random jti. Minting is offline. It writes no ledger event.
// The token carries no audience. It is a legacy token. Prefer
// IssueWithAudience for new tokens.
func Issue(key []byte, agentID, owner string, ttl time.Duration) (string, *Claims, error) {
	return IssueWithAudience(key, agentID, owner, ttl, "")
}

// IssueWithAudience mints one token bound to one audience. The
// audience is the gateway upstream URL. An empty audience mints
// a legacy token with no binding. The ttl must be over zero and
// at most MaxTTL. IssueWithAudience assigns a fresh random jti.
// Minting is offline. It writes no ledger event.
func IssueWithAudience(key []byte, agentID, owner string, ttl time.Duration, audience string) (string, *Claims, error) {
	if len(key) < MinKeyBytes {
		return "", nil, errors.New("token key is too short")
	}
	if strings.TrimSpace(agentID) == "" {
		return "", nil, errors.New("agent id is empty")
	}
	if strings.TrimSpace(owner) == "" {
		return "", nil, errors.New("owner is empty")
	}
	if ttl <= 0 {
		return "", nil, errors.New("token ttl must be over zero")
	}
	if ttl > MaxTTL {
		return "", nil, fmt.Errorf("token ttl exceeds the %s maximum", MaxTTL)
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", nil, err
	}
	now := time.Now().UTC()
	claims := &Claims{
		AgentID:  agentID,
		Owner:    owner,
		Audience: strings.TrimSpace(audience),
		Issued:   now.Unix(),
		Expires:  now.Add(ttl).Unix(),
		ID:       hex.EncodeToString(raw[:]),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", nil, err
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	sig := sign(key, payloadPart)
	return payloadPart + "." + sig, claims, nil
}

// Validate checks a token against a key. It checks the shape,
// the signature, the agent id, the jti, and the expiry. It
// returns the claims when every check passes. It enforces no
// audience. A token that carries an audience is refused. Use
// ValidateWithAudience when the gateway has an audience.
func Validate(key []byte, tok string) (*Claims, error) {
	return ValidateWithAudience(key, tok, "")
}

// ValidateWithAudience checks a token against a key and one
// expected audience. It checks the shape, the signature, the
// agent id, the jti, the audience, the issue time, and the
// expiry. It returns the claims when every check passes. A
// token with no audience is a legacy token. It passes the
// audience check on any gateway. A token with an audience
// passes only when the audience matches the expected value.
// An issue time more than MaxClockSkew in the future is
// refused. The expiry must sit after the issue time.
func ValidateWithAudience(key []byte, tok string, expectedAud string) (*Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, errors.New("token is malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("token payload is not valid base64url")
	}
	want := sign(key, parts[0])
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("token signature is not valid base64url")
	}
	wantBytes, err := base64.RawURLEncoding.DecodeString(want)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(got, wantBytes) {
		return nil, errors.New("token signature is invalid")
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("token payload is not valid JSON")
	}
	if strings.TrimSpace(claims.AgentID) == "" {
		return nil, errors.New("token has no agent id")
	}
	if strings.TrimSpace(claims.ID) == "" {
		return nil, errors.New("token has no id")
	}
	if claims.Audience != "" && claims.Audience != expectedAud {
		return nil, errors.New("token audience does not match this gateway")
	}
	now := time.Now().UTC().Unix()
	if claims.Issued > now+int64(MaxClockSkew/time.Second) {
		return nil, errors.New("token issued in the future")
	}
	if now >= claims.Expires {
		return nil, errors.New("token is expired")
	}
	if claims.Expires <= claims.Issued {
		return nil, errors.New("token expiry is not after its issue time")
	}
	return &claims, nil
}

func sign(key []byte, payloadPart string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payloadPart))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ParseKey decodes one key from text. It accepts hex or base64.
// The text may carry surrounding whitespace. A key under
// MinKeyBytes is refused.
func ParseKey(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("token key is empty")
	}
	if b, err := hex.DecodeString(text); err == nil {
		if len(b) < MinKeyBytes {
			return nil, errors.New("token key is too short")
		}
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(text); err == nil {
			if len(b) < MinKeyBytes {
				return nil, errors.New("token key is too short")
			}
			return b, nil
		}
	}
	return nil, errors.New("token key is not hex or base64")
}

// LoadKeyFile reads one key from a file. The file holds one hex
// or base64 key, with optional surrounding whitespace. Make one
// with: openssl rand -hex 32
func LoadKeyFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKey(string(raw))
}
