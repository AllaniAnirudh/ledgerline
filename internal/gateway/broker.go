package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// The broker is the gateway's credential plane, after Replit's
// Broker component. The agent never holds the upstream's
// credentials. The gateway injects them per request.
//
// Three guarantees, all gateway-wide. This is not per-tool bound
// brokering. That is a later step:
//
//   - Injection: configured headers are set from the broker on
//     every forwarded request. The agent never needs to hold
//     them. A differing agent value never reaches injection.
//     The foreign check below denies it first. Injection only
//     ever adds a missing header or re-states a matching one.
//   - Rejection: a request carrying a brokered header with a
//     different value is denied outright (a foreign credential).
//     A tool call whose arguments contain a brokered secret
//     value is denied before it is witnessed. The secret never
//     reaches the ledger.
//   - Redaction: upstream responses are scanned line by line.
//     Brokered secret values are replaced before the agent sees
//     them. A secret the upstream echoes back does not leak
//     through the gateway.
//
// Credential values come from environment variables only. They
// never come from the config file. A file holding secrets would
// itself need protecting. Env keeps the file safe to keep in a
// repo. A missing, empty, or short (under 8 characters) value
// refuses to start. A short value would false-positive the
// substring scans and deny ordinary traffic.
//
// What the broker does not do: it cannot revoke knowledge the
// agent already has from elsewhere. If the agent arrives already
// knowing a secret, its value is indistinguishable from the
// broker's own. The broker does not scan non-tool traffic
// arguments. It does not redact PTY output, which stays
// secret-bearing.
type Broker struct {
	creds   []Credential
	secrets []string
}

// Credential is one brokered upstream credential.
type Credential struct {
	Name   string
	Header string
	Value  string
}

// BrokerStatus is the safe public view of one credential. It shows
// name and header only, never the value.
type BrokerStatus struct {
	Name   string `json:"name"`
	Header string `json:"header"`
}

// Status returns the public view of the broker's credentials.
func (b *Broker) Status() []BrokerStatus {
	out := make([]BrokerStatus, 0, len(b.creds))
	for _, c := range b.creds {
		out = append(out, BrokerStatus{Name: c.Name, Header: c.Header})
	}
	return out
}

// InjectHeaders sets every brokered header on an outgoing request.
// By the time this runs, the foreign check has already denied any
// differing agent value. This only adds missing headers or
// re-states matching ones.
func (b *Broker) InjectHeaders(h http.Header) {
	for _, c := range b.creds {
		h.Set(c.Header, c.Value)
	}
}

// ForeignHeader returns the first brokered header the incoming
// request carries with a value different from the broker's own.
// It returns "" when the request carries no foreign credential.
// A matching value passes. It is indistinguishable from the
// broker's own.
func (b *Broker) ForeignHeader(r *http.Request) string {
	for _, c := range b.creds {
		if v := r.Header.Get(c.Header); v != "" && v != c.Value {
			return c.Header
		}
	}
	return ""
}

// ContainsSecret reports whether tool arguments contain any
// brokered secret value, in decoded string form or in the raw
// bytes. Decoded scanning catches escaped forms (a \uXXXX escape
// decodes to the secret itself). The raw scan covers arguments
// that do not decode at all.
func (b *Broker) ContainsSecret(args json.RawMessage) bool {
	if len(args) == 0 || len(b.secrets) == 0 {
		return false
	}
	for _, s := range b.secrets {
		if bytes.Contains(args, []byte(s)) {
			return true
		}
	}
	var v any
	if err := json.Unmarshal(args, &v); err != nil {
		return false
	}
	return containsSecretValue(v, b.secrets)
}

func containsSecretValue(v any, secrets []string) bool {
	switch t := v.(type) {
	case string:
		for _, s := range secrets {
			if strings.Contains(t, s) {
				return true
			}
		}
	case map[string]any:
		for _, child := range t {
			if containsSecretValue(child, secrets) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if containsSecretValue(child, secrets) {
				return true
			}
		}
	}
	return false
}

// RedactString replaces every brokered secret value in s.
func (b *Broker) RedactString(s string) string {
	for _, secret := range b.secrets {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	return s
}

// RedactCopy streams src to dst one line at a time, redacting each
// line. Line buffering is sound for the two response shapes MCP
// uses: JSON bodies (one line, or pretty-printed lines) and SSE
// event streams (one event field per line). A secret cannot span
// lines in either shape. JSON strings cannot hold a raw newline.
// An SSE data field is a single line. The final partial line
// is flushed at EOF.
func (b *Broker) RedactCopy(dst io.Writer, src io.Reader) error {
	rd := bufio.NewReader(src)
	for {
		line, err := rd.ReadString('\n')
		if line != "" {
			if _, werr := io.WriteString(dst, b.RedactString(line)); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// brokerFileCredential mirrors the YAML schema. Env names the
// environment variable holding the value. The file never holds a
// value itself.
type brokerFileCredential struct {
	Name   string `yaml:"name"`
	Header string `yaml:"header"`
	Env    string `yaml:"env"`
}

type brokerFile struct {
	Version     int                    `yaml:"version"`
	Credentials []brokerFileCredential `yaml:"credentials"`
}

// LoadBrokerFile reads a broker config file and resolves every
// credential value from the environment. Unknown fields, an
// unsupported version, a multi-document file, a missing or empty
// or short value, or a duplicate name or header are hard errors.
// A half-configured broker must never start.
func LoadBrokerFile(path string) (*Broker, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var bf brokerFile
	if err := dec.Decode(&bf); err != nil {
		return nil, fmt.Errorf("broker: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("broker: multiple documents in one file are not supported")
		}
		return nil, fmt.Errorf("broker: %w", err)
	}
	if bf.Version != 0 && bf.Version != 1 {
		return nil, fmt.Errorf("broker: unsupported version %d (this build understands version 1)", bf.Version)
	}
	b := &Broker{}
	seenNames := map[string]bool{}
	seenHeaders := map[string]bool{}
	for i, fc := range bf.Credentials {
		if strings.TrimSpace(fc.Name) == "" {
			return nil, fmt.Errorf("broker: credential %d has no name", i+1)
		}
		if strings.TrimSpace(fc.Header) == "" {
			return nil, fmt.Errorf("broker: credential %q has no header", fc.Name)
		}
		if strings.TrimSpace(fc.Env) == "" {
			return nil, fmt.Errorf("broker: credential %q has no env", fc.Name)
		}
		if seenNames[fc.Name] {
			return nil, fmt.Errorf("broker: duplicate credential name %q", fc.Name)
		}
		header := textproto.CanonicalMIMEHeaderKey(fc.Header)
		if seenHeaders[header] {
			return nil, fmt.Errorf("broker: duplicate header %q", header)
		}
		seenNames[fc.Name] = true
		seenHeaders[header] = true
		value := os.Getenv(fc.Env)
		if value == "" {
			return nil, fmt.Errorf("broker: credential %q: environment variable %s is unset or empty", fc.Name, fc.Env)
		}
		if len(value) < 8 {
			return nil, fmt.Errorf("broker: credential %q: value from %s is too short to scan safely (need 8+ characters)", fc.Name, fc.Env)
		}
		b.creds = append(b.creds, Credential{Name: fc.Name, Header: header, Value: value})
		b.secrets = append(b.secrets, value)
	}
	if len(b.creds) == 0 {
		return nil, fmt.Errorf("broker: no credentials configured; refusing to start an empty broker")
	}
	return b, nil
}
