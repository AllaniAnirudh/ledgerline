package policy

import "testing"

func TestDecide(t *testing.T) {
	p := New([]string{"exec", "rm"}, []string{"write_file"})

	cases := []struct {
		tool string
		want Decision
	}{
		{"read_file", Allow},
		{"EXEC", Deny}, // case-insensitive
		{"rm", Deny},
		{"write_file", Hold},
		{"Write_File", Hold}, // case-insensitive
		{"unknown_tool", Allow},
	}
	for _, c := range cases {
		if got := p.Decide(c.tool); got != c.want {
			t.Errorf("Decide(%q) = %v, want %v", c.tool, got, c.want)
		}
	}
}

func TestEmptyPolicyAllows(t *testing.T) {
	p := New(nil, nil)
	if got := p.Decide("exec"); got != Allow {
		t.Errorf("empty policy should allow, got %v", got)
	}
}
