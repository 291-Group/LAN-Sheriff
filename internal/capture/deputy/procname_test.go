package deputy

import "testing"

func TestFriendlyName(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		// The case that prompted this: a self-updating tool whose binary is
		// named after its version.
		{"versioned binary", "/Users/example/.local/share/toolkit/versions/2.1.218", "toolkit"},
		{"dotted app dir", "/Users/example/.nvm/versions/node/v20.11.0/bin/node", "node"},
		{"ordinary binary", "/usr/local/bin/curl", "curl"},
		{"ordinary system binary", "/usr/sbin/sshd", "sshd"},
		{"version under bin", "/opt/tool/bin/1.2.3", "tool"},
		{"nothing above it", "/2.1.0", "2.1.0"},
		{"empty", "", ""},
		{"name that merely contains digits", "/usr/bin/python3.11", "python3.11"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := friendlyName(c.path); got != c.want {
				t.Errorf("friendlyName(%q) = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

func TestLooksLikeVersion(t *testing.T) {
	yes := []string{"2.1.218", "v3", "1.0.0-rc2", "20", "1_2_3", "V1.2"}
	// "7z" is the case the narrow rule protects: it starts with a digit but is
	// a real program name, not a version.
	no := []string{"toolkit", "node", "python3.11", "", "v", "curl-8", "7z", "3to2"}
	for _, s := range yes {
		if !looksLikeVersion(s) {
			t.Errorf("looksLikeVersion(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksLikeVersion(s) {
			t.Errorf("looksLikeVersion(%q) = true, want false", s)
		}
	}
}
