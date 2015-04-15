package sshconfig

import "testing"

// Test parsing
func TestParsing(t *testing.T) {
	config := `Host google
  HostName google.se
  User goog
  Port 2222

Host face
  HostName facebook.com
  User mark
  Port 22`

	_, err := parse(config)

	if err != nil {
		t.Errorf("unable to parse config: %s", err.Error())
	}
}
