package sshconfig

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mitchellh/go-homedir"
)

// Test parsing
func TestParsing(t *testing.T) {
	config := `Host google
  HostName google.se
  User goog
  Port 2222
  ProxyCommand ssh -q pluto nc saturn 22
  HostKeyAlgorithms ssh-dss
  # comment
  IdentityFile ~/.ssh/company
  Ciphers aes256-ctr,aes128-cbc
  MACs hmac-md5,hmac-sha2-256


Host face
  HostName facebook.com
  User mark
  Port 22`

	_, err := parse(config, "~/.ssh/config")

	if err != nil {
		t.Errorf("unable to parse config: %s", err.Error())
	}

	configCR := strings.Replace(`Host google
  HostName google.se
  User goog
  Port 2222
  ProxyCommand ssh -q pluto nc saturn 22
  HostKeyAlgorithms ssh-dss
  # comment
  IdentityFile ~/.ssh/company

Host face
  HostName facebook.com
  User mark
  Port 22`, "\n", "\r\n", -1)

	_, err = parse(configCR, "~/.ssh/config")

	if err != nil {
		t.Errorf("unable to parse config: %s", err.Error())
	}
}

func TestTrailingComment(t *testing.T) {
	config := "Host *\n#comment"
	_, err := parse(config, "~/.ssh/config")
	if err != nil {
		t.Errorf("unable to parse config: %s", err.Error())
	}
}

func TestMultipleHost(t *testing.T) {
	config := `Host google google2 aws
  HostName google.se
  User goog
  Port 2222`

	hosts, err := parse(config, "~/.ssh/config")

	if err != nil {
		t.Errorf("unable to parse config: %s", err.Error())
	}

	h := hosts[0]
	if ok := reflect.DeepEqual([]string{"google", "google2", "aws"}, h.Host); !ok {
		t.Error("unexpected host mismatch")
	}

}

// TestTrailingSpace ensures the parser does not hang when attempting to parse
// a Host declaration with a trailing space after a pattern
func TestTrailingSpace(t *testing.T) {
	// in the config below, the first line is "Host google \n"
	config := `
Host googlespace 
    HostName google.com
`
	parse(config, "~/.ssh/config")
}

func TestIgnoreKeyword(t *testing.T) {
	config := `Host google
  HostName google.se
  User goog
  Port 2222
  ProxyCommand ssh -q pluto nc saturn 22
  HostKeyAlgorithms ssh-dss
  # comment
  IdentityOnly yes
  IdentityFile ~/.ssh/company

Host face
  HostName facebook.com
  User mark
  Port 22

Host other
  HostName example.org
  User root
  Port 22
  Ciphers 3des-cbc,blowfish-cbc,cast128-cbc
  MACs hmac-sha1,hmac-sha1-96
  `

	expected := []*SSHHost{
		{
			Host:              []string{"google"},
			HostName:          "google.se",
			User:              "goog",
			Port:              2222,
			HostKeyAlgorithms: "ssh-dss",
			ProxyCommand:      "ssh -q pluto nc saturn 22",
			IdentityFile:      "~/.ssh/company",
		},
		{
			Host:              []string{"face"},
			User:              "mark",
			Port:              22,
			HostName:          "facebook.com",
			HostKeyAlgorithms: "",
			ProxyCommand:      "",
			IdentityFile:      "",
		},
		{
			Host:     []string{"other"},
			User:     "root",
			Port:     22,
			HostName: "example.org",
			Ciphers:  []string{"3des-cbc", "blowfish-cbc", "cast128-cbc"},
			MACs:     []string{"hmac-sha1", "hmac-sha1-96"},
		},
	}
	actual, err := parse(config, "~/.ssh/config")
	if err != nil {
		t.Errorf("unexpected error parsing config: %s", err.Error())
	}

	compare(t, expected, actual)
}

func TestIncludeRelative(t *testing.T) {
	configA := `Include ./b.conf`
	configB := `Host google
  HostName google.se
  User goog
  Port 2222
  ProxyCommand ssh -q pluto nc saturn 22
  HostKeyAlgorithms ssh-dss
  # comment
  IdentityFile ~/.ssh/company

Host face
  HostName facebook.com
  User mark
  Port 22`

	tmpdir := t.TempDir()

	f, err := os.Create(tmpdir + "/b.conf")
	if err != nil {
		t.Errorf("unable to create file: %s", err.Error())
	}
	defer f.Close()

	_, err = f.WriteString(configB)
	if err != nil {
		t.Errorf("unable to write to file: %s", err.Error())
	}

	_, err = parse(configA, tmpdir+"/a.conf")
	if err != nil {
		t.Errorf("unable to parse config: %s", err.Error())
	}
}

func TestIncludeHome(t *testing.T) {
	configA := `Include ~/b.conf`
	configB := `Host google
  HostName google.se
  User goog
  Port 2222
  ProxyCommand ssh -q pluto nc saturn 22
  HostKeyAlgorithms ssh-dss
  # comment
  IdentityFile ~/.ssh/company

Host face
  HostName facebook.com
  User mark
  Port 22`

	tmpdir := t.TempDir()

	homedir.DisableCache = true
	homeEnv := "HOME"
	if runtime.GOOS == "plan9" {
		// On plan9, env vars are lowercase.
		homeEnv = "home"
	}
	err := os.Setenv(homeEnv, tmpdir)
	if err != nil {
		t.Errorf("unable to set HOME env var: %s", err.Error())
	}

	f, err := os.Create(tmpdir + "/b.conf")
	if err != nil {
		t.Errorf("unable to create file: %s", err.Error())
	}
	defer f.Close()

	_, err = f.WriteString(configB)
	if err != nil {
		t.Errorf("unable to write to file: %s", err.Error())
	}

	_, err = parse(configA, tmpdir+"/a.conf")
	if err != nil {
		t.Errorf("unable to parse config: %s", err.Error())
	}
}

func TestIncludeRoot(t *testing.T) {
	tmpdir := t.TempDir()

	configA := fmt.Sprintf(`Include %s/b.conf`, tmpdir)
	configB := `Host google
  HostName google.se
  User goog
  Port 2222
  ProxyCommand ssh -q pluto nc saturn 22
  HostKeyAlgorithms ssh-dss
  # comment
  IdentityFile ~/.ssh/company

Host face
  HostName facebook.com
  User mark
  Port 22`

	homedir.DisableCache = true
	homeEnv := "HOME"
	if runtime.GOOS == "plan9" {
		// On plan9, env vars are lowercase.
		homeEnv = "home"
	}
	err := os.Setenv(homeEnv, tmpdir)
	if err != nil {
		t.Errorf("unable to set HOME env var: %s", err.Error())
	}

	f, err := os.Create(tmpdir + "/b.conf")
	if err != nil {
		t.Errorf("unable to create file: %s", err.Error())
	}
	defer f.Close()

	_, err = f.WriteString(configB)
	if err != nil {
		t.Errorf("unable to write to file: %s", err.Error())
	}

	_, err = parse(configA, tmpdir+"/a.conf")
	if err != nil {
		t.Errorf("unable to parse config: %s", err.Error())
	}
}

func TestLocalForward(t *testing.T) {
	config := `Host google
  HostName google.se
  User goog
  Port 2222
  ProxyCommand ssh -q pluto nc saturn 22
  HostKeyAlgorithms ssh-dss
  # comment
  IdentityOnly yes
  IdentityFile ~/.ssh/company
  LocalForward 1337 duckduckgo.com:443

Host face
  HostName facebook.com
  User mark
  Port 22
  LocalForward 2222 totalylegitserver:22
  LocalForward 0.0.0.0:666 instagram.com:1234`

	expected := []*SSHHost{
		{
			Host:              []string{"google"},
			HostName:          "google.se",
			User:              "goog",
			Port:              2222,
			HostKeyAlgorithms: "ssh-dss",
			ProxyCommand:      "ssh -q pluto nc saturn 22",
			IdentityFile:      "~/.ssh/company",
			LocalForwards: []Forward{
				{
					InHost:  "",
					InPort:  1337,
					OutHost: "duckduckgo.com",
					OutPort: 443,
				},
			},
		},
		{
			Host:              []string{"face"},
			User:              "mark",
			Port:              22,
			HostName:          "facebook.com",
			HostKeyAlgorithms: "",
			ProxyCommand:      "",
			IdentityFile:      "",
			LocalForwards: []Forward{
				{
					InHost:  "",
					InPort:  2222,
					OutHost: "totalylegitserver",
					OutPort: 22,
				},
				{
					InHost:  "0.0.0.0",
					InPort:  666,
					OutHost: "instagram.com",
					OutPort: 1234,
				},
			},
		},
	}
	actual, err := parse(config, "~/.ssh/config")
	if err != nil {
		t.Errorf("unexpected error parsing config: %s", err.Error())
	}

	compare(t, expected, actual)
}

func TestLocalForwardInvalid1(t *testing.T) {
	config := `Host face
  HostName facebook.com
  User mark
  Port 22
  LocalForward 2222 totalylegitserver 22`

	var expected []*SSHHost

	expectedErr := "Invalid forward: \"2222 totalylegitserver 22\""

	actual, err := parse(config, "~/.ssh/config")
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not get expected error: %#v, got %#v", expectedErr, err.Error())
	}

	compare(t, expected, actual)
}

func TestLocalForwardInvalid2(t *testing.T) {
	config := `Host face
  HostName facebook.com
  User mark
  Port 22
  LocalForward 9223372036854775808 totalylegitserver:22`

	var expected []*SSHHost

	expectedErr := "strconv.Atoi: parsing \"9223372036854775808\": value out of range"

	actual, err := parse(config, "~/.ssh/config")
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not get expected error: %#v, got %#v", expectedErr, err.Error())
	}

	compare(t, expected, actual)
}

func TestLocalForwardInvalid3(t *testing.T) {
	config := `Host face
  HostName facebook.com
  User mark
  Port 22
  LocalForward 2222 totalylegitserver:9223372036854775808`

	var expected []*SSHHost

	expectedErr := "strconv.Atoi: parsing \"9223372036854775808\": value out of range"

	actual, err := parse(config, "~/.ssh/config")
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not get expected error: %#v, got %#v", expectedErr, err.Error())
	}

	compare(t, expected, actual)
}

func TestRemoteForward(t *testing.T) {
	config := `Host google
  HostName google.se
  User goog
  Port 2222
  ProxyCommand ssh -q pluto nc saturn 22
  HostKeyAlgorithms ssh-dss
  # comment
  IdentityOnly yes
  IdentityFile ~/.ssh/company
  RemoteForward 1337 duckduckgo.com:443

Host face
  HostName facebook.com
  User mark
  Port 22
  RemoteForward 2222 totalylegitserver:22
  RemoteForward 0.0.0.0:666 instagram.com:1234`

	expected := []*SSHHost{
		{
			Host:              []string{"google"},
			HostName:          "google.se",
			User:              "goog",
			Port:              2222,
			HostKeyAlgorithms: "ssh-dss",
			ProxyCommand:      "ssh -q pluto nc saturn 22",
			IdentityFile:      "~/.ssh/company",
			RemoteForwards: []Forward{
				{
					InHost:  "",
					InPort:  1337,
					OutHost: "duckduckgo.com",
					OutPort: 443,
				},
			},
		},
		{
			Host:              []string{"face"},
			User:              "mark",
			Port:              22,
			HostName:          "facebook.com",
			HostKeyAlgorithms: "",
			ProxyCommand:      "",
			IdentityFile:      "",
			RemoteForwards: []Forward{
				{
					InHost:  "",
					InPort:  2222,
					OutHost: "totalylegitserver",
					OutPort: 22,
				},
				{
					InHost:  "0.0.0.0",
					InPort:  666,
					OutHost: "instagram.com",
					OutPort: 1234,
				},
			},
		},
	}
	actual, err := parse(config, "~/.ssh/config")
	if err != nil {
		t.Errorf("unexpected error parsing config: %s", err.Error())
	}

	compare(t, expected, actual)
}

func TestRemoteForwardInvalid1(t *testing.T) {
	config := `Host face
	HostName facebook.com
	User mark
	Port 22
	RemoteForward abc totalylegitserver:22`

	var expected []*SSHHost

	expectedErr := "Invalid forward: \"abc totalylegitserver:22\""

	actual, err := parse(config, "~/.ssh/config")
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not get expected error: %#v, got %#v", expectedErr, err.Error())
	}

	compare(t, expected, actual)
}

func TestDynamicForward(t *testing.T) {
	config := `Host google
  HostName google.se
  User goog
  Port 2222
  ProxyCommand ssh -q pluto nc saturn 22
  HostKeyAlgorithms ssh-dss
  # comment
  IdentityOnly yes
  IdentityFile ~/.ssh/company
  DynamicForward 8080

Host face
  HostName facebook.com
  User mark
  Port 22
  DynamicForward 8080
  DynamicForward 0.0.0.0:8443`

	expected := []*SSHHost{
		{
			Host:              []string{"google"},
			HostName:          "google.se",
			User:              "goog",
			Port:              2222,
			HostKeyAlgorithms: "ssh-dss",
			ProxyCommand:      "ssh -q pluto nc saturn 22",
			IdentityFile:      "~/.ssh/company",
			DynamicForwards: []DynamicForward{
				{
					Host: "",
					Port: 8080,
				},
			},
		},
		{
			Host:              []string{"face"},
			User:              "mark",
			Port:              22,
			HostName:          "facebook.com",
			HostKeyAlgorithms: "",
			ProxyCommand:      "",
			IdentityFile:      "",
			DynamicForwards: []DynamicForward{
				{
					Host: "",
					Port: 8080,
				},
				{
					Host: "0.0.0.0",
					Port: 8443,
				},
			},
		},
	}
	actual, err := parse(config, "~/.ssh/config")
	if err != nil {
		t.Errorf("unexpected error parsing config: %s", err.Error())
	}

	compare(t, expected, actual)
}

func TestDynamicForward1(t *testing.T) {
	config := `Host face
  HostName facebook.com
  User mark
  Port 22
  DynamicForward abc`

	var expected []*SSHHost

	expectedErr := "Invalid dynamic forward: \"abc\""

	actual, err := parse(config, "~/.ssh/config")
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not get expected error: %#v, got %#v", expectedErr, err.Error())
	}

	compare(t, expected, actual)
}

func TestDynamicForward2(t *testing.T) {
	config := `Host face
  HostName facebook.com
  User mark
  Port 22
  DynamicForward 9223372036854775808`

	var expected []*SSHHost

	expectedErr := "strconv.Atoi: parsing \"9223372036854775808\": value out of range"

	actual, err := parse(config, "~/.ssh/config")
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not get expected error: %#v, got %#v", expectedErr, err.Error())
	}

	compare(t, expected, actual)
}

func compare(t *testing.T, expected, actual []*SSHHost) {
	for i, ac := range actual {
		exMap := toMap(t, expected[i])
		acMap := toMap(t, ac)

		if ok := reflect.DeepEqual(exMap, acMap); !ok {
			t.Errorf("unexpected parsed \n expected: %+v \n actual: %+v", exMap, acMap)
		}
	}
}

func toMap(t *testing.T, a *SSHHost) map[string]interface{} {
	ab, err := json.Marshal(a)
	if err != nil {
		t.Errorf("marshaling expected %s", err)
	}

	var aMap map[string]interface{}
	if err := json.Unmarshal(ab, &aMap); err != nil {
		t.Errorf("unmarshaling expected %s", err)
	}

	return aMap
}

func TestParse(t *testing.T) {
	config := `Host face
	HostName facebook.com
	User mark
	Port 22
	DynamicForward 9223372036854775808`

	ioutil.WriteFile("/tmp/example", []byte(config), os.FileMode(0644))

	actual, err := Parse("/tmp/example")

	var expected []*SSHHost

	expectedErr := "strconv.Atoi: parsing \"9223372036854775808\": value out of range"

	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not get expected error: %#v, got %#v", expectedErr, err.Error())
	}

	compare(t, expected, actual)

}

func TestParseFS(t *testing.T) {
	config := `Host face
	HostName facebook.com
	User mark
	Port 22
	DynamicForward 9223372036854775808`

	memfs := fstest.MapFS{
		"config": &fstest.MapFile{
			Data: []byte(config),
		},
	}

	actual, err := ParseFS(memfs, "config")

	var expected []*SSHHost

	expectedErr := "strconv.Atoi: parsing \"9223372036854775808\": value out of range"

	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not get expected error: %#v, got %#v", expectedErr, err.Error())
	}

	compare(t, expected, actual)

}

func TestParseFSNonExitentFile(t *testing.T) {
	memfs := fstest.MapFS{}

	_, err := ParseFS(memfs, "config")

	expectedErr := "open config: file does not exist"

	if err == nil {
		t.Errorf("Did not get expected error: %#v, got nil", expectedErr)
	}

	if err.Error() != expectedErr {
		t.Errorf("Did not get expected error: %#v, got %#v", expectedErr, err.Error())
	}

}

func TestLexError(t *testing.T) {
	config := "Host face\nHostName facebook.comUser mark\rPort 22\nDynamicForward abc"
	expectedErr := "expected \\n"
	_, err := parse(config, "~/.ssh/config")

	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not get expected error: %#v, got %#v", expectedErr, err.Error())
	}
}

func TestWildcardHost(t *testing.T) {
	config := `Host *
  User mark
  Port 222
  Host empty
  HostName empty.com
  Host onlyport
  Port 2222
  Host onlyuser
  User onlyuser
  Host bothset
  HostName bothset.com
  Port 23
  User bothset`
	expected := []*SSHHost{
		{
			Host: []string{"empty"},
			User: "mark",
			Port: 222,
			HostName: "empty.com",
		}, {
			Host: []string{"onlyport"},
			User: "mark",
			Port: 2222,
		}, {
			Host: []string{"onlyuser"},
			User: "onlyuser",
			Port: 222,
		}, {
			Host: []string{"bothset"},
			User: "bothset",
			Port: 23,
			HostName: "bothset.com",
		},
	}
	parsed, err := parse(config, "~/.ssh/config")
	if err != nil {
		t.Errorf("unexpected error parsing config: %s", err.Error())
	}
	compare(t, expected, parsed)
}

func TestUnmatchedWildcardPost(t *testing.T) {
	config := `Host special*
  User special
  Port 3333
  Host special1
  HostName special1.com
  Host 2special
  Port 2222
  Host nothing
  User nothing
  Host nothingspecial
  User nothingspecial`
	expected := []*SSHHost{
		{
			Host: []string{"special1"},
			User: "special",
			Port: 3333,
			HostName: "special1.com",
		}, {
			Host: []string{"2special"},
			User: "",
			Port: 2222,
		}, {
			Host: []string{"nothing"},
			User: "nothing",
			Port: 22,
		}, {
			Host: []string{"nothingspecial"},
			User: "nothingspecial",
			Port: 22,
		},
	}
	parsed, err := parse(config, "~/.ssh/config")
	if err != nil {
		t.Errorf("unexpected error parsing config: %s", err.Error())
	}
	compare(t, expected, parsed)
}

func TestUnmatchedWildcardPrefix(t *testing.T) {
	config := `Host *special
  User special
  Port 3333
  Host special1
  HostName special1.com
  User special1
  Host 2special
  Port 2222
  Host nothing
  User nothing
  Host nothingspecial
  User nothingspecial`
	expected := []*SSHHost{
		{
			Host: []string{"special1"},
			User: "special1",
			Port: 22,
			HostName: "special1.com",
		}, {
			Host: []string{"2special"},
			User: "special",
			Port: 2222,
		}, {
			Host: []string{"nothing"},
			User: "nothing",
			Port: 22,
		}, {
			Host: []string{"nothingspecial"},
			User: "nothingspecial",
			Port: 3333,
		},
	}
	parsed, err := parse(config, "~/.ssh/config")
	if err != nil {
		t.Errorf("unexpected error parsing config: %s", err.Error())
	}
	compare(t, expected, parsed)
}

func TestUnmatchedWildcardBetween(t *testing.T) {
	config := `Host part*special
  User part33special
  Port 3333
  Host special
  HostName special1.com
  User special1
  Host part
  Port 2222
  Host part_very_complex_special`
	expected := []*SSHHost{
		{
			Host: []string{"special"},
			User: "special1",
			Port: 22,
			HostName: "special1.com",
		}, {
			Host: []string{"part"},
			User: "",
			Port: 2222,
		}, {
			Host: []string{"part_very_complex_special"},
			User: "part33special",
			Port: 3333,
		},
	}
	parsed, err := parse(config, "~/.ssh/config")
	if err != nil {
		t.Errorf("unexpected error parsing config: %s", err.Error())
	}
	compare(t, expected, parsed)
}

func TestMultiWildcard(t *testing.T) {
	config := `Host first*second*third
  User first_second_third
  Port 123
  Host first
  HostName first.com
  User first
  Host second
  Port 222
  Host third
  User third
  Host first_second
  HostName first_second.com
  Host second_third
  User second_third
  Host first_third
  Port 333
  Host first_second_third
  HostName first_second_third.com
  Host first_half_second_half_third`
	expected := []*SSHHost{
		{
			Host: []string{"first"},
			User: "first",
			Port: 22,
			HostName: "first.com",
		}, {
			Host: []string{"second"},
			User: "",
			Port: 222,
		}, {
			Host: []string{"third"},
			User: "third",
			Port: 22,
		}, {
			Host: []string{"first_second"},
			User: "",
			Port: 22,
			HostName: "first_second.com",
		}, {
			Host: []string{"second_third"},
			User: "second_third",
			Port: 22,
		}, {
			Host: []string{"first_third"},
			User: "",
			Port: 333,
		}, {
			Host: []string{"first_second_third"},
			User: "first_second_third",
			Port: 123,
			HostName: "first_second_third.com",
		}, {
			Host: []string{"first_half_second_half_third"},
			User: "first_second_third",
			Port: 123,
		},
	}
	parsed, err := parse(config, "~/.ssh/config")
	if err != nil {
		t.Errorf("unexpected error parsing config: %s", err.Error())
	}
	compare(t, expected, parsed)
}
func TestHostlessFile(t *testing.T) {
	config := `Include ./b.conf
	Include ./a.conf
	VisualHostKey yes`

	configB := `Host google
	  HostName google.se
	  User goog
	  Port 2222`
	configA := `Host face
	  HostName facebook.com
	  User mark
	  Port 22`

	tmpdir := t.TempDir()

	f, err := os.Create(tmpdir + "/b.conf")
	if err != nil {
		t.Errorf("unable to create file: %s", err.Error())
	}
	defer f.Close()

	_, err = f.WriteString(configB)
	if err != nil {
		t.Errorf("unable to write to file: %s", err.Error())
	}

	f, err = os.Create(tmpdir + "/a.conf")
	if err != nil {
		t.Errorf("unable to create file: %s", err.Error())
	}
	defer f.Close()

	_, err = f.WriteString(configA)
	if err != nil {
		t.Errorf("unable to write to file: %s", err.Error())
	}

	_, err = parse(config, tmpdir + "/config")

	if err != nil {
		t.Errorf("unable to parse config: %s", err.Error())
	}
}
