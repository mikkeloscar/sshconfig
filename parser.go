package sshconfig

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/mitchellh/go-homedir"
)

// SSHHost defines a single host entry in a ssh config
type SSHHost struct {
	Host              []string
	HostName          string
	User              string
	Port              int
	ProxyCommand      string
	HostKeyAlgorithms string
	IdentityFile      string
	LocalForwards     []Forward
	RemoteForwards    []Forward
	DynamicForwards   []DynamicForward
}

// Forward defines a single port forward entry
type Forward struct {
	InHost  string
	InPort  int
	OutHost string
	OutPort int
}

// NewForward returns Forward object parsed from LocalForward or RemoteForward string
func NewForward(f string) (Forward, error) {
	r := regexp.MustCompile(`((\S+):)?(\d+)\s+(\S+):(\d+)`)
	m := r.FindStringSubmatch(f)

	if len(m) < 6 {
		return Forward{}, fmt.Errorf("Invalid forward: %#v", f)
	}

	InPort, err := strconv.Atoi(m[3])
	if err != nil {
		return Forward{}, err
	}

	OutPort, err := strconv.Atoi(m[5])
	if err != nil {
		return Forward{}, err
	}

	return Forward{
		InHost:  m[2],
		InPort:  InPort,
		OutHost: m[4],
		OutPort: OutPort,
	}, nil
}

// DynamicForward defines a single dynamic port forward entry
type DynamicForward struct {
	Host string
	Port int
}

// NewDynamicForward returns DForward object parsed from DynamicForward string
func NewDynamicForward(f string) (DynamicForward, error) {
	r := regexp.MustCompile(`((\S+):)?(\d+)`)
	m := r.FindStringSubmatch(f)

	if len(m) < 4 {
		return DynamicForward{}, fmt.Errorf("Invalid dynamic forward: %#v", f)
	}

	InPort, err := strconv.Atoi(m[3])
	if err != nil {
		return DynamicForward{}, err
	}

	return DynamicForward{
		Host: m[2],
		Port: InPort,
	}, nil
}

// MustParse must parse the SSH config given by path or it will panic
func MustParse(path string) []*SSHHost {
	config, err := Parse(path)
	if err != nil {
		panic(err)
	}
	return config
}

// MustParseSSHConfig must parse the SSH config given by path or it will panic
// Deprecated: Use MustParse instead.
func MustParseSSHConfig(path string) []*SSHHost {
	return MustParse(path)
}

// ParseSSHConfig parses a SSH config given by path.
// Deprecated: Use Parse instead.
func ParseSSHConfig(path string) ([]*SSHHost, error) {
	return Parse(path)
}

// Parse parses a SSH config given by path.
func Parse(path string) ([]*SSHHost, error) {
	// read config file
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parse(string(content), path)
}

// ParseFS parses a SSH config given by path contained in fsys.
func ParseFS(fsys fs.FS, path string) ([]*SSHHost, error) {
	// read config file
	content, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, err
	}

	return parse(string(content), path)
}

// parses an openssh config file
func parse(input string, path string) ([]*SSHHost, error) {
	sshConfigs := []*SSHHost{}
	var next item
	var sshHost *SSHHost

	lexer := lex(input)
Loop:
	for {
		token := lexer.nextItem()

		if sshHost == nil {
			if token.typ != itemEOF && token.typ != itemHost && token.typ != itemInclude {
				return nil, fmt.Errorf("%s:%d: config variable before Host variable", path, token.pos)
			}
		} else if token.typ == itemInclude {
			return nil, fmt.Errorf("include not allowed in Host block")
		}

		switch token.typ {
		case itemHost:
			if sshHost != nil {
				sshConfigs = append(sshConfigs, sshHost)
			}

			sshHost = &SSHHost{Host: []string{}, Port: 22}
		case itemHostValue:
			sshHost.Host = strings.Split(token.val, " ")
		case itemHostName:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.HostName = strings.TrimSpace(next.val)
		case itemUser:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.User = strings.TrimSpace(next.val)
		case itemPort:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			port, err := strconv.Atoi(strings.TrimSpace(next.val))
			if err != nil {
				return nil, err
			}
			sshHost.Port = port
		case itemProxyCommand:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.ProxyCommand = next.val
		case itemHostKeyAlgorithms:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.HostKeyAlgorithms = next.val
		case itemIdentityFile:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.IdentityFile = next.val
		case itemLocalForward:
			next = lexer.nextItem()
			f, err := NewForward(next.val)
			if err != nil {
				return nil, err
			}
			sshHost.LocalForwards = append(sshHost.LocalForwards, f)
		case itemRemoteForward:
			next = lexer.nextItem()
			f, err := NewForward(next.val)
			if err != nil {
				return nil, err
			}
			sshHost.RemoteForwards = append(sshHost.RemoteForwards, f)
		case itemDynamicForward:
			next = lexer.nextItem()
			f, err := NewDynamicForward(next.val)
			if err != nil {
				return nil, err
			}
			sshHost.DynamicForwards = append(sshHost.DynamicForwards, f)
		case itemInclude:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}

			includePath, err := parseIncludePath(path, next.val)
			if err != nil {
				return nil, err
			}

			files, err := filepath.Glob(includePath)
			if err != nil {
				return nil, err
			}

			if len(files) == 0 {
				return nil, fmt.Errorf("no files found for include path %s", includePath)
			}

			for _, f := range files {
				includeSshConfigs, err := Parse(f)
				if err != nil {
					return nil, err
				}

				sshConfigs = append(sshConfigs, includeSshConfigs...)
			}
		case itemError:
			return nil, fmt.Errorf("%s at pos %d", token.val, token.pos)
		case itemEOF:
			if sshHost != nil {
				sshConfigs = append(sshConfigs, sshHost)
			}
			break Loop
		default:
			// continue onwards
		}
	}
	return sshConfigs, nil
}

func parseIncludePath(currentPath string, includePath string) (string, error) {
	if strings.HasPrefix(includePath, "~") {
		expandedPath, err := homedir.Expand(includePath)
		if err != nil {
			return "", err
		}

		return expandedPath, nil
	} else if !strings.HasPrefix(includePath, "/") {
		return filepath.Join(filepath.Dir(currentPath), includePath), nil
	}

	return includePath, nil
}
