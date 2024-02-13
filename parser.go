package sshconfig

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"reflect"

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
	Ciphers           []string
	MACs              []string
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
	var wildcardHosts []*SSHHost

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
				if containsWildcard(sshHost) {
					wildcardHosts = append(wildcardHosts, sshHost)
				} else {
					sshConfigs = append(sshConfigs, sshHost)
				}
			}

			sshHost = &SSHHost{Host: []string{}, Port: 0}
		case itemHostValue:
			sshHost.Host = strings.Split(token.val, " ")
		case itemHostName:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.HostName = next.val
		case itemUser:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.User = next.val
		case itemPort:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			port, err := strconv.Atoi(next.val)
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
		case itemCiphers:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.Ciphers = strings.Split(next.val, ",")
		case itemMACs:
			next = lexer.nextItem()
			if next.typ != itemValue {
				return nil, fmt.Errorf(next.val)
			}
			sshHost.MACs = strings.Split(next.val, ",")
		case itemError:
			return nil, fmt.Errorf("%s at pos %d", token.val, token.pos)
		case itemEOF:
			if sshHost != nil {
				if containsWildcard(sshHost) {
					wildcardHosts = append(wildcardHosts, sshHost)
				} else {
					sshConfigs = append(sshConfigs, sshHost)
				}
			}
			break Loop
		default:
			// continue onwards
		}
	}
	if len(wildcardHosts) > 0 {
		sshConfigs = applyWildcardRules(wildcardHosts, sshConfigs)
	}
	assertDefaultPort(sshConfigs)
	return sshConfigs, nil
}

// Because the wildcard feature changed the hardcoded value to 0 in order to detect if there is port in config.
func assertDefaultPort(hosts []*SSHHost) {
	for _, host := range hosts {
		if host.Port == 0 {
			host.Port = 22
		}
	}
}

func applyWildcardRules(wildcardHosts []*SSHHost, sshConfigs []*SSHHost) []*SSHHost {
	for _, wildcardHost := range wildcardHosts {
		for _, host := range sshConfigs {
			matched := matchWildcardHost(wildcardHost, host)
			if !matched {
				break
			}
			mergeSSHConfigs(wildcardHost, host)
		}
	}
	return sshConfigs
}

func matchWildcardHost(wildcardHost *SSHHost, host *SSHHost) bool {
	for _, h := range wildcardHost.Host {
		for _, hh := range host.Host {
			regexpHost := strings.Replace(h, "*", ".*", -1)
			matched, err := regexp.MatchString(regexpHost, hh)
			if matched {
				return true
			}
			if err != nil {
				continue
			}
		}
	}
	return false
}

func containsWildcard(host *SSHHost) bool {
	for _, h := range host.Host {
		if strings.Contains(h, "*") {
			return true
		}
	}
	return false
}

func setFieldByName(host *SSHHost, name string, value interface{}) {
	v := reflect.ValueOf(host).Elem()
	f := v.FieldByName(name)
	strValue := fmt.Sprintf("%v", value)
	currentValue := f.Interface()

	if currentValue != "" && currentValue != 0 {
		return
	}
	if f.Kind() == reflect.Slice {
		return
	}
	switch f.Kind() {
	case reflect.String:
		f.SetString(strValue)
	case reflect.Int:
		i, err := strconv.Atoi(strValue)
		if err != nil {
			panic(err)
		}
		f.SetInt(int64(i))
	case reflect.Bool:
		b, err := strconv.ParseBool(strValue)
		if err != nil {
			panic(err)
		}
		f.SetBool(b)
	case reflect.Float64:
		i, err := strconv.ParseFloat(strValue, 64)
		if err != nil {
			panic(err)
		}
		f.SetFloat(i)
	}
}

func mergeSSHConfigs(source *SSHHost, target *SSHHost) {
	sourceValue := reflect.ValueOf(source).Elem()
	sourceFields := reflect.TypeOf(source).Elem()
	for i := 0; i < sourceFields.NumField(); i++ {
		value := sourceValue.Field(i)
		if value == reflect.Zero(value.Type()) {
			continue
		}
		setFieldByName(target, sourceFields.Field(i).Name, value)
	}
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
