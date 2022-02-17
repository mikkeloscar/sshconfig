# OpenSSH config parser for golang

[![Go Reference](https://pkg.go.dev/badge/github.com/mikkeloscar/sshconfig.svg)](https://pkg.go.dev/github.com/mikkeloscar/sshconfig)
[![Go Report Card](https://goreportcard.com/badge/github.com/mikkeloscar/sshconfig)](https://goreportcard.com/report/github.com/mikkeloscar/sshconfig)
[![Coverage Status](https://coveralls.io/repos/github/mikkeloscar/sshconfig/badge.svg)](https://coveralls.io/github/mikkeloscar/sshconfig)

Parses the config usually found in `~/.ssh/config` or `/etc/ssh/ssh_config`.
Only `Host`, `HostName`, `User`, `Port`, `IdentityFile`, `HostKeyAlgorithms`, `ProxyCommand`, `LocalForward`, `RemoteForward` and `DynamicForward` is implemented at
this point.

[OpenSSH Reference.][openssh_man]

## Usage

Example usage

```go
package main

import (
    "fmt"

    ssh "github.com/mikkeloscar/sshconfig"
)

func main() {
    hosts, err := ssh.ParseSSHConfig("/path/to/ssh_config")
    if err != nil {
        fmt.Println(err)
    }

    for _, host := range hosts {
       fmt.Printf("Hostname: %s User: %s\n", host.HostName, host.User)
    }
}
```

## LICENSE

Copyright (C) 2022  Mikkel Oscar Lyderik Larsen & Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

[openssh_man]: http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man5/ssh_config.5?query=ssh_config&sec=5
