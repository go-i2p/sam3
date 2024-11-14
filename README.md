# README #

STATUS: This project is maintained. I will respond to issues, pull requests, and feature requests within a few days.

[![Go Report Card](https://goreportcard.com/badge/github.com/go-i2p/sam3)](https://goreportcard.com/report/github.com/go-i2p/sam3)

# README #

go library for the I2P [SAMv3.0](https://geti2p.net/en/docs/api/samv3) bridge, used to build anonymous/pseudonymous end-to-end encrypted sockets.

This library is much better than ccondom (that use BOB), much more stable and much easier to maintain.

## Support/TODO ##

**What works:**

* Utils
    * Resolving domain names to I2P destinations
    * .b32.i2p hashes
    * Generating keys/i2p destinations
* Streaming
    * DialI2P() - Connecting to stuff in I2P
    * Listen()/Accept() - Handling incomming connections
    * Implements net.Conn and net.Listener
* Datagrams
    * Implements net.PacketConn
* Raw datagrams
    * Like datagrams, but without addresses

**Does not work:**

* Stream Forwarding
* Probably needs some real-world testing

## Documentation ##

* Latest version-documentation:
    * set your GOPATH
    * Enter `godoc -http=:8081` into your terminal and hit enter.
    * Goto http://localhost:8081, click packages, and navigate to sam3

## Examples ##
```go
package main

import (
	"github.com/go-i2p/sam3"
	"github.com/go-i2p/sam3/i2pkeys"
	"fmt"
)

const yoursam = "127.0.0.1:7656" // sam bridge

func client(server i2pkeys.I2PAddr) {
	sam, _ := sam3.NewSAM(yoursam)
	keys, _ := sam.NewKeys()
	stream, _ := sam.NewStreamSession("clientTun", keys, sam3.Options_Small)
	fmt.Println("Client: Connecting to " + server.Base32())
	conn, _ := stream.DialI2P(server)
	conn.Write([]byte("Hello world!"))
	return
}

func main() {
	sam, _ := NewSAM(yoursam)
	keys, _ := sam.NewKeys()
	stream, _ := sam.NewStreamSession("serverTun", keys, sam3.Options_Medium)
	listener, _ := stream.Listen()
	go client(keys.Addr())
	conn, _ := listener.Accept()
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	fmt.Println("Server received: " + string(buf[:n]))
}
```

The above will write to the terminal:

```text
Client: Connecting to zjnvfh4hs3et5vtz35ogwzrws26zvwkcad5uo5esecvg4qpk5b4a.b32.i2p
Server received: Hello world!
```

Error handling was omitted in the above code for readability.

## Testing ##

* `go test -tags=nettest` runs the whole suite (takes 90+ sec to perform!)
* `go test -short` runs the shorter variant, does not connect to anything

## Verbosity ##
Logging can be enabled and configured using the DEBUG_I2P environment variable. By default, logging is disabled.

There are three available log levels:

- Debug
```shell
export DEBUG_I2P=debug
```
- Warn
```shell
export DEBUG_I2P=warn
```
- Error
```shell
export DEBUG_I2P=error
```

If DEBUG_I2P is set to an unrecognized variable, it will fall back to "debug".

## License ##

Public domain.

## Author ##

* Kalle Vedin `kalle.vedin@fripost.org`
* Unknown Name (majestrate)
* idk
* qiwenmin
