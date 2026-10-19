// A snell-server built from the Go reference implementation, with the same
// command line as the Rust example, used for interop tests.
package main

import (
	stdbufio "bufio"
	"context"
	"flag"
	"fmt"

	"net"
	"os"
	"strings"
	"sync"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type handler struct{}

func (handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		upstream, err := net.Dial("tcp", destination.String())
		if err == nil {
			err = bufio.CopyConn(ctx, conn, upstream)
		} else {
			conn.Close()
		}
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		udp, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			conn.Close()
			if onClose != nil {
				onClose(err)
			}
			return
		}
		var once sync.Once
		closeAll := func() { once.Do(func() { udp.Close(); conn.Close() }) }
		go func() {
			defer closeAll()
			data := make([]byte, 65535)
			for {
				n, addr, readErr := udp.ReadFrom(data)
				if readErr != nil {
					return
				}
				frontHeadroom := N.CalculateFrontHeadroom(conn)
				rearHeadroom := N.CalculateRearHeadroom(conn)
				buffer := buf.NewSize(frontHeadroom + n + rearHeadroom)
				buffer.Resize(frontHeadroom, 0)
				buffer.Write(data[:n])
				if conn.WritePacket(buffer, M.SocksaddrFromNet(addr)) != nil {
					return
				}
			}
		}()
		var loopErr error
		for {
			buffer := buf.NewPacket()
			packetDestination, readErr := conn.ReadPacket(buffer)
			if readErr != nil {
				buffer.Release()
				loopErr = readErr
				break
			}
			udpAddr, resolveErr := net.ResolveUDPAddr("udp", packetDestination.String())
			if resolveErr == nil {
				udp.WriteTo(buffer.Bytes(), udpAddr)
			}
			buffer.Release()
		}
		closeAll()
		if onClose != nil {
			onClose(loopErr)
		}
	}()
}

func parseConfig(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	values := make(map[string]string)
	inSection := false
	scanner := stdbufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = line == "[snell-server]"
			continue
		}
		if !inSection {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("invalid line: %s", line)
		}
		values[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return values, scanner.Err()
}

func main() {
	configPath := flag.String("c", "", "config")
	logLevel := flag.String("l", "error", "log level")
	protocol := flag.String("protocol", "", "v5 or v6")
	flag.Parse()
	config, err := parseConfig(*configPath)
	if err != nil {
		panic(err)
	}
	if *protocol == "" {
		if _, ok := config["mode"]; ok {
			*protocol = "v6"
		} else {
			*protocol = "v5"
		}
	}
	verbose := *logLevel != "error"
	var service snell.Service
	switch *protocol {
	case "v4", "v5":
		obfsMode, err := snell.ParseObfsMode(config["obfs"])
		if err != nil {
			panic(err)
		}
		service, err = snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(config["psk"]), ObfsMode: obfsMode, Handler: handler{}})
		if err != nil {
			panic(err)
		}
	case "v6":
		mode, err := snellv6.ParseMode(config["mode"])
		if err != nil {
			panic(err)
		}
		service, err = snellv6.NewService(snellv6.ServerOptions{PSK: []byte(config["psk"]), Mode: mode, Handler: handler{}})
		if err != nil {
			panic(err)
		}
	default:
		panic("unknown protocol " + *protocol)
	}
	listener, err := net.Listen("tcp", config["listen"])
	if err != nil {
		panic(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			serveErr := service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
			if serveErr != nil {
				conn.Close()
				if verbose {
					fmt.Fprintln(os.Stderr, serveErr)
				}
			}
		}()
	}
}
