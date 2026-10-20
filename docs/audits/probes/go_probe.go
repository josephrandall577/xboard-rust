package main

import (
	"bytes"
	"fmt"
	snell "github.com/sagernet/sing-snell"
	"net"
	"time"
)

func main() {
	for _, h := range [][]byte{{0xff}, []byte("fe80::1%lo0"), []byte("[::1]")} {
		wire := append([]byte{byte(len(h))}, h...)
		wire = append(wire, 1, 187)
		d, e := snell.ReadConnectAddress(bytes.NewReader(wire))
		fmt.Printf("go address input=%x host=%x is_ip=%v error=%v\n", h, []byte(d.AddrString()), d.IsIP(), e)
	}
	data := make([]byte, 142)
	data = append(data, make([]byte, 75)...)
	data = append(data, 0x17, 3, 3, 0, 1, 'A')
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { b.Write(data) }()
	c := snell.ObfsConfig{Mode: snell.ObfsModeTLS}.ServerConn(a)
	c.SetReadDeadline(time.Now().Add(time.Second))
	p := make([]byte, 16)
	n, e := c.Read(p)
	fmt.Printf("go tls empty first record: n=%d error=%v data=%x\n", n, e, p[:n])
	n, e = c.Read(p)
	fmt.Printf("go tls next read: n=%d error=%v data=%x\n", n, e, p[:n])
}
