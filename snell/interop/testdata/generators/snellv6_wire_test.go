package snellv6

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type captureConn struct {
	data bytes.Buffer
}

func (c *captureConn) Read(p []byte) (int, error)       { select {} }
func (c *captureConn) Write(p []byte) (int, error)      { return c.data.Write(p) }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }
func (c *captureConn) WriteVectorised(buffers []*buf.Buffer) error {
	for _, buffer := range buffers {
		c.data.Write(buffer.Bytes())
	}
	buf.ReleaseMulti(buffers)
	return nil
}

func pattern(n int, seed int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*31 + seed*7 + 3)
	}
	return out
}

func short(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:6])
}

func describeWire(p *Profile, psk []byte, wire []byte) string {
	var b strings.Builder
	salt := p.extractSalt(wire[:p.saltBlockLen])
	aead, _ := snell.NewAEAD(snell.DeriveKey(psk, salt[:]))
	nonce := make([]byte, snell.NonceLen)
	offset := p.saltBlockLen
	for seq := uint32(0); offset < len(wire); seq++ {
		prefixLen := p.recordPrefixLen(seq)
		prefix := wire[offset : offset+prefixLen]
		header, err := aead.Open(nil, nonce, wire[offset+prefixLen:offset+prefixLen+snell.HeaderCipherLen], prefix)
		if err != nil {
			panic(err)
		}
		snell.IncreaseNonce(nonce)
		offset += prefixLen + snell.HeaderCipherLen
		paddingLen := int(binary.BigEndian.Uint16(header[3:5]))
		payloadLen := int(binary.BigEndian.Uint16(header[5:7]))
		padding := append([]byte(nil), wire[offset:offset+paddingLen]...)
		offset += paddingLen
		var plain []byte
		if payloadLen > 0 {
			cipher := append([]byte(nil), wire[offset:offset+payloadLen+snell.AEADTagLen]...)
			offset += payloadLen + snell.AEADTagLen
			p.mixPaddingPayload(seq, padding, cipher)
			plain, err = aead.Open(nil, nonce, cipher, padding)
			if err != nil {
				panic(err)
			}
			snell.IncreaseNonce(nonce)
		}
		fmt.Fprintf(&b, "record %d %d %d %d %s %s\n", seq, prefixLen, paddingLen, payloadLen, short(append(append([]byte(nil), prefix...), padding...)), short(plain))
	}
	return b.String()
}

var writeSizes = []int{1, 100, 1400, 5000, 20000, 70000}

func newBuffer(w interface{ FrontHeadroom() int }, payload []byte) *buf.Buffer {
	front := w.FrontHeadroom()
	buffer := buf.NewSize(front + len(payload) + snell.AEADTagLen)
	buffer.Resize(front, 0)
	buffer.Write(payload)
	return buffer
}

func TestDumpWireShape(t *testing.T) {
	out := os.Getenv("VECTORS_OUT")
	if out == "" {
		t.Skip("VECTORS_OUT not set")
	}
	destination := M.ParseSocksaddrHostPort("example.com", 443)
	var b strings.Builder
	for _, psk := range []string{"snell-interop-test-psk-0123456789", "snell-rc-udp-0371991", "generated-psk-7-d885"} {
		p := NewProfile([]byte(psk))
		client, err := NewClient(ClientOptions{PSK: []byte(psk), Mode: ModeDefault})
		if err != nil {
			t.Fatal(err)
		}
		{
			capture := &captureConn{}
			conn := client.DialEarlyConn(capture, destination).(*clientConn)
			conn.Write(pattern(3000, 0))
			for index, size := range writeSizes {
				conn.Write(pattern(size, index+1))
			}
			conn.CloseWrite()
			fmt.Fprintf(&b, "scenario %s write\n%s", psk, describeWire(p, []byte(psk), capture.data.Bytes()))
		}
		{
			capture := &captureConn{}
			conn := client.DialEarlyConn(capture, destination).(*clientConn)
			conn.WriteBuffer(newBuffer(conn, pattern(200, 0)))
			for index, size := range writeSizes {
				conn.WriteBuffer(newBuffer(conn, pattern(size, index+1)))
			}
			conn.CloseWrite()
			fmt.Fprintf(&b, "scenario %s buffer\n%s", psk, describeWire(p, []byte(psk), capture.data.Bytes()))
		}
		{
			capture := &captureConn{}
			writer, err := writeFirstRecord(capture, ModeDefault, []byte(psk), p, pattern(40, 0))
			if err != nil {
				t.Fatal(err)
			}
			var buffers []*buf.Buffer
			for index, size := range writeSizes {
				buffers = append(buffers, newBuffer(writer, pattern(size, index+1)))
			}
			writer.CreateVectorisedWriterFor(capture).WriteVectorised(buffers)
			writer.WriteZeroChunk()
			fmt.Fprintf(&b, "scenario %s vectorised\n%s", psk, describeWire(p, []byte(psk), capture.data.Bytes()))
		}
		{
			capture := &captureConn{}
			writer, err := writeFirstRecord(capture, ModeDefault, []byte(psk), p, pattern(3, 0))
			if err != nil {
				t.Fatal(err)
			}
			for index, size := range []int{20, 600, 1400, 1500, 9000, 0xffff} {
				writer.WritePacketBuffer(newBuffer(writer, pattern(size, index+1)))
			}
			var buffers []*buf.Buffer
			for index, size := range []int{100, 1450, 3000} {
				buffers = append(buffers, newBuffer(writer, pattern(size, index+10)))
			}
			writer.CreatePacketVectorisedWriterFor(capture).WriteVectorised(buffers)
			fmt.Fprintf(&b, "scenario %s packet\n%s", psk, describeWire(p, []byte(psk), capture.data.Bytes()))
		}
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
