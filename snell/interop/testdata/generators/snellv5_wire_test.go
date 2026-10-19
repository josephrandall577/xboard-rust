package snellv5

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
)

type captureWriter struct{ data bytes.Buffer }

func (c *captureWriter) Write(p []byte) (int, error) { return c.data.Write(p) }
func (c *captureWriter) WriteVectorised(buffers []*buf.Buffer) error {
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

func describeV5Wire(psk []byte, wire []byte) string {
	var b strings.Builder
	aead, _ := snell.NewAEAD(snell.DeriveKey(psk, wire[:snell.SaltLen]))
	nonce := make([]byte, snell.NonceLen)
	offset := snell.SaltLen
	for index := 0; offset < len(wire); index++ {
		header, err := aead.Open(nil, nonce, wire[offset:offset+snell.HeaderCipherLen], nil)
		if err != nil {
			panic(err)
		}
		snell.IncreaseNonce(nonce)
		offset += snell.HeaderCipherLen
		paddingLen := int(binary.BigEndian.Uint16(header[3:5]))
		payloadLen := int(binary.BigEndian.Uint16(header[5:7]))
		padding := append([]byte(nil), wire[offset:offset+paddingLen]...)
		offset += paddingLen
		var plain []byte
		if payloadLen > 0 {
			cipher := append([]byte(nil), wire[offset:offset+payloadLen+snell.AEADTagLen]...)
			offset += payloadLen + snell.AEADTagLen
			for i := 0; i < min(len(padding), len(cipher)); i += 2 {
				padding[i], cipher[i] = cipher[i], padding[i]
			}
			plain, err = aead.Open(nil, nonce, cipher, nil)
			if err != nil {
				panic(err)
			}
			snell.IncreaseNonce(nonce)
		}
		fmt.Fprintf(&b, "record %d %d %d %s\n", index, paddingLen, payloadLen, short(plain))
	}
	return b.String()
}

func newBuffer(front int, payload []byte) *buf.Buffer {
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
	psk := []byte("snell-interop-test-psk-0123456789")
	salt := []byte("0123456789abcdef")
	var b strings.Builder
	for _, initialPadding := range []int{256, 300, 511} {
		for _, firstLen := range []int{0, 1, 3000} {
			capture := &captureWriter{}
			aead, _ := snell.NewAEAD(snell.DeriveKey(psk, salt))
			w, err := newWriter(capture, aead, make([]byte, snell.NonceLen))
			if err != nil {
				t.Fatal(err)
			}
			w.initialPaddingLen = initialPadding
			w.WriteFirst(salt, pattern(firstLen, 0))
			for index, size := range []int{1, 100, 1400, 2900, 5000, 20000, 70000, 300000} {
				w.Write(pattern(size, index+1))
			}
			for index, size := range []int{10, 1500, 16383, 40000, 250000} {
				w.WriteBuffer(newBuffer(w.FrontHeadroom(), pattern(size, index+20)))
			}
			var buffers []*buf.Buffer
			for index, size := range []int{500, 0, 16000, 33000, 200000} {
				buffers = append(buffers, newBuffer(w.FrontHeadroom(), pattern(size, index+30)))
			}
			w.CreateVectorisedWriterFor(capture).WriteVectorised(buffers)
			for index, size := range []int{20, 1200, 16383} {
				w.WritePacketBuffer(newBuffer(w.FrontHeadroom(), pattern(size, index+40)))
			}
			buffers = nil
			for index, size := range []int{100, 1450} {
				buffers = append(buffers, newBuffer(w.FrontHeadroom(), pattern(size, index+50)))
			}
			w.CreatePacketVectorisedWriterFor(capture).WriteVectorised(buffers)
			w.WriteZeroChunk()
			fmt.Fprintf(&b, "scenario v5 %d %d\n%s", initialPadding, firstLen, describeV5Wire(psk, capture.data.Bytes()))
		}
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
