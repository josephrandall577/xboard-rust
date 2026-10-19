package snellv6

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprint(v)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func describe(p *Profile) string {
	return fmt.Sprintf("gen=%d pad=%d..%d padCount=%d padInterval=%d small=%d bit=%d..%d prefix=%d..%d mix=%d/%d/%d/%d/%d "+
		"chunk=%d/%d/%d/%d/%d/%d idle=%d write=%d/%d/%d/%d buckets=%s/%s/%s g=%d/%d/%d/%d/%d/%d "+
		"salt=%d/%d/%d headroom=%d/%d",
		p.generator, p.padMin, p.padMax, p.padCount, p.padInterval, p.smallLimit, p.bitMin, p.bitMax,
		p.prefixMinRecord, p.prefixMaxRecord, p.mixMode, p.mixRounds, p.mixStride, p.mixOffsetBase, p.mixBlock,
		p.chunkPolicy, p.chunkInitial, p.firstRecordCap, p.chunkMax, p.chunkStep, p.chunkJitter, p.idleResetSec,
		p.writePolicy, p.writeFirst, p.writeJitter, p.writeJitterPct,
		joinInts(p.chunkBuckets[:]), joinInts(p.writeBuckets[:]), joinInts(p.writeSeq[:]),
		p.g1, p.g2, p.g3, p.g4, p.g5, p.g6, p.saltBlockLen, p.mixStrideHandshake, p.mixRoundsHandshake,
		p.recordPrefixMax, p.padMaxHeadroom)
}

func TestDumpVectors(t *testing.T) {
	out := os.Getenv("VECTORS_OUT")
	if out == "" {
		t.Skip("VECTORS_OUT not set")
	}
	var b strings.Builder
	psks := []string{"snell-interop-test-psk-0123456789", "snell-rc-udp-0371991", "short-psk-12", "a", "0123456789abcdef0123456789abcdef"}
	for i := 0; i < 40; i++ {
		psks = append(psks, fmt.Sprintf("generated-psk-%d-%x", i, i*7919))
	}
	for _, psk := range psks {
		p := NewProfile([]byte(psk))
		fmt.Fprintf(&b, "psk %s\n", psk)
		fmt.Fprintf(&b, "profile %s\n", describe(p))
		var prefixes []int
		for seq := uint32(0); seq < 24; seq++ {
			prefixes = append(prefixes, p.recordPrefixLen(seq))
		}
		fmt.Fprintf(&b, "prefix %s\n", joinInts(prefixes))
		var chunks []int
		for _, seq := range []uint32{0, 1, 2, 5, 17, 100} {
			for _, size := range []int{0, 0x60, 0x200, 0x5b4, 0x1000, 0x3fff, 0x10000} {
				chunks = append(chunks, p.chunkPayloadLimit(seq, size))
			}
		}
		fmt.Fprintf(&b, "chunk %s\n", joinInts(chunks))
		var paddings []int
		for _, seq := range []uint32{0, 1, 2, 3, 7, 8, 11, 12, 33, 1000} {
			for _, payloadLen := range []int{0, 1, 0x60, 0x2ff, 0x300, 0x500, 0x5b4, 0x2000, 0xffff} {
				paddings = append(paddings, p.paddingLen(seq, payloadLen, p.recordPrefixLen(seq), 0, 0))
				paddings = append(paddings, p.paddingLen(seq, payloadLen, p.recordPrefixLen(seq), p.saltBlockLen-saltLen, p.saltBlockLen))
			}
		}
		fmt.Fprintf(&b, "padding %s\n", joinInts(paddings))
		var targets []int
		for _, seq := range []uint32{0, 1, 4, 7, 8, 9, 50} {
			for _, frameLen := range []int{0, 1, 0x40, 0x100, 0x200, 0x400, 0x5b3, 0x5b4, 0x2000, 0x10000} {
				targets = append(targets, p.writeTarget(seq, frameLen))
			}
		}
		fmt.Fprintf(&b, "target %s\n", joinInts(targets))
		for _, seq := range []uint32{0, 1, 2, 3, 9, 0xffffffff} {
			fill := make([]byte, 97)
			p.fillPadding(seq, fill)
			fmt.Fprintf(&b, "fill %d %s\n", seq, hex.EncodeToString(fill))
		}
		for _, seq := range []uint32{0, 5} {
			for _, sizes := range [][2]int{{0, 10}, {10, 0}, {37, 200}, {300, 100}, {1024, 1040}} {
				padding := make([]byte, sizes[0])
				payload := make([]byte, sizes[1])
				for i := range padding {
					padding[i] = byte(i)
				}
				for i := range payload {
					payload[i] = byte(0x80 + i)
				}
				p.mixPaddingPayload(seq, padding, payload)
				fmt.Fprintf(&b, "mix %d %d %d %s %s\n", seq, sizes[0], sizes[1], hex.EncodeToString(padding), hex.EncodeToString(payload))
			}
		}
		salt := []byte("0123456789abcdef")
		block := make([]byte, p.saltBlockLen)
		p.fillPadding(0xffffffff, block)
		p.writeSaltBlock(salt, block)
		extracted := p.extractSalt(block)
		fmt.Fprintf(&b, "salt %s %s\n", hex.EncodeToString(block), hex.EncodeToString(extracted[:]))
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
