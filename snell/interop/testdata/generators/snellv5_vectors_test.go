package snellv5

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDumpVectors(t *testing.T) {
	out := os.Getenv("VECTORS_OUT")
	if out == "" {
		t.Skip("VECTORS_OUT not set")
	}
	var b strings.Builder
	var bloom saltReplayBloom
	bloom.Initialize(saltReplayCacheGenerationSize, saltReplayCacheFalsePositiveRate)
	fmt.Fprintf(&b, "bloom %d %d\n", bloom.bitCount, bloom.hashCount)
	for _, input := range []string{"", "a", "ab", "abc", "abcd", "abcde", "0123456789abcdef", "snell-interop-test-psk-0123456789"} {
		first := bloom.MurmurHash([]byte(input), saltReplayCacheMurmurHashDefaultSeed)
		fmt.Fprintf(&b, "murmur %q %d %d\n", input, first, bloom.MurmurHash([]byte(input), first))
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
