package suite

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	F "github.com/sagernet/sing/common/format"

	"github.com/stretchr/testify/require"
)

// startSnellServer runs the server binary from SNELL_SERVER_BIN (normally the
// Rust snell-server example) in place of the official snell-server container
// used by the original suite.
func startSnellServer(t *testing.T, version string, configContent string, port uint16) {
	binary := os.Getenv("SNELL_SERVER_BIN")
	if binary == "" {
		t.Skip("SNELL_SERVER_BIN not set")
	}
	confDir := t.TempDir()
	confPath := filepath.Join(confDir, "snell.conf")
	require.NoError(t, os.WriteFile(confPath, []byte(configContent), 0o644))
	protocol := version
	if protocol == "v4" {
		protocol = "v5"
	}
	var output bytes.Buffer
	command := exec.Command(binary, "-c", confPath, "-l", "error", "--protocol", protocol)
	command.Stdout = &output
	command.Stderr = &output
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		command.Process.Kill()
		command.Wait()
		if t.Failed() {
			t.Logf("server output:\n%s", output.String())
		}
	})
	address := "127.0.0.1:" + F.ToString(port)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("snell server did not listen on %s:\n%s", address, output.String())
}
