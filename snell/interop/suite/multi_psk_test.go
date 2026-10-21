package suite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

// Exercises the node with an independent Go encoder and no user key, as Surge
// connects. Existing SNELL_SERVER_BIN tests exercise the original library APIs.
func TestV6MultiPskNode(t *testing.T) {
	binary := os.Getenv("XBOARD_SNELL_BIN")
	if binary == "" {
		t.Skip("XBOARD_SNELL_BIN not set")
	}
	psks := []string{"go-independent-alice-psk", "go-independent-bob-psk"}
	var mu sync.Mutex
	totals := map[string][2]int64{}
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/server/user":
			json.NewEncoder(w).Encode(map[string]any{"users": []any{
				map[string]any{"id": 1, "uuid": psks[0]},
				map[string]any{"id": 2, "uuid": psks[1]},
			}})
		case "/api/v2/server/report":
			var report struct {
				Traffic map[string][2]int64 `json:"traffic"`
			}
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			mu.Lock()
			for id, delta := range report.Traffic {
				current := totals[id]
				current[0] += delta[0]
				current[1] += delta[1]
				totals[id] = current
			}
			mu.Unlock()
			io.WriteString(w, `{}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	defer panel.Close()
	port := freePort(t)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	dir := t.TempDir()
	config := fmt.Sprintf(`[node]
listen = %q
mode = "default"
[panel]
url = %q
token = "test-token"
node_id = 1
api_version = 2
pull_interval = 60
push_interval = 1
[admin]
disabled = true
[storage]
path = %q
`, address, panel.URL, filepath.Join(dir, "node.db"))
	path := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(config), 0600))
	output, err := os.Create(filepath.Join(dir, "node.log"))
	require.NoError(t, err)
	command := exec.Command(binary, "-c", path)
	command.Stdout, command.Stderr = output, output
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		command.Process.Kill()
		command.Wait()
		output.Close()
		if t.Failed() {
			log, _ := os.ReadFile(output.Name())
			t.Logf("node: %s", log)
		}
	})
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond)
	echo := startTCPEcho(t)
	udpEcho := startUDPEcho(t)
	expected := make(map[string][2]int64)
	for i, psk := range psks {
		options := snellv6.ClientOptions{PSK: []byte(psk), Mode: snellv6.ModeDefault}
		// Alice sends a forged Bob client_id; her PSK still owns the traffic.
		if i == 0 {
			options.UserKey = []byte(psks[1])
		}
		client, err := snellv6.NewClient(options)
		require.NoError(t, err)
		payload := bytes.Repeat([]byte{byte(i + 1)}, 8192*(i+1))
		// Retry only the readiness probe; count payload only after full sync.
		require.Eventually(t, func() bool {
			transport, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				return false
			}
			defer transport.Close()
			conn, err := client.DialConn(transport, M.ParseSocksaddrHostPort("127.0.0.1", echo))
			if err != nil {
				return false
			}
			conn.SetDeadline(time.Now().Add(time.Second))
			if _, err = conn.Write([]byte{0}); err != nil {
				return false
			}
			probe := make([]byte, 1)
			_, err = io.ReadFull(conn, probe)
			return err == nil && probe[0] == 0
		}, 5*time.Second, 20*time.Millisecond)
		transport, err := net.Dial("tcp", address)
		require.NoError(t, err)
		conn, err := client.DialConn(transport, M.ParseSocksaddrHostPort("127.0.0.1", echo))
		require.NoError(t, err)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write(payload)
		require.NoError(t, err)
		reply := make([]byte, len(payload))
		_, err = io.ReadFull(conn, reply)
		require.NoError(t, err)
		require.Equal(t, payload, reply)
		conn.Close()
		udpTransport, err := net.Dial("tcp", address)
		require.NoError(t, err)
		packetConn, err := client.DialPacketConn(udpTransport)
		require.NoError(t, err)
		udpTransport.SetDeadline(time.Now().Add(5 * time.Second))
		udpPayload := bytes.Repeat([]byte{byte(i + 8)}, 4096)
		udpTarget := M.ParseSocksaddrHostPort("127.0.0.1", udpEcho).UDPAddr()
		_, err = packetConn.WriteTo(udpPayload, udpTarget)
		require.NoError(t, err)
		datagram := make([]byte, 8192)
		n, remote, err := packetConn.ReadFrom(datagram)
		require.NoError(t, err)
		require.Equal(t, udpTarget.String(), remote.String())
		require.Equal(t, udpPayload, datagram[:n])
		packetConn.Close()
		total := int64(len(payload) + 1 + len(udpPayload))
		expected[fmt.Sprint(i+1)] = [2]int64{total, total}
	}
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return totals["1"] == expected["1"] && totals["2"] == expected["2"]
	}, 5*time.Second, 20*time.Millisecond, "traffic must be billed to the PSK owner")
}
