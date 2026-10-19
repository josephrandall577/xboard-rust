package suite

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestV4ObfsTLSAgainstServer(t *testing.T) {
	config := func(port uint16) string {
		return fmt.Sprintf("[snell-server]\nlisten = 0.0.0.0:%d\npsk = %s\nobfs = tls\nipv6 = false\n", port, testPSK)
	}
	t.Run("tcp", func(t *testing.T) {
		port := freePort(t)
		startSnellServer(t, "v5", config(port), port)
		echoPort := startTCPEcho(t)
		client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(testPSK), ObfsMode: snell.ObfsModeTLS, ObfsHost: "obfs.example"})
		require.NoError(t, err)
		serverConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		require.NoError(t, err)
		defer serverConn.Close()
		proxyConn, err := client.DialConn(serverConn, M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
		require.NoError(t, err)
		payload := make([]byte, 256*1024)
		rand.Read(payload)
		go proxyConn.Write(payload)
		received := make([]byte, len(payload))
		proxyConn.SetReadDeadline(time.Now().Add(20 * time.Second))
		_, err = io.ReadFull(proxyConn, received)
		require.NoError(t, err)
		require.True(t, bytes.Equal(payload, received))
		normalScenario{address: fmt.Sprintf("127.0.0.1:%d", port), client: client}.HalfCloseEcho(t, "v4-tls-server")
	})
	t.Run("reuse", func(t *testing.T) {
		port := freePort(t)
		startSnellServer(t, "v5", config(port), port)
		var proxy countingTCPProxy
		proxy.Start(t, fmt.Sprintf("127.0.0.1:%d", port))
		echoPort := startTCPHalfCloseEcho(t)
		delayedEchoPort := startTCPHalfCloseEcho(t, 750*time.Millisecond)
		client, err := snellv4.NewClient(snellv4.ClientOptions{
			PSK: []byte(testPSK), Reuse: true, ObfsMode: snell.ObfsModeTLS, ObfsHost: "obfs.example",
			Dialer: N.SystemDialer, Server: M.ParseSocksaddr(proxy.address),
		})
		require.NoError(t, err)
		defer client.Close()
		scenario := reuseScenario{client: client, destination: M.ParseSocksaddrHostPort("127.0.0.1", echoPort)}
		scenario.RoundTrip(t, "v4-tls-reuse-1")
		scenario.RoundTrip(t, "v4-tls-reuse-2")
		reuseScenario{client: client, destination: M.ParseSocksaddrHostPort("127.0.0.1", delayedEchoPort)}.CloseBeforeServerEOF(t, "v4-tls-drain", time.Second)
		scenario.RoundTrip(t, "v4-tls-reuse-after-drain")
		require.Equal(t, int32(1), proxy.count.Load())
	})
	t.Run("udp", func(t *testing.T) {
		port := freePort(t)
		startSnellServer(t, "v5", config(port), port)
		echoPort := startUDPEcho(t)
		client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(testPSK), ObfsMode: snell.ObfsModeTLS, ObfsHost: "obfs.example"})
		require.NoError(t, err)
		serverConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		require.NoError(t, err)
		defer serverConn.Close()
		packetConn, err := client.DialPacketConn(serverConn)
		require.NoError(t, err)
		target := M.ParseSocksaddrHostPort("127.0.0.1", echoPort).UDPAddr()
		for round := range 5 {
			message := make([]byte, 1200)
			rand.Read(message)
			_, err = packetConn.WriteTo(message, target)
			require.NoError(t, err)
			received := make([]byte, 2048)
			serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, _, readErr := packetConn.ReadFrom(received)
			require.NoError(t, readErr)
			require.True(t, bytes.Equal(message, received[:n]), "round %d", round)
		}
	})
}
