package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	raw := flag.String("url", "", "wss://host:port/ws")
	sni := flag.String("sni", "", "SNI server name (optional)")
	n := flag.Int("n", 5, "messages to send")
	flag.Parse()

	if strings.TrimSpace(*raw) == "" {
		fmt.Fprintln(os.Stderr, "missing -url")
		os.Exit(2)
	}
	u, err := url.Parse(*raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad url:", err)
		os.Exit(2)
	}
	if u.Scheme != "wss" {
		fmt.Fprintln(os.Stderr, "only wss supported")
		os.Exit(2)
	}
	hostport := u.Host
	if !strings.Contains(hostport, ":") {
		hostport += ":443"
	}
	host := u.Hostname()
	if *sni == "" {
		*sni = host
	}

	c, err := tls.Dial("tcp", hostport, &tls.Config{
		ServerName:         *sni,
		InsecureSkipVerify: true, // probe tool; do not use in real clients
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer c.Close()

	key := make([]byte, 16)
	_, _ = rand.Read(key)
	secKey := base64.StdEncoding.EncodeToString(key)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nOrigin: https://%s\r\nUser-Agent: wsprobe/1\r\n\r\n",
		u.RequestURI(), u.Host, secKey, host)
	if _, err := io.WriteString(c, req); err != nil {
		fmt.Fprintln(os.Stderr, "write req:", err)
		os.Exit(1)
	}

	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "read status:", err)
		os.Exit(1)
	}
	if !strings.Contains(status, "101") {
		fmt.Fprintln(os.Stderr, "unexpected status:", strings.TrimSpace(status))
		os.Exit(1)
	}
	// drain headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			fmt.Fprintln(os.Stderr, "read headers:", err)
			os.Exit(1)
		}
		if line == "\r\n" {
			break
		}
	}

	// Send a few masked text frames.
	for i := 0; i < *n; i++ {
		payload := []byte(fmt.Sprintf("pcap-probe-%d-%d", i+1, time.Now().UnixMilli()))
		if err := writeClientTextFrame(c, payload); err != nil {
			fmt.Fprintln(os.Stderr, "write frame:", err)
			os.Exit(1)
		}
		time.Sleep(250 * time.Millisecond)
	}

	// Close
	_ = writeClientClose(c)
	time.Sleep(200 * time.Millisecond)

	fmt.Println("ok")
}

func writeClientTextFrame(w io.Writer, payload []byte) error {
	return writeClientFrame(w, 0x1, payload)
}

func writeClientClose(w io.Writer) error {
	// code 1000
	return writeClientFrame(w, 0x8, []byte{0x03, 0xE8})
}

func writeClientFrame(w io.Writer, opcode byte, payload []byte) error {
	if len(payload) > 1<<20 {
		return fmt.Errorf("payload too large")
	}
	var hdr []byte
	b0 := byte(0x80) | (opcode & 0x0f)
	maskBit := byte(0x80)
	n := len(payload)
	if n < 126 {
		hdr = []byte{b0, maskBit | byte(n)}
	} else if n < 65536 {
		hdr = make([]byte, 4)
		hdr[0] = b0
		hdr[1] = maskBit | 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(n))
	} else {
		hdr = make([]byte, 10)
		hdr[0] = b0
		hdr[1] = maskBit | 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	var mk [4]byte
	_, _ = rand.Read(mk[:])
	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mk[i%4]
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if _, err := w.Write(mk[:]); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}

func wsAccept(secKey string) string {
	const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	sum := sha1.Sum([]byte(secKey + guid))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Ensure unused helper isn't optimized away in tiny builds (keeps parity with server)
var _ = wsAccept
