package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WebSocket frame relay (RFC 6455) after HTTP Upgrade.
// Server frames are sent unmasked; client frames must be masked.

const wsMaxFrame = 1 << 20

type wsRelayStats struct {
	AtUnix      int64 `json:"at_unix"`
	DurMs       int64 `json:"dur_ms"`
	FramesIn    int   `json:"frames_in"`
	FramesOut   int   `json:"frames_out"`
	BytesIn     int64 `json:"bytes_in"`
	BytesOut    int64 `json:"bytes_out"`
	CloseSeen   bool  `json:"close_seen"`
	ReadErr     string `json:"read_err,omitempty"`
}

func wsRelaySeconds() time.Duration {
	s := strings.TrimSpace(os.Getenv("H2EDGE_WS_RELAY_SECONDS"))
	if s == "" {
		return 12 * time.Second
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 12 * time.Second
	}
	if n > 120 {
		n = 120
	}
	return time.Duration(n) * time.Second
}

func readWSFrame(r io.Reader) (opcode byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	opcode = h[0] & 0x0f
	masked := (h[1] & 0x80) != 0
	l7 := uint64(h[1] & 0x7f)
	var length uint64
	switch l7 {
	case 126:
		var x [2]byte
		if _, err = io.ReadFull(r, x[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(x[:]))
	case 127:
		var x [8]byte
		if _, err = io.ReadFull(r, x[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(x[:])
		if length > wsMaxFrame {
			return 0, nil, errors.New("ws frame too large")
		}
	default:
		length = l7
	}
	if length > wsMaxFrame {
		return 0, nil, errors.New("ws frame too large")
	}
	if !masked {
		return 0, nil, errors.New("ws client frame must be masked")
	}
	var mk [4]byte
	if _, err = io.ReadFull(r, mk[:]); err != nil {
		return 0, nil, err
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mk[i%4]
	}
	return opcode, payload, nil
}

func writeWSFrame(w io.Writer, opcode byte, payload []byte) error {
	n := len(payload)
	if n > wsMaxFrame {
		return errors.New("ws payload too large")
	}
	fin := byte(0x80)
	b0 := fin | (opcode & 0x0f)
	var hdr []byte
	if n < 126 {
		hdr = []byte{b0, byte(n)}
	} else if n < 65536 {
		hdr = make([]byte, 4)
		hdr[0] = b0
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(n))
	} else {
		hdr = make([]byte, 10)
		hdr[0] = b0
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// relayWebSocket reads/writes WebSocket frames until max duration or close.
// in must include any bytes buffered after the HTTP request (e.g. bufio).
func relayWebSocket(in io.Reader, out net.Conn, max time.Duration) wsRelayStats {
	deadline := time.Now().Add(max)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	st := wsRelayStats{AtUnix: time.Now().Unix()}

	var wmu sync.Mutex
	safeWrite := func(op byte, p []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = out.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := writeWSFrame(out, op, p); err == nil {
			st.FramesOut++
			st.BytesOut += int64(len(p))
		}
	}

	tick := time.NewTicker(800 * time.Millisecond)
	defer tick.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				msg := []byte(`{"t":` + strconv.FormatInt(time.Now().UnixMilli(), 10) + `,"from":"fp-h2edge"}`)
				safeWrite(0x1, msg)
			}
		}
	}()

	for time.Now().Before(deadline) {
		_ = out.SetReadDeadline(time.Now().Add(2 * time.Second))
		op, payload, err := readWSFrame(in)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			st.ReadErr = err.Error()
			break
		}
		st.FramesIn++
		st.BytesIn += int64(len(payload))
		switch op {
		case 0x8:
			st.CloseSeen = true
			safeWrite(0x8, []byte{0x03, 0xe8})
			st.DurMs = time.Since(time.Unix(st.AtUnix, 0)).Milliseconds()
			return st
		case 0x9:
			safeWrite(0xA, payload)
		case 0xA:
			// ignore pong
		case 0x1, 0x2:
			safeWrite(op, payload)
		}
	}
	cancel()
	safeWrite(0x8, []byte{0x03, 0xe8})
	st.DurMs = time.Since(time.Unix(st.AtUnix, 0)).Milliseconds()
	return st
}
