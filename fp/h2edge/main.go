package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/tlsx"
	"golang.org/x/net/http2"
)

// This server terminates TLS+HTTP/2 and captures HTTP/2 frame-level signals (preface, SETTINGS, WINDOW_UPDATE, PRIORITY)
// before handing the connection to http2.Server.ServeConn by replaying the bytes it already consumed.

type H2FP struct {
	AtUnix       int64             `json:"at_unix"`
	RemoteAddr   string            `json:"remote_addr"`
	Settings     map[uint16]uint32 `json:"settings"`
	SettingsList []string          `json:"settings_list"`
	WindowIncr   []uint32          `json:"window_incr,omitempty"`
	Priority     int               `json:"priority_frames"`
	FramesSeen   map[string]int    `json:"frames_seen"`
	Fingerprint  string            `json:"fingerprint"`
}

type TLSFP struct {
	JA3 string `json:"ja3,omitempty"`
	JA4 string `json:"ja4,omitempty"`
	CH  any    `json:"client_hello,omitempty"`
	// Raw TLS records (base64). ClientHello is the first inbound handshake record.
	ClientHelloRecordB64 string `json:"client_hello_record_b64,omitempty"`
	// ServerHelloRecordB64 is best-effort: first outbound handshake record(s) from server.
	ServerHandshakeRecordB64 string `json:"server_handshake_record_b64,omitempty"`
	ServerHello             any    `json:"server_hello,omitempty"`
}

type Store struct {
	mu     sync.RWMutex
	byH2   map[string]H2FP
	byWS   map[string]WSInfo // ip -> ws handshake info
	ttl    time.Duration
}

type WSInfo struct {
	AtUnix     int64    `json:"at_unix"`
	IP         string   `json:"ip"`
	Fingerprint string  `json:"fingerprint"`
	Origin     string   `json:"origin,omitempty"`
	UserAgent  string   `json:"user_agent,omitempty"`
	Version    string   `json:"version,omitempty"`
	Extensions []string `json:"extensions,omitempty"`
	Protocols  []string `json:"protocols,omitempty"`
}

type h2edgeLoggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *h2edgeLoggingResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *h2edgeLoggingResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func h2edgeAccessLogEnabled() bool {
	v := strings.TrimSpace(os.Getenv("H2EDGE_ACCESS_LOG"))
	switch strings.ToLower(v) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func h2edgeWSLogEnabled() bool {
	v := strings.TrimSpace(os.Getenv("H2EDGE_WS_ACCESS_LOG"))
	switch strings.ToLower(v) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func NewStore(ttl time.Duration) *Store {
	return &Store{byH2: make(map[string]H2FP), byWS: make(map[string]WSInfo), ttl: ttl}
}

func (s *Store) Set(remote string, fp H2FP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byH2[remote] = fp
}

func (s *Store) Get(remote string) (H2FP, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.byH2[remote]
	return v, ok
}

func (s *Store) SetWS(ip string, info WSInfo) {
	ip = strings.TrimSpace(ip)
	if ip == "" || strings.TrimSpace(info.Fingerprint) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info.IP = ip
	if info.AtUnix == 0 {
		info.AtUnix = time.Now().Unix()
	}
	s.byWS[ip] = info
}

func (s *Store) GetWS(ip string) (WSInfo, bool) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return WSInfo{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.byWS[ip]
	return v, ok
}

func main() {
	listen := env("H2EDGE_LISTEN", "0.0.0.0:10443")
	httpListen := env("H2EDGE_HTTP_LISTEN", "")
	certFile := env("H2EDGE_CERT", "")
	keyFile := env("H2EDGE_KEY", "")
	upstream := env("H2EDGE_UPSTREAM", "http://127.0.0.1:9000")

	if strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" {
		log.Fatalf("missing TLS cert/key: set H2EDGE_CERT and H2EDGE_KEY (e.g. /etc/letsencrypt/live/<domain>/fullchain.pem and /etc/letsencrypt/live/<domain>/privkey.pem)")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("load cert/key: %v", err)
	}

	store := NewStore(10 * time.Minute)
	rp := newReverseProxy(upstream)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("h2edge listening on %s", listen)

	// Optional HTTP :80 redirect / ACME webroot handler
	if httpListen != "" {
		go func() {
			log.Printf("h2edge http listening on %s", httpListen)
			_ = http.ListenAndServe(httpListen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Minimal: redirect to https preserving host/path
				target := "https://" + strings.TrimSuffix(r.Host, ":80") + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}))
		}()
	}

	wsListen := strings.TrimSpace(env("H2EDGE_WS_LISTEN", ""))
	if wsListen != "" {
		tlsCfgWS := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
			MinVersion:   tls.VersionTLS12,
		}
		lnWS, err := net.Listen("tcp", wsListen)
		if err != nil {
			log.Fatalf("ws listen: %v", err)
		}
		log.Printf("h2edge ws (HTTP/1.1 only) listening on %s", wsListen)
		go func() {
			for {
				c, err := lnWS.Accept()
				if err != nil {
					log.Printf("ws accept error: %v", err)
					continue
				}
				go handleConnWSOnly(c, tlsCfgWS, store)
			}
		}()
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(c, tlsCfg, store, rp)
	}
}

func handleConnWSOnly(raw net.Conn, tlsCfg *tls.Config, store *Store) {
	defer raw.Close()
	tc := tls.Server(raw, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	handleHTTP1(tc, store)
}

func handleConn(raw net.Conn, tlsCfg *tls.Config, store *Store, rp *httputil.ReverseProxy) {
	defer raw.Close()

	// Capture ClientHello (plaintext TLS record) before handshake for JA3/JA4 + parsed fields.
	chRaw := captureFirstTLSRecord(raw, 64*1024)
	tlsfp := TLSFP{}
	if len(chRaw) > 0 {
		tlsfp.JA4 = computeJA4(chRaw, 't')
		tlsfp.JA3 = computeJA3(chRaw)
		tlsfp.CH = parseClientHello(chRaw)
		tlsfp.ClientHelloRecordB64 = b64Trunc(chRaw, 48*1024)
	}

	// Capture outbound handshake records written by the TLS server during Handshake().
	rec := newWriteRecorder(raw, 96*1024)
	tc := tls.Server(&replayConn{Conn: rec, r: io.MultiReader(bytes.NewReader(chRaw), rec)}, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	tlsfp.ServerHandshakeRecordB64 = b64Trunc(rec.Bytes(), 96*1024)
	tlsfp.ServerHello = parseServerHello(rec.Bytes())
	_ = tc.SetDeadline(time.Time{})

	st := tc.ConnectionState()
	if st.NegotiatedProtocol != "h2" {
		// Support HTTP/1.1 only for WebSocket handshake fingerprinting on /ws.
		handleHTTP1(tc, store)
		return
	}

	remote := raw.RemoteAddr().String()

	// Capture some initial frames, buffering bytes so we can replay them.
	buf := &bytes.Buffer{}
	fp := captureH2(tc, buf, remote)
	store.Set(remote, fp)

	// Replay bytes back into a net.Conn wrapper for http2.Server.
	rc := &replayConn{
		Conn: tc,
		r:    io.MultiReader(bytes.NewReader(buf.Bytes()), tc),
	}

	// Serve HTTP/2 on the replay connection.
	srv := &http2.Server{}
	srv.ServeConn(rc, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			lw := &h2edgeLoggingResponseWriter{ResponseWriter: w}
			switch r.URL.Path {
			case "/api/h2":
				// Retrieve latest capture for this remote if present
				if latest, ok := store.Get(remote); ok {
					fp = latest
				}
				writeJSON(lw, map[string]any{"h2": fp, "tls": tlsfp, "tls_state": summarizeTLS(st)})
				return
			case "/ws":
				// Best-effort: some clients may attempt WebSocket handshake over an h2 connection
				// (e.g. extended CONNECT) or otherwise hit this path. We don't proxy WS frames here,
				// but we can still fingerprint the handshake headers.
				ip := remoteIPOnly(r.RemoteAddr)
				wsi := computeWSInfo(r, ip)
				if ip != "" && wsi.Fingerprint != "" {
					store.SetWS(ip, wsi)
				}
				lw.Header().Set("X-WS-FP", wsi.Fingerprint)
				writeJSON(lw, map[string]any{"ok": true, "ws": wsi, "note": "websocket not proxied; fingerprint captured"})
				return
			case "/health":
				writeJSON(lw, map[string]any{"ok": true})
				return
			case "/__close":
				// Force-close this HTTP/2 connection (best-effort) so the next browser request
				// establishes a fresh TCP/TLS session (useful for capturing handshake in pcap).
				//
				// Firefox may follow 302 redirects on the same H2 connection; if we close that
				// connection quickly, the redirected navigation can get stuck. Instead, when
				// `next` is provided, return a tiny HTML page that performs client-side redirect.
				next := strings.TrimSpace(r.URL.Query().Get("next"))
				if next != "" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Header().Set("Cache-Control", "no-store")
					_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>Reconnecting…</title>
    <meta http-equiv="refresh" content="0;url=` + htmlEscape(next) + `"/>
    <style>
      :root { color-scheme: light dark; }
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 0; padding: 24px; }
      .hint { opacity: .8; font-size: 13px; margin-top: 8px; }
      code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }
    </style>
  </head>
  <body>
    <div style="font-weight:800; font-size:16px;">Reconnecting…</div>
    <div class="hint">Opening a fresh TLS connection for capture.</div>
    <script>location.replace(` + jsonString(next) + `);</script>
  </body>
</html>`))
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
				} else {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					_, _ = w.Write([]byte("{\"ok\":true}\n"))
				}
				go func() {
					// Give browsers time to execute redirect JS before we kill the conn.
					time.Sleep(800 * time.Millisecond)
					_ = rc.Close()
				}()
				return
			default:
				// Reverse proxy to upstream, injecting fingerprint headers.
				if ip := remoteIPOnly(r.RemoteAddr); ip != "" {
					if wsi, ok := store.GetWS(ip); ok {
						r.Header.Set("X-WS-FP", wsi.Fingerprint)
						if wsi.Origin != "" {
							r.Header.Set("X-WS-Origin", wsi.Origin)
						}
						if wsi.UserAgent != "" {
							r.Header.Set("X-WS-UA", wsi.UserAgent)
						}
						if wsi.Version != "" {
							r.Header.Set("X-WS-Version", wsi.Version)
						}
						if b, _ := json.Marshal(wsi.Extensions); len(b) > 0 {
							r.Header.Set("X-WS-Extensions", string(b))
						}
						if b, _ := json.Marshal(wsi.Protocols); len(b) > 0 {
							r.Header.Set("X-WS-Protocols", string(b))
						}
					}
				}
				injectHeaders(r, st, fp, tlsfp)
				rp.ServeHTTP(lw, r)
			}
			if h2edgeAccessLogEnabled() {
				ip := remoteIPOnly(r.RemoteAddr)
				log.Printf("h2 %s %s ip=%s status=%d bytes=%d dur_ms=%d ua=%q",
					r.Method, r.URL.RequestURI(), ip, lw.status, lw.bytes, time.Since(start).Milliseconds(), r.UserAgent())
			}
		}),
	})
}

func handleHTTP1(c net.Conn, store *Store) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	req.RemoteAddr = c.RemoteAddr().String()

	switch req.URL.Path {
	case "/ws":
		handleWSRequest(c, br, req, store)
		return
	case "/health":
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 26\r\n\r\n{\"ok\":true,\"proto\":\"h1\"}\n")
		return
	default:
		_, _ = io.WriteString(c, "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
}

func handleWSRequest(c net.Conn, br *bufio.Reader, r *http.Request, store *Store) {
	ip := remoteIPOnly(r.RemoteAddr)
	wsi := computeWSInfo(r, ip)
	if ip != "" && wsi.Fingerprint != "" {
		store.SetWS(ip, wsi)
	}

	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		// Debug JSON response
		b, _ := json.MarshalIndent(map[string]any{"ws": wsi, "headers": r.Header}, "", "  ")
		body := append(b, '\n')
		_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %d\r\n\r\n", len(body))
		_, _ = c.Write(body)
		return
	}

	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	accept := wsAccept(key)

	_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n")
	_, _ = io.WriteString(c, "Upgrade: websocket\r\n")
	_, _ = io.WriteString(c, "Connection: Upgrade\r\n")
	_, _ = io.WriteString(c, "Sec-WebSocket-Accept: "+accept+"\r\n")
	_, _ = io.WriteString(c, "X-WS-FP: "+wsi.Fingerprint+"\r\n")
	_, _ = io.WriteString(c, "\r\n")

	in := io.MultiReader(br, c)
	start := time.Now()
	stats := relayWebSocket(in, c, wsRelaySeconds())
	if h2edgeWSLogEnabled() {
		log.Printf("ws ip=%s ua=%q origin=%q fp=%s dur_ms=%d frames_in=%d bytes_in=%d frames_out=%d bytes_out=%d close=%t err=%q",
			ip, r.UserAgent(), wsi.Origin, wsi.Fingerprint,
			time.Since(start).Milliseconds(),
			stats.FramesIn, stats.BytesIn, stats.FramesOut, stats.BytesOut, stats.CloseSeen, stats.ReadErr)
	}
	_ = c.Close()
}

func wsAccept(secKey string) string {
	// RFC6455: base64( SHA1( key + GUID ) )
	const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	sum := sha1.Sum([]byte(secKey + guid))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func computeWSInfo(r *http.Request, ip string) WSInfo {
	// Stable fingerprint of WS handshake headers (order-insensitive).
	// Important: do NOT include Sec-WebSocket-Key in fingerprint (it is random).
	get := func(k string) string { return strings.TrimSpace(r.Header.Get(k)) }
	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)

	exts := splitCSV(get("Sec-WebSocket-Extensions"))
	protos := splitCSV(get("Sec-WebSocket-Protocol"))

	payload := map[string]any{
		"method": r.Method,
		"path":   r.URL.Path,
		"proto":  r.Proto,
		"host":   r.Host,
		"ua":     get("User-Agent"),
		"origin": get("Origin"),
		"upgrade": strings.ToLower(get("Upgrade")),
		"conn":    strings.ToLower(get("Connection")),
		"ws_ver":  get("Sec-WebSocket-Version"),
		"ws_ext":  exts,
		"ws_proto": protos,
		"header_names": names,
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return WSInfo{
		AtUnix:      time.Now().Unix(),
		IP:          ip,
		Fingerprint: hex.EncodeToString(sum[:16]),
		Origin:      get("Origin"),
		UserAgent:   get("User-Agent"),
		Version:     get("Sec-WebSocket-Version"),
		Extensions:  exts,
		Protocols:   protos,
	}
}

func remoteIPOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err == nil {
		return h
	}
	// If it's already just an IP
	return strings.TrimSpace(addr)
}

func splitCSV(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type writeRecorder struct {
	net.Conn
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func newWriteRecorder(c net.Conn, limit int) *writeRecorder {
	return &writeRecorder{Conn: c, limit: limit}
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.limit > 0 && w.buf.Len() < w.limit {
		remain := w.limit - w.buf.Len()
		if remain > len(p) {
			remain = len(p)
		}
		_, _ = w.buf.Write(p[:remain])
	}
	return w.Conn.Write(p)
}

func (w *writeRecorder) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]byte, w.buf.Len())
	copy(out, w.buf.Bytes())
	return out
}

func captureH2(c net.Conn, buf *bytes.Buffer, remote string) H2FP {
	fp := H2FP{
		AtUnix:     time.Now().Unix(),
		RemoteAddr: remote,
		Settings:   map[uint16]uint32{},
		FramesSeen: map[string]int{},
	}

	// Read client preface
	pref := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, pref); err != nil {
		return fp
	}
	buf.Write(pref)
	fp.FramesSeen["PREFACE"]++

	fr := http2.NewFramer(io.MultiWriter(buf, io.Discard), io.TeeReader(c, buf))
	// http2.Framer doesn't support deadlines; use conn deadline instead.
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))

	// Read a handful of initial frames (best-effort).
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		name := frameName(f)
		fp.FramesSeen[name]++

		switch t := f.(type) {
		case *http2.SettingsFrame:
			t.ForeachSetting(func(s http2.Setting) error {
				fp.Settings[uint16(s.ID)] = s.Val
				fp.SettingsList = append(fp.SettingsList, fmt.Sprintf("%d=%d", s.ID, s.Val))
				return nil
			})
		case *http2.WindowUpdateFrame:
			fp.WindowIncr = append(fp.WindowIncr, t.Increment)
		case *http2.PriorityFrame:
			fp.Priority++
		}

		// Stop early once we saw SETTINGS + first HEADERS (after that it's mostly request-specific).
		if fp.FramesSeen["SETTINGS"] > 0 && fp.FramesSeen["HEADERS"] > 0 {
			break
		}
	}

	sort.Strings(fp.SettingsList)
	fp.Fingerprint = h2hash(fp)
	_ = c.SetReadDeadline(time.Time{})
	return fp
}

func b64Trunc(b []byte, max int) string {
	if len(b) == 0 {
		return ""
	}
	if max > 0 && len(b) > max {
		b = b[:max]
	}
	return base64.StdEncoding.EncodeToString(b)
}

func newReverseProxy(upstream string) *httputil.ReverseProxy {
	u, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("bad upstream: %v", err)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	orig := rp.Director
	rp.Director = func(r *http.Request) {
		orig(r)
		// Preserve original Host for app logic / display.
		r.Header.Set("X-Forwarded-Host", r.Host)
	}
	return rp
}

func injectHeaders(r *http.Request, st tls.ConnectionState, h2fp H2FP, tlsfp TLSFP) {
	// Frame-level HTTP/2 fingerprint
	r.Header.Set("X-H2-FP", h2fp.Fingerprint)
	if b, _ := json.Marshal(h2fp.SettingsList); len(b) > 0 {
		r.Header.Set("X-H2-Settings", string(b))
	}
	if b, _ := json.Marshal(h2fp.WindowIncr); len(b) > 0 {
		r.Header.Set("X-H2-Window-Incr", string(b))
	}
	r.Header.Set("X-H2-Priority-Frames", fmt.Sprintf("%d", h2fp.Priority))

	// What the client negotiated on the outer connection (useful since upstream sees the proxy hop).
	if st.NegotiatedProtocol != "" {
		r.Header.Set("X-Client-ALPN", st.NegotiatedProtocol)
	}
	r.Header.Set("X-Client-Proto", r.Proto)

	// TLS agreed fields (similar to old Caddy headers)
	r.Header.Set("X-TLS-Version", tlsVersionName(st.Version))
	r.Header.Set("X-TLS-Cipher", tlsCipherName(st.CipherSuite))
	r.Header.Set("X-TLS-Proto", st.NegotiatedProtocol)
	r.Header.Set("X-TLS-Resumed", fmt.Sprintf("%t", st.DidResume))
	r.Header.Set("X-TLS-SNI", st.ServerName)

	// JA3/JA4 + ClientHello tables
	if tlsfp.JA4 != "" {
		r.Header.Set("X-JA4", tlsfp.JA4)
	}
	if tlsfp.JA3 != "" {
		r.Header.Set("JA3", tlsfp.JA3)
	}
	if tlsfp.ClientHelloRecordB64 != "" {
		r.Header.Set("X-TLS-ClientHello-Record-B64", tlsfp.ClientHelloRecordB64)
	}
	if tlsfp.ServerHandshakeRecordB64 != "" {
		r.Header.Set("X-TLS-ServerHandshake-Records-B64", tlsfp.ServerHandshakeRecordB64)
	}
	if tlsfp.ServerHello != nil {
		if b, _ := json.Marshal(tlsfp.ServerHello); len(b) > 0 {
			r.Header.Set("X-TLS-ServerHello-JSON", string(b))
		}
	}
	// HTTP-level fingerprint (approx)
	r.Header.Set("X-HTTP-FP", computeHTTPFP(r))
	if m, ok := tlsfp.CH.(map[string]any); ok {
		// Convert to the X-CH-* headers used by upstream
		if v, _ := json.Marshal(m["alpn"]); len(v) > 0 {
			r.Header.Set("X-CH-ALPN", string(v))
		}
		if v, _ := json.Marshal(m["supported_versions"]); len(v) > 0 {
			r.Header.Set("X-CH-Supported-Versions", string(v))
		}
		if v, _ := json.Marshal(m["cipher_suites"]); len(v) > 0 {
			r.Header.Set("X-CH-Cipher-Suites", string(v))
		}
		if v, _ := json.Marshal(m["extensions"]); len(v) > 0 {
			r.Header.Set("X-CH-Extensions", string(v))
		}
		if v, _ := json.Marshal(m["curves"]); len(v) > 0 {
			r.Header.Set("X-CH-Curves", string(v))
		}
		if v, _ := json.Marshal(m["points"]); len(v) > 0 {
			r.Header.Set("X-CH-Points", string(v))
		}
		if v, _ := json.Marshal(m["signature_schemes"]); len(v) > 0 {
			r.Header.Set("X-CH-Signature-Schemes", string(v))
		}
		if s, _ := m["server_name"].(string); s != "" {
			r.Header.Set("X-CH-Server-Name", s)
		}
		if hv, ok := m["handshake_version"]; ok {
			r.Header.Set("X-CH-Handshake-Version", fmt.Sprintf("%v", hv))
		}
	}
}

func computeHTTPFP(r *http.Request) string {
	// Similar to caddy-httpfp: stable hash from header names + select values
	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	get := func(k string) string { return strings.TrimSpace(r.Header.Get(k)) }
	payload := map[string]any{
		"proto":           r.Proto,
		"method":          r.Method,
		"ua":              get("User-Agent"),
		"accept":          get("Accept"),
		"accept_lang":     get("Accept-Language"),
		"accept_enc":      get("Accept-Encoding"),
		"sec_ch_ua":       get("Sec-CH-UA"),
		"sec_ch_ua_mob":   get("Sec-CH-UA-Mobile"),
		"sec_ch_ua_plat":  get("Sec-CH-UA-Platform"),
		"sec_fetch_site":  get("Sec-Fetch-Site"),
		"sec_fetch_mode":  get("Sec-Fetch-Mode"),
		"sec_fetch_dest":  get("Sec-Fetch-Dest"),
		"sec_fetch_user":  get("Sec-Fetch-User"),
		"upgrade_insecure": get("Upgrade-Insecure-Requests"),
		"pragma":          get("Pragma"),
		"cache_control":   get("Cache-Control"),
		"header_names":    names,
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

func summarizeTLS(st tls.ConnectionState) map[string]any {
	return map[string]any{
		"version":   tlsVersionName(st.Version),
		"cipher":    tlsCipherName(st.CipherSuite),
		"alpn":      st.NegotiatedProtocol,
		"resumed":   st.DidResume,
		"server":    st.ServerName,
		"peer_certs": len(st.PeerCertificates),
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "tls1.3"
	case tls.VersionTLS12:
		return "tls1.2"
	case tls.VersionTLS11:
		return "tls1.1"
	case tls.VersionTLS10:
		return "tls1.0"
	default:
		return fmt.Sprintf("%d", v)
	}
}

func tlsCipherName(id uint16) string {
	// Minimal mapping for the common ones; fallback to numeric.
	switch id {
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("%d", id)
	}
}

func captureFirstTLSRecord(c net.Conn, max int) []byte {
	_ = c.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	defer c.SetReadDeadline(time.Time{})
	h := make([]byte, 5)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil
	}
	if h[0] != 0x16 { // handshake record
		return nil
	}
	l := int(h[3])<<8 | int(h[4])
	if l <= 0 || l > max {
		return nil
	}
	b := make([]byte, 5+l)
	copy(b, h)
	if _, err := io.ReadFull(c, b[5:]); err != nil {
		return nil
	}
	return b
}

func parseClientHello(raw []byte) any {
	ch := &tlsx.ClientHello{}
	if err := ch.Unmarshal(raw); err != nil {
		return map[string]any{"_error": err.Error()}
	}
	return map[string]any{
		"server_name":        ch.SNI,
		"handshake_version":  uint16(ch.HandshakeVersion),
		"cipher_suites":      cipherSuitesToU16(ch.CipherSuites),
		"extensions":         ch.AllExtensions,
		"curves":             ch.SupportedGroups,
		"points":             ch.SupportedPoints,
		"signature_schemes":  ch.SignatureAlgs,
		"alpn":               ch.ALPNs,
		"supported_versions": parseSupportedVersions(raw),
	}
}

// parseServerHello tries to extract ServerHello from outbound TLS handshake records.
// It is best-effort and works reliably for TLS 1.2 and the plaintext part of TLS 1.3.
func parseServerHello(out []byte) any {
	// Find first handshake record (type 0x16) and then find handshake message type 0x02.
	i := 0
	for i+5 <= len(out) {
		if out[i] != 0x16 { // TLS handshake record
			i++
			continue
		}
		if i+5 > len(out) {
			break
		}
		recLen := int(out[i+3])<<8 | int(out[i+4])
		if recLen <= 0 || i+5+recLen > len(out) {
			break
		}
		rec := out[i : i+5+recLen]
		hs := rec[5:]
		if len(hs) < 4 {
			i += 5 + recLen
			continue
		}
		// handshake msg header: type(1) + len(3)
		ht := hs[0]
		hLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if ht == 0x02 && 4+hLen <= len(hs) {
			msg := hs[:4+hLen]
			return parseServerHelloMsg(msg)
		}
		i += 5 + recLen
	}
	return map[string]any{"_error": "server_hello_not_found"}
}

func parseServerHelloMsg(msg []byte) any {
	// msg includes handshake header (4 bytes) then body
	if len(msg) < 4+2+32+1+2+1 {
		return map[string]any{"_error": "server_hello_too_short"}
	}
	body := msg[4:]
	ver := uint16(body[0])<<8 | uint16(body[1])
	off := 2
	off += 32 // random
	sidLen := int(body[off])
	off++
	if off+sidLen+2+1 > len(body) {
		return map[string]any{"_error": "server_hello_bad_session_id"}
	}
	off += sidLen
	cipher := uint16(body[off])<<8 | uint16(body[off+1])
	off += 2
	compress := body[off]
	off++

	exts := []uint16(nil)
	if off+2 <= len(body) {
		extLen := int(body[off])<<8 | int(body[off+1])
		off += 2
		if off+extLen <= len(body) {
			extData := body[off : off+extLen]
			j := 0
			for j+4 <= len(extData) {
				typ := uint16(extData[j])<<8 | uint16(extData[j+1])
				l := int(extData[j+2])<<8 | int(extData[j+3])
				j += 4
				if j+l > len(extData) {
					break
				}
				exts = append(exts, typ)
				j += l
			}
		}
	}

	return map[string]any{
		"version":         fmt.Sprintf("0x%04x", ver),
		"cipher_suite":    fmt.Sprintf("0x%04x", cipher),
		"compression":     int(compress),
		"extensions":      exts,
		"cipher_suite_id": cipher,
	}
}

func cipherSuitesToU16(in []tlsx.CipherSuite) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		out = append(out, uint16(v))
	}
	return out
}

func computeJA3(raw []byte) string {
	parsed := &tlsx.ClientHelloBasic{}
	if err := parsed.Unmarshal(raw); err != nil {
		return ""
	}
	// Bare JA3 as used by caddy-ja3
	buf := &bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("%d,", parsed.HandshakeVersion))
	// Cipher suites
	first := true
	for _, cs := range parsed.CipherSuites {
		v := uint16(cs)
		if isGREASEValue(v) {
			continue
		}
		if !first {
			buf.WriteByte('-')
		}
		first = false
		buf.WriteString(fmt.Sprintf("%d", v))
	}
	buf.WriteByte(',')
	// Extensions (sorted not applied; keep original order) — but we have AllExtensions already
	first = true
	for _, e := range parsed.AllExtensions {
		if isGREASEValue(e) {
			continue
		}
		if !first {
			buf.WriteByte('-')
		}
		first = false
		buf.WriteString(fmt.Sprintf("%d", e))
	}
	buf.WriteByte(',')
	// Supported groups
	first = true
	for _, g := range parsed.SupportedGroups {
		if isGREASEValue(g) {
			continue
		}
		if !first {
			buf.WriteByte('-')
		}
		first = false
		buf.WriteString(fmt.Sprintf("%d", g))
	}
	buf.WriteByte(',')
	// Supported points
	first = true
	for _, p := range parsed.SupportedPoints {
		if !first {
			buf.WriteByte('-')
		}
		first = false
		buf.WriteString(fmt.Sprintf("%d", p))
	}
	sum := md5.Sum(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func computeJA4(raw []byte, proto byte) string {
	// Reuse logic from caddy-ja4 (simplified): compute using our local implementation below.
	out, _ := computeJA4Internal(raw, proto)
	return out
}

// ---- JA4 implementation (ported from caddy-ja4) ----

func isGREASEValue(value uint16) bool {
	if value == 0x0000 {
		return false
	}
	n1 := (value >> 12) & 0xF
	n2 := (value >> 8) & 0xF
	n3 := (value >> 4) & 0xF
	n4 := value & 0xF
	if n1 == n3 && n2 == 0xa && n4 == 0xa {
		return true
	}
	if n1 == n2 && n2 == n3 && n3 == n4 && value != 0x0000 {
		return true
	}
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
	for _, gv := range greaseValues {
		if value == gv {
			return true
		}
	}
	return false
}

func mapTLSVersionJA4(version uint16) string {
	switch version {
	case 0x0300:
		return "00"
	case 0x0301:
		return "01"
	case 0x0302:
		return "02"
	case 0x0303:
		return "13"
	case 0x0304:
		return "13"
	default:
		return "00"
	}
}

func buildHexList(values []uint16) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func computeTruncatedSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	hexHash := hex.EncodeToString(hash[:])
	return hexHash[:12]
}

func computeJA4Internal(payload []byte, protocol byte) (string, error) {
	offset := 0
	if len(payload) < 5 {
		return "", fmt.Errorf("payload too short for TLS record header")
	}
	offset += 5
	if offset+4 > len(payload) {
		return "", fmt.Errorf("payload too short for handshake header")
	}
	handshakeType := payload[offset]
	handshakeLength := int(payload[offset+1])<<16 | int(payload[offset+2])<<8 | int(payload[offset+3])
	offset += 4
	if handshakeType != 0x01 {
		return "", fmt.Errorf("not a Client Hello message")
	}
	if offset+handshakeLength > len(payload) {
		return "", fmt.Errorf("incomplete Client Hello message")
	}

	var ja4Str strings.Builder
	ja4Str.WriteByte(protocol)

	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for client version")
	}
	clientVersion := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2
	if offset+32 > len(payload) {
		return "", fmt.Errorf("payload too short for random")
	}
	offset += 32
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for session ID length")
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if offset+cipherSuitesLen > len(payload) {
		return "", fmt.Errorf("incomplete cipher suites data")
	}
	ciphers := make([]uint16, 0)
	for i := 0; i < cipherSuitesLen; i += 2 {
		cipher := binary.BigEndian.Uint16(payload[offset+i : offset+i+2])
		if !isGREASEValue(cipher) {
			ciphers = append(ciphers, cipher)
		}
	}
	offset += cipherSuitesLen
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for compression methods length")
	}
	compressionMethodsLen := int(payload[offset])
	offset += 1 + compressionMethodsLen
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	extensions := make([]uint16, 0)
	extensionCount := 0
	sniFound := false
	alpn := "00"
	signatureAlgorithms := make([]uint16, 0)
	supportedVersionsFound := false
	highestSupportedVersion := uint16(0)

	extensionsEnd := offset + extensionsLen
	for offset+4 <= extensionsEnd && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > extensionsEnd || offset+extLen > len(payload) {
			break
		}
		extDataEnd := offset + extLen
		if isGREASEValue(extType) {
			offset = extDataEnd
			continue
		}
		if extType == 0x0029 { // pre_shared_key
			offset = extDataEnd
			continue
		}
		extensionCount++
		if extType != 0x0000 && extType != 0x0010 {
			extensions = append(extensions, extType)
		}
		if extType == 0x0000 {
			sniFound = true
		}
		if extType == 0x0010 && extLen > 0 {
			alpnOffset := offset
			if alpnOffset+2 > extDataEnd {
				return "", fmt.Errorf("payload too short for ALPN list length")
			}
			alpnListLen := int(binary.BigEndian.Uint16(payload[alpnOffset : alpnOffset+2]))
			alpnOffset += 2
			if alpnOffset+alpnListLen > extDataEnd {
				return "", fmt.Errorf("incomplete ALPN list")
			}
			if alpnListLen > 0 {
				if alpnOffset+1 > extDataEnd {
					return "", fmt.Errorf("payload too short for ALPN string length")
				}
				alpnStrLen := int(payload[alpnOffset])
				alpnOffset++
				if alpnOffset+alpnStrLen > extDataEnd {
					return "", fmt.Errorf("incomplete ALPN string")
				}
				if alpnStrLen > 0 {
					alpnStr := string(payload[alpnOffset : alpnOffset+alpnStrLen])
					if len(alpnStr) >= 2 {
						alpn = alpnStr[:2]
					} else if len(alpnStr) == 1 {
						alpn = alpnStr + "0"
					}
				}
			}
		}
		if extType == 0x000d {
			sigOffset := offset
			if sigOffset+2 > extDataEnd {
				return "", fmt.Errorf("payload too short for signature algorithms length")
			}
			sigAlgsLen := int(binary.BigEndian.Uint16(payload[sigOffset : sigOffset+2]))
			sigOffset += 2
			if sigOffset+sigAlgsLen > extDataEnd {
				return "", fmt.Errorf("incomplete signature algorithms data")
			}
			for j := 0; j < sigAlgsLen; j += 2 {
				sigAlgo := binary.BigEndian.Uint16(payload[sigOffset+j : sigOffset+j+2])
				if !isGREASEValue(sigAlgo) {
					signatureAlgorithms = append(signatureAlgorithms, sigAlgo)
				}
			}
		}
		if extType == 0x002b {
			supportedVersionsFound = true
			svOffset := offset
			if svOffset+1 > extDataEnd {
				return "", fmt.Errorf("payload too short for supported versions length")
			}
			svLen := int(payload[svOffset])
			svOffset++
			if svOffset+svLen > extDataEnd {
				return "", fmt.Errorf("incomplete supported versions data")
			}
			for j := 0; j < svLen; j += 2 {
				if svOffset+j+2 > extDataEnd {
					break
				}
				version := binary.BigEndian.Uint16(payload[svOffset+j : svOffset+j+2])
				if !isGREASEValue(version) && version > highestSupportedVersion {
					highestSupportedVersion = version
				}
			}
		}
		offset = extDataEnd
	}

	tlsVersion := ""
	if supportedVersionsFound {
		tlsVersion = mapTLSVersionJA4(highestSupportedVersion)
	} else {
		tlsVersion = mapTLSVersionJA4(clientVersion)
	}

	sniIndicator := 'i'
	if sniFound {
		sniIndicator = 'd'
	}

	cipherCountDisplay := len(ciphers)
	if cipherCountDisplay > 99 {
		cipherCountDisplay = 99
	}
	extensionCountDisplay := extensionCount
	if extensionCountDisplay > 99 {
		extensionCountDisplay = 99
	}

	alpnFirstChar := '0'
	alpnLastChar := '0'
	if len(alpn) >= 2 {
		alpnFirstChar = rune(alpn[0])
		alpnLastChar = rune(alpn[1])
	} else if len(alpn) == 1 {
		alpnFirstChar = rune(alpn[0])
		alpnLastChar = '0'
	}

	ja4Str.WriteString(tlsVersion)
	ja4Str.WriteByte(byte(sniIndicator))
	ja4Str.WriteString(fmt.Sprintf("%02d%02d%c%c_", cipherCountDisplay, extensionCountDisplay, alpnFirstChar, alpnLastChar))

	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	ja4b := "000000000000"
	if len(ciphers) > 0 {
		ja4b = computeTruncatedSHA256(buildHexList(ciphers))
	}
	ja4Str.WriteString(ja4b)
	ja4Str.WriteByte('_')

	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })
	extStr := buildHexList(extensions)
	if len(signatureAlgorithms) > 0 {
		extStr += "_" + buildHexList(signatureAlgorithms)
	}
	ja4c := "000000000000"
	if len(extensions) > 0 {
		ja4c = computeTruncatedSHA256(extStr)
	}
	ja4Str.WriteString(ja4c)

	return ja4Str.String(), nil
}

// parseSupportedVersions extracts the supported_versions extension (43) if present.
func parseSupportedVersions(raw []byte) []uint16 {
	if len(raw) < 5+4+2+32+1 {
		return nil
	}
	hs := raw[5:]
	if len(hs) < 6 {
		return nil
	}
	i := 4 + 2 + 32
	if len(hs) < i+1 {
		return nil
	}
	sidLen := int(hs[i])
	i += 1 + sidLen
	if len(hs) < i+2 {
		return nil
	}
	csLen := int(binary.BigEndian.Uint16(hs[i : i+2]))
	i += 2 + csLen
	if len(hs) < i+1 {
		return nil
	}
	compLen := int(hs[i])
	i += 1 + compLen
	if len(hs) < i+2 {
		return nil
	}
	extLen := int(binary.BigEndian.Uint16(hs[i : i+2]))
	i += 2
	if len(hs) < i+extLen {
		return nil
	}
	exts := hs[i : i+extLen]
	j := 0
	for j+4 <= len(exts) {
		typ := binary.BigEndian.Uint16(exts[j : j+2])
		l := int(binary.BigEndian.Uint16(exts[j+2 : j+4]))
		j += 4
		if j+l > len(exts) {
			return nil
		}
		if typ == 43 {
			body := exts[j : j+l]
			if len(body) < 1 {
				return nil
			}
			listLen := int(body[0])
			body = body[1:]
			if listLen > len(body) {
				return nil
			}
			body = body[:listLen]
			out := make([]uint16, 0, len(body)/2)
			for k := 0; k+2 <= len(body); k += 2 {
				out = append(out, binary.BigEndian.Uint16(body[k:k+2]))
			}
			return out
		}
		j += l
	}
	return nil
}

func frameName(f http2.Frame) string {
	switch f.(type) {
	case *http2.SettingsFrame:
		return "SETTINGS"
	case *http2.WindowUpdateFrame:
		return "WINDOW_UPDATE"
	case *http2.PriorityFrame:
		return "PRIORITY"
	case *http2.HeadersFrame:
		return "HEADERS"
	case *http2.DataFrame:
		return "DATA"
	default:
		return "OTHER"
	}
}

func h2hash(fp H2FP) string {
	// Stable hash across the main H2 signals.
	payload := map[string]any{
		"settings":      fp.SettingsList,
		"window_incr":   fp.WindowIncr,
		"priority":      fp.Priority,
		"frames_seen":   fp.FramesSeen,
		"negotiated_h2": true,
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

func writeJSON(w http.ResponseWriter, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Do not force status=200 here; keep any status set by caller.
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}

func render(fp H2FP) string {
	j, _ := json.MarshalIndent(fp, "", "  ")
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>H2 Edge Fingerprint</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 0; }
    header { padding: 20px 24px; border-bottom: 1px solid rgba(127,127,127,.25); }
    main { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
    pre { margin: 0; padding: 12px 14px; overflow: auto; font-size: 12.5px; line-height: 1.45; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; border: 1px solid rgba(127,127,127,.25); border-radius: 14px; }
    a { color: inherit; }
    .hint { opacity: .75; font-size: 13px; margin-top: 6px; }
  </style>
</head>
<body>
  <header>
    <div style="font-weight:800; font-size:18px;">HTTP/2 frame-level fingerprint (edge)</div>
    <div class="hint"><a href="/api/h2">/api/h2</a> • This endpoint must be the first HTTP/2 server to see frames.</div>
  </header>
  <main>
    <pre>` + htmlEscape(string(j)) + `</pre>
  </main>
</body>
</html>`
}

func htmlEscape(s string) string {
	repl := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return repl.Replace(s)
}

func jsonString(s string) string {
	// Minimal safe JS string literal via JSON encoding.
	b, _ := json.Marshal(s)
	return string(b)
}

func env(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
}

