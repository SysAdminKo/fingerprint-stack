package main

import (
	"context"
	"archive/zip"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
)

type Payload struct {
	Time    string                 `json:"time"`
	Request map[string]any         `json:"request"`
	TLS     map[string]any         `json:"tls"`
	CH      map[string]any         `json:"client_hello"`
	Headers map[string][]string    `json:"headers"`
	Extra   map[string]any         `json:"extra,omitempty"`
}

type pcapJob struct {
	Token     string
	TargetIP  string
	Path      string
	Ready     bool
	Started   bool
	Err       string
	StartedAt time.Time
	DurS      int
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *loggingResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *loggingResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func accessLogEnabled() bool {
	v := strings.TrimSpace(os.Getenv("FP_ACCESS_LOG"))
	switch strings.ToLower(v) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func withAccessLog(next http.Handler) http.Handler {
	if !accessLogEnabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lw, r)
		d := time.Since(start)
		raIP, _ := splitHostPort(r.RemoteAddr)
		log.Printf("http %s %s proto=%s host=%s ip=%s status=%d bytes=%d dur_ms=%d ua=%q",
			r.Method, r.URL.RequestURI(), r.Proto, r.Host, raIP, lw.status, lw.bytes, d.Milliseconds(), firstHeader(r, "User-Agent"))
	})
}

// tcpdumpHostPortFilter builds bpf: tcp and host <ip> and (port 443 or port 8443 ...).
// 443 и 8443 всегда включены (HTTPS и отдельный WS listener), чтобы в .pcap попадал wss на 8443
// даже если FP_PCAP_EXTRA_PORTS пустой или устаревший unit-файл.
func tcpdumpHostPortFilter(targetIP string, extraPortsCSV string) []string {
	ports := []string{"443", "8443"}
	for _, seg := range strings.Split(extraPortsCSV, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		dup := false
		for _, p := range ports {
			if p == seg {
				dup = true
				break
			}
		}
		if !dup {
			ports = append(ports, seg)
		}
	}
	if len(ports) == 1 {
		return []string{"tcp", "and", "host", targetIP, "and", "port", ports[0]}
	}
	out := []string{"tcp", "and", "host", targetIP, "and", "("}
	for i, p := range ports {
		if i > 0 {
			out = append(out, "or")
		}
		out = append(out, "port", p)
	}
	out = append(out, ")")
	return out
}

func main() {
	addr := env("FP_LISTEN", "127.0.0.1:9000")
	readmePath := env("FP_README_PATH", "/home/drzbodun/README.md")
	publicHost := strings.TrimSpace(env("FP_PUBLIC_HOST", ""))
	wsPublicURL := strings.TrimSpace(env("FP_WS_PUBLIC_URL", ""))
	pcapIface := env("FP_PCAP_IFACE", "any")
	// Дополнительные порты к уже обязательным 443+8443 (например 8080 для отладки).
	pcapExtraPorts := strings.TrimSpace(env("FP_PCAP_EXTRA_PORTS", ""))
	pcapBin := env("FP_PCAP_TCPDUMP", "/usr/sbin/tcpdump")
	// Persistent capture directory (pcap + json snapshots).
	pcapSaveDir := env("FP_PCAP_SAVE_DIR", "/var/lib/fp/pcap")
	_ = os.MkdirAll(pcapSaveDir, 0o700)
	// Temp directory used only for legacy /api/pcap streaming (kept for now).
	pcapTmpDir := env("FP_PCAP_DIR", "/tmp/fp-pcaps")
	_ = os.MkdirAll(pcapTmpDir, 0o700)

	jobsMu := &sync.Mutex{}
	jobs := map[string]*pcapJob{}

	trusted := parseTrustedProxyCIDRs(env("FP_TRUSTED_PROXY_CIDRS", "127.0.0.1/8,::1/128"))

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := buildPayload(r, trusted)
		// If this page load is associated with an active capture token,
		// persist the /api/all snapshot next to the pcap.
		if tok := strings.TrimSpace(r.URL.Query().Get("pcap_token")); tok != "" {
			jobsMu.Lock()
			job := jobs[tok]
			jobsMu.Unlock()
			if job != nil {
				jsonPath := strings.TrimSuffix(job.Path, ".pcap") + "-api-all.json"
				// Best-effort; do not overwrite if already written.
				if _, err := os.Stat(jsonPath); err != nil {
					if b, err2 := json.MarshalIndent(p, "", "  "); err2 == nil {
						_ = os.WriteFile(jsonPath, append(b, '\n'), 0o600)
					}
				}
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(renderHTML(p, publicHost, wsPublicURL)))
	})

	mux.HandleFunc("/api/all", func(w http.ResponseWriter, r *http.Request) {
		p := buildPayload(r, trusted)
		writeJSON(w, p)
	})
	mux.HandleFunc("/readme", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(readmePath)
		if err != nil {
			http.Error(w, "failed to read README", http.StatusInternalServerError)
			return
		}
		rendered, err := renderMarkdown(string(b))
		if err != nil {
			http.Error(w, "failed to render README", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		title := "README — " + filepath.Base(readmePath)
		_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>` + htmlEscape(title) + `</title>
    <style>
      :root { color-scheme: light dark; }
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 0; }
      header { padding: 14px 24px; border-bottom: 1px solid rgba(127,127,127,.25); position: sticky; top: 0; backdrop-filter: blur(8px); background: color-mix(in oklab, canvas, transparent 15%); }
      main { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
      a { color: inherit; }
      .row { display:flex; gap:12px; flex-wrap:wrap; align-items:baseline; justify-content:space-between; }
      .hint { opacity: .75; font-size: 13px; }
      .badge { display: inline-block; padding: 2px 8px; border: 1px solid rgba(127,127,127,.35); border-radius: 999px; font-size: 12px; opacity: .85; }
      article { line-height: 1.55; }
      article h1, article h2, article h3 { line-height: 1.25; margin-top: 1.2em; }
      article h1 { font-size: 26px; margin-top: 0.2em; }
      article h2 { font-size: 18px; margin-top: 1.4em; padding-top: .4em; border-top: 1px solid rgba(127,127,127,.22); }
      article h3 { font-size: 15px; opacity: .95; }
      article p { margin: .7em 0; }
      article ul, article ol { padding-left: 1.2em; }
      article li { margin: .25em 0; }
      article code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; font-size: 0.95em; padding: 0 6px; border: 1px solid rgba(127,127,127,.25); border-radius: 8px; }
      article pre { overflow:auto; padding: 12px 14px; border: 1px solid rgba(127,127,127,.25); border-radius: 14px; }
      article pre code { border: 0; padding: 0; }
      article blockquote { margin: 1em 0; padding: 8px 14px; border-left: 3px solid rgba(127,127,127,.35); opacity: .95; }
      article table { width: 100%; border-collapse: collapse; margin: 12px 0; }
      article th, article td { border-bottom: 1px solid rgba(127,127,127,.18); padding: 10px 10px; text-align: left; vertical-align: top; }
      article th { font-size: 12px; letter-spacing: .03em; text-transform: uppercase; opacity: .85; }
      .toc { margin-top: 12px; padding: 10px 12px; border: 1px solid rgba(127,127,127,.25); border-radius: 14px; opacity: .95; }
      .toc a { text-decoration: none; border-bottom: 1px dotted rgba(127,127,127,.45); }
      .toc a:hover { border-bottom-style: solid; }
    </style>
  </head>
  <body>
    <header>
      <div class="row">
        <div style="display:flex; gap:10px; align-items:baseline; flex-wrap:wrap;">
          <div style="font-weight:800; font-size:16px;">README</div>
          <div class="badge">` + htmlEscape(filepath.Base(readmePath)) + `</div>
        </div>
        <div class="hint"><a href="/">← back</a></div>
      </div>
    </header>
    <main>
      <article class="markdown-body">` + rendered + `</article>
    </main>
  </body>
</html>`))
	})
	mux.HandleFunc("/api/readme", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(readmePath)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"path": readmePath, "readme": string(b)})
	})
	mux.HandleFunc("/api/clean", func(w http.ResponseWriter, r *http.Request) {
		p := buildPayload(r, trusted)
		writeJSON(w, map[string]any{
			"ja4": p.TLS["ja4"],
			"ja3": p.TLS["ja3"],
			"tls": map[string]any{
				"version":       p.TLS["version"],
				"cipher_suite":  p.TLS["cipher_suite"],
				"alpn":          p.TLS["alpn"],
				"resumed":       p.TLS["resumed"],
				"server_name":   p.TLS["server_name"],
				"handshake_sni": p.CH["server_name"],
			},
			"client_hello": p.CH,
		})
	})
	mux.HandleFunc("/api/tls", func(w http.ResponseWriter, r *http.Request) {
		p := buildPayload(r, trusted)
		writeJSON(w, map[string]any{
			"tls":          p.TLS,
			"client_hello": p.CH,
		})
	})
	mux.HandleFunc("/api/handshake", func(w http.ResponseWriter, r *http.Request) {
		p := buildPayload(r, trusted)
		writeJSON(w, map[string]any{
			"handshake": p.Extra["handshake_dump"],
		})
	})
	mux.HandleFunc("/api/tcp", func(w http.ResponseWriter, r *http.Request) {
		p := buildPayload(r, trusted)
		writeJSON(w, map[string]any{
			"tcp": p.Extra["tcp_fingerprint"],
		})
	})
	mux.HandleFunc("/api/ttl", func(w http.ResponseWriter, r *http.Request) {
		p := buildPayload(r, trusted)
		writeJSON(w, map[string]any{
			"ttl": p.Extra["ttl"],
		})
	})
	mux.HandleFunc("/api/pcap/start", func(w http.ResponseWriter, r *http.Request) {
		raIP, _ := splitHostPort(r.RemoteAddr)
		xff := firstHeader(r, "X-Forwarded-For")
		clientIP := strings.TrimSpace(firstClientIP(raIP, xff))
		targetIP := strings.TrimSpace(r.URL.Query().Get("ip"))
		if targetIP == "" {
			targetIP = clientIP
		}
		if net.ParseIP(targetIP) == nil {
			writeJSON(w, map[string]any{"error": "invalid ip", "ip": targetIP})
			return
		}

		durS := 3
		if v := strings.TrimSpace(r.URL.Query().Get("dur_s")); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				durS = n
			}
		}
		if durS < 1 {
			durS = 1
		}
		if durS > 10 {
			durS = 10
		}

		token := randToken(16)
		base := "handshake-" + time.Now().UTC().Format("20060102T150405Z") + "-" + strings.ReplaceAll(targetIP, ":", "_") + "-" + token
		path := filepath.Join(pcapSaveDir, base+".pcap")

		job := &pcapJob{
			Token:     token,
			TargetIP:  targetIP,
			Path:      path,
			StartedAt: time.Now(),
			DurS:      durS,
		}
		jobsMu.Lock()
		jobs[token] = job
		jobsMu.Unlock()

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durS+2)*time.Second)
			defer cancel()

			args := []string{
				"-i", pcapIface,
				"-w", job.Path,
				"-U",
				"-n",
				"-s", "0",
			}
			bpfParts := tcpdumpHostPortFilter(job.TargetIP, pcapExtraPorts)
			args = append(args, bpfParts...)
			log.Printf("pcap start token=%s ip=%s bpf=%s", job.Token, job.TargetIP, strings.Join(bpfParts, " "))

			cmd := exec.CommandContext(ctx, pcapBin, args...)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			// Start first (so we can signal readiness to the caller),
			// then wait for it to finish (by timeout).
			err := cmd.Start()
			jobsMu.Lock()
			job.Started = (err == nil)
			jobsMu.Unlock()
			if err == nil {
				err = cmd.Wait()
			}

			jobsMu.Lock()
			defer jobsMu.Unlock()
			if err != nil && ctx.Err() == nil {
				job.Err = strings.TrimSpace(stderr.String())
				if job.Err == "" {
					job.Err = err.Error()
				}
			}
			job.Ready = true

			// Cleanup old jobs (files are intentionally kept on disk).
			cutoff := time.Now().Add(-10 * time.Minute)
			for k, j := range jobs {
				if j.StartedAt.Before(cutoff) {
					delete(jobs, k)
				}
			}
		}()

		// Wait briefly until tcpdump is actually running to avoid races
		// where the browser reconnects before capture starts.
		deadline := time.Now().Add(900 * time.Millisecond)
		for time.Now().Before(deadline) {
			jobsMu.Lock()
			started := job.Started
			jobsMu.Unlock()
			if started {
				break
			}
			time.Sleep(30 * time.Millisecond)
		}

		bpfParts := tcpdumpHostPortFilter(targetIP, pcapExtraPorts)
		writeJSON(w, map[string]any{
			"ok":     true,
			"token":  token,
			"ip":     targetIP,
			"dur_s":  durS,
			"bpf":    strings.Join(bpfParts, " "),
			"result": "/api/pcap/result?token=" + token,
		})
	})
	mux.HandleFunc("/api/pcap/result", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(r.URL.Query().Get("token"))
		probe := strings.TrimSpace(r.URL.Query().Get("probe")) == "1"
		if token == "" {
			writeJSON(w, map[string]any{"error": "missing token"})
			return
		}
		jobsMu.Lock()
		job := jobs[token]
		jobsMu.Unlock()
		if job == nil {
			writeJSON(w, map[string]any{"error": "unknown token"})
			return
		}
		if !job.Ready {
			if probe {
				w.WriteHeader(202)
				writeJSON(w, map[string]any{"status": "capturing", "token": token})
			} else {
				w.WriteHeader(202)
				_, _ = w.Write([]byte("capturing\n"))
			}
			return
		}
		if job.Err != "" {
			writeJSON(w, map[string]any{"error": job.Err, "token": token})
			return
		}
		filename := filepath.Base(job.Path)
		if probe {
			writeJSON(w, map[string]any{"status": "ready", "token": token, "filename": filename})
			return
		}
		// Return a ZIP archive containing both .pcap and api-all snapshot JSON.
		jsonPath := strings.TrimSuffix(job.Path, ".pcap") + "-api-all.json"
		zipName := strings.TrimSuffix(filename, ".pcap") + ".zip"

		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+zipName+`"`)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)

		zw := zip.NewWriter(w)
		defer func() { _ = zw.Close() }()

		if err := zipAddFile(zw, filename, job.Path); err != nil {
			log.Printf("zip add pcap error: %v", err)
			return
		}
		// Add JSON snapshot if available; otherwise include an error stub.
		if _, err := os.Stat(jsonPath); err == nil {
			_ = zipAddFile(zw, filepath.Base(jsonPath), jsonPath)
		} else {
			fw, _ := zw.Create(filepath.Base(strings.TrimSuffix(filename, ".pcap") + "-api-all.json"))
			_, _ = io.WriteString(fw, "{\"error\":\"api-all snapshot not found (try reloading the page with pcap_token during capture)\"}\n")
		}
	})
	mux.HandleFunc("/api/pcap", func(w http.ResponseWriter, r *http.Request) {
		raIP, _ := splitHostPort(r.RemoteAddr)
		xff := firstHeader(r, "X-Forwarded-For")
		clientIP := strings.TrimSpace(firstClientIP(raIP, xff))
		targetIP := strings.TrimSpace(r.URL.Query().Get("ip"))
		if targetIP == "" {
			targetIP = clientIP
		}
		if net.ParseIP(targetIP) == nil {
			writeJSON(w, map[string]any{"error": "invalid ip", "ip": targetIP})
			return
		}

		durS := 3
		if v := strings.TrimSpace(r.URL.Query().Get("dur_s")); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				durS = n
			}
		}
		if durS < 1 {
			durS = 1
		}
		if durS > 10 {
			durS = 10
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(durS+2)*time.Second)
		defer cancel()

		// tcpdump filter: packets to/from clientIP on 443 (and optional WS port, e.g. 8443).
		args := []string{
			"-i", pcapIface,
			"-w", "-",
			"-U",
			"-n",
			"-s", "0",
		}
		args = append(args, tcpdumpHostPortFilter(targetIP, pcapExtraPorts)...)

		cmd := exec.CommandContext(ctx, pcapBin, args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			writeJSON(w, map[string]any{"error": err.Error(), "stderr": stderr.String()})
			return
		}

		filename := "handshake-" + time.Now().UTC().Format("20060102T150405Z") + "-" + strings.ReplaceAll(targetIP, ":", "_") + ".pcap"
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.WriteHeader(200)

		_, copyErr := io.Copy(w, stdout)
		waitErr := cmd.Wait()
		if copyErr == nil && waitErr != nil && !errors.Is(waitErr, context.DeadlineExceeded) && ctx.Err() == nil {
			// Best-effort: if client already received headers, we can't change status; just log.
			log.Printf("pcap tcpdump wait error: %v (stderr=%q)", waitErr, stderr.String())
		}
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           withAccessLog(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("fingerprint upstream listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func randToken(n int) string {
	if n <= 0 {
		n = 16
	}
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const hex = "0123456789abcdef"
	out := make([]byte, 0, n*2)
	for _, v := range b {
		out = append(out, hex[v>>4], hex[v&0x0f])
	}
	return string(out)
}

func zipAddFile(zw *zip.Writer, name string, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, _ := f.Stat()
	h := &zip.FileHeader{
		Name:   name,
		Method: zip.Deflate,
	}
	if info != nil {
		h.SetModTime(info.ModTime())
	}
	w, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

type trustedProxySet struct {
	prefixes []netip.Prefix
	raw      string
}

func parseTrustedProxyCIDRs(s string) trustedProxySet {
	raw := strings.TrimSpace(s)
	if raw == "" {
		raw = "127.0.0.1/8,::1/128"
	}
	parts := strings.Split(raw, ",")
	out := make([]netip.Prefix, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pr, err := netip.ParsePrefix(p)
		if err != nil {
			continue
		}
		out = append(out, pr)
	}
	return trustedProxySet{prefixes: out, raw: raw}
}

func (t trustedProxySet) isTrusted(ipStr string) bool {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return false
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	for _, pr := range t.prefixes {
		if pr.Contains(ip) {
			return true
		}
	}
	return false
}

func buildPayload(r *http.Request, trusted trustedProxySet) Payload {
	now := time.Now().Format(time.RFC3339Nano)

	raIP, raPort := splitHostPort(r.RemoteAddr)
	proxyTrusted := trusted.isTrusted(raIP)

	xff := ""
	if proxyTrusted {
		xff = firstHeader(r, "X-Forwarded-For")
	}
	clientIP := firstClientIP(raIP, xff)

	edgeHeader := func(k string) string {
		if !proxyTrusted {
			return ""
		}
		return firstHeader(r, k)
	}
	edgeHeaderAnyCase := func(k string) string {
		if !proxyTrusted {
			return ""
		}
		return firstHeaderAnyCase(r, k)
	}

	tls := map[string]any{
		"ja4":         edgeHeader("X-JA4"),
		"ja3":         edgeHeaderAnyCase("JA3"), // edge sets request header "JA3"
		"http_fp":     edgeHeader("X-HTTP-FP"),
		"ws": map[string]any{
			"fp":         edgeHeader("X-WS-FP"),
			"origin":     edgeHeader("X-WS-Origin"),
			"ua":         edgeHeader("X-WS-UA"),
			"version":    edgeHeader("X-WS-Version"),
			"extensions": mustJSONList[string](edgeHeader("X-WS-Extensions")),
			"protocols":  mustJSONList[string](edgeHeader("X-WS-Protocols")),
		},
		"h2_fp":       edgeHeader("X-H2-FP"),
		"h2_settings": mustJSONList[string](edgeHeader("X-H2-Settings")),
		"h2_window_incr": mustJSONList[uint32](edgeHeader("X-H2-Window-Incr")),
		"h2_priority_frames": edgeHeader("X-H2-Priority-Frames"),
		"version":     edgeHeader("X-TLS-Version"),
		"cipher_suite": edgeHeader("X-TLS-Cipher"),
		"alpn":        edgeHeader("X-TLS-Proto"),
		"resumed":     edgeHeader("X-TLS-Resumed"),
		"server_name": edgeHeader("X-TLS-SNI"),
	}

	handshake := map[string]any{
		"client_hello_record_b64":          edgeHeader("X-TLS-ClientHello-Record-B64"),
		"server_handshake_records_b64":     edgeHeader("X-TLS-ServerHandshake-Records-B64"),
		"server_hello_json":                mustJSONObj(edgeHeader("X-TLS-ServerHello-JSON")),
	}

	ch := map[string]any{
		"server_name":        edgeHeader("X-CH-Server-Name"),
		"handshake_version":  edgeHeader("X-CH-Handshake-Version"),
		"alpn":               mustJSONList[string](edgeHeader("X-CH-ALPN")),
		"supported_versions": mustJSONList[uint16](edgeHeader("X-CH-Supported-Versions")),
		"cipher_suites":      mustJSONList[uint16](edgeHeader("X-CH-Cipher-Suites")),
		"extensions":         mustJSONList[uint16](edgeHeader("X-CH-Extensions")),
		"curves":             mustJSONList[uint16](edgeHeader("X-CH-Curves")),
		"points":             mustJSONList[uint8](edgeHeader("X-CH-Points")),
		"signature_schemes":  mustJSONList[uint16](edgeHeader("X-CH-Signature-Schemes")),
	}

	// Sort request headers for readability in UI.
	hdrs := map[string][]string{}
	for k, v := range r.Header {
		hdrs[k] = v
	}

	req := map[string]any{
		"method":       r.Method,
		"host":         r.Host,
		"uri":          r.URL.RequestURI(),
		// NOTE: upstream sees the proxy hop protocol (often HTTP/1.1).
		// Prefer outer/client protocol if edge passes it through.
		"proto":             firstNonEmpty(edgeHeader("X-Client-Proto"), r.Proto),
		"proto_upstream":    r.Proto,
		"proto_client_alpn": edgeHeader("X-Client-ALPN"),
		"remote_ip":    raIP,
		"remote_port":  raPort,
		"client_ip":    clientIP,
		"xff":          xff,
		"user_agent":   firstHeader(r, "User-Agent"),
		"accept":       firstHeader(r, "Accept"),
		"accept_lang":  firstHeader(r, "Accept-Language"),
		"accept_enc":   firstHeader(r, "Accept-Encoding"),
		"cf_ip":        firstHeader(r, "CF-Connecting-IP"),
		"true_client":  firstHeader(r, "True-Client-IP"),
		"via":          firstHeader(r, "Via"),
		"forwarded":    firstHeader(r, "Forwarded"),
	}

	return Payload{
		Time:    now,
		Request: req,
		TLS:     tls,
		CH:      ch,
		Headers: hdrs,
		Extra: map[string]any{
			"tcp_fingerprint": p0fFingerprint(clientIP),
			"ttl":             ttlByIP(clientIP),
			"handshake_dump":  handshake,
			"trusted_proxy": map[string]any{
				"ok":    proxyTrusted,
				"cidrs": trusted.raw,
			},
			"note":            "HTTP/2 frame-level fingerprinting not implemented yet",
		},
	}
}

func renderHTML(p Payload, publicHost string, wsPublicURL string) string {
	prettyAll, _ := json.MarshalIndent(p, "", "  ")
	prettyHdr, _ := json.MarshalIndent(p.Headers, "", "  ")

	// Extract typed lists for table rendering
	alpn := asStringList(p.CH["alpn"])
	supportedVersions := asU16List(p.CH["supported_versions"])
	ciphers := asU16List(p.CH["cipher_suites"])
	exts := asU16List(p.CH["extensions"])
	curves := asU16List(p.CH["curves"])
	points := asU8List(p.CH["points"])
	sigs := asU16List(p.CH["signature_schemes"])

	hostForTitle := strings.TrimSpace(publicHost)
	if hostForTitle == "" {
		hostForTitle = asString(p.Request["host"])
	}
	if hostForTitle == "" {
		hostForTitle = "localhost"
	}

	return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Fingerprint — ` + htmlEscape(hostForTitle) + `</title>
    <style>
      :root { color-scheme: light dark; }
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 0; }
      header { padding: 20px 24px; border-bottom: 1px solid rgba(127,127,127,.25); }
      main { padding: 20px 24px; display: grid; gap: 16px; max-width: 1200px; margin: 0 auto; }
      .grid { display: grid; grid-template-columns: 1fr; gap: 16px; }
      @media (min-width: 980px) { .grid { grid-template-columns: 1fr 1fr; } }
      section { border: 1px solid rgba(127,127,127,.25); border-radius: 14px; overflow: hidden; }
      section > h2 { margin: 0; padding: 12px 14px; font-size: 14px; letter-spacing: .04em; text-transform: uppercase; border-bottom: 1px solid rgba(127,127,127,.25); }
      pre { margin: 0; padding: 12px 14px; overflow: auto; font-size: 12.5px; line-height: 1.45; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }
      table { width: 100%; border-collapse: collapse; }
      td { padding: 10px 12px; vertical-align: top; border-bottom: 1px solid rgba(127,127,127,.18); }
      td.k { width: 34%; font-weight: 650; opacity: .9; }
      td.v { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; font-size: 12.5px; }
      a { color: inherit; }
      .row { display:flex; gap:12px; flex-wrap:wrap; align-items:baseline; }
      .row2 { display:flex; gap:12px; flex-wrap:wrap; align-items:center; justify-content:space-between; }
      .badge { display: inline-block; padding: 2px 8px; border: 1px solid rgba(127,127,127,.35); border-radius: 999px; font-size: 12px; opacity: .85; }
      .hint { opacity: .75; font-size: 13px; margin-top: 6px; }
      .links a { margin-right: 12px; opacity: .9; }
      .btn { appearance: none; border: 1px solid rgba(127,127,127,.35); background: color-mix(in oklab, canvas, transparent 10%); color: inherit; border-radius: 12px; padding: 8px 12px; font-weight: 650; cursor: pointer; }
      .btn:disabled { opacity: .6; cursor: not-allowed; }
      .ctl { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
      select { border: 1px solid rgba(127,127,127,.35); background: transparent; color: inherit; border-radius: 10px; padding: 6px 10px; }
      /* Firefox: option popup can get white bg + white text in dark mode unless explicit */
      select option { background: Canvas; color: CanvasText; }
      select:focus { outline: 2px solid color-mix(in oklab, Highlight, transparent 55%); outline-offset: 2px; }
      .status { font-size: 12px; opacity: .8; }
      .disclaimer { margin: 0; }
      .disclaimer > h2 {
        margin: 0;
        padding: 14px 16px 10px 16px;
        font-size: 16px;
        letter-spacing: 0;
        text-transform: none;
        border-bottom: 0;
      }
      .disclaimer .box {
        border: 1px solid rgba(127,127,127,.35);
        border-radius: 14px;
        padding: 14px 16px;
        background: color-mix(in oklab, canvas, transparent 10%);
        margin: 0 16px 14px 16px;
      }
      .disclaimer .title {
        font-weight: 800;
        letter-spacing: .02em;
        font-size: 14.5px;
        margin-bottom: 6px;
      }
      .disclaimer .text {
        font-size: 13.5px;
        line-height: 1.45;
        opacity: .95;
      }
      .disclaimer .actions {
        margin-top: 12px;
        display: flex;
        gap: 10px;
        align-items: center;
        flex-wrap: wrap;
      }
      .disclaimer .actions .status { opacity: .9; }
      .disclaimer code {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: .95em;
        padding: 0 6px;
        border: 1px solid rgba(127,127,127,.25);
        border-radius: 8px;
      }
    </style>
  </head>
  <body>
    <header>
      <div class="row2">
        <div class="row">
          <div style="font-weight:800; font-size:18px;">Fingerprint viewer</div>
          <div class="badge">` + htmlEscape(p.Time) + `</div>
        </div>
      </div>
      <div class="hint links">
        <a href="/api/all">/api/all</a>
        <a href="/api/clean">/api/clean</a>
        <a href="/api/tls">/api/tls</a>
        <a href="/api/tcp">/api/tcp</a>
        <a href="/api/ttl">/api/ttl</a>
        <a href="/api/handshake">/api/handshake</a>
        <a href="/api/pcap?dur_s=3">/api/pcap</a>
        <a href="/readme">/readme</a>
      </div>
    </header>
    <script>
      (function () {
        const initialWsFp = ` + jsonString(asString(asMap(p.TLS["ws"])["fp"])) + `;
        const wsPublicUrl = ` + jsonString(wsPublicURL) + `;
        let st = null;

        function filenameFromDisposition(cd) {
          if (!cd) return '';
          const m = /filename="?([^"]+)"?/i.exec(cd);
          return m ? m[1] : '';
        }

        function wsUrl() {
          if (wsPublicUrl) return wsPublicUrl;
          const h = location.hostname;
          const wsPort = '8443';
          if (location.protocol === 'https:') {
            return 'wss://' + h + ':' + wsPort + '/ws';
          }
          return 'ws://' + h + ':' + wsPort + '/ws';
        }

        async function triggerWsProbe() {
          try { await fetch('/ws', { cache: 'no-store' }); } catch (_) {}
        }

        function triggerWsHandshake() {
          return new Promise((resolve) => {
            const maxMs = 13000;
            let ws;
            let iv = null;
            try {
              ws = new WebSocket(wsUrl());
            } catch (_) {
              resolve();
              return;
            }
            const t = setTimeout(() => {
              if (iv) clearInterval(iv);
              try { ws.close(); } catch (_) {}
              resolve();
            }, maxMs);
            ws.onopen = () => {
              iv = setInterval(() => {
                try { ws.send('pcap-ping-' + Date.now()); } catch (_) {}
              }, 400);
            };
            ws.onerror = () => { if (iv) clearInterval(iv); clearTimeout(t); resolve(); };
            ws.onclose = () => { if (iv) clearInterval(iv); clearTimeout(t); resolve(); };
          });
        }

        async function pollDownloadViaIframe(token) {
          const probeUrl = '/api/pcap/result?probe=1&token=' + encodeURIComponent(token);
          const downloadUrl = '/api/pcap/result?token=' + encodeURIComponent(token);
          const start = Date.now();
          while (Date.now() - start < 20000) {
            const resp = await fetch(probeUrl, { cache: 'no-store' });
            if (resp.status === 202) {
              if (st) st.textContent = 'capturing...';
              await new Promise(r => setTimeout(r, 500));
              continue;
            }
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            const j = await resp.json();
            if (!j || j.status !== 'ready') throw new Error('unexpected probe response');

            // Firefox-friendly download: set iframe src to attachment URL.
            let frame = document.getElementById('pcap_dl_iframe');
            if (!frame) {
              frame = document.createElement('iframe');
              frame.id = 'pcap_dl_iframe';
              frame.style.display = 'none';
              document.body.appendChild(frame);
            }
            frame.src = downloadUrl;
            return;
          }
          throw new Error('timeout waiting for pcap');
        }

        function navClose(nextUrl) {
          // Navigation-based close is most reliable in Firefox.
          location.href = '/__close?next=' + encodeURIComponent(nextUrl);
        }

        function init() {
          const btn = document.getElementById('pcap_btn');
          const dur = document.getElementById('pcap_dur');
          st = document.getElementById('pcap_status');
          if (!btn || !dur || !st) return;

          // If page loaded with a token, poll and download automatically.
          const sp = new URLSearchParams(location.search);
          const tokenOnLoad = sp.get('pcap_token');
          if (tokenOnLoad) {
            btn.disabled = true;
            st.textContent = 'capturing...';
            // While capture is running, trigger /ws from the client so WS traffic appears in pcap.
            Promise.resolve()
              .then(() => triggerWsProbe())
              .then(() => triggerWsHandshake())
              .catch(() => {});

            pollDownloadViaIframe(tokenOnLoad).then(() => {
              st.textContent = 'downloaded, reloading...';
              // drop token from URL
              sp.delete('pcap_token');
              const next = location.pathname + (sp.toString() ? '?' + sp.toString() : '') + location.hash;
              history.replaceState(null, '', next);
              setTimeout(() => location.reload(), 400);
            }).catch(e => {
              st.textContent = 'failed: ' + (e && e.message ? e.message : String(e));
              btn.disabled = false;
            });
            return;
          }

          // Auto-trigger WS handshake/probe on load when ws_fp is empty.
          // Use bounded retries to avoid infinite reload loops.
          const wsTry = parseInt(sp.get('ws_try') || '0', 10) || 0;
          if (!initialWsFp && wsTry < 3) {
            Promise.resolve()
              .then(() => triggerWsProbe())
              .then(() => triggerWsHandshake())
              .then(() => {
                const sp3 = new URLSearchParams(location.search);
                sp3.set('ws_try', String(wsTry + 1));
                location.search = sp3.toString();
              });
          } else if (initialWsFp && wsTry > 0) {
            // Clean up helper param once populated.
            sp.delete('ws_try');
            const next = location.pathname + (sp.toString() ? '?' + sp.toString() : '') + location.hash;
            history.replaceState(null, '', next);
          }

          btn.addEventListener('click', async () => {
            btn.disabled = true;
            st.textContent = 'starting capture...';
            const durS = parseInt(dur.value || '3', 10) || 3;
            try {
              const resp = await fetch('/api/pcap/start?dur_s=' + encodeURIComponent(String(durS)), { cache: 'no-store' });
              if (!resp.ok) throw new Error('HTTP ' + resp.status);
              const j = await resp.json();
              if (!j || !j.token) throw new Error('bad response');
              st.textContent = 'reconnecting...';
              const sp2 = new URLSearchParams(location.search);
              sp2.set('pcap_token', j.token);
              const next = location.pathname + '?' + sp2.toString() + location.hash;
              navClose(next);
            } catch (e) {
              st.textContent = 'failed: ' + (e && e.message ? e.message : String(e));
              btn.disabled = false;
            }
          });
        }

        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', init, { once: true });
        } else {
          init();
        }
      })();
    </script>
    <main>
      <section class="disclaimer" role="note" aria-label="pcap capture notice">
        <h2>Notice: what gets collected & saved</h2>
        <div class="box">
          <div class="text">
            Нажимая <code>Capture .pcap</code>, вы запускаете серверный <code>tcpdump</code>. Будет сохранён <code>.pcap</code> с пакетами TCP/443 для вашего IP за выбранное время, а также рядом сохранится снапшот <code>/api/all</code> (request headers и fingerprints: JA3/JA4, TLS/ClientHello, H2/HTTP, p0f, TTL). Файлы сохраняются на сервере в директорию <code>FP_PCAP_SAVE_DIR</code>.
          </div>
          <div class="actions">
            <label class="status" for="pcap_dur">pcap:</label>
            <select id="pcap_dur" aria-label="pcap duration seconds">
              <option value="1">1s</option>
              <option value="2">2s</option>
              <option value="3" selected>3s</option>
              <option value="5">5s</option>
              <option value="8">8s</option>
              <option value="10">10s</option>
            </select>
            <button id="pcap_btn" class="btn" type="button">Capture .pcap</button>
            <span id="pcap_status" class="status"></span>
          </div>
        </div>
      </section>
      <div class="grid">
        <section>
          <h2>Fingerprints + agreed TLS</h2>
          <table>
            <tr><td class="k">JA4</td><td class="v">` + htmlEscape(asString(p.TLS["ja4"])) + `</td></tr>
            <tr><td class="k">JA3</td><td class="v">` + htmlEscape(asString(p.TLS["ja3"])) + `</td></tr>
            <tr><td class="k">WS fp (last)</td><td class="v">` + htmlEscape(asString(asMap(p.TLS["ws"])["fp"])) + `</td></tr>
            <tr><td class="k">TLS version</td><td class="v">` + htmlEscape(asString(p.TLS["version"])) + `</td></tr>
            <tr><td class="k">Cipher suite</td><td class="v">` + htmlEscape(asString(p.TLS["cipher_suite"])) + `</td></tr>
            <tr><td class="k">ALPN (agreed)</td><td class="v">` + htmlEscape(asString(p.TLS["alpn"])) + `</td></tr>
            <tr><td class="k">Resumed</td><td class="v">` + htmlEscape(asString(p.TLS["resumed"])) + `</td></tr>
            <tr><td class="k">SNI (agreed)</td><td class="v">` + htmlEscape(asString(p.TLS["server_name"])) + `</td></tr>
          </table>
          <div class="hint" style="padding: 0 14px 14px 14px;">
            HTTP/3 disabled to preserve TLS ClientHello fingerprints.
          </div>
        </section>

        <section>
          <h2>WebSocket handshake (last)</h2>
          <table>
            <tr><td class="k">WS fp</td><td class="v">` + htmlEscape(asString(asMap(p.TLS["ws"])["fp"])) + `</td></tr>
            <tr><td class="k">Origin</td><td class="v">` + htmlEscape(asString(asMap(p.TLS["ws"])["origin"])) + `</td></tr>
            <tr><td class="k">User-Agent</td><td class="v">` + htmlEscape(asString(asMap(p.TLS["ws"])["ua"])) + `</td></tr>
            <tr><td class="k">Version</td><td class="v">` + htmlEscape(asString(asMap(p.TLS["ws"])["version"])) + `</td></tr>
            <tr><td class="k">Extensions</td><td class="v">` + htmlEscape(asString(asMap(p.TLS["ws"])["extensions"])) + `</td></tr>
            <tr><td class="k">Protocols</td><td class="v">` + htmlEscape(asString(asMap(p.TLS["ws"])["protocols"])) + `</td></tr>
          </table>
          <div class="hint" style="padding: 0 14px 14px 14px;">
            WebSocket по умолчанию: <code>wss://&lt;host&gt;:8443/ws</code> (отдельный TLS listener на edge). Переопределение: <code>FP_WS_PUBLIC_URL</code>. В <code>.pcap</code> порт 8443 учитывается через <code>FP_PCAP_EXTRA_PORTS</code>.
          </div>
        </section>

        <section>
          <h2>Request details</h2>
          <table>
            <tr><td class="k">Method</td><td class="v">` + htmlEscape(asString(p.Request["method"])) + `</td></tr>
            <tr><td class="k">Host</td><td class="v">` + htmlEscape(asString(p.Request["host"])) + `</td></tr>
            <tr><td class="k">URI</td><td class="v">` + htmlEscape(asString(p.Request["uri"])) + `</td></tr>
            <tr><td class="k">Proto (client)</td><td class="v">` + htmlEscape(asString(p.Request["proto"])) + `</td></tr>
            <tr><td class="k">Proto (upstream)</td><td class="v">` + htmlEscape(asString(p.Request["proto_upstream"])) + `</td></tr>
            <tr><td class="k">ALPN (client)</td><td class="v">` + htmlEscape(asString(p.Request["proto_client_alpn"])) + `</td></tr>
            <tr><td class="k">Remote</td><td class="v">` + htmlEscape(asString(p.Request["remote_ip"])) + `:` + htmlEscape(asString(p.Request["remote_port"])) + `</td></tr>
            <tr><td class="k">Client IP</td><td class="v">` + htmlEscape(asString(p.Request["client_ip"])) + `</td></tr>
            <tr><td class="k">X-Forwarded-For</td><td class="v">` + htmlEscape(asString(p.Request["xff"])) + `</td></tr>
            <tr><td class="k">User-Agent</td><td class="v">` + htmlEscape(asString(p.Request["user_agent"])) + `</td></tr>
          </table>
        </section>
      </div>

      <section>
        <h2>TCP / IP stack fingerprint (p0f)</h2>
        <pre>` + htmlEscape(asString(p.Extra["tcp_fingerprint"])) + `</pre>
      </section>

      <section>
        <h2>IP TTL (passive, eBPF)</h2>
        <pre>` + htmlEscape(asString(p.Extra["ttl"])) + `</pre>
      </section>

      <section>
        <h2>TLS handshake dumps (ClientHello / ServerHello)</h2>
        <pre>` + htmlEscape(asString(p.Extra["handshake_dump"])) + `</pre>
        <div class="hint" style="padding: 0 14px 14px 14px;">ClientHello is the first inbound TLS handshake record. ServerHello is best-effort extracted from outbound handshake records (TLS 1.3 beyond ServerHello is encrypted).</div>
      </section>

      <div class="grid">
        <section>
          <h2>Supported TLS (ClientHello)</h2>
          <table>
            <tr><td class="k">Handshake SNI</td><td class="v">` + htmlEscape(asString(p.CH["server_name"])) + `</td></tr>
            <tr><td class="k">Handshake version</td><td class="v">` + htmlEscape(asString(p.CH["handshake_version"])) + `</td></tr>
            <tr><td class="k">Supported versions</td><td class="v">` + htmlEscape(joinU16(supportedVersions)) + `</td></tr>
            <tr><td class="k">ALPNs</td><td class="v">` + htmlEscape(strings.Join(alpn, ", ")) + `</td></tr>
            <tr><td class="k">Signature schemes</td><td class="v">` + htmlEscape(joinU16(sigs)) + `</td></tr>
          </table>
        </section>

        <section>
          <h2>TLS extensions / curves</h2>
          <table>
            <tr><td class="k">Curves</td><td class="v">` + htmlEscape(joinU16(curves)) + `</td></tr>
            <tr><td class="k">Points</td><td class="v">` + htmlEscape(joinU8(points)) + `</td></tr>
            <tr><td class="k">Extensions</td><td class="v">` + htmlEscape(joinU16(exts)) + `</td></tr>
          </table>
        </section>
      </div>

      <section>
        <h2>TLS cipher suites (ClientHello)</h2>
        <pre>` + htmlEscape(joinU16Lines(ciphers, 12)) + `</pre>
      </section>

      <section><h2>Raw headers</h2><pre>` + htmlEscape(string(prettyHdr)) + `</pre></section>
      <section><h2>All collected data (JSON)</h2><pre>` + htmlEscape(string(prettyAll)) + `</pre></section>
    </main>
  </body>
</html>`
}

func writeJSON(w http.ResponseWriter, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Do not force status=200 here; some handlers intentionally set non-200 (e.g. 202 while capturing).
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}

func mustJSONList[T any](s string) any {
	if strings.TrimSpace(s) == "" {
		return []T(nil)
	}
	var out []T
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return map[string]any{"_raw": s, "_error": err.Error()}
	}
	return out
}

func mustJSONObj(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return map[string]any{"_raw": s, "_error": err.Error()}
	}
	return out
}

func firstHeader(r *http.Request, k string) string {
	return strings.TrimSpace(r.Header.Get(k))
}

func firstHeaderAnyCase(r *http.Request, k string) string {
	if v := r.Header.Get(k); v != "" {
		return strings.TrimSpace(v)
	}
	kl := strings.ToLower(k)
	for hk, hv := range r.Header {
		if strings.ToLower(hk) == kl && len(hv) > 0 {
			return strings.TrimSpace(hv[0])
		}
	}
	return ""
}

func splitHostPort(addr string) (string, string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return h, p
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

func renderMarkdown(src string) (string, error) {
	md := goldmark.New(
		goldmark.WithExtensions(
			extension.GFM, // tables, strikethrough, task lists
		),
		goldmark.WithRendererOptions(
			// Do NOT allow raw HTML passthrough (keep it safe).
			html.WithXHTML(),
		),
	)
	var buf strings.Builder
	if err := md.Convert([]byte(src), &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstClientIP(remoteIP, xff string) string {
	xff = strings.TrimSpace(xff)
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	return remoteIP
}

func p0fFingerprint(ip string) any {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	// p0f observes packets to/from the host; for best results, it needs to see
	// the client's SYN/ACK flows. We query it opportunistically.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	sock := env("P0F_SOCK", "/var/run/p0f.sock")
	out, err := exec.CommandContext(ctx, "/usr/sbin/p0f-client", sock, ip).CombinedOutput()
	if err != nil {
		return map[string]any{
			"ip":    ip,
			"error": strings.TrimSpace(err.Error()),
			"out":   strings.TrimSpace(string(out)),
		}
	}
	return parseP0FOutput(ip, string(out))
}

func parseP0FOutput(ip, out string) any {
	out = strings.TrimSpace(out)
	if out == "" {
		return map[string]any{"ip": ip, "raw": ""}
	}
	lines := strings.Split(out, "\n")
	m := map[string]any{
		"ip":  ip,
		"raw": out,
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "Key = value"
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" {
				m[strings.ToLower(strings.ReplaceAll(k, " ", "_"))] = v
			}
		}
	}
	return m
}

func ttlByIP(ip string) any {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	base := env("TTL_API", "http://127.0.0.1:9100")
	url := base + "/api/ttl/ip/" + ip

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return map[string]any{"ip": ip, "error": err.Error()}
	}
	defer resp.Body.Close()

	var obj map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return map[string]any{"ip": ip, "error": err.Error()}
	}
	if v, ok := obj["ttl"]; ok {
		return v
	}
	return obj
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func asMap(v any) map[string]any {
	if v == nil {
		return map[string]any{}
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	// try JSON roundtrip for map[string]any-ish payloads
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func asStringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, it := range t {
			out = append(out, asString(it))
		}
		return out
	default:
		return nil
	}
}

func asU16List(v any) []uint16 {
	switch t := v.(type) {
	case []uint16:
		return t
	case []any:
		out := make([]uint16, 0, len(t))
		for _, it := range t {
			switch n := it.(type) {
			case float64:
				out = append(out, uint16(n))
			case int:
				out = append(out, uint16(n))
			}
		}
		return out
	default:
		return nil
	}
}

func asU8List(v any) []uint8 {
	switch t := v.(type) {
	case []uint8:
		return t
	case []any:
		out := make([]uint8, 0, len(t))
		for _, it := range t {
			switch n := it.(type) {
			case float64:
				out = append(out, uint8(n))
			case int:
				out = append(out, uint8(n))
			}
		}
		return out
	default:
		return nil
	}
}

func joinU16(in []uint16) string {
	if len(in) == 0 {
		return ""
	}
	sb := strings.Builder{}
	for i, v := range in {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(strconv.Itoa(int(v)))
	}
	return sb.String()
}

func joinU8(in []uint8) string {
	if len(in) == 0 {
		return ""
	}
	sb := strings.Builder{}
	for i, v := range in {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(strconv.Itoa(int(v)))
	}
	return sb.String()
}

func joinU16Lines(in []uint16, perLine int) string {
	if len(in) == 0 {
		return ""
	}
	if perLine <= 0 {
		perLine = 12
	}
	sb := strings.Builder{}
	for i, v := range in {
		if i > 0 {
			if i%perLine == 0 {
				sb.WriteString("\n")
			} else {
				sb.WriteString(", ")
			}
		}
		sb.WriteString(strconv.Itoa(int(v)))
	}
	return sb.String()
}

