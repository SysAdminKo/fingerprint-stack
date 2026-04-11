package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	Token            string
	TargetIP         string
	Path             string
	Ready            bool
	Started          bool
	Err              string
	StartedAt        time.Time
	EndedAt          time.Time // tcpdump finished; used for journalctl --until (stable if pcap downloaded later)
	DurS             int
	UserOSLabel      string // optional: from UI for download filename
	UserBrowserLabel string
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
	wsFanout := envInt("FP_WS_FANOUT", 2)
	wsPayloadBytes := envInt("FP_WS_PAYLOAD_BYTES", 4096)
	wsIntervalMs := envInt("FP_WS_INTERVAL_MS", 80)
	wsBlastMaxMs := envInt("FP_WS_MAX_MS", 13000)
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
	h2edgeJournalUnit := strings.TrimSpace(env("FP_H2EDGE_JOURNAL_UNIT", "fp-h2edge"))

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
		_, _ = w.Write([]byte(renderHTML(p, publicHost, wsPublicURL, wsFanout, wsPayloadBytes, wsIntervalMs, wsBlastMaxMs)))
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
			Token:            token,
			TargetIP:         targetIP,
			Path:             path,
			StartedAt:        time.Now(),
			DurS:             durS,
			UserOSLabel:      clampPcapUserLabel(r.URL.Query().Get("user_os"), 120),
			UserBrowserLabel: clampPcapUserLabel(r.URL.Query().Get("user_browser"), 120),
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

			completedAt := time.Now()
			jobsMu.Lock()
			if err != nil && ctx.Err() == nil {
				job.Err = strings.TrimSpace(stderr.String())
				if job.Err == "" {
					job.Err = err.Error()
				}
			}
			job.Ready = true
			job.EndedAt = completedAt

			// Cleanup old jobs (files are intentionally kept on disk).
			cutoff := time.Now().Add(-10 * time.Minute)
			for k, j := range jobs {
				if j.StartedAt.Before(cutoff) {
					delete(jobs, k)
				}
			}
			jobsMu.Unlock()

			logPath := strings.TrimSuffix(job.Path, ".pcap") + "-h2edge.log"
			writePcapH2EdgeLog(logPath, job.Token, job.StartedAt, job.EndedAt, h2edgeJournalUnit, job.TargetIP)
		}()

		// Wait until tcpdump is actually running to avoid races where the browser
		// reconnects (and sends ClientHello) before capture starts.
		//
		// We intentionally wait a bit longer than “feels necessary” because missing
		// the first TCP segment(s) of the ClientHello is enough for Wireshark to show
		// a different handshake than what edge captured in JSON.
		deadline := time.Now().Add(2 * time.Second)
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
		diskPcapName := filepath.Base(job.Path)
		fallbackStem := strings.TrimSuffix(diskPcapName, ".pcap")
		jsonPath := strings.TrimSuffix(job.Path, ".pcap") + "-api-all.json"
		stem := buildPcapDownloadStem(job, jsonPath, fallbackStem)
		pcapName := stem + ".pcap"
		if probe {
			writeJSON(w, map[string]any{"status": "ready", "token": token, "filename": pcapName})
			return
		}
		// Download filename: optional user labels + auto-detected OS/browser (see buildPcapDownloadStem); disk path unchanged.

		f, err := os.Open(job.Path)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": err.Error(), "token": token})
			return
		}
		defer f.Close()

		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition", attachmentContentDisposition(pcapName))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		if _, err := io.Copy(w, f); err != nil {
			log.Printf("pcap download copy: %v", err)
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

		job := &pcapJob{
			UserOSLabel:      clampPcapUserLabel(r.URL.Query().Get("user_os"), 120),
			UserBrowserLabel: clampPcapUserLabel(r.URL.Query().Get("user_browser"), 120),
		}
		brName, brVer := parseBrowser(r)
		osName, osVer := parseOS(r)
		stem := buildDownloadStemFromAuto(job.UserOSLabel, job.UserBrowserLabel, autoBrowserOS{brName, brVer, osName, osVer})
		filename := stem + ".pcap"
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition", attachmentContentDisposition(filename))
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

func stripCHQuotes(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	return strings.TrimSpace(s)
}

func headerFirstCI(h map[string][]string, want string) string {
	if h == nil {
		return ""
	}
	wl := strings.ToLower(want)
	for k, vs := range h {
		if strings.ToLower(k) == wl && len(vs) > 0 {
			return strings.TrimSpace(vs[0])
		}
	}
	return ""
}

// parseOSFromHeadersAndUA prefers Client Hints when present, but if only the platform name is
// sent (common: Sec-CH-UA-Platform without Sec-CH-UA-Platform-Version on first visit — the full
// version hint requires Accept-CH / a prior response), the version is taken from User-Agent
// (e.g. Windows NT 10.0 → 10.0).
func parseOSFromHeadersAndUA(h map[string][]string, ua string) (name, version string) {
	plat := stripCHQuotes(headerFirstCI(h, "Sec-CH-UA-Platform"))
	platVer := stripCHQuotes(headerFirstCI(h, "Sec-CH-UA-Platform-Version"))
	if plat == "" && platVer == "" {
		return parseOSFromUA(ua)
	}
	uaName, uaVer := parseOSFromUA(ua)
	name = plat
	version = platVer
	if name == "" {
		name = uaName
	}
	if version == "" {
		version = uaVer
	}
	return name, version
}

var (
	reOSWindowsNT = regexp.MustCompile(`Windows NT ([0-9.]+)`)
	reOSAndroid   = regexp.MustCompile(`Android ([0-9]+(?:\.[0-9]+)*)`)
	reOSIOS       = regexp.MustCompile(`(?:CPU iPhone OS|CPU OS|iPhone OS) ([0-9_]+)`)
	reOSMac       = regexp.MustCompile(`Mac OS X ([0-9_]+)`)
)

func parseOSFromUA(ua string) (name, version string) {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "", ""
	}
	if m := reOSWindowsNT.FindStringSubmatch(ua); len(m) >= 2 {
		return "Windows", m[1]
	}
	if m := reOSAndroid.FindStringSubmatch(ua); len(m) >= 2 {
		return "Android", m[1]
	}
	if m := reOSIOS.FindStringSubmatch(ua); len(m) >= 2 {
		return "iOS", strings.ReplaceAll(m[1], "_", ".")
	}
	if m := reOSMac.FindStringSubmatch(ua); len(m) >= 2 {
		return "macOS", strings.ReplaceAll(m[1], "_", ".")
	}
	if strings.Contains(ua, "Linux") {
		return "Linux", ""
	}
	return "", ""
}

func parseOS(r *http.Request) (name, version string) {
	return parseOSFromHeadersAndUA(r.Header, firstHeader(r, "User-Agent"))
}

func clampPcapUserLabel(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 {
		max = 120
	}
	r := []rune(s)
	if len(r) > max {
		s = string(r[:max])
	}
	return strings.TrimSpace(s)
}

// autoBrowserOS holds detected browser/OS strings for the "auto …" segment of download filenames.
type autoBrowserOS struct {
	brName, brVer, osName, osVer string
}

func parseAutoBrowserOSFromJSONFile(jsonPath string) (autoBrowserOS, bool) {
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		return autoBrowserOS{}, false
	}
	var snap struct {
		Request map[string]any      `json:"request"`
		Headers map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(b, &snap); err != nil {
		return autoBrowserOS{}, false
	}
	brName := strings.TrimSpace(asString(snap.Request["browser"]))
	brVer := strings.TrimSpace(asString(snap.Request["browser_version"]))
	ua := asString(snap.Request["user_agent"])
	if brName == "" {
		bn, bv := parseBrowserFromUA(ua)
		brName, brVer = bn, bv
	}
	osName, osVer := parseOSFromHeadersAndUA(snap.Headers, ua)
	return autoBrowserOS{brName, brVer, osName, osVer}, true
}

// pcapUserFieldOrNull returns the trimmed user input, or the literal "null" if empty.
func pcapUserFieldOrNull(s string) string {
	if strings.TrimSpace(s) == "" {
		return "null"
	}
	return strings.TrimSpace(s)
}

// buildDownloadStemFromAuto builds: [user OS or null], [user browser or null], auto <detected OS>, auto <detected browser>.
// Empty input fields are represented as the literal "null". Detected chunks are prefixed with "auto ".
func buildDownloadStemFromAuto(userOS, userBrowser string, auto autoBrowserOS) string {
	autoBr := strings.TrimSpace(strings.TrimSpace(auto.brName + " " + auto.brVer))
	autoOS := strings.TrimSpace(strings.TrimSpace(auto.osName + " " + auto.osVer))
	if autoBr == "" {
		autoBr = "unknown browser"
	}
	if autoOS == "" {
		autoOS = "unknown OS"
	}
	autoSeg := "auto " + autoOS + ", auto " + autoBr

	userSeg := pcapUserFieldOrNull(userOS) + ", " + pcapUserFieldOrNull(userBrowser)
	stem := userSeg + ", " + autoSeg
	return sanitizeDownloadFilename(stem)
}

func buildPcapDownloadStem(job *pcapJob, jsonPath, fallbackStem string) string {
	if job == nil {
		job = &pcapJob{}
	}
	auto, ok := parseAutoBrowserOSFromJSONFile(jsonPath)
	if !ok {
		stem := buildDownloadStemFromAuto(job.UserOSLabel, job.UserBrowserLabel, autoBrowserOS{"unknown browser", "", "unknown OS", ""})
		if stem == "" {
			return fallbackStem
		}
		return stem
	}
	stem := buildDownloadStemFromAuto(job.UserOSLabel, job.UserBrowserLabel, auto)
	if stem == "" {
		return fallbackStem
	}
	return stem
}

func sanitizeDownloadFilename(s string) string {
	s = strings.TrimSpace(s)
	repl := strings.NewReplacer(
		`/`, "-", `\`, "-", `:`, "-", `*`, "", `?`, "", `"`, "'", `<`, "", `>`, "", `|`, "-",
	)
	s = repl.Replace(s)
	var b strings.Builder
	for _, r := range s {
		if r < 32 || r == 127 {
			continue
		}
		b.WriteRune(r)
	}
	s = strings.TrimSpace(b.String())
	if len(s) > 240 {
		s = strings.TrimRight(s[:240], " .")
	}
	return s
}

func sanitizeASCIIFilenameFallback(filename string) string {
	var b strings.Builder
	for _, r := range filename {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '_', r == '.', r == ',', r == '(', r == ')':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), " ._")
	if out == "" {
		return ""
	}
	if len(out) > 120 {
		out = out[:120]
		out = strings.TrimRight(out, " ._")
	}
	return out
}

func attachmentContentDisposition(filename string) string {
	fb := sanitizeASCIIFilenameFallback(filename)
	if fb == "" {
		fb = "download.bin"
	}
	return `attachment; filename="` + fb + `"; filename*=UTF-8''` + url.PathEscape(filename)
}

// writePcapH2EdgeLog pulls fp-h2edge journal lines for this capture. Includes:
//   - lines with pcap_token=<token>
//   - h2 / ws access lines with ip=<TargetIP> (same client as tcpdump filter), so early requests
//     with pcap_token=- are still present when H2EDGE_ACCESS_LOG=1.
// Requires H2EDGE_ACCESS_LOG=1 / H2EDGE_WS_ACCESS_LOG=1 on edge for request lines.
func writePcapH2EdgeLog(outPath, token string, startedAt, endedAt time.Time, unit, targetIP string) {
	if strings.TrimSpace(unit) == "" {
		unit = "fp-h2edge"
	}
	if endedAt.IsZero() {
		endedAt = startedAt.Add(5 * time.Minute)
	}
	journalctl := "/usr/bin/journalctl"
	if _, err := os.Stat(journalctl); err != nil {
		journalctl = "journalctl"
	}
	// Wide window: __close navigation before start; traffic may finish slightly after tcpdump.
	since := startedAt.Add(-4 * time.Minute)
	until := endedAt.Add(5 * time.Minute)
	args := []string{
		"-u", unit,
		"--since", since.Format("2006-01-02 15:04:05"),
		"--until", until.Format("2006-01-02 15:04:05"),
		"-o", "short-precise",
		"--no-pager",
	}
	cmd := exec.Command(journalctl, args...)
	out, jErr := cmd.CombinedOutput()
	needleTok := "pcap_token=" + token

	var matched []string
	seen := map[string]struct{}{}
	if jErr == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimRight(line, "\r")
			if line == "" {
				continue
			}
			if !h2edgeJournalLineWanted(line, needleTok, targetIP) {
				continue
			}
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			matched = append(matched, line)
		}
	}

	var sb strings.Builder
	sb.WriteString("# fp-h2edge journal snippet (capture token ")
	sb.WriteString(token)
	sb.WriteString(", target ip ")
	sb.WriteString(targetIP)
	sb.WriteString(")\n# window: ")
	sb.WriteString(since.UTC().Format(time.RFC3339))
	sb.WriteString(" .. ")
	sb.WriteString(until.UTC().Format(time.RFC3339))
	sb.WriteString(" UTC\n")
	sb.WriteString("# Includes: pcap_token=<token> OR ((\" h2 \" or \" ws ip=\") AND ip=<TargetIP>).\n")
	if jErr != nil {
		sb.WriteString("# journalctl failed: ")
		sb.WriteString(jErr.Error())
		sb.WriteString("\n")
		if len(out) > 0 {
			sb.WriteString(string(out))
			if out[len(out)-1] != '\n' {
				sb.WriteByte('\n')
			}
		}
	}
	for _, line := range matched {
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	if jErr == nil && len(matched) == 0 {
		sb.WriteString("# No lines matched. Enable H2EDGE_ACCESS_LOG=1 (and H2EDGE_WS_ACCESS_LOG=1 for WS).\n")
		sb.WriteString("# Token-only lines need /?pcap_token=" + token + " on the H2 connection.\n")
	}
	_ = os.WriteFile(outPath, []byte(sb.String()), 0o600)
}

func h2edgeJournalLineWanted(line, needleTok, targetIP string) bool {
	if strings.Contains(line, needleTok) {
		return true
	}
	if targetIP == "" {
		return false
	}
	ipTag := "ip=" + targetIP
	idx := strings.Index(line, ipTag)
	if idx < 0 {
		return false
	}
	tail := line[idx+len(ipTag):]
	if len(tail) > 0 && tail[0] != ' ' && tail[0] != '\t' {
		return false
	}
	if strings.Contains(line, " h2 ") {
		return true
	}
	// WS access line: "... ws ip=..." (no space between ws and ip)
	if strings.Contains(line, " ws ip=") {
		return true
	}
	return false
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

	brName, brVer := parseBrowser(r)

	tls := map[string]any{
		"ja4":         edgeHeader("X-JA4"),
		"ja3":         edgeHeaderAnyCase("JA3"), // edge sets request header "JA3"
		"http_fp":     edgeHeader("X-HTTP-FP"),
		"remote_addr": edgeHeader("X-TLS-Remote-Addr"),
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
		"h2_frame_log":            mustJSONArr(edgeHeader("X-H2-Frame-Log")),
		"h2_frame_log_truncated":  edgeHeader("X-H2-Frame-Log-Truncated"),
		"h2_frame_total":          edgeHeader("X-H2-Frame-Total"),
		"version":     edgeHeader("X-TLS-Version"),
		"cipher_suite": edgeHeader("X-TLS-Cipher"),
		"alpn":        edgeHeader("X-TLS-Proto"),
		"resumed":     edgeHeader("X-TLS-Resumed"),
		"server_name": edgeHeader("X-TLS-SNI"),
	}

	handshake := map[string]any{
		"client_hello_record_b64":          edgeHeader("X-TLS-ClientHello-Record-B64"),
		"client_hello_record_len":          edgeHeader("X-TLS-ClientHello-Record-Len"),
		"client_hello_record_hex_prefix":   edgeHeader("X-TLS-ClientHello-Record-Hex"),
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

	edgeTiming := map[string]any{}
	if v := strings.TrimSpace(edgeHeader("X-Edge-Request-Start-Unix")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			edgeTiming["request_start_unix_ns"] = n
		}
	}
	if v := strings.TrimSpace(edgeHeader("X-Edge-Request-Interval-MS")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			edgeTiming["request_interval_ms"] = n
		}
	}
	if v := strings.TrimSpace(edgeHeader("X-Edge-Prev-TTFB-MS")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			edgeTiming["prev_ttfb_ms"] = n
		}
	}

	// Sort request headers for readability in UI.
	hdrs := map[string][]string{}
	for k, v := range r.Header {
		hdrs[k] = v
	}

	osName, osVer := parseOSFromHeadersAndUA(hdrs, firstHeader(r, "User-Agent"))

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
		"user_agent":      firstHeader(r, "User-Agent"),
		"browser":         brName,
		"browser_version": brVer,
		"os_name":         osName,
		"os_version":      osVer,
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
			"edge_timing":     edgeTiming,
			"trusted_proxy": map[string]any{
				"ok":    proxyTrusted,
				"cidrs": trusted.raw,
			},
		},
	}
}

func renderHTML(p Payload, publicHost string, wsPublicURL string, wsFanout int, wsPayloadBytes int, wsIntervalMs int, wsBlastMaxMs int) string {
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
	edgeTiming := asMap(p.Extra["edge_timing"])

	hostForTitle := strings.TrimSpace(publicHost)
	if hostForTitle == "" {
		hostForTitle = asString(p.Request["host"])
	}
	if hostForTitle == "" {
		hostForTitle = "localhost"
	}

	autoOSLabel := joinNameVer(asString(p.Request["os_name"]), asString(p.Request["os_version"]))
	autoBrLabel := joinNameVer(asString(p.Request["browser"]), asString(p.Request["browser_version"]))

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
      table { width: 100%; border-collapse: collapse; table-layout: fixed; }
      td { padding: 10px 12px; vertical-align: top; border-bottom: 1px solid rgba(127,127,127,.18); }
      td.k { width: 34%; min-width: 160px; font-weight: 650; opacity: .9; }
      td.v {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: 12.5px;
        white-space: normal;
        overflow-wrap: anywhere;
        word-break: break-word;
      }
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
      .pcap-labels { display: grid; gap: 10px; margin-top: 12px; width: 100%; max-width: 520px; }
      .pcap-field { display: flex; flex-direction: column; gap: 4px; align-items: flex-start; }
      .pcap-field label { font-size: 12.5px; font-weight: 650; opacity: .95; }
      .pcap-field input[type="text"] {
        width: 100%; max-width: 480px; box-sizing: border-box;
        border: 1px solid rgba(127,127,127,.35); background: transparent; color: inherit;
        border-radius: 10px; padding: 8px 10px; font-size: 13px;
      }
      .pcap-field input[type="text"]::placeholder { opacity: .55; }
      .pcap-field input[type="text"]:focus { outline: 2px solid color-mix(in oklab, Highlight, transparent 55%); outline-offset: 2px; }
      .pcap-hint { font-size: 13.5px; opacity: .9; line-height: 1.5; }
      .pcap-hint-block { display: block; max-width: 520px; margin-top: 2px; }
      .pcap-hint-block strong { font-weight: 650; opacity: .95; }
      .pcap-hint-lead {
        color: #ff0000;
        font-weight: 750;
        margin-right: 2px;
      }
      @media (prefers-color-scheme: dark) {
        .pcap-hint-lead { color: #ff5252; }
      }
      .pcap-auto-copy {
        margin-left: 4px;
        display: inline-block;
        vertical-align: baseline;
        font: inherit;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: 12.5px;
        cursor: pointer;
        border: 1px solid rgba(127,127,127,.4);
        border-radius: 8px;
        padding: 2px 8px 3px;
        background: color-mix(in oklab, canvas, transparent 6%);
        color: inherit;
      }
      .pcap-auto-copy:hover { border-color: rgba(127,127,127,.65); }
      .pcap-auto-copy:focus { outline: 2px solid color-mix(in oklab, Highlight, transparent 55%); outline-offset: 2px; }
      .pcap-auto-copy.pcap-copied { border-color: color-mix(in oklab, Highlight, transparent 35%); }
      .pcap-auto-placeholder { opacity: .65; font-style: italic; }
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
      pre.json-block { max-height: 280px; margin: 0; padding: 12px 14px; overflow: auto; font-size: 12px; line-height: 1.45; }
      section.subhint { padding: 0 14px 12px 14px; font-size: 12px; opacity: .8; border-top: 1px solid rgba(127,127,127,.12); }
      details.fold { margin: 0; }
      details.fold > summary {
        list-style: none;
        cursor: pointer;
        user-select: none;
        padding: 12px 14px;
        font-weight: 800;
        font-size: 16px;
        border-bottom: 1px solid rgba(127,127,127,.18);
        display: flex;
        align-items: center;
        gap: 10px;
      }
      details.fold > summary::-webkit-details-marker { display: none; }
      details.fold > summary::before {
        content: "▸";
        width: 14px;
        opacity: .85;
        transform: translateY(-1px);
      }
      details.fold[open] > summary::before { content: "▾"; }
      details.fold > .fold-body { padding: 10px 14px 12px 14px; }
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
        const wsFanout = ` + strconv.Itoa(clampInt(wsFanout, 1, 50)) + `;
        const wsPayloadBytes = ` + strconv.Itoa(clampInt(wsPayloadBytes, 1, 1<<20)) + `;
        const wsIntervalMs = ` + strconv.Itoa(clampInt(wsIntervalMs, 10, 2000)) + `;
        const wsMaxMs = ` + strconv.Itoa(clampInt(wsBlastMaxMs, 500, 120000)) + `;
        let st = null;

        function filenameFromDisposition(cd) {
          if (!cd) return '';
          const m = /filename="?([^"]+)"?/i.exec(cd);
          return m ? m[1] : '';
        }

        function wsUrl() {
          const sp = new URLSearchParams(location.search);
          const pt = sp.get('pcap_token');
          if (wsPublicUrl) {
            try {
              const u = new URL(wsPublicUrl);
              if (pt) u.searchParams.set('pcap_token', pt);
              return u.toString();
            } catch (_) {
              return wsPublicUrl;
            }
          }
          const h = location.hostname;
          const wsPort = '8443';
          const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
          const u = new URL(proto + '//' + h + ':' + wsPort + '/ws');
          if (pt) u.searchParams.set('pcap_token', pt);
          return u.toString();
        }

        async function triggerWsProbe() {
          try { await fetch('/ws', { cache: 'no-store' }); } catch (_) {}
        }

        function makePayload(n) {
          const base = 'pcap-ping-' + Date.now() + '-';
          if (n <= base.length) return base.slice(0, n);
          const need = n - base.length;
          return base + 'x'.repeat(need);
        }

        function triggerWsHandshake() {
          return new Promise((resolve) => {
            const maxMs = wsMaxMs;
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
                try { ws.send(makePayload(wsPayloadBytes)); } catch (_) {}
              }, 400);
            };
            ws.onerror = () => { if (iv) clearInterval(iv); clearTimeout(t); resolve(); };
            ws.onclose = () => { if (iv) clearInterval(iv); clearTimeout(t); resolve(); };
          });
        }

        function triggerWsBlast() {
          // Open multiple parallel sockets and send larger payloads frequently.
          const conns = [];
          const payload = makePayload(wsPayloadBytes);
          const maxMs = wsMaxMs;
          const n = wsFanout;
          return new Promise((resolve) => {
            let alive = 0;
            let done = false;
            const finish = () => {
              if (done) return;
              done = true;
              for (const c of conns) {
                try { if (c.iv) clearInterval(c.iv); } catch (_) {}
                try { c.ws.close(); } catch (_) {}
              }
              resolve();
            };

            const t = setTimeout(finish, maxMs);
            for (let i = 0; i < n; i++) {
              let ws;
              try {
                ws = new WebSocket(wsUrl());
              } catch (_) {
                continue;
              }
              const c = { ws, iv: null };
              conns.push(c);
              ws.onopen = () => {
                alive++;
                c.iv = setInterval(() => {
                  try { ws.send(payload); } catch (_) {}
                }, wsIntervalMs);
              };
              ws.onerror = () => {};
              ws.onclose = () => {
                try { if (c.iv) clearInterval(c.iv); } catch (_) {}
              };
            }
            // Even if some sockets fail to open, still run for the duration.
            // Keep the timer; finish() will close everything.
            void alive;
            void t;
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
          const pcapUserOs = document.getElementById('pcap_user_os');
          const pcapUserBr = document.getElementById('pcap_user_browser');
          st = document.getElementById('pcap_status');
          if (!btn || !dur || !st) return;

          (function bindPcapAutoCopy() {
            const root = document.querySelector('.pcap-labels');
            if (!root) return;
            root.addEventListener('click', function(ev) {
              const el = ev.target.closest('.pcap-auto-copy');
              if (!el) return;
              ev.preventDefault();
              const txt = (el.textContent || '').replace(/\s+/g, ' ').trim();
              if (!txt) return;
              const tgt = el.getAttribute('data-pcap-fill');
              if (tgt === 'os') {
                const inp = document.getElementById('pcap_user_os');
                if (inp) inp.value = txt;
              } else if (tgt === 'browser') {
                const inp = document.getElementById('pcap_user_browser');
                if (inp) inp.value = txt;
              }
              if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(txt).then(function() {
                  el.classList.add('pcap-copied');
                  setTimeout(function() { el.classList.remove('pcap-copied'); }, 900);
                }).catch(function() {
                  el.classList.add('pcap-copied');
                  setTimeout(function() { el.classList.remove('pcap-copied'); }, 900);
                });
              } else {
                el.classList.add('pcap-copied');
                setTimeout(function() { el.classList.remove('pcap-copied'); }, 900);
              }
            });
          })();

          // If page loaded with a token, poll and download automatically.
          const sp = new URLSearchParams(location.search);
          const tokenOnLoad = sp.get('pcap_token');
          if (tokenOnLoad) {
            btn.disabled = true;
            st.textContent = 'capturing...';
            // If we just navigated via /__close (pcap_step=1), close once more quickly
            // to maximize the chance that the token request and subsequent traffic are on
            // a fresh TCP/TLS connection captured from the start.
            const step = sp.get('pcap_step');
            if (step === '1') {
              sp.set('pcap_step', '2');
              const next2 = location.pathname + '?' + sp.toString() + location.hash;
              setTimeout(() => navClose(next2), 350);
            } else if (step === '2') {
              // Clean up the helper param; keep token.
              sp.delete('pcap_step');
              const next = location.pathname + '?' + sp.toString() + location.hash;
              history.replaceState(null, '', next);
            }
            // While capture is running, trigger /ws from the client so WS traffic appears in pcap.
            Promise.resolve()
              .then(() => triggerWsProbe())
              .then(() => triggerWsBlast())
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
              .then(() => triggerWsBlast())
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
              const qs = new URLSearchParams();
              qs.set('dur_s', String(durS));
              const uo = pcapUserOs && String(pcapUserOs.value || '').trim();
              const ub = pcapUserBr && String(pcapUserBr.value || '').trim();
              if (uo) qs.set('user_os', uo);
              if (ub) qs.set('user_browser', ub);
              const resp = await fetch('/api/pcap/start?' + qs.toString(), { cache: 'no-store' });
              if (!resp.ok) throw new Error('HTTP ' + resp.status);
              const j = await resp.json();
              if (!j || !j.token) throw new Error('bad response');
              st.textContent = 'reconnecting...';
              // Small client-side delay as an extra safety net: even if /api/pcap/start
              // returned, browsers can be very fast to reuse/establish connections.
              await new Promise(r => setTimeout(r, 400));
              const sp2 = new URLSearchParams(location.search);
              sp2.set('pcap_token', j.token);
              // Force a second close shortly after the first navigation to reduce the chance
              // that the token request lands on an already-established connection that started
              // before tcpdump began writing.
              sp2.set('pcap_step', '1');
              const next1 = location.pathname + '?' + sp2.toString() + location.hash;
              navClose(next1);
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
            Нажимая <code>Capture .pcap</code>, вы запускаете серверный <code>tcpdump</code>. Будет сохранён <code>.pcap</code> с пакетами TCP/443 для вашего IP за выбранное время, рядом на сервере — снапшот <code>/api/all</code> (headers и fingerprints: JA3/JA4, TLS/ClientHello, H2/HTTP, p0f, TTL) и фрагмент journal <code>fp-h2edge</code> с вашим <code>pcap_token</code> (нужны <code>H2EDGE_ACCESS_LOG=1</code> на edge). Скачивание отдаёт только <code>.pcap</code>. Файлы сохраняются на сервере в <code>FP_PCAP_SAVE_DIR</code>.
          </div>
          <div class="pcap-labels">
            <div class="pcap-field">
              <label for="pcap_user_os">Операционная система и её версия</label>
              <input type="text" id="pcap_user_os" name="user_os" maxlength="120" autocomplete="off" placeholder="например: Windows 11" />
              <span class="pcap-hint pcap-hint-block"><span class="pcap-hint-lead">Как вводить:</span> укажите систему и номер версии <strong>полностью</strong>, вплоть до последнего значащего знака (как в сведениях об ОС: <code>winver</code>, <code>sw_vers</code>, <code>uname -a</code>). <strong>Авто по этому запросу</strong> — нажмите, чтобы подставить в поле (и в буфер обмена): ` + pcapHintAutoChip(autoOSLabel, "os") + `</span>
            </div>
            <div class="pcap-field">
              <label for="pcap_user_browser">Браузер и его версия</label>
              <input type="text" id="pcap_user_browser" name="user_browser" maxlength="120" autocomplete="off" placeholder="например: Chrome 131" />
              <span class="pcap-hint pcap-hint-block"><span class="pcap-hint-lead">Как вводить:</span> укажите браузер и версию <strong>полностью</strong>, вплоть до последнего знака в номере (как в «О браузере» / <code>chrome://version</code> и т.п.). <strong>Авто по этому запросу</strong> — нажмите, чтобы подставить в поле (и в буфер обмена): ` + pcapHintAutoChip(autoBrLabel, "browser") + `</span>
            </div>
          </div>
          <div class="actions">
            <label class="status" for="pcap_dur">pcap:</label>
            <select id="pcap_dur" aria-label="pcap duration seconds">
              <option value="1">1s</option>
              <option value="2">2s</option>
              <option value="3">3s</option>
              <option value="5" selected>5s</option>
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
          <h2>TLS (agreed session)</h2>
          <table>
            <tr><td class="k">JA4</td><td class="v">` + htmlEscape(asString(p.TLS["ja4"])) + `</td></tr>
            <tr><td class="k">JA3</td><td class="v">` + htmlEscape(asString(p.TLS["ja3"])) + `</td></tr>
            <tr><td class="k">TLS remote (ip:port)</td><td class="v">` + htmlEscape(asString(p.TLS["remote_addr"])) + `</td></tr>
            <tr><td class="k">TLS version</td><td class="v">` + htmlEscape(asString(p.TLS["version"])) + `</td></tr>
            <tr><td class="k">Cipher suite</td><td class="v">` + htmlEscape(asString(p.TLS["cipher_suite"])) + `</td></tr>
            <tr><td class="k">ALPN (agreed)</td><td class="v">` + htmlEscape(asString(p.TLS["alpn"])) + `</td></tr>
            <tr><td class="k">Resumed</td><td class="v">` + htmlEscape(asString(p.TLS["resumed"])) + `</td></tr>
            <tr><td class="k">SNI (agreed)</td><td class="v">` + htmlEscape(asString(p.TLS["server_name"])) + `</td></tr>
          </table>
          <div class="hint" style="padding: 0 14px 14px 14px;">HTTP/3 отключён, чтобы сохранять согласованный TLS/ALPN и ClientHello.</div>
        </section>

        <section>
          <h2>HTTP (application layer)</h2>
          <table>
            <tr><td class="k">HTTP fp</td><td class="v">` + htmlEscape(asString(p.TLS["http_fp"])) + `</td></tr>
            <tr><td class="k">Method</td><td class="v">` + htmlEscape(asString(p.Request["method"])) + `</td></tr>
            <tr><td class="k">Host</td><td class="v">` + htmlEscape(asString(p.Request["host"])) + `</td></tr>
            <tr><td class="k">URI</td><td class="v">` + htmlEscape(asString(p.Request["uri"])) + `</td></tr>
            <tr><td class="k">Proto (client)</td><td class="v">` + htmlEscape(asString(p.Request["proto"])) + `</td></tr>
            <tr><td class="k">Browser</td><td class="v">` + htmlEscape(asString(p.Request["browser"])) + ` ` + htmlEscape(asString(p.Request["browser_version"])) + `</td></tr>
            <tr><td class="k">User-Agent</td><td class="v">` + htmlEscape(asString(p.Request["user_agent"])) + `</td></tr>
            <tr><td class="k">Accept</td><td class="v">` + htmlEscape(asString(p.Request["accept"])) + `</td></tr>
            <tr><td class="k">Accept-Language</td><td class="v">` + htmlEscape(asString(p.Request["accept_lang"])) + `</td></tr>
            <tr><td class="k">Accept-Encoding</td><td class="v">` + htmlEscape(asString(p.Request["accept_enc"])) + `</td></tr>
          </table>
          <div class="subhint">Хэш <code>X-HTTP-FP</code> считается на edge до инъекции <code>X-H2-*</code> / <code>JA3</code> (см. <code>fp-h2edge</code>).</div>
        </section>
      </div>

      <section>
        <h2>HTTP/2 (frame-level, edge)</h2>
        <table>
          <tr><td class="k">H2 fp</td><td class="v">` + htmlEscape(asString(p.TLS["h2_fp"])) + `</td></tr>
          <tr><td class="k">Frames (total seen)</td><td class="v">` + htmlEscape(asString(p.TLS["h2_frame_total"])) + `</td></tr>
          <tr><td class="k">Priority frames</td><td class="v">` + htmlEscape(asString(p.TLS["h2_priority_frames"])) + `</td></tr>
          <tr><td class="k">Frame log truncated</td><td class="v">` + htmlEscape(asString(p.TLS["h2_frame_log_truncated"])) + `</td></tr>
        </table>
        <div class="hint" style="padding: 8px 14px 4px 14px;">SETTINGS / WINDOW_UPDATE / inbound frame log — снимаются на <code>fp-h2edge</code> в начале соединения (см. <code>H2EDGE_H2_*</code>).</div>
        <pre class="json-block">` + htmlEscape("settings:\n"+prettyJSON(p.TLS["h2_settings"])+"\n\nwindow_incr:\n"+prettyJSON(p.TLS["h2_window_incr"])+"\n\nframe_log:\n"+prettyJSON(p.TLS["h2_frame_log"])) + `</pre>
      </section>

      <section>
        <h2>Edge timing</h2>
        <table>
          <tr><td class="k">Request start (unix ns)</td><td class="v">` + htmlEscape(asString(edgeTiming["request_start_unix_ns"])) + `</td></tr>
          <tr><td class="k">Since previous response ended (ms)</td><td class="v">` + htmlEscape(asString(edgeTiming["request_interval_ms"])) + `</td></tr>
          <tr><td class="k">Previous request TTFB (ms)</td><td class="v">` + htmlEscape(asString(edgeTiming["prev_ttfb_ms"])) + `</td></tr>
        </table>
        <div class="hint" style="padding: 0 14px 14px 14px;">Заголовки задаёт <code>fp-h2edge</code> на проксируемом запросе. Интервал — от конца предыдущего ответа edge до начала этого запроса на том же TCP-соединении. TTFB текущего ответа к клиенту — заголовок ответа <code>X-Edge-TTFB-MS</code>.</div>
      </section>

      <div class="grid">
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
          <h2>Connection / routing</h2>
          <table>
            <tr><td class="k">Proto (upstream hop)</td><td class="v">` + htmlEscape(asString(p.Request["proto_upstream"])) + `</td></tr>
            <tr><td class="k">ALPN (client, outer TLS)</td><td class="v">` + htmlEscape(asString(p.Request["proto_client_alpn"])) + `</td></tr>
            <tr><td class="k">Remote</td><td class="v">` + htmlEscape(asString(p.Request["remote_ip"])) + `:` + htmlEscape(asString(p.Request["remote_port"])) + `</td></tr>
            <tr><td class="k">Client IP</td><td class="v">` + htmlEscape(asString(p.Request["client_ip"])) + `</td></tr>
            <tr><td class="k">X-Forwarded-For</td><td class="v">` + htmlEscape(asString(p.Request["xff"])) + `</td></tr>
            <tr><td class="k">CF-Connecting-IP</td><td class="v">` + htmlEscape(asString(p.Request["cf_ip"])) + `</td></tr>
            <tr><td class="k">True-Client-IP</td><td class="v">` + htmlEscape(asString(p.Request["true_client"])) + `</td></tr>
            <tr><td class="k">Via</td><td class="v">` + htmlEscape(asString(p.Request["via"])) + `</td></tr>
            <tr><td class="k">Forwarded</td><td class="v">` + htmlEscape(asString(p.Request["forwarded"])) + `</td></tr>
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

      <section>
        <details class="fold">
          <summary>Raw headers</summary>
          <div class="fold-body"><pre>` + htmlEscape(string(prettyHdr)) + `</pre></div>
        </details>
      </section>
      <section>
        <details class="fold">
          <summary>All collected data (JSON)</summary>
          <div class="fold-body"><pre>` + htmlEscape(string(prettyAll)) + `</pre></div>
        </details>
      </section>
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

func parseBrowser(r *http.Request) (name string, version string) {
	uaName, uaVer := parseBrowserFromUA(firstHeader(r, "User-Agent"))
	chName, chVer := parseBrowserFromCH(r)

	if chName == "" {
		return uaName, uaVer
	}
	// If CH only tells us "Chromium"/"Chrome" but UA has a more specific brand
	// (Opera/Edge/YaBrowser), prefer the UA result.
	switch strings.ToLower(strings.TrimSpace(chName)) {
	case "chromium", "chrome", "google chrome":
		switch strings.ToLower(strings.TrimSpace(uaName)) {
		case "opera", "edge", "yabrowser":
			if uaVer != "" {
				return uaName, uaVer
			}
		}
	}
	return chName, chVer
}

func parseBrowserFromCH(r *http.Request) (name string, version string) {
	// Chromium-based browsers often provide brand/version info via Client Hints.
	// We accept either full version list or the basic Sec-CH-UA list.
	full := strings.TrimSpace(firstHeaderAnyCase(r, "Sec-CH-UA-Full-Version-List"))
	if full == "" {
		full = strings.TrimSpace(firstHeaderAnyCase(r, "Sec-Ch-Ua-Full-Version-List"))
	}
	if full != "" {
		// Example:
		//  "Not(A:Brand";v="8", "Chromium";v="144", "YaBrowser";v="26.3"
		type bv struct{ b, v string }
		pairs := parseCHBrandVersions(full)
		if n, v := pickBestBrowserPair(pairs); n != "" {
			return n, v
		}
	}

	ua := strings.TrimSpace(firstHeaderAnyCase(r, "Sec-CH-UA"))
	if ua == "" {
		ua = strings.TrimSpace(firstHeaderAnyCase(r, "Sec-Ch-Ua"))
	}
	if ua != "" {
		// Basic list has brands but version is often truncated.
		pairs := parseCHBrandVersions(ua)
		if n, v := pickBestBrowserPair(pairs); n != "" {
			return n, v
		}
	}
	return "", ""
}

func parseCHBrandVersions(s string) []struct{ b, v string } {
	// Parse `"Brand";v="123"` pairs.
	re := regexp.MustCompile(`"([^"]+)"\s*;\s*v="([^"]+)"`)
	m := re.FindAllStringSubmatch(s, -1)
	out := make([]struct{ b, v string }, 0, len(m))
	for _, mm := range m {
		if len(mm) < 3 {
			continue
		}
		b := strings.TrimSpace(mm[1])
		v := strings.TrimSpace(mm[2])
		if b == "" {
			continue
		}
		out = append(out, struct{ b, v string }{b: b, v: v})
	}
	return out
}

func pickBestBrowserPair(pairs []struct{ b, v string }) (name, version string) {
	// Prefer “real” brands over GREASE-like placeholders.
	// Order tuned for this project (Yandex is common in your traffic).
	prefer := []string{
		"YaBrowser",
		"Yandex",
		"Yandex Browser",
		"Google Chrome",
		"Chrome",
		"Chromium",
		"Microsoft Edge",
		"Edge",
		"Opera",
		"Firefox",
		"Safari",
	}

	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	byNorm := map[string]struct{ b, v string }{}
	for _, p := range pairs {
		byNorm[norm(p.b)] = p
	}
	for _, p := range prefer {
		if v, ok := byNorm[norm(p)]; ok {
			return v.b, v.v
		}
	}
	// As a last resort, pick first non-placeholder.
	for _, p := range pairs {
		bn := norm(p.b)
		if strings.Contains(bn, "not") && strings.Contains(bn, "brand") {
			continue
		}
		return p.b, p.v
	}
	return "", ""
}

func parseBrowserFromUA(ua string) (name string, version string) {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "", ""
	}
	// Order matters.
	type rule struct {
		name string
		re   *regexp.Regexp
	}
	rules := []rule{
		{name: "YaBrowser", re: regexp.MustCompile(`\bYaBrowser/([0-9]+(?:\.[0-9]+)*)`)},
		{name: "Edge", re: regexp.MustCompile(`\bEdg/([0-9]+(?:\.[0-9]+)*)`)},
		{name: "Opera", re: regexp.MustCompile(`\bOPR/([0-9]+(?:\.[0-9]+)*)`)},
		{name: "Firefox", re: regexp.MustCompile(`\bFirefox/([0-9]+(?:\.[0-9]+)*)`)},
		// Safari on iOS/macOS usually has Version/x.y and Safari/…
		{name: "Safari", re: regexp.MustCompile(`\bVersion/([0-9]+(?:\.[0-9]+)*)\b.*\bSafari/`)},
		{name: "Chrome", re: regexp.MustCompile(`\bChrome/([0-9]+(?:\.[0-9]+)*)`)},
	}
	for _, rr := range rules {
		m := rr.re.FindStringSubmatch(ua)
		if len(m) >= 2 {
			return rr.name, m[1]
		}
	}
	return "", ""
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

// mustJSONArr parses a JSON array (e.g. H2 frame log from edge).
func mustJSONArr(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []any
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

func joinNameVer(name, ver string) string {
	name = strings.TrimSpace(name)
	ver = strings.TrimSpace(ver)
	switch {
	case name == "" && ver == "":
		return ""
	case ver == "":
		return name
	case name == "":
		return ver
	default:
		return name + " " + ver
	}
}

// pcapHintAutoChip renders a chip for auto-detected OS or browser; field is "os" or "browser" for data-pcap-fill.
func pcapHintAutoChip(nameVer, field string) string {
	nameVer = strings.TrimSpace(nameVer)
	if nameVer == "" {
		return `<span class="pcap-auto-placeholder" title="Не удалось автоопределить на этом запросе">нет данных</span>`
	}
	if field != "os" && field != "browser" {
		field = "os"
	}
	return `<button type="button" class="pcap-auto-copy" data-pcap-fill="` + field + `" title="Подставить автоопределённое значение в поле ввода">` + htmlEscape(nameVer) + `</button>`
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

func envInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
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
		return map[string]any{"ok": false, "reason": "empty_ip"}
	}
	base := env("TTL_API", "http://127.0.0.1:9100")
	url := base + "/api/ttl/ip/" + ip

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return map[string]any{"ip": ip, "ok": false, "reason": "ttl_api_error", "error": err.Error()}
	}
	defer resp.Body.Close()

	var obj map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return map[string]any{"ip": ip, "ok": false, "reason": "ttl_api_bad_json", "error": err.Error()}
	}
	if v, ok := obj["ttl"]; ok {
		// netagent returns {"ttl": null} when it has no data for this IP yet.
		if v == nil {
			return map[string]any{"ip": ip, "ok": false, "reason": "no_data_yet"}
		}
		return map[string]any{"ip": ip, "ok": true, "ttl": v}
	}
	return map[string]any{"ip": ip, "ok": false, "reason": "unexpected_response", "raw": obj}
}

func prettyJSON(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		b, _ = json.Marshal(v)
	}
	return string(b)
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

