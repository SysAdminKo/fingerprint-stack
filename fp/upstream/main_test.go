package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTcpdumpHostPortFilter(t *testing.T) {
	t.Parallel()
	got := tcpdumpHostPortFilter("203.0.113.5", "")
	want := []string{"tcp", "and", "host", "203.0.113.5", "and", "(", "port", "443", "or", "port", "8443", ")"}
	if len(got) != len(want) {
		t.Fatalf("len %d vs %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("i=%d got %q want %q", i, got[i], want[i])
		}
	}
	got2 := tcpdumpHostPortFilter("10.0.0.1", "8080, 443 ,8080")
	if !strings.Contains(strings.Join(got2, " "), "8080") {
		t.Fatalf("extra port: %v", got2)
	}
}

func TestH2edgeJournalLineWanted(t *testing.T) {
	t.Parallel()
	tok := "pcap_token=abc123def"
	lineH2 := `Apr 6 12:00:00 h fp-h2edge[1]: 2026/04/06 12:00:00 h2 GET / ip=198.51.100.2 status=200 bytes=1 dur_ms=1 interval_ms=0 prev_ttfb_ms=0 ttfb_ms=1 pcap_token=- ua="x"`
	if !h2edgeJournalLineWanted(lineH2, tok, "198.51.100.2") {
		t.Fatal("expected ip match for h2")
	}
	if h2edgeJournalLineWanted(lineH2, tok, "198.51.100.20") {
		t.Fatal("prefix IP must not match")
	}
	lineTok := `h2 GET / pcap_token=abc123def`
	if !h2edgeJournalLineWanted(lineTok, tok, "1.2.3.4") {
		t.Fatal("token match alone")
	}
	lineWS := `Apr 6 12:00:00 h fp-h2edge[1]: 2026/04/06 12:00:00 ws ip=198.51.100.2 ua= fp= dur_ms=1 frames_in=1 bytes_in=1 frames_out=1 bytes_out=1 close=true pcap_token=- err=""`
	if !h2edgeJournalLineWanted(lineWS, tok, "198.51.100.2") {
		t.Fatal("ws line")
	}
	if h2edgeJournalLineWanted(`listening on`, tok, "198.51.100.2") {
		t.Fatal("noise")
	}
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	t.Parallel()
	tr := parseTrustedProxyCIDRs("")
	if !tr.isTrusted("127.0.0.1") || !tr.isTrusted("::1") {
		t.Fatal("defaults")
	}
	tr2 := parseTrustedProxyCIDRs("192.0.2.0/24, bad, 2001:db8::/32")
	if !tr2.isTrusted("192.0.2.7") || tr2.isTrusted("192.0.3.1") {
		t.Fatal("custom cidr")
	}
	if tr2.isTrusted("") || tr2.isTrusted("not-an-ip") {
		t.Fatal("invalid ip")
	}
}

func TestSplitHostPort(t *testing.T) {
	t.Parallel()
	h, p := splitHostPort("10.0.0.2:9000")
	if h != "10.0.0.2" || p != "9000" {
		t.Fatal(h, p)
	}
	h2, p2 := splitHostPort("nocolon")
	if h2 != "nocolon" || p2 != "" {
		t.Fatal(h2, p2)
	}
}

func TestFirstClientIP(t *testing.T) {
	t.Parallel()
	if firstClientIP("10.0.0.1", "  198.51.100.1 , 8.8.8.8") != "198.51.100.1" {
		t.Fatal()
	}
	if firstClientIP("10.0.0.1", "") != "10.0.0.1" {
		t.Fatal()
	}
}

func TestFirstHeaderAnyCase(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("ja3", "lowercase-key")
	if firstHeaderAnyCase(r, "JA3") != "lowercase-key" {
		t.Fatal()
	}
}

func TestClampInt(t *testing.T) {
	t.Parallel()
	if clampInt(5, 10, 20) != 10 || clampInt(25, 10, 20) != 20 || clampInt(15, 10, 20) != 15 {
		t.Fatal()
	}
}

func TestEnvInt(t *testing.T) {
	t.Setenv("FP_TEST_INT", "")
	if envInt("FP_TEST_INT", 7) != 7 {
		t.Fatal()
	}
	t.Setenv("FP_TEST_INT", "42")
	if envInt("FP_TEST_INT", 7) != 42 {
		t.Fatal()
	}
	t.Setenv("FP_TEST_INT", "nope")
	if envInt("FP_TEST_INT", 3) != 3 {
		t.Fatal()
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()
	if got := firstNonEmpty("", "  x ", "y"); got != "  x " {
		t.Fatalf("firstNonEmpty returns original string: %q", got)
	}
}

func TestParseP0FOutput(t *testing.T) {
	t.Parallel()
	m := parseP0FOutput("1.2.3.4", "OS = Linux\nLink = Ethernet\n")
	mm, ok := m.(map[string]any)
	if !ok {
		t.Fatalf("type %T", m)
	}
	if mm["os"] != "Linux" {
		t.Fatalf("%v", mm)
	}
}

func TestMustJSONHelpers(t *testing.T) {
	t.Parallel()
	if mustJSONList[string](`["a","b"]`) == nil {
		t.Fatal()
	}
	raw, ok := mustJSONList[string]("not-json").(map[string]any)
	if !ok || raw["_error"] == nil {
		t.Fatalf("expected error map, got %T", mustJSONList[string]("not-json"))
	}
	if mustJSONObj(`{"a":1}`) == nil {
		t.Fatal()
	}
	if mustJSONArr(`[1,2]`) == nil {
		t.Fatal()
	}
}

func TestHTMLEscapeUpstream(t *testing.T) {
	t.Parallel()
	if htmlEscape("<") != "&lt;" {
		t.Fatal()
	}
}

func TestJSONStringUpstream(t *testing.T) {
	t.Parallel()
	if jsonString("\n") != `"\n"` {
		t.Fatal(jsonString("\n"))
	}
}

func TestRenderMarkdown_smoke(t *testing.T) {
	out, err := renderMarkdown("## Title\n\n* item\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Title") || !strings.Contains(out, "<ul>") {
		t.Fatalf("unexpected markdown render")
	}
}

func TestPrettyJSON(t *testing.T) {
	t.Parallel()
	s := prettyJSON(map[string]int{"a": 1})
	if !strings.Contains(s, `"a"`) {
		t.Fatal(s)
	}
}

func TestAsString(t *testing.T) {
	t.Parallel()
	if asString(nil) != "" || asString("x") != "x" || asString(42) != "42" {
		t.Fatal()
	}
}

func TestRandToken_format(t *testing.T) {
	t.Parallel()
	tok := randToken(16)
	if len(tok) != 32 { // hex
		t.Fatal(len(tok))
	}
	for _, c := range tok {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		t.Fatalf("bad char %q in %q", c, tok)
	}
}

func TestBuildPayload_smoke(t *testing.T) {
	if testing.Short() {
		t.Skip("calls p0f-client and TTL HTTP")
	}
	tr := parseTrustedProxyCIDRs("127.0.0.0/8")
	r := httptest.NewRequest(http.MethodGet, "/?x=1", nil)
	r.RemoteAddr = "127.0.0.1:55555"
	r.Host = "example.test"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	r.Header.Set("X-JA4", "ja4test")
	r.Header.Set("X-H2-FP", "h2test")
	r.Header.Set("X-Edge-Request-Start-Unix", "1700000000000000000")
	r.Header.Set("X-Edge-Request-Interval-MS", "3")
	r.Header.Set("X-Edge-Prev-TTFB-MS", "4")
	r.Header.Set("User-Agent", "UT/1")
	p := buildPayload(r, tr)
	if p.Request["client_ip"] != "198.51.100.9" {
		t.Fatalf("client_ip %v", p.Request["client_ip"])
	}
	if p.TLS["ja4"] != "ja4test" || p.TLS["h2_fp"] != "h2test" {
		t.Fatalf("tls %v", p.TLS)
	}
	et, ok := p.Extra["edge_timing"].(map[string]any)
	if !ok {
		t.Fatal("edge_timing type")
	}
	if et["request_start_unix_ns"].(int64) != 1700000000000000000 {
		t.Fatalf("edge_timing ns: %v", et["request_start_unix_ns"])
	}
	if et["request_interval_ms"].(int64) != 3 || et["prev_ttfb_ms"].(int64) != 4 {
		t.Fatalf("edge_timing ms: %v", et)
	}
}

func TestParseOSFromHeadersAndUA_fillsVersionFromUA(t *testing.T) {
	t.Parallel()
	h := map[string][]string{
		"Sec-CH-UA-Platform": {`"Windows"`},
	}
	ua := `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0`
	n, v := parseOSFromHeadersAndUA(h, ua)
	if n != "Windows" || v != "10.0" {
		t.Fatalf("got %q %q want Windows 10.0", n, v)
	}
}

func TestParseOSFromUA(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ua, wantOS, wantVer string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120", "Windows", "10.0"},
		{"Mozilla/5.0 (Linux; Android 14; Pixel) AppleWebKit", "Android", "14"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)", "iOS", "17.2"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macOS", "10.15.7"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "Linux", ""},
	}
	for _, tc := range cases {
		osName, osVer := parseOSFromUA(tc.ua)
		if osName != tc.wantOS || osVer != tc.wantVer {
			t.Fatalf("UA %q: got %q %q want %q %q", tc.ua, osName, osVer, tc.wantOS, tc.wantVer)
		}
	}
}

func TestBuildPcapDownloadStem(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "snap-api-all.json")
	j := `{
  "request": {
    "browser": "Chrome",
    "browser_version": "120",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0)"
  },
  "headers": {
    "Sec-CH-UA-Platform": ["\"Windows\""],
    "Sec-CH-UA-Platform-Version": ["\"15.0.0\""]
  }
}
`
	if err := os.WriteFile(p, []byte(j), 0o600); err != nil {
		t.Fatal(err)
	}
	job := &pcapJob{}
	stem := buildPcapDownloadStem(job, p, "fallback")
	if stem != "null, null, auto Windows 15.0.0, auto Chrome 120" {
		t.Fatalf("stem %q", stem)
	}
	job2 := &pcapJob{UserOSLabel: "Windows 11", UserBrowserLabel: "Chrome 131"}
	stem2 := buildPcapDownloadStem(job2, p, "fallback")
	if stem2 != "Windows 11, Chrome 131, auto Windows 15.0.0, auto Chrome 120" {
		t.Fatalf("stem with user labels %q", stem2)
	}
	job3 := &pcapJob{UserOSLabel: "Windows 11"}
	stem3 := buildPcapDownloadStem(job3, p, "fallback")
	if stem3 != "Windows 11, null, auto Windows 15.0.0, auto Chrome 120" {
		t.Fatalf("stem one user field %q", stem3)
	}
	stMissing := buildPcapDownloadStem(job, filepath.Join(dir, "missing.json"), "fb")
	if stMissing != "null, null, auto unknown OS, auto unknown browser" {
		t.Fatalf("missing json: %q", stMissing)
	}
	stPartial := buildPcapDownloadStem(&pcapJob{UserOSLabel: "My OS"}, filepath.Join(dir, "missing.json"), "fb")
	if stPartial != "My OS, null, auto unknown OS, auto unknown browser" {
		t.Fatalf("missing file with user label: %q", stPartial)
	}
}
