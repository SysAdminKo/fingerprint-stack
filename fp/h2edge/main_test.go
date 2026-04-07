package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRemoteIPOnly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr, want string
	}{
		{"192.0.2.1:443", "192.0.2.1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"10.0.0.5", "10.0.0.5"},
	}
	for _, tc := range tests {
		if got := remoteIPOnly(tc.addr); got != tc.want {
			t.Errorf("remoteIPOnly(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestHTMLEscape(t *testing.T) {
	t.Parallel()
	if got := htmlEscape(`<a href="x">y</a>`); got != `&lt;a href=&quot;x&quot;&gt;y&lt;/a&gt;` {
		t.Fatalf("htmlEscape: %q", got)
	}
}

func TestJSONString(t *testing.T) {
	t.Parallel()
	if got := jsonString("a\"b\nc"); got != `"a\"b\nc"` {
		t.Fatalf("jsonString: %q", got)
	}
}

func TestB64Trunc(t *testing.T) {
	t.Parallel()
	if b64Trunc(nil, 10) != "" {
		t.Fatal("empty in")
	}
	raw := []byte{0, 1, 2, 3, 4, 5}
	full := b64Trunc(raw, 0)
	tr := b64Trunc(raw, 3)
	if len(tr) >= len(full) {
		t.Fatalf("trunc expected shorter: full=%q tr=%q", full, tr)
	}
}

func TestH2ConnTiming(t *testing.T) {
	var ct h2ConnTiming
	i0, p0 := ct.beginRequest()
	if i0 != 0 || p0 != 0 {
		t.Fatalf("first begin: interval=%d prev=%d", i0, p0)
	}
	ct.endRequest(42)
	time.Sleep(8 * time.Millisecond)
	i1, p1 := ct.beginRequest()
	if p1 != 42 {
		t.Fatalf("prev TTFB: %d", p1)
	}
	if i1 < 1 {
		t.Fatalf("expected positive interval, got %d", i1)
	}
	ct.endRequest(7)
	_, p2 := ct.beginRequest()
	if p2 != 7 {
		t.Fatalf("prev after second: %d", p2)
	}
}

func TestTTFBWriter(t *testing.T) {
	rr := httptest.NewRecorder()
	var out int64
	start := time.Now().Add(-15 * time.Millisecond)
	w := &ttfbWriter{ResponseWriter: rr, start: start, out: &out}
	w.WriteHeader(404)
	if out < 10 || out > 500 {
		t.Fatalf("ttfb ms out of range: %d", out)
	}
	if rr.Header().Get("X-Edge-TTFB-MS") == "" {
		t.Fatal("missing X-Edge-TTFB-MS")
	}
	if rr.Code != 404 {
		t.Fatalf("code %d", rr.Code)
	}
	rr2 := httptest.NewRecorder()
	var out2 int64
	w2 := &ttfbWriter{ResponseWriter: rr2, start: time.Now(), out: &out2}
	if _, err := w2.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if out2 < 0 || rr2.Code != 200 {
		t.Fatalf("implicit 200: code=%d ttfb=%d", rr2.Code, out2)
	}
}

func TestShouldSkipHeaderForFP(t *testing.T) {
	t.Parallel()
	if !shouldSkipHeaderForFP("connection") || !shouldSkipHeaderForFP("x-forwarded-for") {
		t.Fatal("expected skip")
	}
	if shouldSkipHeaderForFP("user-agent") {
		t.Fatal("UA must not skip")
	}
}

func TestComputeHTTPFP_stable(t *testing.T) {
	t.Parallel()
	makeReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://example.test/path?q=1", nil)
		r.Host = "example.test"
		r.Proto = "HTTP/2.0"
		r.Header.Set("User-Agent", "TestUA/1")
		r.Header.Set("Accept", "text/html")
		r.Header.Set("X-Forwarded-For", "10.0.0.1") // skipped for FP
		return r
	}
	a := computeHTTPFP(makeReq())
	b := computeHTTPFP(makeReq())
	if a != b {
		t.Fatalf("unstable fp: %s vs %s", a, b)
	}
	// Change visible header → different hash
	r2 := makeReq()
	r2.Header.Set("Accept", "application/json")
	if computeHTTPFP(r2) == a {
		t.Fatal("expected different fp when Accept changes")
	}
}

func TestH2hashStable(t *testing.T) {
	t.Parallel()
	fp := H2FP{
		SettingsList: []string{"1=4096"},
		WindowIncr:   []uint32{123},
		Priority:     2,
		FramesSeen:   map[string]int{"SETTINGS": 1},
		FrameLog: []H2FrameSample{
			{Type: "SETTINGS", StreamID: 0, Length: 6, Flags: 0, DeltaMs: 1.5},
		},
		FrameTotal: 1,
	}
	h1 := h2hash(fp)
	h2 := h2hash(fp)
	if h1 != h2 || len(h1) != 32 {
		t.Fatalf("h2hash: %q len=%d", h1, len(h1))
	}
	seq := h2FrameSeq(fp)
	if len(seq) != 1 || seq[0] != "SETTINGS:0:0" {
		t.Fatalf("h2FrameSeq: %v", seq)
	}
}

func TestTlsNames(t *testing.T) {
	t.Parallel()
	if tlsVersionName(tls.VersionTLS12) != "tls1.2" {
		t.Fatal(tlsVersionName(tls.VersionTLS12))
	}
	if tlsCipherName(tls.TLS_AES_128_GCM_SHA256) != "TLS_AES_128_GCM_SHA256" {
		t.Fatal(tlsCipherName(tls.TLS_AES_128_GCM_SHA256))
	}
	if tlsCipherName(0xffff) != "65535" {
		t.Fatal(tlsCipherName(0xffff))
	}
}

func TestSummarizeTLS(t *testing.T) {
	st := tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
		ServerName:         "ex.test",
		DidResume:          true,
	}
	m := summarizeTLS(st)
	if m["version"] != "tls1.3" || m["alpn"] != "h2" || m["server"] != "ex.test" {
		t.Fatalf("%v", m)
	}
}

func TestStoreH2WS(t *testing.T) {
	s := NewStore(time.Minute)
	s.Set("1.2.3.4:5", H2FP{Fingerprint: "fp1"})
	fp, ok := s.Get("1.2.3.4:5")
	if !ok || fp.Fingerprint != "fp1" {
		t.Fatal()
	}
	s.SetWS("", WSInfo{Fingerprint: "x"}) // no-op
	s.SetWS("10.0.0.1", WSInfo{Fingerprint: ""}) // no-op
	s.SetWS("10.0.0.2", WSInfo{Fingerprint: "wf"})
	w, ok := s.GetWS("10.0.0.2")
	if !ok || w.Fingerprint != "wf" || w.IP != "10.0.0.2" {
		t.Fatalf("%v %v", w, ok)
	}
}

func TestInjectHeaders_setsEdgeAndH2(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Proto = "HTTP/2.0"
	st := tls.ConnectionState{
		Version:            tls.VersionTLS12,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
		ServerName:         "sn",
	}
	h2 := H2FP{
		Fingerprint: "h2fp",
		SettingsList: []string{"3=100"},
		FrameTotal:  3,
	}
	tlsfp := TLSFP{JA4: "ja4x", JA3: "ja3x"}
	injectHeaders(r, st, h2, tlsfp, edgeTiming{
		RequestStartUnixNano: 123456789,
		IntervalMs:           10,
		PrevTTFBMs:           20,
	})
	if r.Header.Get("X-H2-FP") != "h2fp" || r.Header.Get("X-JA4") != "ja4x" || r.Header.Get("JA3") != "ja3x" {
		t.Fatal("core headers")
	}
	if r.Header.Get("X-Edge-Request-Start-Unix") != "123456789" {
		t.Fatal("start unix")
	}
	if r.Header.Get("X-Edge-Request-Interval-MS") != "10" || r.Header.Get("X-Edge-Prev-TTFB-MS") != "20" {
		t.Fatal("edge timing headers")
	}
	if r.Header.Get("X-HTTP-FP") == "" {
		t.Fatal("X-HTTP-FP")
	}
}

func TestWsAccept(t *testing.T) {
	// RFC 6455 example
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	want := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got := wsAccept(key); got != want {
		t.Fatalf("wsAccept: %q want %q", got, want)
	}
}

func TestH2edgeAccessLogEnabled(t *testing.T) {
	t.Setenv("H2EDGE_ACCESS_LOG", "")
	if h2edgeAccessLogEnabled() {
		t.Fatal("empty")
	}
	t.Setenv("H2EDGE_ACCESS_LOG", "1")
	if !h2edgeAccessLogEnabled() {
		t.Fatal("1")
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("FP_TEST_ENV_XYZ", "")
	if env("FP_TEST_ENV_XYZ", "d") != "d" {
		t.Fatal()
	}
	t.Setenv("FP_TEST_ENV_XYZ", "  v  ")
	if env("FP_TEST_ENV_XYZ", "d") != "v" {
		t.Fatal()
	}
}
