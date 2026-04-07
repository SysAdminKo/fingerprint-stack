package main

import (
	"testing"
	"time"
)

func TestWsRelaySeconds(t *testing.T) {
	t.Setenv("H2EDGE_WS_RELAY_SECONDS", "")
	if d := wsRelaySeconds(); d != 12*time.Second {
		t.Fatalf("default: %v", d)
	}
	t.Setenv("H2EDGE_WS_RELAY_SECONDS", "5")
	if d := wsRelaySeconds(); d != 5*time.Second {
		t.Fatalf("5: %v", d)
	}
	t.Setenv("H2EDGE_WS_RELAY_SECONDS", "999")
	if d := wsRelaySeconds(); d != 120*time.Second {
		t.Fatalf("cap 120: %v", d)
	}
}

func TestWsServerInterval(t *testing.T) {
	t.Setenv("H2EDGE_WS_SERVER_INTERVAL_MS", "")
	if d := wsServerInterval(); d != 800*time.Millisecond {
		t.Fatalf("default: %v", d)
	}
	t.Setenv("H2EDGE_WS_SERVER_INTERVAL_MS", "100")
	if d := wsServerInterval(); d != 100*time.Millisecond {
		t.Fatalf("100: %v", d)
	}
}

func TestWsServerMsgBytes(t *testing.T) {
	t.Setenv("H2EDGE_WS_SERVER_MSG_BYTES", "")
	if n := wsServerMsgBytes(); n != 80 {
		t.Fatalf("default %d", n)
	}
	t.Setenv("H2EDGE_WS_SERVER_MSG_BYTES", "2000")
	if n := wsServerMsgBytes(); n != 2000 {
		t.Fatalf("2000: %d", n)
	}
}

func TestWsServerTextPayload_length(t *testing.T) {
	// Small n uses a minimal JSON branch (not exactly n bytes).
	pSmall := wsServerTextPayload(20)
	if len(pSmall) < 10 || len(pSmall) > 40 {
		t.Fatalf("small payload len %d", len(pSmall))
	}
	for _, n := range []int{200, 2000} {
		p := wsServerTextPayload(n)
		if len(p) != n {
			t.Fatalf("n=%d got len %d", n, len(p))
		}
	}
}

func TestWsMaxFrame_const(t *testing.T) {
	if wsMaxFrame < 1024 {
		t.Fatal(wsMaxFrame)
	}
}
