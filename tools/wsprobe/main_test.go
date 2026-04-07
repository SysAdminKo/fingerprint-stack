package main

import (
	"bytes"
	"testing"
)

func TestWriteClientTextFrame_masked(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello")
	if err := writeClientTextFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if len(b) < 2+4+len(payload) { // hdr + mask + payload
		t.Fatalf("short frame: %d", len(b))
	}
	if b[0]&0x0f != 0x1 {
		t.Fatalf("opcode %x", b[0])
	}
	if b[1]&0x80 == 0 {
		t.Fatal("client frame must be masked")
	}
	ln := int(b[1] & 0x7f)
	if ln != len(payload) {
		t.Fatalf("len byte %d vs payload %d", ln, len(payload))
	}
}

func TestWriteClientClose(t *testing.T) {
	var buf bytes.Buffer
	if err := writeClientClose(&buf); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if len(b) < 8 || b[0]&0x0f != 0x8 {
		t.Fatalf("close frame: % x", b)
	}
}
