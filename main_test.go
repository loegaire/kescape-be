package main

import (
	"net"
	"testing"
)

func TestListenWithFallbackSkipsBusyPort(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer busy.Close()

	ln, err := listenWithFallback(busy.Addr().String())
	if err != nil {
		t.Fatalf("listenWithFallback: %v", err)
	}
	defer ln.Close()

	if ln.Addr().String() == busy.Addr().String() {
		t.Errorf("fallback reused busy address %s", busy.Addr())
	}
}

func TestListenWithFallbackInvalidAddr(t *testing.T) {
	if _, err := listenWithFallback("nonsense"); err == nil {
		t.Fatal("expected error for address without a port")
	}
}
