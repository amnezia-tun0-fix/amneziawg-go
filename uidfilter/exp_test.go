package uidfilter

import (
	"net"
	"runtime"
	"testing"
	"time"
)

// installExp installs f with experimental options o.
func installExp(t testing.TB, f PacketFilter, o ExpOptions) *reader {
	ExpLoad = func() ExpOptions { return o }
	t.Cleanup(func() { ExpLoad = nil })
	return install(t, f)
}

func icmp4(typ byte) []byte {
	p := ipv4Packet(1, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 0, 0)
	p[20] = typ
	return p
}

func icmp6(typ byte) []byte {
	p := make([]byte, 48)
	p[0] = 0x60
	p[6] = 58
	copy(p[ipv6OffsetSrc:], net.ParseIP("fd00::2"))
	copy(p[ipv6OffsetDst:], net.ParseIP("2001:db8::2"))
	p[40] = typ
	return p
}

// With KernelICMP, ICMP that only the kernel can send passes; echo requests,
// which a ping socket can send, stay dropped. Without it, all ICMP is dropped.
func TestExpKernelICMP(t *testing.T) {
	rd := installExp(t, &countingFilter{}, ExpOptions{KernelICMP: true})
	for _, typ := range []byte{0, 3, 11} {
		if !rd.check(icmp4(typ)) {
			t.Errorf("ICMPv4 type %d dropped", typ)
		}
	}
	for _, typ := range []byte{1, 2, 3, 129} {
		if !rd.check(icmp6(typ)) {
			t.Errorf("ICMPv6 type %d dropped", typ)
		}
	}
	if rd.check(icmp4(8)) || rd.check(icmp6(128)) {
		t.Error("an echo request passed")
	}

	rd = installExp(t, &countingFilter{}, ExpOptions{})
	if rd.check(icmp4(0)) || rd.check(icmp6(129)) {
		t.Error("ICMP passed without the option")
	}
}

// Fragments still follow their first one when they go through unattributable.
func TestExpFragmentsStillFollow(t *testing.T) {
	rd := installExp(t, &countingFilter{}, ExpOptions{})
	first, later := fragments(5555, 7)
	if !rd.verdict(t, first) {
		t.Fatal("first fragment of an allowed flow denied")
	}
	if !rd.check(later) {
		t.Error("later fragment of an allowed flow dropped")
	}
	if h := current.Load(); h.stats.fragFirst.Load() == 0 || h.stats.fragFollow.Load() == 0 {
		t.Error("fragments not counted")
	}
}

func TestExpWorkers(t *testing.T) {
	Set(nil)
	time.Sleep(10 * time.Millisecond)
	before := runtime.NumGoroutine()
	installExp(t, &countingFilter{}, ExpOptions{Workers: 8})
	if n := runtime.NumGoroutine(); n < before+8 {
		t.Errorf("expected 8 workers, goroutines went %d -> %d", before, n)
	}
}

func TestExpHeldPerFlow(t *testing.T) {
	gate := make(chan struct{})
	rd := installExp(t, &countingFilter{gate: gate}, ExpOptions{HeldPerFlow: 2})
	for i := 0; i < 5; i++ {
		rd.check(udpPacket(5555, net.IPv4(1, 1, 1, 1), byte(i)))
	}
	close(gate)
	rd.settle(t)
	if n := len(rd.r.released()); n != 2 {
		t.Errorf("released %d packets, want 2", n)
	}
	if current.Load().stats.heldCap.Load() != 3 {
		t.Error("held-cap drops not counted")
	}
}

func TestParseExpOptions(t *testing.T) {
	o := ParseExpOptions("rv, ra2,sa,icmp,frag,w8,h32,bogus")
	want := ExpOptions{KernelICMP: true, Workers: 8, HeldPerFlow: 32}
	if o != want {
		t.Errorf("got %+v", o)
	}
	if s := o.String(); s != "icmp,w8,h32" {
		t.Errorf("String: %s", s)
	}
	if (ExpOptions{}).String() != "none" || ParseExpOptions("") != (ExpOptions{}) {
		t.Error("empty options")
	}
}

// The counters report through ExpLogf, and only when something changed.
func TestExpReport(t *testing.T) {
	var lines []string
	ExpLogf = func(format string, args ...any) { lines = append(lines, format) }
	t.Cleanup(func() { ExpLogf = nil })
	rd := installExp(t, &countingFilter{}, ExpOptions{})
	rd.verdict(t, udpPacket(5555, net.IPv4(1, 1, 1, 1), 0))
	h := current.Load()
	prev := h.report(nil, time.Second)
	if len(lines) != 1 {
		t.Fatalf("expected one report line, got %d", len(lines))
	}
	h.report(prev, time.Second)
	if len(lines) != 1 {
		t.Error("a report was logged although nothing changed")
	}
}
