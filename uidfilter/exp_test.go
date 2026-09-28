package uidfilter

import (
	"bytes"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// installExp installs f with experimental options o.
func installExp(t testing.TB, f PacketFilter, o ExpOptions) *reader {
	ExpLoad = func() ExpOptions { return o }
	t.Cleanup(func() { ExpLoad = nil })
	return install(t, f)
}

// switchFilter allows or denies everything, as told, and counts calls; with a
// gate set, every call waits until it is closed.
type switchFilter struct {
	deny  atomic.Bool
	gate  atomic.Pointer[chan struct{}]
	calls atomic.Int32
	last  atomic.Pointer[string]
}

func (f *switchFilter) Allow(network, srcIP string, srcPort int, dstIP string, dstPort int) bool {
	f.calls.Add(1)
	s := network + " " + net.JoinHostPort(srcIP, itoa(srcPort)) + " -> " + net.JoinHostPort(dstIP, itoa(dstPort))
	f.last.Store(&s)
	if g := f.gate.Load(); g != nil {
		<-*g
	}
	return !f.deny.Load()
}

func (f *switchFilter) block() chan struct{} {
	g := make(chan struct{})
	f.gate.Store(&g)
	return g
}

// With Revalidate, an allowed flow whose verdict expired keeps passing while it
// is judged again: the burst that TestProofExpiredVerdictDropsBurst loses gets
// through, and the filter is asked once.
func TestExpRevalidateKeepsBurst(t *testing.T) {
	f := &switchFilter{}
	rd := installExp(t, f, ExpOptions{Revalidate: true})
	if !rd.verdict(t, udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)) {
		t.Fatal("expected allow")
	}
	gate := f.block()
	advanceClock(cacheTTL)
	for i := 0; i < 20; i++ {
		if !rd.check(udpPacket(5555, net.IPv4(1, 1, 1, 1), byte(i))) {
			t.Fatalf("packet %d of an allowed flow was held or dropped while it was judged again", i)
		}
	}
	close(gate)
	rd.settle(t)
	if n := f.calls.Load(); n != 2 {
		t.Errorf("expected one lookup to judge the flow again, got %d in all", n)
	}
	if !rd.check(udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)) {
		t.Error("the new verdict was not applied")
	}
	if n := current.Load().stats.revalPass.Load(); n != 1 {
		t.Errorf("expected the new verdict to be applied once, got %d", n)
	}
}

// A new verdict that denies the flow takes effect on the next packet.
func TestExpRevalidateDenyApplies(t *testing.T) {
	f := &switchFilter{}
	rd := installExp(t, f, ExpOptions{Revalidate: true})
	p := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)
	if !rd.verdict(t, p) {
		t.Fatal("expected allow")
	}
	f.deny.Store(true)
	advanceClock(cacheTTL)
	if !rd.check(p) {
		t.Fatal("expected the stale verdict to pass the packet that starts the lookup")
	}
	rd.settle(t)
	if rd.check(p) {
		t.Error("a packet passed after the flow was denied")
	}
}

// The stale verdict is honoured for maxHoldTime at most: past it, packets are
// held again until the lookup answers.
func TestExpRevalidateGraceEnds(t *testing.T) {
	f := &switchFilter{}
	rd := installExp(t, f, ExpOptions{Revalidate: true})
	p := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)
	if !rd.verdict(t, p) {
		t.Fatal("expected allow")
	}
	gate := f.block()
	advanceClock(cacheTTL)
	if !rd.check(p) {
		t.Fatal("expected a pass within the grace period")
	}
	advanceClock(maxHoldTime)
	if rd.check(p) {
		t.Error("a packet passed on a verdict expired longer than maxHoldTime")
	}
	close(gate)
	rd.settle(t)
	if n := len(rd.r.released()); n != 2 {
		t.Errorf("expected the held packet to be released after the lookup, %d released in all", n)
	}
}

// While the pending table is full, an allowed flow with a stale verdict keeps
// passing: established UDP flows ride out a flood of new ones, as TCP does.
func TestExpRevalidatePendingFull(t *testing.T) {
	f := &switchFilter{}
	rd := installExp(t, f, ExpOptions{Revalidate: true})
	established := udpPacket(1000, net.IPv4(1, 1, 1, 1), 0)
	if !rd.verdict(t, established) {
		t.Fatal("expected allow")
	}
	gate := f.block()
	for i := 0; i < maxPendingFlows; i++ {
		rd.check(udpPacket(2000+i, net.IPv4(1, 1, 1, 1), 0))
	}
	advanceClock(cacheTTL)
	for i := 0; i < 10; i++ {
		if !rd.check(established) {
			t.Fatal("an established flow was dropped at its TTL while the table was full")
		}
	}
	close(gate)
	rd.settle(t)
}

// With SynAckByListener, a SYN-ACK is judged by who listens on its source.
func TestExpSynAckByListener(t *testing.T) {
	f := &switchFilter{}
	rd := installExp(t, f, ExpOptions{SynAckByListener: true})
	if rd.check(tcpPacket(8080, tcpFlagSYN|tcpFlagACK)) {
		t.Fatal("a SYN-ACK passed without a verdict")
	}
	rd.settle(t)
	if got := *f.last.Load(); got != "tcp 10.0.0.2:8080 -> 0.0.0.0:0" {
		t.Errorf("unexpected question: %s", got)
	}
	if n := len(rd.r.released()); n != 1 {
		t.Errorf("expected the SYN-ACK to be released, got %d", n)
	}
	// A SYN is judged by its own tuple as before.
	rd.check(tcpPacket(5555, tcpFlagSYN))
	rd.settle(t)
	if got := *f.last.Load(); got != "tcp 10.0.0.2:5555 -> 1.1.1.1:443" {
		t.Errorf("unexpected question for a SYN: %s", got)
	}
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
// which a ping socket can send, stay dropped.
func TestExpKernelICMP(t *testing.T) {
	rd := installExp(t, &switchFilter{}, ExpOptions{KernelICMP: true})
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
}

// fragments splits a UDP datagram from srcPort into a first fragment carrying
// the UDP header and a later one, with the given identification.
func fragments(srcPort int, id uint16) (first, later []byte) {
	first = append(ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), srcPort, 53), make([]byte, 20)...)
	first[4], first[5] = byte(id>>8), byte(id)
	first[6] = 0x20 // MF
	later = ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 0, 0)
	later[4], later[5] = byte(id>>8), byte(id)
	later[7] = 3 // offset 24
	return
}

// With Fragments, the first fragment is judged by its ports and the later ones
// follow it, in order; a later fragment whose first one was never seen is
// dropped, and so are the fragments of a denied flow.
func TestExpFragments(t *testing.T) {
	f := &switchFilter{}
	rd := installExp(t, f, ExpOptions{Fragments: true})
	first, later := fragments(5555, 0x1234)
	if rd.check(first) || rd.check(later) {
		t.Fatal("a fragment passed before its flow was judged")
	}
	rd.settle(t)
	got := rd.r.released()
	if len(got) != 2 || !bytes.Equal(got[0], first) || !bytes.Equal(got[1], later) {
		t.Fatalf("expected both fragments released in order, got %d packets", len(got))
	}
	// The flow is cached now: the next datagram passes at once.
	first2, later2 := fragments(5555, 0x1235)
	if !rd.check(first2) || !rd.check(later2) {
		t.Error("fragments of an allowed, cached flow were held")
	}
	// A later fragment with no first one.
	_, orphan := fragments(5555, 0x9999)
	if rd.check(orphan) {
		t.Error("a fragment whose first fragment was never seen passed")
	}
	// A denied flow.
	f.deny.Store(true)
	first3, later3 := fragments(6666, 0x2000)
	rd.check(first3)
	rd.check(later3)
	rd.settle(t)
	if rd.check(later3) {
		t.Error("a fragment of a denied flow passed")
	}
	if n := len(rd.r.released()); n != 2 {
		t.Errorf("fragments of a denied flow were released: %d packets in all", n)
	}
	if n := f.calls.Load(); n != 2 {
		t.Errorf("expected one lookup per flow, got %d", n)
	}
}

func TestExpWorkers(t *testing.T) {
	Set(nil)
	time.Sleep(10 * time.Millisecond)
	before := runtime.NumGoroutine()
	installExp(t, &switchFilter{}, ExpOptions{Workers: 8})
	if n := runtime.NumGoroutine(); n < before+8 {
		t.Errorf("expected 8 workers, goroutines went %d -> %d", before, n)
	}
}

func TestParseExpOptions(t *testing.T) {
	o := ParseExpOptions("rv, sa,icmp,frag,w8,h32,bogus")
	want := ExpOptions{Revalidate: true, SynAckByListener: true, KernelICMP: true, Fragments: true, Workers: 8, HeldPerFlow: 32}
	if o != want {
		t.Errorf("got %+v", o)
	}
	if s := o.String(); s != "rv,sa,icmp,frag,w8,h32" {
		t.Errorf("String: %s", s)
	}
	if (ExpOptions{}).String() != "none" || ParseExpOptions("") != (ExpOptions{}) {
		t.Error("empty options")
	}
}

// The counters report through ExpLogf.
func TestExpReport(t *testing.T) {
	var lines []string
	ExpLogf = func(format string, args ...any) { lines = append(lines, format) }
	t.Cleanup(func() { ExpLogf = nil })
	rd := installExp(t, &switchFilter{}, ExpOptions{})
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
