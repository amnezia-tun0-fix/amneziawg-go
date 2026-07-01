package uidfilter

import (
	"net"
	"testing"
)

// ipv4Packet builds a minimal IPv4 packet with the given L4 protocol and ports.
func ipv4Packet(proto byte, src, dst net.IP, srcPort, dstPort int) []byte {
	p := make([]byte, 24)
	p[0] = 0x45 // version 4, IHL 5 (20 bytes)
	p[9] = proto
	copy(p[ipv4OffsetSrc:], src.To4())
	copy(p[ipv4OffsetDst:], dst.To4())
	p[20] = byte(srcPort >> 8)
	p[21] = byte(srcPort)
	p[22] = byte(dstPort >> 8)
	p[23] = byte(dstPort)
	return p
}

// countingFilter denies a specific source port and records call count.
type countingFilter struct {
	denySrcPort int
	calls       int
}

func (f *countingFilter) Allow(network, srcIP string, srcPort int, dstIP string, dstPort int) bool {
	f.calls++
	return srcPort != f.denySrcPort
}

func TestParse5TupleTCP(t *testing.T) {
	p := ipv4Packet(ipProtoTCP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 54321, 443)
	network, src, srcPort, dst, dstPort, ok := parse5Tuple(p)
	if !ok || network != "tcp" || src.String() != "10.0.0.2" || srcPort != 54321 ||
		dst.String() != "1.1.1.1" || dstPort != 443 {
		t.Fatalf("bad parse: %v %v %d %v %d ok=%v", network, src, srcPort, dst, dstPort, ok)
	}
}

func TestParse5TupleNonTCPUDP(t *testing.T) {
	// protocol 1 = ICMP → no ports, ok must be false
	p := ipv4Packet(1, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 0, 0)
	if _, _, _, _, _, ok := parse5Tuple(p); ok {
		t.Error("expected ok=false for ICMP")
	}
}

func TestAllowNoFilter(t *testing.T) {
	Set(nil)
	p := ipv4Packet(ipProtoTCP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 4444, 443)
	if !AllowOutboundPacket(p) {
		t.Error("expected allow when no filter installed")
	}
}

func TestAllowDenyAndCache(t *testing.T) {
	f := &countingFilter{denySrcPort: 4444}
	Set(f)
	t.Cleanup(func() { Set(nil) })

	denied := ipv4Packet(ipProtoTCP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 4444, 443)
	allowed := ipv4Packet(ipProtoTCP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 5555, 443)

	if AllowOutboundPacket(denied) {
		t.Error("expected deny for blocked source port")
	}
	if !AllowOutboundPacket(allowed) {
		t.Error("expected allow for unblocked source port")
	}
	// Repeat: decisions must come from cache, not new filter calls.
	callsBefore := f.calls
	for i := 0; i < 5; i++ {
		AllowOutboundPacket(denied)
		AllowOutboundPacket(allowed)
	}
	if f.calls != callsBefore {
		t.Errorf("expected cache hits (no extra filter calls), got %d extra", f.calls-callsBefore)
	}
}

func TestNonTCPUDPPassesThrough(t *testing.T) {
	Set(&countingFilter{denySrcPort: -1})
	t.Cleanup(func() { Set(nil) })
	icmp := ipv4Packet(1, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 0, 0)
	if !AllowOutboundPacket(icmp) {
		t.Error("non-TCP/UDP packets should pass through")
	}
}
