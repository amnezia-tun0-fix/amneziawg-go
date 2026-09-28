package uidfilter

// Tests that pin down current behaviour found in a review of the filter
// (2026-09-28). They document what happens, not what should happen: each one
// states the consequence in its comment. Experimental branch only.

import (
	"net"
	"sync"
	"testing"
)

// tupleFilter allows everything and records what it was asked.
type tupleFilter struct {
	mu    sync.Mutex
	calls []string
}

func (f *tupleFilter) Allow(network, srcIP string, srcPort int, dstIP string, dstPort int) bool {
	f.mu.Lock()
	f.calls = append(f.calls, network+" "+net.JoinHostPort(srcIP, itoa(srcPort))+" -> "+net.JoinHostPort(dstIP, itoa(dstPort)))
	f.mu.Unlock()
	return true
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// An allowed UDP flow whose cached verdict has expired is judged again, and while
// that lookup runs, only maxHeldPerFlow of its packets are kept. The rest of a
// burst is dropped, although the flow was allowed before and is allowed after.
// On a device this happens to every active UDP flow once per cacheTTL; how many
// packets are lost depends on the packet rate and the lookup latency.
func TestProofExpiredVerdictDropsBurst(t *testing.T) {
	f := &countingFilter{denySrcPort: -1}
	rd := install(t, f)
	if !rd.verdict(t, udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)) {
		t.Fatal("expected allow")
	}
	before := len(rd.r.released())

	f.gate = make(chan struct{}) // the next lookup takes as long as the test wants
	advanceClock(cacheTTL)
	const burst = 20
	passed := 0
	for i := 0; i < burst; i++ {
		if rd.check(udpPacket(5555, net.IPv4(1, 1, 1, 1), byte(i))) {
			passed++
		}
	}
	close(f.gate)
	rd.settle(t)
	released := len(rd.r.released()) - before
	dropped := burst - passed - released
	t.Logf("burst of %d after expiry: %d passed at once, %d released after the lookup, %d dropped",
		burst, passed, released, dropped)
	if dropped != burst-maxHeldPerFlow {
		t.Errorf("expected %d packets dropped, got %d", burst-maxHeldPerFlow, dropped)
	}
}

// A SYN-ACK carries SYN, so it is held and judged like a new connection, with
// the packet's own addresses. On the device its source is a request socket
// (TCP_NEW_SYN_RECV), and inet_diag reports uid 0 for those
// (net/ipv4/inet_diag.c, inet_req_diag_fill). In "only listed apps" mode uid 0
// is outside the VPN, so the platform answers INVALID_UID and the SYN-ACK is
// dropped: a connection opened through the tunnel towards a listed app on the
// phone never completes.
func TestProofSynAckJudgedByItsOwnTuple(t *testing.T) {
	f := &tupleFilter{}
	rd := install(t, f)
	const ack = 0x10
	synAck := tcpPacket(8080, tcpFlagSYN|ack)
	if rd.check(synAck) {
		t.Fatal("a SYN-ACK passed without a verdict")
	}
	rd.settle(t)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 1 || f.calls[0] != "tcp 10.0.0.2:8080 -> 1.1.1.1:443" {
		t.Errorf("unexpected filter calls: %q", f.calls)
	}
}

// While a filter is installed, every fragment of a fragmented datagram is
// dropped, the first one included, although it carries the ports. A UDP
// datagram larger than the tun MTU (1280 on the test phone) from an allowed app
// never arrives.
func TestProofFragmentsOfAllowedDatagramDropped(t *testing.T) {
	f := &countingFilter{denySrcPort: -1}
	rd := install(t, f)
	first := ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 5555, 53)
	first[4], first[5] = 0x12, 0x34 // identification
	first[6] = 0x20                  // MF, offset 0
	later := ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 0, 0)
	later[4], later[5] = 0x12, 0x34
	later[7] = 0xb9 // offset 185 * 8 = 1480
	if rd.check(first) || rd.check(later) {
		t.Fatal("a fragment passed")
	}
	rd.settle(t)
	if n := f.calls.Load(); n != 0 {
		t.Errorf("fragments are dropped without asking, yet the filter was asked %d times", n)
	}
	if n := len(rd.r.released()); n != 0 {
		t.Errorf("%d fragments released", n)
	}
}

// ICMP that only the kernel can emit is dropped along with echo requests. An
// unprivileged ping socket can send echo requests only (net/ipv4/ping.c,
// ping_supported), so echo replies, destination unreachable and time exceeded
// leaving the phone are the kernel's answers to packets that came in through
// the tunnel.
func TestProofKernelICMPDropped(t *testing.T) {
	rd := install(t, &countingFilter{denySrcPort: -1})
	for _, typ := range []byte{0, 3, 11} { // echo reply, unreachable, time exceeded
		p := ipv4Packet(1, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 0, 0)
		p[20] = typ
		if rd.check(p) {
			t.Errorf("ICMP type %d passed", typ)
		}
	}
}
