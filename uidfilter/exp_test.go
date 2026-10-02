package uidfilter

import (
	"fmt"
	"net"
	"runtime"
	"strings"
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
	o := ParseExpOptions("rv, ra2,sa,icmp,frag,w8,h32,c=noref,bogus")
	want := ExpOptions{KernelICMP: true, Workers: 8, HeldPerFlow: 32, CacheMode: CacheNoRefresh}
	if o != want {
		t.Errorf("got %+v", o)
	}
	if s := o.String(); s != "icmp,w8,h32,c=noref" {
		t.Errorf("String: %s", s)
	}
	if (ExpOptions{}).String() != "none" || ParseExpOptions("") != (ExpOptions{}) {
		t.Error("empty options")
	}
	for m, name := range cacheModeNames {
		if got := ParseExpOptions("c=" + name).CacheMode; got != CacheMode(m) {
			t.Errorf("c=%s parsed as %v", name, got)
		}
	}
	if ParseExpOptions("c=bogus").CacheMode != CachePR {
		t.Error("an unknown cache mode is not the release one")
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

// --- verdict cache variants ---

var allModes = []CacheMode{CachePR, CacheFIFO, CacheNoRefresh, CacheHold, CacheF174}

func installMode(t testing.TB, f PacketFilter, m CacheMode) *reader {
	return installExp(t, f, ExpOptions{CacheMode: m})
}

// sendEvery has the socket behind p send once every step for d, each lookup
// answered before the next packet, and returns when the last packet passed,
// counted from the start, or -1 if none did.
func sendEvery(t *testing.T, rd *reader, p []byte, step, d time.Duration) time.Duration {
	t.Helper()
	last := time.Duration(-1)
	for el := time.Duration(0); el < d; el += step {
		if rd.check(p) {
			last = el
		}
		rd.settle(t)
		advanceClock(step)
	}
	return last
}

// How long a socket that takes over the 5-tuple of a closed allowed flow keeps
// passing on that flow's verdict, in each mode, with every lookup answered at
// once. The closed flow either sent once (fresh) or for 5 s before closing
// (active), so that its verdict had been refreshed. The window is counted from
// the takeover; "never" means it was still open after 30 s.
func TestExpTakeoverWindow(t *testing.T) {
	const step = 100 * time.Millisecond
	want := map[CacheMode][2]time.Duration{ // fresh, active; -1 for "never closes"
		CachePR:        {2 * time.Second, 1200 * time.Millisecond},
		CacheFIFO:      {-1, -1},
		CacheNoRefresh: {9900 * time.Millisecond, 4900 * time.Millisecond},
		CacheHold:      {1900 * time.Millisecond, 1100 * time.Millisecond},
		CacheF174:      {-1, -1},
	}
	for _, m := range allModes {
		for i, active := range []time.Duration{0, 5 * time.Second} {
			f := &countingFilter{denySrcPort: -1}
			rd := installMode(t, f, m)
			p := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)
			if !rd.verdict(t, p) {
				t.Fatal("expected allow")
			}
			if active > 0 {
				sendEvery(t, rd, p, step, active)
			}
			f.denySrcPort = 5555 // the allowed socket closed, a denied one took the 5-tuple
			last := sendEvery(t, rd, p, step, 30*time.Second)
			got := "never"
			if last < 30*time.Second-step {
				got = last.String()
			}
			t.Logf("%-5s after %v of sending: the last packet of the takeover passed at %s", m, active, got)
			w := want[m][i]
			if (w < 0) != (last == 30*time.Second-step) || (w >= 0 && last != w) {
				t.Errorf("%s, active %v: last packet passed at %v, want %v", m, active, last, w)
			}
		}
	}
}

// A verdict the workers reached is applied when the reader next sees its flow,
// however late, and the cache then counts its age from that moment. On a
// quiet tunnel nothing else collects it, so a socket that takes over the
// 5-tuple a minute later passes on a minute-old lookup, for refreshAfter more.
// Both the first verdict of a flow and a refreshed one behave so.
func TestExpLateCollectedVerdict(t *testing.T) {
	const step = 100 * time.Millisecond
	for _, refreshed := range []bool{false, true} {
		f := &countingFilter{denySrcPort: -1}
		rd := install(t, f)
		p := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)
		rd.check(p) // held: the flow's first lookup
		if refreshed {
			rd.settle(t)
			rd.check(p) // collects the verdict
			advanceClock(refreshAfter)
			if !rd.check(p) { // starts the refresh
				t.Fatal("expected the valid verdict to pass")
			}
		}
		rd.settle(t) // the lookup said allow; nothing on this reader collects it
		f.denySrcPort = 5555
		advanceClock(time.Minute)
		last := sendEvery(t, rd, p, step, 10*time.Second)
		t.Logf("refreshed=%v: the last packet of a takeover a minute after the lookup passed at %v", refreshed, last)
		if last != refreshAfter {
			t.Errorf("refreshed=%v: last packet of the takeover passed at %v, want %v", refreshed, last, refreshAfter)
		}
	}
}

// The first packet of any new flow on the same reader collects the verdicts
// waiting, and the late takeover is then caught as usual.
func TestExpVerdictCollectedByOtherFlow(t *testing.T) {
	f := &countingFilter{denySrcPort: -1}
	rd := install(t, f)
	p := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)
	rd.check(p)
	rd.settle(t)
	rd.check(udpPacket(6666, net.IPv4(1, 1, 1, 1), 0)) // another flow's first packet
	rd.settle(t)
	f.denySrcPort = 5555
	advanceClock(time.Minute)
	if rd.check(p) {
		t.Error("a verdict collected a minute ago passed a packet")
	}
}

// A flood of denied flows, as any app bound to tun0 can send, against the
// verdict of an allowed flow judged before it: kept, or pushed out and judged
// again, with its packets held meanwhile.
func TestExpFloodAgainstAllowedFlow(t *testing.T) {
	keeps := map[CacheMode]bool{CachePR: true, CacheNoRefresh: true, CacheHold: true}
	for _, m := range allModes {
		f := &countingFilter{denyDstIP: "2.2.2.2"}
		rd := installMode(t, f, m)
		allowed := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)
		if !rd.verdict(t, allowed) {
			t.Fatal("expected allow")
		}
		for i := 0; i < 2*cacheMaxEntries; i++ {
			rd.check(udpPacket(10000+i, net.IPv4(2, 2, 2, 2), 0))
			if i%200 == 199 {
				rd.settle(t)
			}
		}
		rd.settle(t)
		rd.check(udpPacket(9999, net.IPv4(2, 2, 2, 2), 0)) // collects the last verdicts
		kept := cached(rd, allowed)
		t.Logf("%-5s after %d denied flows: the allowed verdict is kept: %v", m, 2*cacheMaxEntries, kept)
		if kept != keeps[m] {
			t.Errorf("%s: allowed verdict kept=%v after the flood, want %v", m, kept, keeps[m])
		}
	}
}

func udpKey(p []byte) flowKey {
	_, src, srcPort, dst, dstPort, _ := parse5Tuple(p)
	k := flowKey{proto: ipProtoUDP, ipLen: net.IPv4len, srcPort: uint16(srcPort), dstPort: uint16(dstPort)}
	copy(k.srcIP[:], src)
	copy(k.dstIP[:], dst)
	return k
}

// cached reports whether rd's cache holds a verdict for the UDP flow of p. It
// reads the cache directly: a check would depend on the real clock, which a
// slow run under -race can move past refreshAfter.
func cached(rd *reader, p []byte) bool {
	k := udpKey(p)
	if s := rd.g.s; s.exp != nil && s.exp.isFIFO() {
		_, ok := s.exp.fifo.m[k]
		return ok
	}
	_, ok := rd.g.s.cache.m[k]
	return ok
}

// A denied flow never passes a packet, in any mode, however long it sends.
func TestExpDeniedFlowNeverPasses(t *testing.T) {
	for _, m := range allModes {
		rd := installMode(t, &countingFilter{denySrcPort: 4444}, m)
		if last := sendEvery(t, rd, udpPacket(4444, net.IPv4(1, 1, 1, 1), 0), 100*time.Millisecond, 30*time.Second); last >= 0 {
			t.Errorf("%s: a denied flow passed a packet at %v", m, last)
		}
		if n := len(rd.r.released()); n != 0 {
			t.Errorf("%s: %d held packets of a denied flow released", m, n)
		}
	}
}

// In f174 every TCP packet goes through the cache: a SYN on a 5-tuple judged
// before takes its verdict, and a packet of a connection whose verdict is not
// cached is held and judged. In the release cache only SYNs are judged, each
// afresh, and nothing else waits.
func TestExpF174TCP(t *testing.T) {
	for _, m := range []CacheMode{CachePR, CacheF174} {
		f := &countingFilter{denySrcPort: -1}
		rd := installMode(t, f, m)
		syn := tcpPacket(5555, tcpFlagSYN)
		rd.check(syn)
		rd.settle(t) // allowed
		f.denySrcPort = 5555 // a new socket of a denied app on the same 5-tuple
		for i := 0; i < 2; i++ {
			passed := rd.check(syn)
			rd.settle(t)
			if want := m == CacheF174; passed != want {
				t.Errorf("%s: SYN %d on a 5-tuple allowed before passed=%v, want %v", m, i, passed, want)
			}
		}
		if want := int32(map[CacheMode]int{CachePR: 3, CacheF174: 1}[m]); f.calls.Load() != want {
			t.Errorf("%s: %d lookups for three SYNs, want %d", m, f.calls.Load(), want)
		}
		passed := rd.check(tcpPacket(6666, tcpFlagACK)) // a connection never seen
		if want := m == CachePR; passed != want {
			t.Errorf("%s: an ACK of a connection without a cached verdict passed=%v, want %v", m, passed, want)
		}
	}
}

// The snapshot counts entries by verdict, age and port class, without
// addresses, and is logged by the next report.
func TestExpCacheSnapshot(t *testing.T) {
	var lines []string
	ExpLogf = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { ExpLogf = nil })
	for _, m := range []CacheMode{CachePR, CacheFIFO} {
		lines = lines[:0]
		rd := installMode(t, &countingFilter{denySrcPort: 4444}, m)
		rd.verdict(t, udpPacket(5555, net.IPv4(1, 1, 1, 1), 0))
		advanceClock(3 * time.Second)
		rd.verdict(t, udpPacket(4444, net.IPv4(1, 1, 1, 1), 0))
		h := current.Load()
		prev := h.report(nil, time.Second)                // asks for a snapshot
		rd.check(udpPacket(7777, net.IPv4(1, 1, 1, 1), 0)) // a new flow: the reader takes it
		h.report(prev, time.Second)
		var snap string
		for _, l := range lines {
			if strings.HasPrefix(l, "uidfilter-exp-v1: cache ") {
				snap = l
			}
		}
		want := fmt.Sprintf("uidfilter-exp-v1: cache mode=%s allow=1 deny=1 tcp=0 dead=0 age_allow=0/1/0/0/0 age_deny=1/0/0/0/0 oldest_allow=3s port_allow=53:0,443:1,stun:0,other:0", m)
		if snap != want {
			t.Errorf("%s: snapshot\n got %q\nwant %q", m, snap, want)
		}
	}
}

// --- benchmarks: a packet of a UDP flow whose verdict is cached, per mode ---

// fillCache stores n verdicts of other flows in rd's cache, as a busy phone
// would have them.
func fillCache(rd *reader, n int) {
	s := rd.g.s
	for i := 0; i < n; i++ {
		k := cacheKey(i+1, ipProtoUDP)
		if s.exp != nil && s.exp.isFIFO() {
			s.exp.fifo.put(k, i%2 == 0, 0)
		} else {
			s.cache.put(k, i%2 == 0, 0)
		}
	}
}

// One flow, or 256 flows in turn, with the cache empty or holding 3800 other
// verdicts: the FIFO stays full on a phone, the release cache only holds the
// last 10 s. Run the binary several times with -test.count 1 to interleave.
func BenchmarkExpCachedUDP(b *testing.B) {
	for _, m := range allModes {
		for _, flows := range []int{1, 256} {
			for _, fill := range []int{0, 3800} {
				b.Run(fmt.Sprintf("%s/flows=%d/fill=%d", m, flows, fill), func(b *testing.B) {
					rd := installMode(b, &countingFilter{denySrcPort: -1}, m)
					pkts := make([][]byte, flows)
					for i := range pkts {
						pkts[i] = ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 20000+i, 443)
						rd.check(pkts[i])
					}
					rd.settle(b)
					fillCache(rd, fill)
					for _, p := range pkts {
						if !rd.check(p) {
							b.Fatal("unexpected deny")
						}
						// The holder's clock follows the real one: stamp the
						// verdict an hour ahead, so that no mode reaches its
						// refresh or expiry while the hit path is measured.
						if s := rd.g.s; s.exp == nil || !s.exp.isFIFO() {
							s.cache.put(udpKey(p), true, current.Load().now.Load()+int64(time.Hour))
						}
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if !rd.check(pkts[i%flows]) {
							b.Fatal("unexpected deny")
						}
					}
				})
			}
		}
	}
}

// A packet of an established TCP connection: passed on its flags in release,
// looked up in the cache in f174.
func BenchmarkExpEstablishedTCP(b *testing.B) {
	for _, m := range []CacheMode{CachePR, CacheF174} {
		b.Run(m.String(), func(b *testing.B) {
			rd := installMode(b, &countingFilter{denySrcPort: -1}, m)
			p := benchPacket()
			rd.verdict(b, p)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !rd.check(p) {
					b.Fatal("unexpected deny")
				}
			}
		})
	}
}

// A flood of new denied flows against the cache alone: every key is new, so
// each packet misses and its verdict is stored. The release cache evicts
// when full; the FIFO drops its oldest key.
func BenchmarkExpCacheFlood(b *testing.B) {
	for _, m := range []CacheMode{CachePR, CacheFIFO} {
		b.Run(m.String(), func(b *testing.B) {
			rd := installMode(b, &countingFilter{denySrcPort: -1}, m)
			rd.verdict(b, udpPacket(5555, net.IPv4(1, 1, 1, 1), 0))
			s := rd.g.s
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k := cacheKey(i+100000, ipProtoUDP)
				if s.exp != nil {
					if _, ok := s.exp.fifo.m[k]; !ok {
						s.exp.fifo.put(k, false, 0)
					}
				} else if _, _, ok := s.cache.get(k, 0); !ok {
					s.cache.put(k, false, 0)
				}
			}
		})
	}
}
