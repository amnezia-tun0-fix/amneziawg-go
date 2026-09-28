package uidfilter

// Experimental instrumentation and prototypes for measuring the filter on a
// device. Never part of a pull request: it lives on exp/* branches only.
//
// Options are read from ExpLoad when a filter is installed and once a second,
// so that a device build can switch them without being rebuilt. The zero
// value is the reviewed behaviour. Counters are reported through ExpLogf every
// expReportEvery ticks, as deltas, when anything changed.

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// ExpOptions switch experimental behaviour.
type ExpOptions struct {
	Revalidate       bool // UDP: pass on an expired allowed verdict while the flow is judged again
	RefreshAfter     int  // UDP: seconds after which a valid allowed verdict is judged again in the background; 0 = never
	SynAckByListener bool // judge a SYN-ACK by the owner of its listening socket
	KernelICMP       bool // pass ICMP that an unprivileged socket cannot send
	Fragments        bool // judge IPv4 fragments by their first fragment
	Workers          int  // filter calls at once; 0 means workers
	HeldPerFlow      int  // packets held per flow; 0 means maxHeldPerFlow
}

func (o ExpOptions) String() string {
	var s []string
	if o.Revalidate {
		s = append(s, "rv")
	}
	if o.RefreshAfter > 0 {
		s = append(s, fmt.Sprintf("ra%d", o.RefreshAfter))
	}
	if o.SynAckByListener {
		s = append(s, "sa")
	}
	if o.KernelICMP {
		s = append(s, "icmp")
	}
	if o.Fragments {
		s = append(s, "frag")
	}
	if o.Workers > 0 {
		s = append(s, fmt.Sprintf("w%d", o.Workers))
	}
	if o.HeldPerFlow > 0 {
		s = append(s, fmt.Sprintf("h%d", o.HeldPerFlow))
	}
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ",")
}

// ParseExpOptions reads a comma-separated list: rv, raN, sa, icmp, frag, wN, hN.
func ParseExpOptions(v string) ExpOptions {
	var o ExpOptions
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		switch {
		case f == "rv":
			o.Revalidate = true
		case strings.HasPrefix(f, "ra"):
			fmt.Sscanf(f[2:], "%d", &o.RefreshAfter)
		case f == "sa":
			o.SynAckByListener = true
		case f == "icmp":
			o.KernelICMP = true
		case f == "frag":
			o.Fragments = true
		case strings.HasPrefix(f, "w"):
			fmt.Sscanf(f[1:], "%d", &o.Workers)
		case strings.HasPrefix(f, "h"):
			fmt.Sscanf(f[1:], "%d", &o.HeldPerFlow)
		}
	}
	if o.Workers > 64 {
		o.Workers = 64
	}
	return o
}

var (
	// ExpLoad, when set, supplies the options.
	ExpLoad func() ExpOptions
	// ExpLogf, when set, receives the counters.
	ExpLogf func(format string, args ...any)
)

const expReportEvery = 5 // ticks of clockInterval

func (h *holder) loadOpts() {
	var o ExpOptions
	if ExpLoad != nil {
		o = ExpLoad()
	}
	if old := h.opts.Load(); old == nil || *old != o {
		h.opts.Store(&o)
		if ExpLogf != nil && old != nil {
			ExpLogf("uidfilter-exp-v1: options %s", o)
		}
	}
}

func (h *holder) workerCount() int {
	if o := h.opts.Load(); o != nil && o.Workers > 0 {
		return o.Workers
	}
	return workers
}

func (h *holder) heldPerFlow(o *ExpOptions) int {
	if o.HeldPerFlow > 0 {
		return o.HeldPerFlow
	}
	return maxHeldPerFlow
}

// --- counters ---

const (
	unattrICMP4 = iota
	unattrICMP6
	unattrFrag
	unattrV6Ext
	unattrOther
	unattrKinds
)

var unattrNames = [unattrKinds]string{"icmp4", "icmp6", "frag", "v6ext", "other"}

// latency buckets, upper bounds in microseconds; the last one is open
var latBounds = [...]int64{100, 250, 500, 1000, 2000, 5000, 10000, 20000, 50000}

const latBuckets = len(latBounds) + 1

var expEvictions atomic.Int64

type expStats struct {
	jobs, pendingFull, jobsFull, heldCap, heldBytes, tooOld atomic.Int64
	allow, deny, released, rounds, maxRounds                atomic.Int64
	unattr                                                  [unattrKinds]atomic.Int64
	kernelICMP, synAck                                      atomic.Int64
	revalStart, revalPass, revalDeny, expired               atomic.Int64
	refreshStart, refreshPass, refreshDeny                  atomic.Int64
	fragFirst, fragFollow, fragOrphan                       atomic.Int64
	lat                                                     [2][latBuckets]atomic.Int64 // [deny, allow]
	latMax                                                  [2]atomic.Int64
	pendingNow, cacheNow                                    atomic.Int64
}

func (s *expStats) observe(allow bool, d time.Duration, rounds int64) {
	i := 0
	if allow {
		i = 1
		s.allow.Add(1)
	} else {
		s.deny.Add(1)
	}
	us := d.Microseconds()
	b := len(latBounds)
	for j, ub := range latBounds {
		if us < ub {
			b = j
			break
		}
	}
	s.lat[i][b].Add(1)
	for {
		m := s.latMax[i].Load()
		if us <= m || s.latMax[i].CompareAndSwap(m, us) {
			break
		}
	}
	s.rounds.Add(rounds)
	for {
		m := s.maxRounds.Load()
		if rounds <= m || s.maxRounds.CompareAndSwap(m, rounds) {
			break
		}
	}
}

// snapshot flattens the counters into name=value pairs, in a fixed order.
func (s *expStats) snapshot() []expCounter {
	c := []expCounter{
		{"jobs", s.jobs.Load()}, {"allow", s.allow.Load()}, {"deny", s.deny.Load()},
		{"released", s.released.Load()}, {"rounds", s.rounds.Load()},
		{"drop_pending_full", s.pendingFull.Load()}, {"drop_jobs_full", s.jobsFull.Load()},
		{"drop_held_cap", s.heldCap.Load()}, {"drop_held_bytes", s.heldBytes.Load()},
		{"drop_too_old", s.tooOld.Load()},
		{"kernel_icmp_passed", s.kernelICMP.Load()}, {"synack_judged", s.synAck.Load()},
		{"udp_expired_rejudged", s.expired.Load()},
		{"reval_started", s.revalStart.Load()}, {"reval_allow", s.revalPass.Load()}, {"reval_deny", s.revalDeny.Load()},
		{"refresh_started", s.refreshStart.Load()}, {"refresh_allow", s.refreshPass.Load()}, {"refresh_deny", s.refreshDeny.Load()},
		{"frag_first", s.fragFirst.Load()}, {"frag_followed", s.fragFollow.Load()}, {"frag_orphan", s.fragOrphan.Load()},
		{"cache_evictions", expEvictions.Load()},
	}
	for k := 0; k < unattrKinds; k++ {
		c = append(c, expCounter{"unattr_" + unattrNames[k], s.unattr[k].Load()})
	}
	for i, name := range []string{"lat_deny", "lat_allow"} {
		for b := 0; b < latBuckets; b++ {
			label := "inf"
			if b < len(latBounds) {
				label = fmt.Sprintf("%d", latBounds[b])
			}
			c = append(c, expCounter{fmt.Sprintf("%s_lt%sus", name, label), s.lat[i][b].Load()})
		}
	}
	return c
}

type expCounter struct {
	name string
	v    int64
}

// report logs the counters that changed since prev, and returns the new snapshot.
func (h *holder) report(prev []expCounter, elapsed time.Duration) []expCounter {
	cur := h.stats.snapshot()
	if ExpLogf == nil {
		return cur
	}
	var parts []string
	for i, c := range cur {
		d := c.v
		if prev != nil {
			d -= prev[i].v
		}
		if d != 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", c.name, d))
		}
	}
	if len(parts) == 0 {
		return cur
	}
	o := h.opts.Load()
	ExpLogf("uidfilter-exp-v1: %.0fs opts=%s workers=%d pending=%d cache=%d max_rounds=%d lat_max_allow=%dus lat_max_deny=%dus %s",
		elapsed.Seconds(), o, h.workerCount(), h.stats.pendingNow.Load(), h.stats.cacheNow.Load(),
		h.stats.maxRounds.Swap(0), h.stats.latMax[1].Swap(0), h.stats.latMax[0].Swap(0), strings.Join(parts, " "))
	return cur
}

// --- packets the filter cannot attribute ---

func classify(p []byte) int {
	if len(p) < 1 {
		return unattrOther
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return unattrOther
		}
		if frag := int(p[6])<<8 | int(p[7]); frag&(ipv4FlagMF|ipv4MaskFragOffset) != 0 {
			return unattrFrag
		}
		if p[9] == 1 {
			return unattrICMP4
		}
	case 6:
		if len(p) < 40 {
			return unattrOther
		}
		switch p[6] {
		case 58:
			return unattrICMP6
		case 0, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254:
			return unattrV6Ext
		}
	}
	return unattrOther
}

// isEchoRequest reports whether an ICMP packet is an echo request, the only
// ICMP message an unprivileged ping socket may send (net/ipv4/ping.c,
// ping_supported). Everything else ICMP leaving the phone is the kernel's
// answer to a packet that arrived through the tunnel.
func isEchoRequest(p []byte, kind int) bool {
	if kind == unattrICMP4 {
		ihl := int(p[0]&0x0f) * 4
		return len(p) <= ihl || p[ihl] == 8
	}
	return len(p) <= 40 || p[40] == 128
}

// unattributable handles a packet parse5Tuple rejected: counted, then dropped,
// unless an experimental option has a better answer.
func (s *flowState) unattributable(h *holder, o *ExpOptions, p []byte, r Releaser) bool {
	kind := classify(p)
	switch kind {
	case unattrICMP4, unattrICMP6:
		if o.KernelICMP && !isEchoRequest(p, kind) {
			h.stats.kernelICMP.Add(1)
			return true
		}
	case unattrFrag:
		if o.Fragments {
			return s.fragment(h, o, p, r)
		}
	}
	h.stats.unattr[kind].Add(1)
	return false
}

// --- IPv4 fragments, judged by the first one ---

const maxFragIDs = 1024

type fragKey struct {
	src, dst [4]byte
	id       uint16
	proto    uint8
}

type fragEntry struct {
	key  flowKey
	pass bool  // the first fragment needed no verdict (TCP without SYN)
	at   int64 // coarse clock when the first fragment was seen
}

// fragment handles an IPv4 fragment. The first one carries the ports and is
// judged like any packet of its flow; the later ones follow it by (source,
// destination, protocol, identification), for maxHoldTime. A later fragment
// whose first one was not seen is dropped.
func (s *flowState) fragment(h *holder, o *ExpOptions, p []byte, r Releaser) bool {
	var fk fragKey
	copy(fk.src[:], p[ipv4OffsetSrc:ipv4OffsetSrc+4])
	copy(fk.dst[:], p[ipv4OffsetDst:ipv4OffsetDst+4])
	fk.id = uint16(p[4])<<8 | uint16(p[5])
	fk.proto = p[9]
	now := h.now.Load()
	ihl := int(p[0]&0x0f) * 4

	if (int(p[6])<<8|int(p[7]))&ipv4MaskFragOffset == 0 {
		if !isTCPOrUDP(p[9]) || ihl < 20 || len(p) < ihl+4 {
			h.stats.unattr[unattrFrag].Add(1)
			return false
		}
		key := flowKey{proto: p[9], ipLen: 4,
			srcPort: uint16(p[ihl])<<8 | uint16(p[ihl+1]), dstPort: uint16(p[ihl+2])<<8 | uint16(p[ihl+3])}
		copy(key.srcIP[:], fk.src[:])
		copy(key.dstIP[:], fk.dst[:])
		pass := false
		if p[9] == ipProtoTCP && len(p) > ihl+tcpOffsetFlags && p[ihl+tcpOffsetFlags]&tcpFlagSYN == 0 {
			pass = true
		}
		if len(s.frags) >= maxFragIDs {
			clear(s.frags)
		}
		s.frags[fk] = fragEntry{key: key, pass: pass, at: now}
		h.stats.fragFirst.Add(1)
		if pass {
			return true
		}
		return s.decide(h, o, key, p, r, now)
	}

	e, ok := s.frags[fk]
	if !ok || now-e.at > maxHoldTime.Nanoseconds() {
		h.stats.fragOrphan.Add(1)
		return false
	}
	h.stats.fragFollow.Add(1)
	if e.pass {
		return true
	}
	return s.decide(h, o, e.key, p, r, now)
}

// --- UDP verdicts judged again without holding ---

// revalidate handles a packet of a UDP flow whose allowed verdict expired less
// than maxHoldTime ago. The packet passes on the old verdict, and the flow is
// judged again unless it already is; the new verdict replaces the old one when
// the reader next sees the flow. Past maxHoldTime the flow goes back to hold.
func (s *flowState) revalidate(h *holder, key flowKey, r Releaser, now int64) bool {
	return s.rejudge(h, key, r, now, &h.stats.revalStart, &h.stats.revalPass, &h.stats.revalDeny)
}

// refresh handles a packet of a UDP flow whose allowed verdict is still valid but
// older than RefreshAfter: it passes, as it would anyway, and the flow is judged
// again in the background. No packet waits and none passes on a verdict older
// than cacheTTL, and a socket that took over the 5-tuple of an allowed flow is
// denied about RefreshAfter after the lookup it inherited, not cacheTTL.
func (s *flowState) refresh(h *holder, key flowKey, r Releaser, now int64) bool {
	return s.rejudge(h, key, r, now, &h.stats.refreshStart, &h.stats.refreshPass, &h.stats.refreshDeny)
}

// rejudge passes a packet on its flow's old verdict and judges the flow again
// unless it already is; the new verdict replaces the old one when the reader
// next sees the flow.
func (s *flowState) rejudge(h *holder, key flowKey, r Releaser, now int64, started, pass, deny *atomic.Int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pf, ok := s.pending[key]; ok {
		if !pf.decided {
			return true
		}
		delete(s.pending, key)
		s.cache.put(key, pf.allow, now)
		if pf.allow {
			pass.Add(1)
		} else {
			deny.Add(1)
		}
		return pf.allow
	}
	if s.waiting >= maxPendingFlows {
		return true // no room now: tried again on the next packet
	}
	select {
	case h.jobs <- job{s, key}:
	default:
		return true
	}
	s.pending[key] = &pendingFlow{r: r}
	s.waiting++
	started.Add(1)
	return true
}

type cacheLookup uint8

const (
	cacheMiss cacheLookup = iota
	cacheHit
	cacheExpired // an expired entry, now deleted
	cacheStale   // an allowed entry expired less than maxHoldTime ago, kept
)

// lookup is get with the experimental grace period for allowed verdicts. It
// also returns when the entry expires, so that its age costs no second lookup.
func (c *decisionCache) lookup(k flowKey, now int64, keepStale bool) (bool, int64, cacheLookup) {
	e, ok := c.m[k]
	if !ok {
		return false, 0, cacheMiss
	}
	if e.expiresAt > now {
		return e.allow, e.expiresAt, cacheHit
	}
	if keepStale && e.allow && now-e.expiresAt < maxHoldTime.Nanoseconds() {
		return true, e.expiresAt, cacheStale
	}
	delete(c.m, k)
	return false, 0, cacheExpired
}
