package uidfilter

// Experimental instrumentation for measuring the filter on a device. Never
// part of a pull request: it lives on the lab branch only, on top of release.
//
// Options are read from ExpLoad when a filter is installed and once a second,
// so that a device build can switch them without being rebuilt. The zero
// value is the release behaviour. Counters are reported through ExpLogf every
// expReportEvery ticks, as deltas, when anything changed.

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// ExpOptions switch experimental behaviour.
type ExpOptions struct {
	KernelICMP  bool      // pass ICMP that an unprivileged socket cannot send
	Workers     int       // filter calls at once, taken when a filter is installed; 0 means workers
	HeldPerFlow int       // packets held per flow; 0 means maxHeldPerFlow
	CacheMode   CacheMode // the verdict cache, taken when a filter is installed
}

func (o ExpOptions) String() string {
	var s []string
	if o.KernelICMP {
		s = append(s, "icmp")
	}
	if o.Workers > 0 {
		s = append(s, fmt.Sprintf("w%d", o.Workers))
	}
	if o.HeldPerFlow > 0 {
		s = append(s, fmt.Sprintf("h%d", o.HeldPerFlow))
	}
	if o.CacheMode != CachePR {
		s = append(s, "c="+o.CacheMode.String())
	}
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ",")
}

// ParseExpOptions reads a comma-separated list: icmp, wN, hN, c=MODE. Anything
// else is ignored, including the prototypes of earlier lab builds (rv, raN, sa, frag),
// which are now part of the release code or were dropped.
func ParseExpOptions(v string) ExpOptions {
	var o ExpOptions
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		switch {
		case f == "icmp":
			o.KernelICMP = true
		case strings.HasPrefix(f, "c="):
			for m, name := range cacheModeNames {
				if f[2:] == name {
					o.CacheMode = CacheMode(m)
				}
			}
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

func (h *holder) expOpts() *ExpOptions {
	if o := h.opts.Load(); o != nil {
		return o
	}
	return &ExpOptions{}
}

func (h *holder) workerCount() int {
	if o := h.expOpts(); o.Workers > 0 {
		return o.Workers
	}
	return workers
}

func (h *holder) heldPerFlow() int {
	if o := h.expOpts(); o.HeldPerFlow > 0 {
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
	refreshStart, refreshPass, refreshDeny                  atomic.Int64
	fragFirst, fragFollow, fragOrphan                       atomic.Int64
	lat                                                     [2][latBuckets]atomic.Int64 // [deny, allow]
	latMax                                                  [2]atomic.Int64
	pendingNow, cacheNow                                    atomic.Int64

	snapWant atomic.Bool               // set by each report, cleared by the reader that takes a snapshot
	snap     atomic.Pointer[cacheSnap] // the latest snapshot
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
		{"refresh_started", s.refreshStart.Load()}, {"refresh_allow", s.refreshPass.Load()}, {"refresh_deny", s.refreshDeny.Load()},
		{"frag_first", s.fragFirst.Load()}, {"frag_followed", s.fragFollow.Load()}, {"frag_orphan", s.fragOrphan.Load()},
		{"cache_evictions", expEvictions.Load()},
		{"fifo_evicted_allow", expFIFOEvictedAllow.Load()}, {"fifo_evicted_deny", expFIFOEvictedDeny.Load()},
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
// It also logs what the cache held when the reader last took a snapshot, and
// asks for a new one.
func (h *holder) report(prev []expCounter, elapsed time.Duration) []expCounter {
	cur := h.stats.snapshot()
	if ExpLogf == nil {
		return cur
	}
	if snap := h.stats.snap.Swap(nil); snap != nil {
		ExpLogf("uidfilter-exp-v1: cache %s", snap)
	}
	h.stats.snapWant.Store(true)
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
	ExpLogf("uidfilter-exp-v1: %.0fs opts=%s cmode=%s workers=%d pending=%d cache=%d max_rounds=%d lat_max_allow=%dus lat_max_deny=%dus %s",
		elapsed.Seconds(), h.expOpts(), h.cache, h.workerCount(), h.stats.pendingNow.Load(), h.stats.cacheNow.Load(),
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

// unattributable handles a packet parse5Tuple rejected: IPv4 fragments follow
// their first one as in release, kernel ICMP passes with the icmp option, and
// everything else is counted by kind and dropped.
func (s *flowState) unattributable(h *holder, p []byte, r Releaser) bool {
	kind := classify(p)
	switch kind {
	case unattrICMP4, unattrICMP6:
		if h.expOpts().KernelICMP && !isEchoRequest(p, kind) {
			h.stats.kernelICMP.Add(1)
			return true
		}
	case unattrFrag:
		if p[0]>>4 == 4 && isTCPOrUDP(p[9]) {
			return s.fragment(h, p, r)
		}
	}
	h.stats.unattr[kind].Add(1)
	return false
}

// --- verdict cache variants, for the comparison asked for on amneziawg-go#199 ---

// CacheMode selects how verdicts are cached. It is taken when a filter is
// installed, so a running filter never changes its cache; to switch, remove
// the filter and put it back (debug.awg.strict=0, then 1).
type CacheMode uint8

const (
	// CachePR is the release cache: a UDP verdict expires after cacheTTL, an
	// allowed flow still sending after refreshAfter is judged again while its
	// packets pass, and a full cache evicts denied verdicts first.
	CachePR CacheMode = iota
	// CacheFIFO is the cache proposed on #199: no expiry and no refresh, a FIFO
	// of cacheMaxEntries UDP verdicts, allowed and denied alike.
	CacheFIFO
	// CacheNoRefresh expires a verdict after cacheTTL without refreshing it, so
	// an active flow is held while it is judged again (strict.3).
	CacheNoRefresh
	// CacheHold judges an allowed flow again after refreshAfter, as release
	// does, but holds its packets meanwhile instead of passing them.
	CacheHold
	// CacheF174 is CacheFIFO with every TCP packet going through it as well,
	// as in amneziawg-go#174: a SYN on a 5-tuple seen before takes its verdict,
	// and a packet of a connection whose verdict was evicted is judged again.
	CacheF174
)

var cacheModeNames = [...]string{"pr", "fifo", "noref", "hold", "f174"}

func (m CacheMode) String() string {
	if int(m) < len(cacheModeNames) {
		return cacheModeNames[m]
	}
	return fmt.Sprintf("c%d", m)
}

// expCache is a Gate's cache in a mode other than CachePR. CacheNoRefresh and
// CacheHold keep their verdicts in the release decisionCache; the FIFO modes
// keep them here.
type expCache struct {
	mode CacheMode
	fifo fifoCache
}

// fifoCache is the cache of #174: a map, and a ring of its keys in the order
// they were stored. A full cache drops its oldest key, whatever its verdict.
type fifoCache struct {
	m     map[flowKey]bool
	order []flowKey
	at    []int64 // when each key in order was stored, for the snapshot
	head  int
	size  int
}

func (s *flowState) expInit(h *holder) {
	if h.cache == CachePR {
		return
	}
	s.exp = &expCache{mode: h.cache}
	if s.exp.isFIFO() {
		s.exp.fifo = fifoCache{
			m:     make(map[flowKey]bool, cacheMaxEntries),
			order: make([]flowKey, cacheMaxEntries),
			at:    make([]int64, cacheMaxEntries),
		}
	}
}

func (e *expCache) isFIFO() bool { return e.mode == CacheFIFO || e.mode == CacheF174 }

// expDecide is decide for the modes other than CachePR.
func (s *flowState) expDecide(h *holder, key flowKey, packet []byte, r Releaser, now int64) bool {
	switch s.exp.mode {
	case CacheNoRefresh:
		if key.proto == ipProtoUDP {
			if allow, _, found := s.cache.get(key, now); found {
				return allow
			}
		}
	case CacheHold:
		if key.proto == ipProtoUDP {
			if allow, due, found := s.cache.get(key, now); found && !(allow && due) {
				return allow
			}
		}
	case CacheFIFO, CacheF174:
		if key.proto == ipProtoUDP || s.exp.mode == CacheF174 {
			if allow, found := s.exp.fifo.m[key]; found {
				return allow
			}
		}
	}
	return s.hold(h, key, packet, r, now)
}

// store keeps a verdict the workers reached, and reports whether it did: the
// modes that use the release cache leave it to the release code.
func (e *expCache) store(key flowKey, allow bool, now int64) bool {
	if !e.isFIFO() || (key.proto == ipProtoTCP && e.mode != CacheF174) {
		return false
	}
	e.fifo.put(key, allow, now)
	return true
}

func (c *fifoCache) put(k flowKey, allow bool, now int64) {
	if _, ok := c.m[k]; ok {
		c.m[k] = allow
		return
	}
	if c.size == len(c.order) {
		old := c.order[c.head]
		if c.m[old] {
			expFIFOEvictedAllow.Add(1)
		} else {
			expFIFOEvictedDeny.Add(1)
		}
		delete(c.m, old)
	} else {
		c.size++
	}
	c.order[c.head], c.at[c.head] = k, now
	c.m[k] = allow
	if c.head++; c.head == len(c.order) {
		c.head = 0
	}
}

var expFIFOEvictedAllow, expFIFOEvictedDeny atomic.Int64

// --- what the cache holds: a snapshot every report, without addresses ---

// entry ages, upper bounds in seconds; the last bucket is open
var snapAgeBounds = [...]int64{2, 10, 60, 600}

const snapAges = len(snapAgeBounds) + 1

// destination port classes of allowed entries
const (
	portDNS = iota
	portHTTPS
	portSTUN
	portOther
	portClasses
)

var portClassNames = [portClasses]string{"53", "443", "stun", "other"}

func portClass(p uint16) int {
	switch p {
	case 53:
		return portDNS
	case 443:
		return portHTTPS
	case 3478, 19302:
		return portSTUN
	}
	return portOther
}

// cacheSnap is what one Gate's cache held at one moment.
type cacheSnap struct {
	mode        CacheMode
	allow, deny int
	tcp         int // TCP entries, CacheF174 only
	dead        int // expired and not yet removed: they decide nothing
	ageAllow    [snapAges]int
	ageDeny     [snapAges]int
	portAllow   [portClasses]int
	oldestAllow int64 // seconds
}

func (c *cacheSnap) add(k flowKey, allow bool, age int64) {
	secs := age / int64(time.Second)
	b := len(snapAgeBounds)
	for i, ub := range snapAgeBounds {
		if secs < ub {
			b = i
			break
		}
	}
	if k.proto == ipProtoTCP {
		c.tcp++
	}
	if !allow {
		c.deny++
		c.ageDeny[b]++
		return
	}
	c.allow++
	c.ageAllow[b]++
	c.portAllow[portClass(k.dstPort)]++
	if secs > c.oldestAllow {
		c.oldestAllow = secs
	}
}

// expSnapshot records what the cache holds. It runs on the tun-read goroutine,
// which owns the cache, when a report has asked for it.
func (s *flowState) expSnapshot(h *holder, now int64) {
	h.stats.snapWant.Store(false)
	snap := &cacheSnap{mode: h.cache}
	if s.exp != nil && s.exp.isFIFO() {
		f := &s.exp.fifo
		for i := 0; i < f.size; i++ {
			snap.add(f.order[i], f.m[f.order[i]], now-f.at[i])
		}
	} else {
		for k, e := range s.cache.m {
			if e.expiresAt <= now {
				snap.dead++
				continue
			}
			snap.add(k, e.allow, now-(e.expiresAt-cacheTTL.Nanoseconds()))
		}
	}
	h.stats.snap.Store(snap)
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, "/")
}

func (c *cacheSnap) String() string {
	ports := make([]string, portClasses)
	for i, n := range c.portAllow {
		ports[i] = fmt.Sprintf("%s:%d", portClassNames[i], n)
	}
	return fmt.Sprintf("mode=%s allow=%d deny=%d tcp=%d dead=%d age_allow=%s age_deny=%s oldest_allow=%ds port_allow=%s",
		c.mode, c.allow, c.deny, c.tcp, c.dead, joinInts(c.ageAllow[:]), joinInts(c.ageDeny[:]),
		c.oldestAllow, strings.Join(ports, ","))
}
