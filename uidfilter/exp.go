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
	KernelICMP  bool // pass ICMP that an unprivileged socket cannot send
	Workers     int  // filter calls at once, taken when a filter is installed; 0 means workers
	HeldPerFlow int  // packets held per flow; 0 means maxHeldPerFlow
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
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ",")
}

// ParseExpOptions reads a comma-separated list: icmp, wN, hN. Anything else is
// ignored, including the prototypes of earlier lab builds (rv, raN, sa, frag),
// which are now part of the release code or were dropped.
func ParseExpOptions(v string) ExpOptions {
	var o ExpOptions
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		switch {
		case f == "icmp":
			o.KernelICMP = true
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
	ExpLogf("uidfilter-exp-v1: %.0fs opts=%s workers=%d pending=%d cache=%d max_rounds=%d lat_max_allow=%dus lat_max_deny=%dus %s",
		elapsed.Seconds(), h.expOpts(), h.workerCount(), h.stats.pendingNow.Load(), h.stats.cacheNow.Load(),
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
