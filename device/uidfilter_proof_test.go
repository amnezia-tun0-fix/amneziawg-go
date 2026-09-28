/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// Held packets are released from uidfilter's worker goroutines, which hold no
// reference on the encryption queue, unlike every upstream caller of
// SendStagedPackets (the tun reader holds one, peers hold one until Stop, and
// Stop waits for the timers first). A release racing Close can therefore reach
// the encryption queue after it is closed. This stress test releases packets in
// a tight loop while the device closes, many times; a "send on closed channel"
// panic fails it. Experimental branch only: iterations from
// UIDFILTER_RACE_ITERATIONS, default 50.
func TestProofReleaseRacesClose(t *testing.T) {
	iterations := 50
	if s := os.Getenv("UIDFILTER_RACE_ITERATIONS"); s != "" {
		iterations, _ = strconv.Atoi(s)
	}
	for it := 0; it < iterations; it++ {
		pair := genTestPair(t, false)
		pair.Send(t, Ping, nil) // completes a handshake, so a keypair exists
		msg := tuntest.Ping(pair[1].ip, pair[0].ip)

		var wg sync.WaitGroup
		stop := make(chan struct{})
		for w := 0; w < releasers(); w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					pair[1].dev.ReleaseOutboundPacket(msg)
				}
			}()
		}
		pair[1].dev.Close()
		close(stop)
		wg.Wait()
		pair[0].dev.Close()
	}
}

// releasers is how many goroutines release packets at once, from
// UIDFILTER_RACE_RELEASERS, default 4 (the number of uidfilter workers).
func releasers() int {
	if n, err := strconv.Atoi(os.Getenv("UIDFILTER_RACE_RELEASERS")); err == nil && n > 0 {
		return n
	}
	return 4
}
