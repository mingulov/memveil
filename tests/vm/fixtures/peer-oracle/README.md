# Peer-oracle recorded fixtures

Recorded tracefs oracle bytes from the pinned 7.0.14 guest
during hook-coverage qualification of the outer DMA API
(`dma_map_phys`/`dma_unmap_phys`) on the pcnet path. The
offline oracle tests parse these exact bytes and must
reproduce the qualified pairing counts exactly; the tests
pin both digests and refuse silently edited fixtures.

- `step3-trace.txt`: traffic window, 500 maps + 500 unmaps,
  all owned-NIC, zero orphans.
- `step5-trace.txt`: down/up bracket window, 20/20 pre,
  32 teardown unmaps of pre-existing mappings, 53/21 post
  with a 32-mapping held ring.

DMA/bus addresses in these files are ephemeral disposable
guest values, kept only because the pairing correlator is
`(device, dma_addr)`: parsing and pairing fidelity cannot
be proven without them. Live-leg exports never carry them;
the guest pairs in-guest and exports opaque key ids plus
counts only.
