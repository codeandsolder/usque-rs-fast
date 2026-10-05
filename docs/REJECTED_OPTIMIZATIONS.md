# Rejected, neutral, and superseded performance experiments

This is the "do not rediscover this from scratch" companion to
[`BENCHMARKING.md`](BENCHMARKING.md).

The September-October 2026 optimization campaign produced roughly fifty named
candidate configurations, artifacts, or benchmark isolates. They were **not**
fifty independent architectural ideas. Many were controlled variants of the
same mechanism: different packet targets, deadlines, activation rules,
deactivation rules, profiler settings, dependency pins, or source-matched
controls.

A useful mental model is **about a dozen independent mechanism families plus a
large number of policy and attribution variants**.

Before implementing an apparently obvious native-TUN optimization, search this
file for the mechanism and its aliases. A candidate marked `REJECTED` or
`NEUTRAL` should not be a first-pass experiment again unless something material
about the surrounding architecture has changed.

## Status vocabulary

- **REJECTED** — measured on an appropriate native path and failed the
  promotion gate. Do not retry as a first-pass candidate.
- **NEUTRAL** — correct and viable, but the measured effect was inside noise or
  too small/inconsistent to promote.
- **SUPERSEDED** — an older form of an idea that evolved into a better variant.
  Do not rerun the old form; start from the accepted descendant/current policy.
- **INCONCLUSIVE** — historical evidence had a confound or never reached a
  promotion-grade gate. This is not evidence that the idea is bad.
- **DEFERRED** — plausible, but either structurally expensive or below the
  current opportunity threshold. Revisit only when adjacent architecture makes
  it natural.
- **ACCEPTED DESCENDANT** — this exact variant failed or was superseded, but a
  later form of the same mechanism is in the maintained stack.

## Family index

| Family | Representative variants | Final disposition |
|---|---|---|
| Cross-iteration TUN batching / ready-drain policy | fixed delays, cap 2/8, fixed-PPS gate, self-calibration, adaptive v1/v2/v2.1/v2.2/v3, deadline sweeps, split gate, streak hysteresis, activation sweeps, deadline-only | **ACCEPTED DESCENDANT**, many old variants rejected/superseded |
| RX QUIC flush deferral | fixed/deferred flush, adaptive/fixed controller states, profiler on/off isolates | **REJECTED** |
| TX DATAGRAM ownership / pooling | truncate-resize v1, O(1) v2, factory isolate, alignment isolate, aligned final pool | **NEUTRAL** final form; earlier forms **REJECTED** |
| Outer UDP / QUIC send batching | cross-packet GSO burst, zero-delay sendmmsg, connected `send()` tail | **REJECTED** |
| Timestamp reuse | recvmmsg RX / GSO TX shared timestamp | **REJECTED** |
| quiche code layout / outlining | receive outline, lost-frame outline, post-handshake slow helper | **REJECTED** |
| Post-handshake / 0-RTT steady-state micro paths | early post-handshake no-work return, outlined version, empty 0-RTT queue fast path | no promotable whole-host win; **REJECTED/EXHAUSTED** |
| tun-rs checksum specialization | hand-written AVX2/SAD, pseudo-header specialization | SAD **REJECTED** end-to-end; pseudo-header **DEFERRED** |
| tun-rs GRO data movement | remove packet `.to_vec()`, flow-map lookup/hash variants | copy removal **REJECTED**; entry+AHash descendants accepted |
| quiche path/CID/cache surgery | SCID shortcut, broader active-path cache, inline `ConnectionId` / short-header allocation removal | SCID shortcut accepted; broader variants **REJECTED/NEUTRAL** |
| DATAGRAM crypto/header specialization | BoringSSL scatter-seal, `write_pkt_type()` Short fast path, redundant accounting removal | scatter/header fast paths **REJECTED**; direct accounting accepted |
| Event-loop/readiness/timer changes | reusable timer bundle, unbiased select, UDP readiness-clear, late drain/microcoalesce | **REJECTED/SUPERSEDED** |
| Recovery/container micro-rewrites | `Vec<Acked>::drain(..)` -> slice+clear, metadata-layout ideas | rewrite rationale invalid; broader layout work **DEFERRED** |

The table deliberately groups candidate *configurations* into mechanisms. For
example, the TUN batching family alone accounts for a double-digit number of
named candidates.

---

## 1. Cross-iteration TUN batching / ready-drain policy

### What survived

The underlying mechanism is real: after one awaited TUN read, draining packets
that are **already ready** before flushing QUIC lets quiche pack more inner
DATAGRAMs per outer packet and activates the existing UDP GSO path.

Early same-path tests at 40 Mbit/s / 256-byte packets reduced process CPU by
about 13.5% and `sendto` count by about 48%. At 65 Mbit/s the effect was larger:
about 18.2% lower process CPU and about 67% fewer `sendto` calls.

That mechanism is an accepted ancestor of the maintained adaptive policy.

### Variants that should not be rediscovered

#### Unconditional ready-drain — `SUPERSEDED`

It was excellent at sufficiently high packet rates but regressed low-rate
operation where there usually was no useful backlog. The lesson is not "ready
drain is bad"; it is **do not enable it unconditionally**.

#### Drain cap 2 vs cap 8 — `NEUTRAL`

At 40 Mbit/s, cap 2 and cap 8 differed by about 0.15% total CPU, i.e. noise.
Cap 8 retained stronger batching and was the configuration used for the
promotion-grade mechanism result.

Do not reopen cap tuning unless a new workload shows fairness/latency pressure.

#### Fixed packets-per-second gate — `REJECTED`

A WAW-specific hysteresis rule (enable around 10.5k pps, disable around 10.0k
pps) removed the low-rate regression, but encoded the break-even point of one
Zen 2 + virtio_net environment.

It was deliberately rejected as non-portable.

Alias/provenance breadcrumb: `rejected-fixed-pps-ready-drain.patch`.

#### Adaptive v1 — `SUPERSEDED`

Too eager. A single dense burst could activate retention and reintroduced
low-rate overhead. Later versions required repeated qualifying receive events.

Do not use the early "one burst means dense traffic" rule.

#### Adaptive v2 — `SUPERSEDED`

High tier:
- roughly neutral at 50/100 Mbit/s,
- about 5-6% host-wide improvement at 200 Mbit/s.

But MT7621 validation found a real low-rate regression around 5 Mbit/s: about
6% host cost and about 3% candidate-process overhead.

The mechanism was retained, the policy was not.

#### Adaptive v2.1 — useful ancestor, later superseded

Moved the low-rate rejection check before an unnecessary `Instant::now()` so
non-qualifying receive events did not pay a clock read. This removed v2's
repeatable MT7621 5 Mbit/s regression and was effectively no-regression at
5/10/20 Mbit/s after the stability gate was fixed.

Later policy work evolved beyond it; do not go backwards to v2/v2.1 as a new
candidate.

#### Adaptive v2.2 — `REJECTED`

A seemingly semantics-preserving cleanup removed another inactive-path
end-of-loop clock read. It nevertheless produced a reproducible small
regression.

Dedicated 10 Mbit/s low-tier confirmation had four valid host deltas:

`+2.20%, +0.64%, +4.08%, +1.92%`

Median host regression: **+2.06%**. Candidate-process median: **+2.05%**.

This is a useful warning that tiny hot-loop layout/timing changes are not free
merely because the source-level policy is equivalent.

#### Adaptive v3 (enable after 2 dense events) — `REJECTED`

Changed the dense-event activation requirement from 3 events to 2.

It was stopped after two complete repeats because the direction was clearly
inferior; RX100 host deltas were **+9.73% and +7.14%**. It also increased
low/mid-rate regression risk.

Do not retry "just lower the activation streak to 2".

#### Static target/deadline sweeps — mostly `SUPERSEDED`

Targets 1/2/4/8/16 and target-4 deadlines 250/500/1000 us were screened.
Target 4 was the only useful region, but static timing did not generalize across
rates.

The important later result was the rate crossover, not a magic fixed delay.

#### Split activation/deadline gate — fixed activation windows `REJECTED`

Six-repeat same-ELF confirmation showed the problem clearly.

At RX50:
- a250/d1000: **+14.59%** median vs p1,
- a500/d1000: **+9.48%**.

At RX100:
- a250/d1000: **-6.95%**,
- a500/d1000: **-9.21%**.

So fixed activation timing could be a strong high-rate win while being a real
mid-rate regression. A single fixed activation window was rejected.

#### Enable-streak hysteresis 3/5/8 — `REJECTED`

Same-ELF screen at RX50/RX100:

- e3: RX50 +4.16%, RX100 -5.19%,
- e5: RX50 +11.66%, RX100 -5.59%,
- e8: RX50 -0.07%, RX100 +0.32%.

No streak preserved both the low-rate guardrail and high-rate benefit.

#### e5 activation 500/250/125 us — `REJECTED`

Follow-up screen:

- a500: RX50 -2.30%, RX100 +3.57%,
- a250: RX50 -5.46%, RX100 -3.34%,
- a125: RX50 -4.14%, RX100 +4.17%.

Simple trigger-window/streak tuning was therefore exhausted.

#### Deadline-only deactivation — accepted descendant

The key policy change was to stop treating a successful target-filled batch as
"slow" merely because fill time exceeded a threshold. Only actual deadline
expiry contributes to disabling retention.

The selected screen policy (target 4, activation 125 us, deadline 1000 us)
gave:
- RX50: -1.05% median, 8/8 quality,
- RX100: -7.52% median, 7/8 wins, 8/8 quality.

If revisiting this family, start from the maintained descendant of this policy,
not from the rejected variants above.

---

## 2. Bounded RX QUIC flush deferral — `REJECTED`

This was the campaign's best example of a profiler-created false lead.

The mechanism looked excellent under diagnostic instrumentation:
- 5/5 pairs favored deferral,
- idle-adjusted host CPU/Gbit about **-7.20%**,
- process CPU/Gbit about **-12.50%**,
- QUIC flush calls/Gbit about **-24.64%**,
- UDP send syscalls/Gbit about **-27.84%**.

Clean native promotion tests did not reproduce it:

- current production RX50: **+3.15%** median host, only 1/5 wins;
- clean old-quiche adaptive: **+1.83%**, 1/5;
- clean old-quiche fixed policy: **-0.34%**, 3/5 with huge spread;
- exact historical diagnostic ELF with profiler disabled: **-1.03%**, 3/5.

Turning the flow profiler off on the same diagnostic lineage collapsed the
large apparent benefit. The counters are useful mechanism evidence; they are
not a production optimization result.

Do not retry bounded RX flush deferral unless the event-loop architecture has
changed enough to invalidate this instrumentation isolate.

Aliases: `RX_FLUSH_EVERY`, flush-defer, bounded flush deferral.

---

## 3. TX DATAGRAM buffer ownership / pooling

### v1 truncate/resize recycle — `REJECTED`

The first pool moved the working TUN `Vec` into quiche, truncated to active
DATAGRAM length, then resized on recycle. The resize zero-filled the tail every
packet, replacing an avoided payload copy with a large store. Live TX collapsed
badly.

Do not implement a pool that shrinks and zero-fills a packet-sized allocation
on every recycle.

### v2 O(1) recycle — `REJECTED`

Removing truncate/resize fixed the obvious zero-fill bug but did not fix the
performance regression.

At a throughput-matched 100 Mbit/s pair:
- baseline: 7.42 CPU-s,
- v2: 9.10 CPU-s,
- roughly **22.6% worse** CPU/Gbit.

Some later candidate runs also entered pathological low-progress states.

### Default-equivalent custom `BufFactory` — `NEUTRAL`

A factory-identity isolate did **not** reproduce the v2 regression. Three clean
40 Mbit/s pairs appeared about 4.1% better in median, but that was treated as
codegen/layout noise rather than a promotable optimization.

The generic factory type itself was not the problem.

### Alignment isolate — root cause found

The bad pool placed the TUN/IP packet immediately after the two-byte
CONNECT-IP prefix, moving the packet copy destination from an allocation-aligned
base to `base + 2`.

Restoring packet start to offset 64 removed the catastrophic regression.

This is an important implementation constraint for any future ownership work:
**preserve useful packet alignment**.

### Final aligned pool — `NEUTRAL`

At about 100 Mbit/s:
- accepted no-pool baseline: 8.01 process CPU-s,
- aligned pooled candidate: 8.12 process CPU-s.

Wire-correct, architecturally viable, but performance-neutral.

Pooling/recycling the allocation is not itself a useful first-pass target.

### True copy-boundary removal — `DEFERRED`

A conceptually different design could receive TUN packets with MASQUE headroom
and transfer ownership of that buffer directly into quiche's queued DATAGRAM
representation.

That removes a copy boundary rather than merely recycling allocations, but
requires integrated buffer ownership/factory work. Current profiles put the
likely ceiling at only a few percent. Revisit if a future architecture already
needs that ownership model.

---

## 4. QUIC cross-packet GSO/send batching and UDP send tweaks

### quiche `send_gso_burst()` v1 — `REJECTED`

The prototype hoisted timestamp sampling, active-path selection,
handshake/0-RTT checks, PMTU setup, and `SendInfo` construction across an
equal-segment GSO burst.

Stable 65 Mbit/s pairs showed only about **0.79% median apparent process-CPU
improvement**.

Hardware counters moved the wrong way:
- instructions: **+4.6%**,
- branches: **+4.9%**,
- branch misses: **+4.7%**,
- task-clock: essentially unchanged.

Do not add complexity to this v1 design.

### Zero-delay `sendmmsg` without queued work — `REJECTED/EXHAUSTED`

The underlying problem was not lack of a syscall API. With one useful packet
available at a time, a zero-delay batching call has nothing to batch.

The accepted ready-drain mechanism attacked the source of batching opportunity
instead: expose multiple ready inner packets before QUIC flush.

Do not retry sendmmsg as a first-pass change unless the producer now naturally
queues multiple outer packets.

### Connected UDP `send()` vs `send_to()` tail — `REJECTED`

The socket was already connected, so a current-stack probe replaced the
non-GSO tail `send_to(first_info.to)` with connected `send()`.

Five accepted RX100 pair deltas in idle-adjusted host CPU/Gbit:

`-3.40%, +2.34%, +0.65%, -14.55%, +11.23%`

Median: **+0.65%**, only 2/5 host wins.

Process CPU median was slightly favorable, but the whole-host result was
neutral/noisy. Do not widen or promote.

---

## 5. Batch timestamp reuse — `REJECTED`

The idea was to reuse one `Instant` for one `recvmmsg` receive burst or one UDP
GSO transmit burst instead of sampling the clock per packet. Profiles made this
plausible because clock acquisition was visible at roughly 1.5-2.5% of CPU.

Current-stack native RX100 result, five quality-clean pairs:

`+3.93%, +4.36%, +8.50%, +1.53%, +12.87%`

Median idle-adjusted host CPU/Gbit: **+4.36%**, **0/5 wins**.

Some userspace/process counters could move slightly in the attractive direction
while the whole-host score consistently regressed.

Decision: reject. Do not run a new RX50 widening screen unless the surrounding
send/receive architecture changes.

Aliases: `*_at` quiche APIs, batch timestamp reuse,
`perf/batch-timestamp-reuse-20261001`.

---

## 6. quiche code layout / outlining

### Generic receive-path outlining — `REJECTED`

One receive-path outline reduced candidate process CPU/Gbit by about **1.96%**
while **increasing raw host CPU/Gbit by about 5.21%**.

This is the canonical process-vs-kernel warning: a prettier userspace profile
can make the machine slower.

### Lost-frame outlining — `REJECTED`

Current-stack RX100, five quality-clean pairs:

`-5.49%, +14.74%, +5.20%, +10.49%, +1.68%`

Median idle-adjusted host CPU/Gbit: **+5.20%**, only 1/5 wins.

Do not resurrect the branch merely because `send_single` is large or frontend
counters are visible.

### Post-handshake slow-helper outlining — `REJECTED`

The simple post-handshake early-return genuinely removed user-space work (see
next section), so a cold/noinline slow helper was tested to improve instruction
locality.

Compared with the simple early-return form:
- total process CPU: **0.00%**,
- user cycles: ~tied,
- instructions: +0.40%,
- branches: +0.49%,
- branch misses: **+8.2%**.

Outlining did not convert the real work reduction into a runtime win and made
branch behavior worse.

---

## 7. Post-handshake / 0-RTT no-work micro paths

### Post-handshake ExData early return — `NEUTRAL`, not promoted

`send_on_path()` rebuilt TLS callback state and cloned transport parameters
before discovering that no post-handshake data was pending.

Moving the existing no-work condition earlier was semantically sound and
measurably reduced work:

- user CPU: about **-5%** in one clean split,
- instructions: about **-5.3%**,
- Cachegrind instruction refs: about **-3.8%**,
- L1-I misses: about **-4.2%**.

But the small-packet workload was about 80% system CPU. Same-path total process
CPU stayed neutral/slightly worse (roughly +0.2 to +0.3%).

The optimization is a useful proof that the userspace work was real, but not a
whole-process performance promotion.

### 0-RTT empty-queue fast path — `EXHAUSTED/LOW VALUE`

`process_undecrypted_0rtt_packets()` was only about 0.4% self in the relevant
profile. An empty-queue early return was a valid micro-fast-path hypothesis, but
the later native review closed the post-handshake/0-RTT micro-probe family
without a promotable whole-host win.

Do not make this a first-pass target. Revisit only if a new profile shows the
0-RTT helper has become materially hotter.

---

## 8. tun-rs checksum specialization

### Hand-written AVX2 / `VPSADBW` checksum — `REJECTED` end-to-end

This is another important microbenchmark trap.

On EPYC 7282 the local final-checksum implementation was genuinely much faster:
- 1500 B: about 56.0 ns -> 42.3 ns (~24% faster),
- 4096 B: about 151 ns -> 92.7 ns (~39%),
- 65536 B: about 2374 ns -> 1411 ns (~41%).

It passed broad scalar-equivalence checks.

On the **current full tunnel**, two independent five-pair RX100 campaigns
produced ten accepted pairs overall:
- idle-adjusted host CPU/Gbit median: **+2.17%**,
- raw host median: **+2.14%**,
- only **2/10** host wins,
- process CPU median: +0.84%.

The microbenchmark win does not survive the system boundary. Current native
profiles put the checksum function at only about 0.7-1.2% self cycles in
relevant modes.

Do not retry checksum SIMD as a first-pass tunnel optimization.

### Fixed pseudo-header checksum specialization — `DEFERRED`

Promising in microbench work, but whole-GRO attribution was unstable and it
never earned promotion evidence.

Only revisit if a new profile makes checksum construction a materially larger
fraction of end-to-end cost.

---

## 9. tun-rs GRO data movement / lookup

### Remove GRO packet `.to_vec()` — `REJECTED`

The allocation/copy removal was functionally correct but slower in corrected
standalone CPU probes.

Do not assume "one fewer allocation" is a win in this path; buffer shape,
aliasing, and copy/codegen effects matter.

### Flow-map lookup and hash — accepted descendants

These are here to prevent overgeneralizing the previous rejection.

Two changes **did** work in surgical GRO probes:
- replace `contains_key` + `get_mut` with one entry lookup;
- use randomized AHash for the flow table.

They produced strong standalone improvements and were maintained.

So the durable lesson is not "leave GRO alone"; it is "the obvious packet-copy
removal lost, while lookup/hash work was the useful local target."

---

## 10. quiche path/CID/cache/allocation work

### SCID receive shortcut — accepted

Checking the already-linked active SCID before the ordinary byte-match scan
produced a reproducible small win and was maintained.

### Broader active-path cache/state — `REJECTED/NOT JUSTIFIED`

After the SCID shortcut, expanding the cached state did not expose enough
remaining benefit to justify additional state/invalidation complexity.

Do not restart broad path-cache surgery without a new profile.

### Inline `ConnectionId` / short-header allocation removal — `NEUTRAL`

Eight clean pairs were effectively noise, median around **-0.12%**.

Correct cleanup, not a useful performance target.

### CID representation surgery after SCID shortcut — `DEFERRED`

Later profiles put the residual opportunity below larger frontend/event-loop
costs. Only revisit if CID/path lookup becomes hot again.

---

## 11. DATAGRAM crypto/header/bookkeeping specialization

### BoringSSL DATAGRAM scatter-seal / `extra_in` — `REJECTED`

Wire-correct, about **2.6% worse CPU/bit**.

BoringSSL's AES-GCM/GHASH path is already highly optimized/vectorized; avoiding
one apparent copy through this interface did not help.

### DATAGRAM `write_pkt_type()` early Short fast path — `REJECTED`

About **+0.5% / noise**. Not worth carrying a special branch.

### Direct DATAGRAM frame accounting — accepted

Avoiding redundant work for an already-encoded DATAGRAM frame did survive its
gate and is part of the maintained quiche hot path.

Again, do not infer from the rejected crypto/header shortcuts that all DATAGRAM
bookkeeping work was fruitless.

---

## 12. Event-loop, timer, readiness, and late-coalescing changes

### EventLoopIteration / reusable timer / unbiased-select bundle — `REJECTED`

The bundle did not reproduce as a useful end-to-end win. The unbiased-select
piece by itself was consistently worse.

Do not reintroduce select fairness changes for performance without a new
correctness/latency reason and fresh evidence.

### UDP readiness-clear / `try_peek()` stale-readiness path — `REJECTED`

Current-stack RX100, five accepted pairs:
- idle-adjusted host median: **+6.63%**,
- raw-host median: +5.59%,
- only 1/5 wins.

Historical evidence had been conflicting/noisy; the current-stack test closes
it.

### Late drain / short wait for one more TUN packet — `REJECTED`

A late-drain probe at 40 Mbit/s produced:
- candidate: 13.870 CPU-s, 0.017% loss,
- control: 13.770 CPU-s, 0.00068% loss.

Worse CPU and worse loss.

Do not add an arbitrary short sleep/wait after reaching `WouldBlock` merely to
manufacture a batch.

### Microcoalesce — `SUPERSEDED`

Later adaptive batching/deadline policy explored the same underlying
coalescing tradeoff with better controls. Do not resurrect the old branch.

---

## 13. Recovery/container micro-rewrites

### `Vec<Acked>::drain(..)` -> slice iteration + `clear()` — rationale rejected

An older hot-path stack carried this as an "avoid allocation churn" change.
Review later established that `drain(..)` retains vector capacity and `Acked`
has no drop glue. The claimed allocation-churn rationale was therefore wrong,
and no independent benchmark justified the signature/control-flow churn.

It was removed from the refreshed hot-path stack.

### Recovery metadata layout — `DEFERRED`

Profiles show recovery/accounting at only a few percent. Splitting hot/cold
metadata or reducing copy volume remains plausible, but no measured candidate
earned a promotion.

Do not start here before a fresh profile says recovery has become dominant.

---

## What the "~50 candidates" actually means

Counting benchmark labels/artifacts gives a much larger number than counting
ideas.

A representative example is the TUN batching family:

1. static packet targets,
2. static deadlines,
3. zero-delay ready drain,
4. cap 2,
5. cap 8,
6. unconditional policy,
7. fixed-PPS policy,
8. self-calibration,
9. adaptive v1,
10. adaptive v2,
11. adaptive v2.1,
12. adaptive v2.2,
13. adaptive v3,
14. split activation/deadline,
15. enable-streak e3,
16. e5,
17. e8,
18. e5/a500,
19. e5/a250,
20. e5/a125,
21. deadline-only a500,
22. a250,
23. a125,
24. current-main/full-LTO confirmations.

Those are useful experiments, but they are not 24 independent optimization
concepts.

Across the whole campaign, the candidate count collapses to roughly the dozen
mechanism families above, with controls and policy variants accounting for much
of the rest.

## Rules for revisiting a closed candidate

A closed candidate becomes worth another look only when at least one of these
is true:

1. **The architecture changed.** Example: direct L4 replaces packet-stream
   proxying, changing syscall/buffer boundaries.
2. **The measured hotspot moved.** A fresh native profile now shows the closed
   subsystem is materially hotter.
3. **The old failure mechanism is explicitly removed.** Example: a future TX
   ownership design removes the copy boundary rather than merely pooling the
   same allocation.
4. **The target environment is intentionally different.** An architecture-
   specific optimization may be valid if it is gated/scoped rather than sold
   as a universal default.
5. **The old evidence was inconclusive rather than rejected.** Preserve that
   distinction.

"Maybe the noise will like it this time" is not a reason to rerun a rejected
candidate.

## Current native-TUN frontier

The final Rust 1.99/full-LTO native profile no longer shows an obvious large
tun-rs/usque/quiche micro-hotspot:

- RX100 is fragmented across crypto, `send_single`, event-loop work,
  `handle_udp_event`, clock acquisition, copies, and ~1% TUN functions.
- TX100 is heavier but similarly distributed across `send_single`, crypto,
  recovery, copies, allocator work, and small TUN buckets.
- UTX35 did not expose any hidden tun-rs function above about 1%.

The practical conclusion is that the current native TUN path is optimized
enough that another first-pass micro-optimization is unlikely to be a large
win. The next large opportunity is architectural: the proxy/direct-L4 path,
not another round of the closed candidates in this ledger.
