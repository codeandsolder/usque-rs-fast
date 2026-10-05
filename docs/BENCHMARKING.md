# Performance benchmarking

This document records the methodology and the important conclusions from the September–October 2026 performance campaign across **usque-rs-fast**, **quiche-fast**, and **tun-rs-fast**.

The goal is not to preserve every transient candidate. It is to preserve the parts that are expensive to rediscover:

- what we actually measured,
- why the metric is defined the way it is,
- which test topologies expose which bottlenecks,
- how long a sample must run before it is trustworthy,
- how candidates were compared without silently changing another layer,
- which profiler results are diagnostic rather than performance evidence,
- which optimizations survived matched-rate A/B testing,
- and which apparently promising ideas turned out to be noise or regressions.

If a future benchmark disagrees with this document, prefer a reproducible new measurement — but first check the pitfalls section. Most of the surprising results during this campaign came from measuring the wrong boundary, mixing saturation with efficiency, or changing more than one layer at once.

## What the benchmark is trying to answer

The primary question is:

> For the same useful inner-IP traffic, how much host CPU does the complete tunnel consume?

That is deliberately broader than “how much CPU does the `usque-rs` process consume?”. A change in usque, quiche, or tun-rs can move work between userspace and the kernel. A candidate that saves 5% of process CPU while causing 8% more kernel work is a regression for the machine running the tunnel.

The primary efficiency metric is therefore:

**raw host-wide busy CPU seconds / steady inner-L3 Gbit**

where:

- host CPU is taken from cgroup-v2 `cpu.stat` `usage_usec` when available,
- the denominator is bytes observed at the benchmark TUN,
- establishment is excluded from steady-state efficiency,
- userspace, kernel, IRQ/softirq, the fixed traffic generator, and the lightweight sampler are all inside the headline host boundary.

Candidate-process CPU, kernel CPU, softirq activity, retransmits, packet drops, and generator-subtracted “transport CPU” are still collected, but they are diagnostics. They do not replace the headline metric.

### Why inner-L3 bytes are the denominator

Application goodput is useful for detecting failure or saturation, but it is not the right denominator for tunnel efficiency. QUIC/MASQUE framing, TCP behavior, buffering, and measurement timing can make application accounting differ from the amount of useful IP traffic the tunnel actually moved.

The campaign used TUN counters as the stable inner boundary:

- RX: TUN RX bytes,
- TX and UTX: TUN TX bytes.

Application-delivered throughput remains a quality/saturation check.

## Test topologies

Two deliberately different tiers were used. An optimization was not considered generally safe just because it won on one CPU class.

### Low tier: MT7621 router

Path:

`Xiaomi Redmi Router AC2100 / MT7621 -> Cloudflare WARP CONNECT-IP -> stardust-ams`

Characteristics:

- MIPS MT7621-class CPU,
- OpenWrt 23.05.4 ramips/mt7621,
- inner traffic is IPv6,
- the outer MASQUE connection stays on the router's native IPv4 path,
- extremely useful for exposing syscall, batching, wakeup, and fixed per-packet costs.

Only the benchmark destination `/128` was routed through the temporary benchmark TUN. The router's normal/default routes were saved and checked after every sample.

The router is a constrained target, so a rate that is a normal matched-efficiency point on the high tier may be a saturation point here.

### High tier: stardust-waw

Path:

`stardust-waw / EPYC 7282 -> Cloudflare WARP CONNECT-IP -> stardust-ams`

Characteristics:

- x86-64 EPYC host,
- outer connection uses native IPv6,
- wide enough CPU headroom to inspect kernel/userspace split and higher rates,
- primary environment for perf/cachegrind follow-up and fine-grained A/B confirmation.

The normal `usque-ipv4.service` was stopped only for the benchmark sample and restarted and verified after every sample.

### Additional profiling host

The Ryzen laptop was also used in later profiler/counter comparisons. Cross-machine profiler results were used to see whether a hot path was architecture-specific. They were not mixed directly into the primary low/high efficiency score.

## Traffic modes

The benchmark exercised three steady-state directions:

| Mode | Traffic | Purpose |
|---|---|---|
| RX | paced TCP, AMS -> target | receive/decrypt/QUIC receive/TUN-write path |
| TX | paced TCP, target -> AMS | TUN-read/QUIC send/encrypt path |
| UTX | paced fixed-size UDP, target -> AMS | packet-rate-sensitive transmit path without TCP congestion behavior dominating |

UTX used a TCP control channel so the receiver could report packet/byte counts independently.

An IDLE sample was also collected per candidate/tier. Idle-adjusted CPU/Gbit is useful diagnostically, but raw host CPU/Gbit remained the promotion metric.

## Sample structure

Every measurement has two conceptually separate phases.

### 1. Establishment

Connection setup is timed until the route is usable.

Establishment is reported independently because it answers a different question from steady-state forwarding efficiency. Charging handshake/setup work to an 8-second traffic window makes a fast steady-state implementation look artificially expensive and makes results depend heavily on session duration.

### 2. Continuous steady flow

Warmup and the measured interval are one continuous flow. The traffic stream is not restarted at the steady-state boundary.

The final promotion-grade configuration uses:

- roughly 0.75–1.5 s warmup depending on profile,
- 1 s measurement bins,
- **8 s steady-state window**,
- 3 s only for smoke/functional sanity.

## Why 8 seconds

This was calibrated rather than guessed.

The corrected cgroup-v2 calibration campaign compared prefixes of the same sample against the full 8-second result. A prefix was considered converged only when host CPU/Gbit was within 2% of the full window, inner throughput was within 1%, and later prefixes stayed inside the bound.

Worst matched-rate host-CPU/Gbit error seen at each prefix:

| Prefix | Worst error vs 8 s |
|---:|---:|
| 2 s | 20.74% |
| 3 s | 9.64% |
| 4 s | 7.21% |
| 5 s | 15.39% |
| 6 s | 8.35% |
| 7 s | 2.31% |
| 8 s | reference |

The non-monotonic 5–6 s errors are exactly why “a few seconds looks stable” was not good enough.

**Rule:** use 8 s for standard/full performance comparisons. A 3 s smoke test can prove that the candidate works, not that it is faster.

## CPU accounting

A tiny C sampler was used to avoid contaminating every one-second bin with repeated `awk`, `cat`, or shell process startup.

Per sample/bin it records, among other things:

- cgroup-v2 `cpu.stat` usage/user/system,
- `/proc/stat` as a diagnostic/fallback,
- candidate and traffic-generator process CPU,
- IRQ and softirq CPU,
- `NET_RX`, `NET_TX`, and timer softirq deltas,
- `/proc/net/softnet_stat`,
- TUN and relevant interface counters.

### Primary clock

`/sys/fs/cgroup/cpu.stat` `usage_usec` is the primary CPU clock on both benchmark tiers.

`/proc/stat` is retained as a diagnostic, not mixed into the primary score. Steal time is recorded separately so a noisy VM interval can be rejected.

### Do not optimize the process in isolation

A recurring lesson was that process CPU can move in the opposite direction from whole-host CPU.

The clearest example was an RX “outline” candidate at high-tier 100 Mbit/s:

- inner throughput: effectively unchanged,
- candidate process CPU/Gbit: about **1.96% lower**,
- raw host CPU/Gbit: about **5.21% higher**.

If we had optimized against process CPU, that regression would have looked like a win.

## Standard matrix

The standard campaign matrix used these requested rates:

| Tier | RX Mbit/s | TX Mbit/s | UTX Mbit/s |
|---|---|---|---|
| low | 5, 10, 20, 30, 40 | 5, 10, 15, 20, 30 | 2, 5, 10, 15 |
| high | 25, 50, 100, 200, 300, 400 | 25, 50, 100, 150, 200 | 20, 35, 50, 65 |

UTX used 256-byte payloads in the standard matrix to make packet-rate overhead visible.

Not every requested point is a valid efficiency comparison. When the candidate or baseline cannot sustain the requested behavior, the point describes the saturation knee/ceiling instead.

## Repeats and ordering

Standard comparisons used two repeats and deliberately changed order:

- rate order is reversed on the second repeat,
- candidate order alternates.

This reduces drift/order bias from CPU frequency, VM neighbors, network state, and thermal effects.

For small effects, we used larger paired campaigns (for example 12-pair confirmation runs) rather than trusting one or two samples.

## Quality gate

A result is only a performance result after it passes behavior/quality checks.

The campaign gate checked:

1. equivalent useful inner traffic at a matched point, or explicitly classified saturation behavior;
2. no material softnet/drop/retransmit regression;
3. low sampler/host contamination and acceptable steal;
4. stable enough one-second bins;
5. raw host CPU/Gbit, not merely candidate process CPU;
6. for a general optimization, directionally consistent evidence across both tiers where practical.

A failed quality point may still be useful for finding the saturation knee. It must not be averaged into matched-rate efficiency numbers.

## Candidate isolation

A three-repository stack makes accidental confounding very easy.

When measuring a change in one layer:

- pin the other two layers,
- keep feature/environment knobs identical,
- keep the compiler/toolchain identical unless the toolchain itself is the experiment,
- record exact candidate binary hashes,
- do not compare a “latest everything” binary to an older fixed stack and attribute the delta to one library.

This became especially important for quiche and tun-rs work, where small code changes can shift work into kernel networking.

### Compiler changes are their own experiment

Rust 1.98 vs 1.99 and “all-current” validation was explicitly A/B tested on both the high tier and the router.

Results were mixed by point rather than a universal 1.99 win. For example, high-tier 100 Mbit/s runs moved by several percent depending on the exact fixed/all-current candidate, while router 5/10/20 Mbit/s results also changed direction between rates.

The lesson is not that one compiler was categorically faster. The lesson is:

> **Never claim a source optimization across a toolchain change. Pin the compiler for the code A/B, then validate the compiler separately.**

## Important findings from the campaign

These are representative results that survived enough control to be useful as future baselines. Percentages are not universal constants; topology, kernel, compiler, and hardware matter.

### TUN write batching / adaptive batching

The receive path spends meaningful time getting decoded packets into the TUN device. We explored fixed batching, delay sweeps, and adaptive policies before settling on an adaptive candidate worth retaining.

Representative matched RX results for the `adaptive4` candidate:

| Tier / rate | Baseline host s/Gbit | adaptive4 host s/Gbit | Approx. change |
|---|---:|---:|---:|
| low RX 10 Mbit/s | 81.843 | 80.440 | -1.7% |
| high RX 50 Mbit/s | 3.571 | 3.516 | -1.5% |
| high RX 100 Mbit/s | 3.087 | 2.947 | -4.5% |

The exact best policy evolved during the campaign; the durable result is that TUN write aggregation is a real whole-host lever, but it must be bounded to avoid latency/pathological buffering.

### Checksum work — early positive screen, later rejected

An early high-tier RX 100 Mbit/s comparison made the checksum candidate look independently useful:

- baseline: 3.319 host s/Gbit,
- checksum candidate: 3.228 host s/Gbit,
- approximately **-2.73%** raw host CPU/Gbit.

The same campaign also had an early adaptive-TUN-write + checksum combination at 3.100 host s/Gbit versus the 3.319 baseline (about **-6.59%**) with matched inner throughput.

Those runs are retained as historical evidence of why repeated current-stack confirmation matters, **not** as the final checksum conclusion. After the surrounding stack stabilized, two independent five-pair RX100 campaigns produced ten accepted current-stack pairs: checksum SAD had a **+2.17% median idle-adjusted host CPU/Gbit**, +2.14% raw-host median, and only 2/10 host wins. The final native profiles also put checksum at only about 0.7–1.2% self cycles.

**Current disposition: reject checksum SAD as an end-to-end tunnel optimization.** See [Rejected, neutral, and superseded performance experiments](REJECTED_OPTIMIZATIONS.md#8-tun-rs-checksum-specialization) for the local microbenchmark gains and the superseding whole-tunnel result.

### quiche receive/hot-path work

A focused paired confirmation run found a promising quiche hot-path change at high-tier RX 50 Mbit/s:

- median raw host CPU/Gbit delta: **-5.84%**,
- mean: -5.74%,
- 9 wins out of 12 pairs,
- median throughput delta: -0.025%.

At 100 Mbit/s the same campaign was much less convincing:

- median: **-1.58%**,
- mean: +0.46%,
- 7/12 wins,
- throughput effectively unchanged.

A later matched-final 100 Mbit/s comparison was essentially flat at about **-0.09%** host CPU/Gbit.

The durable conclusion is therefore narrower than “hotpath is 6% faster”: the change exposed a real 50-Mbit/s effect in that environment, but the benefit was rate-sensitive and did not reproduce as a robust 100-Mbit/s win. Future quiche work should repeat paired runs at more than one rate.

### A useful negative result: outlining

The receive-path outlining experiment is retained because it demonstrates a benchmark failure mode:

- candidate process CPU/Gbit improved ~1.96%,
- raw host CPU/Gbit regressed ~5.21%,
- kernel accounting also moved the wrong way.

This candidate should not be resurrected merely because a userspace profiler makes it look attractive.

### Direct/native TUN write experiments

Cachegrind-driven work compared a “matched” path with a more direct write path. A native high-tier RX 200 Mbit/s A/B was directionally favorable to the direct candidate:

- direct: 2.568 host s/Gbit,
- matched: 2.670 host s/Gbit,
- both passed quality 3/3 with virtually identical inner throughput.

The important process lesson is that the native A/B, not the Cachegrind run, is the evidence. Instrumented runs were used to identify instruction-level candidates.

## Profiling: how it was used

We used several complementary profiling modes:

- Cachegrind / `cg_annotate`,
- native `perf`,
- hardware-counter passes,
- L1/cache-focused counter passes,
- trace/perf comparisons,
- the normal cgroup/TUN benchmark around the profiler work.

Profiles were run on both EPYC and Ryzen where useful to distinguish architecture-specific effects.

### Cachegrind is not a throughput benchmark

Under Cachegrind, even a low-rate 10 Mbit/s RX run consumed tens of host CPU seconds/Gbit and the relative ordering changed enough that it was not suitable as the promotion score.

For example, instrumented 10 Mbit/s runs showed roughly:

- stock: 47.366 host s/Gbit,
- matched: 49.409,
- direct: 47.443.

Those numbers are useful only inside the profiler experiment. Do not compare them to native runs or use them as production efficiency estimates.

### Correct workflow

1. Use native benchmark data to identify a real regression/opportunity.
2. Reproduce a controlled workload under Cachegrind/perf.
3. Use the profiler to generate a hypothesis about functions/instructions/cache behavior.
4. Make one focused change.
5. Return to a **native, matched-rate, pinned-stack A/B**.
6. Promote only if native host CPU/Gbit improves without failing quality.

## Experiment families explored

The campaign generated many intermediate candidates. Their names are useful breadcrumbs if archived artifacts are available, but names alone are not evidence.

Before proposing another native-TUN optimization, also read [Rejected, neutral, and superseded performance experiments](REJECTED_OPTIMIZATIONS.md). It records the failed variants, neutral results, superseded policy revisions, aliases, and the conditions under which a closed idea is actually worth revisiting. In particular, the roughly fifty named candidate configurations collapse to about a dozen mechanism families; much of the count came from controlled policy and parameter variants rather than independent architectural ideas.

### Harness / measurement
- cgroup-v2 accounting correction,
- duration calibration and convergence,
- sampler overhead checks,
- idle baselines,
- candidate/rate ordering,
- resumable campaigns with binary hashing,
- saturation/quality classification.

### TUN path
- fixed TUN-write packet counts,
- TUN-write delay sweeps,
- adaptive write batching v2 / v2.1 / v2.2,
- low-tier control and high-tier focused runs,
- direct/native write comparisons,
- checksum-path variants.

### usque scheduling / receive policy
- RX flush-defer variants,
- readiness-clear behavior,
- deadline-only and deadline screening,
- gate split / gate hysteresis / activation variants,
- timestamp reuse,
- connected-send variants,
- flow-profile variants,
- 0-RTT-related screening.

These were mostly used to map the policy space and isolate where work was being paid. Unless an experiment has a native matched-rate confirmation, treat it as exploratory.

### quiche
- receive/hot-path candidates,
- receive-ladder variants,
- deadline/polling experiments,
- P1/focused candidates,
- outline experiment,
- current-vs-pinned validation.

### Toolchain / integration
- Rust 1.98 vs 1.99,
- fixed dependency stack vs “all current” stack,
- post-quiche and tun pin checks,
- low-tier and high-tier revalidation after integration changes.

## Reproducibility contract

The original campaign harness lived in a separate benchmark workspace, but the following is the behavioral contract for reproducing the results.

A valid harness should persist at least:

- exact candidate manifest,
- benchmark profile,
- SHA-256 of every candidate binary,
- environment/feature knobs,
- raw candidate output,
- raw restoration output,
- per-sample data,
- one-second bins,
- establishment times,
- summary CSV/Markdown,
- duration convergence data,
- run metadata.

The original harness wrote a partial sample CSV after each successful sample so interrupted multi-hour campaigns could be inspected and resumed safely.

### Resume must be strict

Resume should refuse to silently continue if:

- the manifest changed,
- the profile changed,
- a candidate binary hash changed,
- the tier/mode/rate identity changed.

Completed idle baselines can be restored; only genuinely missing samples should rerun.

This matters because recompiling “the same source” with a different toolchain or dependency lockfile can move performance enough to invalidate the comparison.

## Build-cache note

The OpenWrt/MIPS helper binaries were cross-built and cached. Cache identity was content/build-identity based rather than mtime based.

That is intentional: some remote file-write paths used during development did not reliably advance timestamps. An mtime-only cache can therefore reuse stale benchmark helpers and create extremely convincing nonsense.

## Interpreting saturation

Efficiency and maximum throughput are related but different questions.

A rate is a matched-efficiency point when both candidates deliver equivalent useful traffic with acceptable quality. CPU/Gbit can be compared there.

A rate near or beyond the knee is a saturation point. At saturation:

- delivered throughput may diverge,
- one candidate may take longer to deliver the requested bytes,
- one-second bin variance rises,
- CPU/Gbit can look “better” simply because less useful work was done.

Use saturation points to compare capacity/ceiling, not to support a matched-efficiency percentage.

## Common mistakes we already made once

Do not repeat these:

- **Using process CPU as the headline.** Kernel work can reverse the conclusion.
- **Comparing requested Mbit/s instead of achieved inner traffic.** Requested rate is not the denominator.
- **Mixing setup and steady state.** Establishment is a separate metric.
- **Trusting 3–6 second samples.** Calibration showed errors up to 8.35% at 6 s.
- **Treating a saturated point as an efficiency point.**
- **Changing quiche/tun/usque/compiler together.** Pin the rest of the stack.
- **Believing one profiler.** Cachegrind/perf are hypothesis generators; native A/B is the scoreboard.
- **Comparing Cachegrind absolute numbers to native numbers.**
- **Ignoring candidate order.** Alternate order and reverse rate sweeps.
- **Assuming compiler upgrades are free performance.** A/B them independently.
- **Using stale cross-compiled helpers because an mtime cache said they were current.**
- **Promoting a tiny win from one sample.** Pair/repeat when the expected effect is close to run noise.

## Recommended workflow for future optimization work

For a new candidate:

1. Pin usque, quiche, tun-rs, compiler, lockfiles, and benchmark knobs.
2. Run a smoke sample to prove functionality.
3. Pick one or two non-saturated points that exercise the target path.
4. Run 8-second matched native A/B samples with alternating candidate order.
5. If the expected gain is small, use enough paired repetitions to see the distribution.
6. Check inner throughput and quality before looking at CPU.
7. Inspect raw host CPU/Gbit first, then process/kernel/softirq diagnostics.
8. If promising, expand across rates and the other tier.
9. Use perf/Cachegrind only after a real effect or bottleneck is identified.
10. Re-run a final pinned-stack campaign after integration/rebase/toolchain changes.

For a generally promoted optimization, keep the raw artifacts long enough that somebody can audit the exact binary, environment, and quality gate later.

## Repository-specific notes

- **usque-rs-fast** owns the end-to-end performance contract and integration decisions.
- **tun-rs-fast** also has its own synthetic `tun-benchmark2` benchmark. Those numbers test the library more directly and are useful, but are not interchangeable with this whole-tunnel host-CPU/Gbit methodology.
- **quiche-fast** should validate hot-path changes in both its own tests/benchmarks and the downstream usque harness, because QUIC changes can move work between the library, syscalls, and kernel networking.

See the companion downstream-validation notes in the quiche-fast and tun-rs-fast repositories for the subset of this methodology most relevant to those libraries.
