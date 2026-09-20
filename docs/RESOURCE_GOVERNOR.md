# Resource Governor

Central bounded-execution authority for all v1.1 discovery
(`configctl-core/src/governor.rs`).

## Principle

No discovery subsystem carries its own ad-hoc limits. Every subsystem —
walker, package probes, toolchain probes, service probes, credential
probes, hardware probes — consumes budgets from a single shared
`ResourceGovernor` created per scan. Exhaustion is recorded as
`LIMIT_REACHED` with the exact budget named (`file_budget`,
`subprocess_budget`, `wall_clock_budget`, …), the scan finishes
`PARTIAL`, and nothing is silently omitted.

## Budgets

| Budget | Default | Hard ceiling | Notes |
|---|---|---|---|
| `max_wall_time` | 10 min | 120 min | Whole-scan deadline |
| `max_workers` | min(8, CPU) | 32 | Advisory pool size |
| `max_file_count` | 5,000,000 | 50,000,000 | Files visited, all roots |
| `max_directory_entries` | 10,000,000 | 100,000,000 | `read_dir` entries |
| `max_total_bytes_read` | 20 GiB | 1 TiB | File content bytes |
| `max_single_file_read` | 256 MiB | 1 GiB | Largest fully-read file |
| `max_recursion_depth` | 64 | 256 | Traversal depth |
| `max_symlink_depth` | 16 | 64 | Chain resolution |
| `max_subprocesses` | 256 | 2048 | Whole-scan spawns |
| `max_subprocess_runtime` | 10 s | 120 s | Per-process timeout |
| `max_subprocess_output` | 1 MiB | 64 MiB | Per-process stdout+stderr cap |
| `max_memory_bytes` | 2 GiB | 32 GiB | Soft cap for scan buffers |

The `max_subprocesses` default (256, not the 64 originally sketched) was
set by benchmarking: a full scan issues ~70 spawns (10 system probes, 11
package managers, ~40 version probes, services, credentials, hardware),
so 256 leaves 3× headroom while staying firmly bounded.

Every user override passes through `sanitize()` — even explicit flags
cannot request values above the hard ceilings.

## CLI overrides

```bash
configctl scan --max-time 20m --max-bytes 100GiB --workers 4
configctl scan --max-files 1000000 --max-memory 4GiB
configctl scan --follow-mounts --scan-network
```

Durations accept `ms`/`s`/`m`/`h` (bare numbers are seconds); byte counts
accept `K/M/G` and `KiB/MiB/GiB` (bare numbers are bytes).

## Sub-governors

- **CPU**: worker pool starts at `max_workers` and yields under load
  (`/proc/loadavg` vs parallelism): high pressure halves workers,
  critical pressure drops to one. Discovery yields to the machine.
- **Memory**: streaming traversal, bounded buffers, incremental parsing.
  On pressure the expensive operation stops with `LIMIT_REACHED`;
  the scan continues with safe discovery. configctl never OOMs a host.
- **I/O**: metadata-first scanning, lazy content reads, per-file and
  total byte budgets, no repeated hashing within a scan.
- **Subprocess**: every spawn goes through `governed_run()` — one RAII
  slot, fixed argv (never a shell), governor timeout, capped output,
  exit/signal accounting. Hangs are killed; infinite output is capped
  (pipe EOF terminates the writer); unkillable children are reported
  timed-out after a bounded reap instead of hanging the scanner.

## Filesystem safety

- Iterative (non-recursive) traversal; symlink chains resolved with
  `read_link` only, max 16, cycle detection.
- Mount-aware: device-boundary detection keeps the walk on the scan-root
  filesystem by default; crossings are recorded as `external_mount`,
  not descended into. `--follow-mounts` opts out explicitly.
- Special files (sockets, FIFOs, devices) are recorded, never opened.
- Kernel pseudo-filesystems and network mounts are classified
  (`RecordOnly`) from the mount table before traversal is decided.

## Reporting

Every scan ends with a governor snapshot (elapsed, files, bytes,
subprocesses, limit hit, CPU/memory pressure) and a completeness report:

```text
observed / mapped / skipped + reasons + completeness % + COMPLETE|PARTIAL
```

`COMPLETE` is reported only when nothing was skipped and no budget fired.
