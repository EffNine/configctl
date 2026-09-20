# configctl v1.1 — Hardcore Mapping Philosophy

> configctl is comprehensive by default. Resource governors prevent
> pathological discovery from monopolizing or hanging the host.

## The shift from v1.0

v1.0 was intentionally conservative: a small dotfile allowlist, a dozen
project markers, apt-only packages, and silent omission of everything
outside those registries.

v1.1 inverts the default:

```text
unknown → discover → classify UNKNOWN → preserve metadata
```

instead of `unknown → ignore`, and:

```text
discover broadly → classify → capture where possible
→ mark non-reproducible resources explicitly
```

instead of `not explicitly allowlisted → exclude`.

## The pipeline

```text
DISCOVER EVERYTHING RELEVANT
        ↓
CLASSIFY EVERYTHING (with evidence)
        ↓
CAPTURE EVERYTHING REPRODUCIBLE
        ↓
REFERENCE EVERYTHING SENSITIVE (secret://, never values)
        ↓
RECORD EVERYTHING ELSE (observed with an explicit reason)
```

## What hardcore does NOT mean

Hardcore describes **discovery breadth**, not execution recklessness:

- Discovery/capture is aggressive: dotfiles, projects, packages across
  eleven managers, executables, systemd units, environment, credentials
  metadata, hardware, symlinks, mounts.
- Execution stays gated: every planned operation carries a
  `PlanActionClass` (`SAFE_REPRODUCE`, `PRIVILEGED`, `DESTRUCTIVE`,
  `MACHINE_SPECIFIC`, `SECRET_REQUIRED`, `UNSUPPORTED`, `MANUAL`).
  The apply engine refuses `PRIVILEGED`, `DESTRUCTIVE`, and
  `UNSUPPORTED` operations even when their kind would otherwise dispatch.
- Safety comes from **resource governance, not conservative discovery**:
  one central `ResourceGovernor` bounds wall time, CPU pressure response,
  memory, I/O, files, directory entries, subprocesses, output, recursion,
  symlink depth, and concurrency. See `RESOURCE_GOVERNOR.md`.

## Never silent

A resource that is not captured must say why, in the report:

```text
.bashrc                  action: capture    (portable shell configuration)
~/.ssh/id_ed25519        action: reference  (secret credential material)
/mnt/nfs/project         action: observe    (network filesystem, record-only)
target/                  action: exclude    (generated build artifact)
```

Partial scans report `PARTIAL` with named reasons and a completeness
percentage — never `COMPLETE` when a budget stopped traversal early.

## What is explicitly out of scope

No AI layer, no telemetry, no uploads, no cloud dependency, no remote
execution, no GUI. No execution of discovered scripts or `.env` files. No
reads of device files, no blocking on FIFOs, no shell invocation, no raw
secret storage. The v1.0.0-rc.1 tag and history are immutable.
