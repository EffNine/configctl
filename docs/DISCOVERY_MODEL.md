# Discovery Model (v1.1)

The discovery engine maps the Linux development environment broadly:
filesystem, projects, packages, toolchains, services, environment,
credentials metadata, hardware, symlinks, and mounts.

## Stages

```text
SCAN → DISCOVER → CLASSIFY → REDACT → REPORT   (read-only, no mutation)
```

1. **Mounts first**: parse `/proc/self/mountinfo`, classify each mount
   (local / remote / pseudo), decide traversal per mount.
2. **Walk each root** with the bounded walker (governor-attached):
   every visit carries kind/size/executable; symlinks, specials, and
   directories are yielded for mapping, never followed/opened.
3. **Classify every visit** into the inventory (counts, class histogram,
   symlink relationships, dotfile records).
4. **Detect projects** (60-marker registry; weak markers enrich but never
   declare), map project content roles from visited paths.
5. **Probe ecosystems**: 11 package managers, PATH executables with
   registry-gated version probes, systemd user+system units, process
   environment (names only), credential metadata, hardware context.
6. **Report completeness**: observed = mapped + skipped, with named
   reasons and `COMPLETE`/`PARTIAL` status.

## Project markers

Strong markers declare a project (manifests, lockfiles, build files, task
runners, containers, CI, VCS roots). Weak markers (`.editorconfig`,
`.vscode`, `.nvmrc`, `.tool-versions`, `.envrc`, `.gitignore`, …) enrich
hints but never declare a project alone — a config-only directory stays
a config directory (still fully mapped as dotfiles/configs).

## Content roles

Project files are role-mapped by pure path heuristics:

```text
source | configuration | script | toolchain | manifest | lockfile |
ci | container | documentation | env_schema |
generated | cache | dependency | secret | binary | unknown
```

`src/` vs `target/` is the canonical example: generated/cache content is
recorded with an exclusion reason, not silently ignored and not captured.

## Version probing

Arbitrary binaries are never executed. A version probe runs only when:

- the basename is in the fixed-argv `VERSION_PROBES` registry, and
- a governor subprocess slot is available (timeout + output cap apply).

Probe output is cleaned (first line, no control chars, ≤ 200 chars).

## Redaction

Secret values are never stored: `.env` values feed in-memory type
inference only; process environment contributes names + PATH
decomposition + a tight display-safe allowlist; credential files
contribute existence/mode/counts. Every sink (human, JSON, bundle) passes
the redaction registry, and bundles are leak-checked after writing.
