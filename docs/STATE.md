# STATE.md — state directory and database (P3/P4/P7)

Root: `$XDG_STATE_HOME/configctl` (default `~/.local/state/configctl`),
created `0700`. Override with `--state-dir`.

```text
$STATE/
├── state.db            # SQLite (WAL), 0600: plans, journal, history, resources
├── plans/<id>.json    # redacted plan documents, 0600 (hash-verified on load)
├── backups/objects/   # content-addressed file backups, 0600
├── audit.log           # append-only human-readable trail (no values), 0600
└── .lock               # flock target for apply/rollback
```

## Schema

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE resources (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, locator TEXT NOT NULL,
  owner_profile TEXT, fingerprint TEXT, updated_at INTEGER NOT NULL,
  UNIQUE(kind, locator));
CREATE TABLE plans (
  id TEXT PRIMARY KEY, profile TEXT NOT NULL, profile_hash TEXT NOT NULL,
  state_hash TEXT NOT NULL, plan_hash TEXT NOT NULL, status TEXT NOT NULL,
  approved_at INTEGER, created_at INTEGER NOT NULL,
  doc_path TEXT NOT NULL, bundle_dir TEXT NOT NULL DEFAULT '');
CREATE TABLE journal (
  id INTEGER PRIMARY KEY, plan_id TEXT NOT NULL, op_id TEXT NOT NULL,
  phase TEXT NOT NULL, backup_sha TEXT, detail TEXT, recorded_at INTEGER NOT NULL);
CREATE TABLE history (
  id INTEGER PRIMARY KEY, plan_id TEXT, op_id TEXT, action TEXT NOT NULL,
  result TEXT NOT NULL, recorded_at INTEGER NOT NULL, detail TEXT);
```

Plan `status`: `planned → approved → applying → applied`, with `partial`
on failure and `rolled_back` after rollback. Plans are immutable: the stored
hash must match a recomputation over the document or loading fails.

## Ownership

A file target is *managed* iff `resources` attributes it to the profile.
The store never contains secret values — only hashes, refs, and metadata.
