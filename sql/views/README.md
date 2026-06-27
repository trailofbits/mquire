# SQL Views

Reusable SQL views that are automatically loaded by mquire on startup. Install them with `just install-views`.

## Directory structure

Views are organized by operating system and architecture:

```
sql/views/
  common/
    common/       # Views for all platforms and architectures
  linux/
    common/       # Linux views for all architectures
    intel/        # Linux views specific to Intel/x86_64
```

The `common` directory acts as a wildcard: views placed there apply to all platforms or architectures.

## Load order

When mquire starts, it loads SQL files from the autostart directory (`$HOME/.config/trailofbits/mquire/autostart/`) in the following order:

1. `common/common/`: platform and architecture independent
2. `common/{arch}/`: architecture-specific, all platforms
3. `{os}/common/`: platform-specific, all architectures
4. `{os}/{arch}/`: platform and architecture specific

Files within each directory are sorted alphabetically by filename.

## Numbering convention

View filenames are prefixed with a number to control execution order. Ranges are allocated by category:

| Range | Category | Description |
|-------|----------|-------------|
| 000–099 | Foundation | Deduplicated base tables (e.g., `processes`) |
| 100–199 | Per-process analysis | Views joining process data with files, network, memory |
| 200–299 | Security / detection | Rootkit detection, anomaly comparison |
| 300+ | Reserved | Future categories |

Leave gaps between your custom views (increments of 10) so new shipped views can be inserted without renumbering.

## Shipped views

### Linux

| File | View name | Description |
|------|-----------|-------------|
| [`000_processes.sql`](linux/common/000_processes.sql) | `processes` | Deduplicated process list across all discovery sources, filtered to user-space process leaders |
| [`100_process_network_connections.sql`](linux/common/100_process_network_connections.sql) | `process_network_connections` | Maps network connections to owning processes by joining through file descriptors |
| [`110_process_libraries.sql`](linux/common/110_process_libraries.sql) | `process_libraries` | Lists shared libraries mapped into each process, for spotting unexpected loaded objects |
| [`120_process_capabilities.sql`](linux/common/120_process_capabilities.sql) | `process_capabilities` | Quick-peek capability overview: one row per process, each set (effective/permitted/inheritable/ambient/bounding) rendered as a compact value (`ALL`, `''` for empty, or the space-separated cap names); `NULL` means the set was unreadable |
| [`200_tasklist_pidns_differences.sql`](linux/common/200_tasklist_pidns_differences.sql) | `tasklist_pidns_differences` | Detects processes present in the `task_list` discovery source but missing from `pid_ns` (or vice versa), a rootkit-hiding indicator |
| [`210_process_anon_wx_regions.sql`](linux/common/210_process_anon_wx_regions.sql) | `process_anon_wx_regions` | List per-process anonymous W+X memory regions, as an indicator for code injection |
| [`220_ld_env_override_processes.sql`](linux/common/220_ld_env_override_processes.sql) | `ld_env_override_processes` | Lists processes that override the dynamic linker via `LD_PRELOAD` / `LD_AUDIT` / `LD_LIBRARY_PATH` |
