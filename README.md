# mquire

mquire, a play on the `memory` and `inquire` words, is a memory querying tool inspired by [osquery](https://github.com/osquery/osquery).

## Key advantage: No external debug symbols needed

**mquire can analyze Linux kernel memory snapshots without requiring external debug symbols.**

Everything needed for analysis is already embedded in the memory dump itself. This means you can analyze:
- Unknown or custom kernels you've never seen before
- Any Linux distribution without preparation
- Memory snapshots where external debug symbols are unavailable or lost

### Requirements

**Kernel version requirements**:
- **BTF support**: Kernel 4.18 or newer with BTF enabled (most modern distributions enable it by default)
- **Kallsyms support**: Kernel 6.4 or newer (due to changes in `scripts/kallsyms.c` format)

## How it works

mquire analyzes kernel memory by reading two types of information that are embedded in modern Linux kernels:

1. **Type information from BTF** ([BPF Type Format](https://www.kernel.org/doc/html/next/bpf/btf.html)) - Describes the structure and layout of kernel data types. BTF data is parsed using the [btfparse crate](https://crates.io/crates/btfparse).
2. **Symbol information from Kallsyms** - Provides the memory locations of kernel symbols (same data used by `/proc/kallsyms`)

By combining type information with symbol locations, mquire can find and read complex kernel data structures like:
- Process memory mappings (using maple tree structures)
- Cached file data (using XArray structures)
- Kernel log messages

This makes it possible to extract files directly from the kernel's file cache, even if they've been deleted from disk.

### Compatibility notes

The Kallsyms scanner depends on the data format from `scripts/kallsyms.c` in the kernel source. If future kernel versions change this format, the scanner heuristics may need updates.

## Capabilities

### Tables

mquire provides SQL tables to query different aspects of the system or the state of the tool itself.

> **mquire is not a database.** Each query reconstructs kernel data structures by scanning memory and following pointers. There are no precomputed indexes or cached results: every table access is a traversal of kernel data. Use `AS MATERIALIZED` to avoid redundant scans (see [Query Optimization](#query-optimization)), and provide constraints like `task` when querying per-process tables like `task_open_files` and `memory_mappings` to limit the scan to a single process.

> **Design principle: virtual addresses as join keys.** Tables use `virtual_address` (the kernel address of the underlying data structure) as the canonical join key: not `pid` or other user-visible identifiers. This is intentional, because the same PID can appear multiple times across different discovery sources and root tasks, while a virtual address uniquely identifies a specific kernel object. Both the SQL tables and the underlying `LinuxOperatingSystem` API are built around this convention.

#### System information

- **os_version** - Kernel version and architecture
- **system_info** - Hostname and domain name
- **boot_time** - System boot time
- **kallsyms** - Kernel symbol addresses (same data as `/proc/kallsyms`)
- **dmesg** - Kernel ring buffer messages (same data as `dmesg` command)

#### Process information

- **tasks** - Running processes with command lines and binary paths. Each task is discovered via multiple independent sources, which is useful for rootkit detection. See [Comparing task enumeration methods for rootkit detection](#comparing-task-enumeration-methods-for-rootkit-detection) and [Deduplicated process list](#deduplicated-process-list).
- **task_open_files** - Files opened by each process (requires `task` constraint - see examples below)
- **memory_mappings** - Memory regions mapped by each process (requires `task` constraint)

#### Kernel modules

- **kernel_modules** - Loaded kernel modules with metadata (name, state, version, parameters, taint flags)

#### Network information

- **network_connections** - Active network connections (TCP sockets)
- **network_interfaces** - Network interfaces with IP addresses and MAC addresses

#### File system

- **syslog_file** - System logs read from the kernel's file cache (works even if log files are deleted or unavailable, as long as they're cached in memory)

#### Debugging

- **mquire_diagnostics** - Internal mquire logs showing analysis progress, warnings, and errors

## Commands

mquire provides three main commands:

- **`mquire shell`** - Start an interactive SQL shell to query memory snapshots
- **`mquire query`** - Execute a single SQL query and output results (supports JSON or table format)
- **`mquire command`** - Execute custom commands on memory snapshots (e.g., `.task_tree`, `.system_version`, `.dump`)

## Dot Commands

mquire provides special commands prefixed with a dot (`.`) to distinguish them from SQL queries.

### Built-in Commands

These commands work in the interactive shell and with `mquire query`:

- **`.tables`** - List all available tables
- **`.schema`** - Show schema for all tables
- **`.schema <table>`** - Show schema for a specific table
- **`.commands`** - List all available custom commands
- **`.exit`** - Exit the interactive shell (shell only)

### Custom Commands

These commands work in the interactive shell and with `mquire command`:

Use `--help` with any command to see available options and usage information. For example: `.task_tree --help`

#### `.system_version`

Display the operating system version information.

This is a convenience command equivalent to `SELECT * FROM os_version`, but with formatted output.

#### `.task_tree`

Display a hierarchical tree of running processes and threads, similar to the `pstree` command on Linux.

**Options:**
- `--show-threads` - Include threads in addition to processes. When enabled, displays both TGID and TID for each entry.
- `--use-real-parent` - Use the `real_parent` field instead of `parent` for building the tree structure. The `real_parent` field shows the original parent process before any reparenting (useful for tracking process creation chains even after parent processes exit).

**Notes:**
- The format is `[TGID TID]` when showing threads, or `[TGID]` when threads are hidden. TGID (Thread Group ID) is what's commonly called PID. For main threads (where TGID == TID), both values will be the same.

#### `.carve`

Carve a region of virtual memory to disk. This command extracts raw memory content from a specific virtual address range using a given page table, useful for extracting process memory, heap contents, or other memory regions.

**Arguments:**
- `ROOT_PAGE_TABLE` - The physical address of the root page table (hex string with optional 0x prefix). This determines the address space to use for translation.
- `VIRTUAL_ADDRESS` - The virtual address to start carving from (hex string with optional 0x prefix).
- `SIZE` - Number of bytes to carve.
- `DESTINATION_PATH` - Output file path where the carved memory will be written.

**Notes:**
- The command shows a summary of mapped vs unmapped regions before writing.
- Unmapped regions are filled with zeros in the output file.

#### `.dump`

Extract files from the kernel's file cache to recover files directly from memory. This command iterates through all tasks and their open file descriptors, extracting file contents from the page cache.

**Arguments:**
- `OUTPUT` - Output directory for extracted files. Files are organized by TGID (e.g., `tgid_1234/path/to/file`).

**Notes:**
- Currently works with files opened through file descriptors (from the process file descriptor table).
- Does not yet support extracting data from memory-mapped files.
- Empty files (no data in page cache) are skipped.
- Regions with read errors are zero-padded in the output.

## Use cases

mquire is designed for:

- **Forensic analysis** - Analyze memory snapshots from compromised systems to understand what was running and what files were accessed
- **Incident response** - Quickly query memory dumps to find evidence of malicious activity
- **Security research** - Study kernel internals and process behavior from memory snapshots
- **Malware analysis** - Examine running processes and their file operations without detection
- **Custom tooling** - Build your own analysis tools using the **mquire** library crate, which provides a reusable API for kernel memory analysis

## Building and installation

### Pre-built packages from CI

Pre-built packages are available as artifacts from CI runs. You can download them from the [Actions tab](https://github.com/trailofbits/mquire/actions) by selecting a successful workflow run and downloading the artifacts. The following package formats are available:

- **linux-deb-package** - Debian/Ubuntu `.deb` package
- **linux-rpm-package** - Fedora/RHEL/CentOS `.rpm` package
- **linux-tgz-package** - Generic Linux `.tar.gz` archive

### Building from source

mquire is written in Rust. To build it:

```bash
# Clone the repository
git clone https://github.com/trailofbits/mquire
cd mquire

# Build the project
cargo build --release

# The binary will be in target/release/
# - mquire: Unified tool with shell, query, and command modes
```

## Acquiring a memory snapshot

We recommend [AVML](https://github.com/microsoft/avml) for acquiring memory snapshots. [LiME](https://github.com/504ensicsLabs/LiME) was previously suggested but is no longer actively maintained.

### Using AVML

```bash
sudo avml output.lime
```

> **Important:** Do not use `--compress` when acquiring snapshots for mquire. mquire does not support compressed AVML snapshots. If you have a compressed snapshot, use `avml-convert` to decompress it first: `avml-convert compressed.lime uncompressed.lime`

See the [AVML documentation](https://github.com/microsoft/avml) for additional options.

## Getting started

Once you have a memory snapshot, you can interact with it using SQL queries and custom commands. mquire provides three ways to interact with snapshots:

### Interactive shell

Start an interactive SQL shell:

```bash
mquire shell /path/to/memory.raw
```

This opens a prompt where you can run both SQL queries and commands interactively:

```bash
mquire> .tables                      # List all available tables
mquire> .schema tasks                # Show schema for a specific table
mquire> SELECT * FROM tasks;         # Run SQL queries
mquire> .task_tree --show-threads    # Run custom commands
mquire> .exit                        # Exit the shell
```

### One-off SQL queries

Execute a single SQL query or built-in command from the command line:

```bash
# Output as JSON (default)
mquire query /path/to/memory.raw "SELECT * FROM os_version"

# Output as table format
mquire query /path/to/memory.raw "SELECT * FROM tasks" --format table

# Built-in commands work too
mquire query /path/to/memory.raw ".tables"
mquire query /path/to/memory.raw ".schema tasks"
```

### Execute custom commands

Run custom commands for specialized analysis:

```bash
# List all available commands (default behavior)
mquire command /path/to/memory.raw

# Display system version
mquire command /path/to/memory.raw ".system_version"

# Show process tree
mquire command /path/to/memory.raw ".task_tree"

# Show process tree with threads
mquire command /path/to/memory.raw ".task_tree --show-threads"

# Get help for a command
mquire command /path/to/memory.raw ".task_tree --help"
```

## Autostart SQL Files

mquire automatically loads and executes SQL files from `~/.config/trailofbits/mquire/autostart/` when starting the shell or executing queries. This is useful for:

- Creating reusable SQL views
- Setting up custom tables
- Defining frequently-used queries

**Features:**
- SQL files are executed in alphabetical order
- Files must have a `.sql` extension
- Errors are displayed but don't block execution
- Works with both `mquire shell` and `mquire query` commands

### Deduplicated process list

The `tasks` table discovers tasks using multiple independent sources (e.g., `task_list`, `pid_ns`) so that investigators can compare them and detect rootkits. This means each process may appear more than once. For everyday use, create a `processes` view that deduplicates and filters to user-space process leaders.

Create a file `~/.config/trailofbits/mquire/autostart/000_processes.sql`:

```sql
-- Deduplicated process view across all discovery sources.
-- The tasks table may return the same task from multiple sources for rootkit detection.
-- This view provides a clean, single-row-per-process result by deduplicating across sources.
CREATE VIEW IF NOT EXISTS processes AS
WITH tasks_mat AS MATERIALIZED (
  SELECT * FROM tasks
  WHERE type = 'thread_group_leader'
    AND pid > 0
)
SELECT DISTINCT
  pid,
  ppid,
  tgid,
  comm,
  binary_path,
  command_line,
  environment,
  uid,
  gid,
  page_table,
  virtual_address,
  type
FROM tasks_mat;
```

Then query the view:

```sql
SELECT pid, comm, binary_path FROM processes ORDER BY pid;
```

### Creating a reusable view for process network connections

Create a file `~/.config/trailofbits/mquire/autostart/001_process_network_connections.sql`:

```sql
CREATE VIEW IF NOT EXISTS process_network_connections AS
WITH
  network_connections_mat AS MATERIALIZED (
    SELECT * FROM network_connections
  ),

  task_open_files_mat AS MATERIALIZED (
    SELECT * FROM task_open_files
  ),

  -- Deduplicate tasks by virtual_address since the default query returns
  -- results from multiple enumeration sources
  tasks_mat AS MATERIALIZED (
    SELECT DISTINCT virtual_address, pid, tgid, comm, binary_path
    FROM tasks
    WHERE type = 'thread_group_leader'
  )

SELECT
  t.pid,
  t.comm,
  t.binary_path,
  nc.protocol,
  nc.local_address,
  nc.local_port,
  nc.remote_address,
  nc.remote_port,
  nc.state,
  nc.type as ip_type,
  nc.inode
FROM network_connections_mat nc
JOIN task_open_files_mat tof ON nc.inode = tof.inode
JOIN tasks_mat t ON tof.task = t.virtual_address
ORDER BY t.pid, nc.local_port;
```

Then query the view:

```sql
SELECT * FROM process_network_connections WHERE comm = 'sshd';
```

### Comparing task enumeration methods for rootkit detection

Rootkits often hide processes by unlinking them from the kernel's task list while keeping them running. mquire supports multiple task enumeration strategies that can be compared to detect such hidden processes.

> **Note:** The `task_list` source aggressively follows pointers within `task_struct` (e.g., `parent`, `children`, `sibling`, `group_leader`) to maximize process discovery. This may occasionally yield invalid entries from corrupted or stale pointers in memory.

Create a file `~/.config/trailofbits/mquire/autostart/002_hidden_process_detection.sql`:

```sql
CREATE VIEW IF NOT EXISTS hidden_processes AS
WITH
  tasks_from_task_list AS MATERIALIZED (
    SELECT virtual_address, pid, comm
    FROM tasks
    WHERE source = 'task_list'
  ),

  tasks_from_pid_ns AS MATERIALIZED (
    SELECT virtual_address, pid, comm
    FROM tasks
    WHERE source = 'pid_ns'
  )

SELECT
  COALESCE(tl.pid, pn.pid) AS pid,
  COALESCE(tl.comm, pn.comm) AS comm,
  COALESCE(tl.virtual_address, pn.virtual_address) AS virtual_address,
  CASE
    WHEN tl.virtual_address IS NULL THEN 'hidden_from_task_list'
    WHEN pn.virtual_address IS NULL THEN 'hidden_from_pid_ns'
    ELSE 'visible'
  END AS visibility
FROM tasks_from_task_list tl
FULL OUTER JOIN tasks_from_pid_ns pn
  ON tl.virtual_address = pn.virtual_address
WHERE tl.virtual_address IS NULL OR pn.virtual_address IS NULL;
```

Then query for potentially hidden processes:

```sql
SELECT * FROM hidden_processes;
```

## Query Optimization

**mquire queries require reconstructing kernel data structures from virtual memory by dereferencing pointers using embedded type information and debug symbols. This processing can be expensive, so use query optimization techniques to improve performance dramatically.**

### Materialization with `AS MATERIALIZED`

Use the `AS MATERIALIZED` hint to cache table results when tables are used in JOINs or accessed multiple times.

**When to materialize:**
- Tables that are expensive to generate (e.g., `tasks` requires walking linked lists of process structures, dereferencing multiple pointers per process)
- Tables used in JOINs (accessed multiple times during query execution)
- Tables referenced multiple times in the same query

**Example:**

```sql
-- Find network connections for a specific process using materialization
WITH
  target_tasks AS MATERIALIZED (
    SELECT * FROM tasks WHERE comm = 'sshd' AND type = 'thread_group_leader'
  ),

  network_connections_mat AS MATERIALIZED (
    SELECT * FROM network_connections
  )

SELECT
  t.tgid,
  t.comm,
  nc.local_address,
  nc.local_port,
  nc.remote_address,
  nc.remote_port,
  nc.state,
  nc.protocol
FROM target_tasks t
JOIN task_open_files tof ON tof.task = t.virtual_address
JOIN network_connections_mat nc ON nc.inode = tof.inode;
```

**Note:** The `task_open_files` and `memory_mappings` tables use the `task` column as a generator input. When joined with the `tasks` table, SQLite automatically passes the constraint via nested loop joins, making direct JOINs efficient.

**Performance impact:** Materialization can provide significant speedup for queries with JOINs (typically 2-5x faster)

**Example benchmark results:**

*Test performed on an Ubuntu 24.04 snapshot (kernel 6.8.0-63), 351 processes, 50 connections, 2142 open files. Performance will vary based on snapshot size, kernel version, and hardware.*

| Method | Real Time | User Time | Speedup |
|--------|-----------|-----------|---------|
| WITHOUT materialization | 12.067s | 16.373s | baseline |
| WITH materialization | 3.171s | 8.786s | **3.8x faster** |

### JOIN Order Optimization

**Start with the smallest table and JOIN toward larger tables** to minimize rows processed early in the query pipeline.

**Typical table sizes:**
- `network_connections`: smallest - only processes with network activity
- `tasks`: medium - all processes
- `task_open_files`: largest - all open file descriptors

**Optimal order:**

Start with the filtered tasks table and join toward larger tables:

```sql
FROM target_tasks t                                       -- filtered tasks
JOIN task_open_files tof ON tof.task = t.virtual_address  -- open files
JOIN network_connections_mat nc ON nc.inode = tof.inode   -- matching connections
```

### Understanding Query Execution

Use `EXPLAIN QUERY PLAN` to see how SQLite executes your query:

```sql
EXPLAIN QUERY PLAN
SELECT ...
FROM target_tasks t
JOIN task_open_files tof ON tof.task = t.virtual_address
JOIN network_connections_mat nc ON nc.inode = tof.inode;
```

Look for:
- **BLOOM FILTER**: SQLite's optimization for large JOINs
- **AUTOMATIC COVERING INDEX**: Temporary indexes created for lookups
- **SCAN**: Full table scan (expected for the driving table)
- **SEARCH**: Index-based lookup (efficient)

### Best Practices

1. **Always materialize expensive tables** used in JOINs
2. **Start with the smallest table** as your driving table
3. **Use multiline SQL** in scripts for readability
4. **Check query plans** with `EXPLAIN QUERY PLAN` for complex queries
5. **Avoid `SELECT *`** in production - specify only needed columns

### File extraction

Extract files from memory to disk:

```bash
mquire command /path/to/memory.raw ".dump /output/directory"
```

### Example queries

All queries use standard SQL syntax.

#### System version

```bash
$ mquire shell ubuntu2404_6.14.0-37-generic.lime
mquire> SELECT * FROM os_version;
arch:"x86_64" kernel_version:"6.14.0-37-generic" system_version:"#37~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Nov 20 10:25:38 UTC 2"
```

#### System information

```bash
$ mquire shell ubuntu2404_6.14.0-37-generic.lime
mquire> SELECT * FROM system_info;
domain:"(none)" hostname:"ubuntu2404"
```

#### Kernel modules

```bash
$ mquire shell ubuntu2404_6.14.0-37-generic.lime
mquire> SELECT name, state, src_version, parameters FROM kernel_modules LIMIT 5;
name:"snd_seq_dummy" state:"live" src_version:"7A40E0FD47A0746D1C9CD85" parameters:"ump (perm: 0o444), duplex (perm: 0o444), ports (perm: 0o444)" 
name:"snd_hrtimer" state:"live" src_version:"81EE6D58896E2C2E63E252D" parameters:"<null>" 
name:"qrtr" state:"live" src_version:"473C5AB47E04ECEA0106681" parameters:"<null>" 
name:"virtio_rng" state:"live" src_version:"0852940240D554836D22CB2" parameters:"<null>" 
name:"intel_rapl_msr" state:"live" src_version:"34853C4F5EB8FCAD28ACFB3" parameters:"<null>" 
```

#### Running tasks

```bash
$ mquire shell ubuntu2404_6.14.0-37-generic.lime
mquire> SELECT comm, binary_path, command_line FROM tasks WHERE command_line NOT NULL AND comm LIKE "%systemd%";
comm:"systemd" binary_path:"/usr/lib/systemd/systemd" command_line:"/sbin/init splash"
comm:"systemd-oomd" binary_path:"/usr/lib/systemd/systemd-oomd" command_line:"/usr/lib/systemd/systemd-oomd"
comm:"systemd-resolve" binary_path:"/usr/lib/systemd/systemd-resolved" command_line:"/usr/lib/systemd/systemd-resolved"
comm:"systemd-udevd" binary_path:"/usr/bin/udevadm" command_line:"/usr/lib/systemd/systemd-udevd"
comm:"systemd" binary_path:"/usr/lib/systemd/systemd" command_line:"/usr/lib/systemd/systemd --user"
comm:"systemd-logind" binary_path:"/usr/lib/systemd/systemd-logind" command_line:"/usr/lib/systemd/systemd-logind"
comm:"systemd-journal" binary_path:"/usr/lib/systemd/systemd-journald" command_line:"/usr/lib/systemd/systemd-journald"
comm:"systemd-timesyn" binary_path:"/usr/lib/systemd/systemd-timesyncd" command_line:"/usr/lib/systemd/systemd-timesyncd"
```

#### Connections

Find network connections for a specific process by joining tasks, task_open_files, and network_connections.

```bash
$ mquire shell ubuntu2404_6.14.0-37-generic.lime
mquire> SELECT
  t.tgid,
  t.comm,
  nc.protocol,
  nc.local_address,
  nc.local_port,
  nc.remote_address,
  nc.remote_port,
  nc.state
FROM tasks t
JOIN task_open_files tof ON tof.task = t.virtual_address
JOIN network_connections nc ON nc.inode = tof.inode
WHERE t.comm = 'sshd';
tgid:"1134" comm:"sshd" protocol:"tcp" local_address:"0.0.0.0" local_port:"22" remote_address:"<null>" remote_port:"<null>" state:"listen"
tgid:"1134" comm:"sshd" protocol:"tcp" local_address:"::" local_port:"22" remote_address:"<null>" remote_port:"<null>" state:"listen"
```

#### Task open files

List open files for specific processes by joining `tasks` with `task_open_files`:

```bash
$ mquire shell ubuntu2404_6.14.0-37-generic.lime
mquire> SELECT t.comm, tof.path
FROM tasks t
JOIN task_open_files tof ON tof.task = t.virtual_address
WHERE t.comm LIKE '%systemd%'
LIMIT 10;
comm:"systemd" path:"/null"
comm:"systemd" path:"/null"
comm:"systemd" path:"/null"
comm:"systemd" path:"/kmsg"
comm:"systemd" path:"[eventpoll]"
comm:"systemd" path:"[signalfd]"
comm:"systemd" path:"inotify"
comm:"systemd" path:"/"
comm:"systemd" path:"[timerfd]"
comm:"systemd" path:"/usr/lib/systemd/systemd-executor"
```

#### Command-line query examples

##### JSON output (default)

```bash
$ mquire query --format=json ubuntu2404_6.14.0-37-generic.lime "SELECT * FROM os_version"
[
  {
    "arch": "x86_64",
    "kernel_version": "6.14.0-37-generic",
    "system_version": "#37~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Nov 20 10:25:38 UTC 2"
  }
]
```

##### Table output

```bash
$ mquire query --format=table ubuntu2404_6.14.0-37-generic.lime "SELECT * FROM os_version"
arch:"x86_64" kernel_version:"6.14.0-37-generic" system_version:"#37~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Nov 20 10:25:38 UTC 2"
```

#### Custom command examples

##### List available commands

```bash
$ mquire command ubuntu2404_6.14.0-37-generic.lime
Available commands:
  .carve               Carve a region of virtual memory to disk
  .dump                Dump all open files from tasks to disk
  .system_version      Display the operating system version
  .task_tree           Display a hierarchical task tree
```

##### Display system version

```bash
$ mquire command ubuntu2404_6.14.0-37-generic.lime ".system_version"
System Version: #37~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Nov 20 10:25:38 UTC 2
Kernel Version: 6.14.0-37-generic
Architecture: x86_64
```

##### Display process tree

```bash
$ mquire command ubuntu2404_6.8.0-63-generic.lime .task_tree | head -n 10
Parent: task_struct::parent
Threads: Disabled
Page Table: paddr(0x0000000001a60000)

└─ [0] (ffffffff90c0fcc0) swapper/0
   ╎   ↳ [0] (ffff982a00e33518) \xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd,)\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x0e
   ├─ [1] (ffff982a0084a8c0) systemd
   │  ├─ [430] (ffff982a0d27a8c0) systemd-journal
   │  ├─ [495] (ffff982a08a88000) systemd-udevd
   │  ├─ [786] (ffff982a07a60000) systemd-oomd
```

**Note:** When multiple `task_struct` entries exist with the same TID (Thread ID, which can occur due to memory corruption or snapshot timing), duplicate entries are displayed with the continuation symbol `╎   ↳` indented under the primary entry. The format is `[TGID] (virtual_address) name` when threads are hidden, or `[TGID TID]` when showing threads (where TGID is the Thread Group ID, commonly known as PID).

#### Extract files from memory

```bash
$ mquire command ubuntu2404_6.14.0-37-generic.lime ".dump ./extracted_files"
Legend: SK = skipped, OK = all good, ER = errored

Summary:
  Total files processed: 1234
  Successfully dumped: 1156
  Skipped: 45
  Errors: 33

File Status:
  OK /usr/lib/systemd/systemd (TGID 1)
  OK /etc/passwd (TGID 1)
  SK /dev/null (TGID 1)
  ...
```

## Troubleshooting

Use the `--debug` flag to enable verbose debug messages during initialization and analysis:

```bash
mquire --debug command /path/to/memory.raw ".system_version"
```

- **`shell` and `query` modes**: Debug messages are stored in the `mquire_diagnostics` SQL table. Query them with `SELECT * FROM mquire_diagnostics;`
- **`command` mode**: Debug messages are printed directly to stderr.

For initialization issues that prevent mquire from successfully loading the snapshot, using `command` mode with a simple command like `.system_version` is recommended, as it prints debug output to stderr immediately without needing to query the `mquire_diagnostics` table.

## Configuration

mquire can be configured via a TOML file at `$HOME/.config/trailofbits/mquire/config.toml`. If the file does not exist, default values are used.

### Available options and default values

```toml
[database]
# Maximum number of entries retained in the mquire_diagnostics table.
# During initialization, all entries are kept regardless of this limit.
# Once initialization completes, new log entries trigger eviction of the
# oldest entries when the total exceeds this value.
mquire_diagnostics_max_entries = 1000
```

## Development

This project uses [just](https://github.com/casey/just) as a command runner. Run `just` to see available commands:

| Command | Description |
|---------|-------------|
| `just check` | Run all checks (cargo check, cargo clippy, cargo fmt, ruff, mypy) |
| `just test` | Run unit tests |
| `just format` | Format code (cargo fmt, ruff) |
| `just integration-test` | Run SQL query integration tests |
| `just integration-update` | Update expected test output |
| `just package` | Build release packages |

### SQL query integration tests

These tests verify mquire produces correct output for queries against memory snapshots.

- **`just integration-test`** - Run tests and compare output to expected JSON files
- **`just integration-update`** - Update expected JSON files with actual output (use when changing table schemas)

After running `integration-update`, review the git diff to ensure changes match your expectations before committing.

**Adding new tests:** Create a `.sql` file and matching `.json` file in the appropriate snapshot directory, then run `just integration-update` to populate the expected output.

## Contributing

Contributions are welcome! When contributing, please follow these guidelines:

1. **Test your changes** - Make sure your changes work correctly before submitting
2. **Keep dependencies minimal** - Only add new dependencies when absolutely necessary
3. **Avoid caching volatile data** - Do not cache values that could move or change within kernel objects. Only cache stable references like:
   - Kallsyms location
   - `init_task` virtual address
   - BTF data

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
