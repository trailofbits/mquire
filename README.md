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

mq provides SQL tables to query different aspects of the system or the state of the tool itself:

#### System information

- **os_version** - Kernel version and architecture
- **system_info** - Hostname and domain name

#### Process information

- **tasks** - Running processes with command lines and binary paths
- **task_open_files** - Files opened by each process
- **cgroups** - Control groups for processes
- **memory_mappings** - Memory regions mapped by each process

#### File system

- **syslog** - System logs read from the kernel's file cache (works even if log files are deleted or unavailable, as long as they're cached in memory)

### Debugging

- **log_messages** - Internal mquire logs showing analysis progress, warnings, and errors

### Tools

- **mq-file-dump** - Extract files from the kernel's file cache to recover files directly from memory. Currently works with files opened through file descriptors (from the process file descriptor table). Does not yet support extracting data from memory-mapped files.

## Use cases

mquire is designed for:

- **Forensic analysis** - Analyze memory snapshots from compromised systems to understand what was running and what files were accessed
- **Incident response** - Quickly query memory dumps to find evidence of malicious activity
- **Security research** - Study kernel internals and process behavior from memory snapshots
- **Malware analysis** - Examine running processes and their file operations without detection
- **Custom tooling** - Build your own analysis tools using the **libmquire** library, which provides a reusable API for kernel memory analysis

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

# The binaries will be in target/release/
# - mq: Main query tool
# - mq-file-dump: File extraction tool
```

## Acquiring a memory snapshot

1. Compile the [LiME](https://github.com/504ensicsLabs/LiME) project
2. Acquire a raw memory snapshot by loading the built kernel module: `insmod ./lime-x.x.x-xx-generic.ko 'path=/path/to/memory/dump.bin format=padded'`

## Getting started

Once you have a memory snapshot, you can query it using SQL:

### Basic SQLite commands

#### Discovering available tables

There is no hosted table list yet, but you can easily discover what's available from the command line using the following queries:

```bash
# List all available tables
mq /path/to/memory.raw '.tables'
```

```bash
# Show the schema of a specific table
mq /path/to/memory.raw '.schema tasks'
```

### Example queries

All other queries use standard SQL syntax.

#### System version

```bash
mq /path/to/memory.raw 'SELECT * FROM os_version;'
```

```
arch:"x86_64" kernel_version:"6.2.0-39-generic" system_version:"#40~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Nov 16 10:53:04 UTC 2"
```

#### System information

```bash
mq /path/to/memory.raw 'SELECT * FROM system_info;'
```

```
domain:"(none)" hostname:"ubuntu2204-mquire"
```

#### Running tasks

```bash
mq /path/to/memory.raw \
  'SELECT comm, binary_path, command_line
   FROM tasks
   WHERE command_line NOT NULL AND comm LIKE "%systemd%";'
```

```
comm:"systemd" binary_path:"/usr/lib/systemd/systemd" command_line:"/sbin/init splash"
comm:"systemd-journal" binary_path:"/usr/lib/systemd/systemd-journald" command_line:"/lib/systemd/systemd-journald"
comm:"systemd-udevd" binary_path:"/usr/bin/udevadm" command_line:"/lib/systemd/systemd-udevd"
comm:"systemd-oomd" binary_path:"/usr/lib/systemd/systemd-oomd" command_line:"/lib/systemd/systemd-oomd"
comm:"systemd-resolve" binary_path:"/usr/lib/systemd/systemd-resolved" command_line:"/lib/systemd/systemd-resolved"
comm:"systemd-timesyn" binary_path:"/usr/lib/systemd/systemd-timesyncd" command_line:"/lib/systemd/systemd-timesyncd"
comm:"systemd" binary_path:"/usr/lib/systemd/systemd" command_line:"/lib/systemd/systemd --user"
comm:"systemd-logind" binary_path:"/usr/lib/systemd/systemd-logind" command_line:"/lib/systemd/systemd-logind"
```

#### Task open files

```bash
mq /path/to/memory.raw \
  'SELECT
    tasks.pid, tasks.binary_path, tasks.command_line,
    task_open_files.path
  FROM tasks
  JOIN task_open_files ON tasks.pid = task_open_files.pid
  WHERE path LIKE "/home/%";'
```

```
...
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/user/snap/firefox/common/.mozilla/firefox/8tljoy31.default/permissions.sqlite"
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/user/snap/firefox/common/.mozilla/firefox/8tljoy31.default/places.sqlite"
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/user/snap/firefox/common/.mozilla/firefox/8tljoy31.default/cookies.sqlite"
...
```

## Contributing

Contributions are welcome! When contributing, please follow these guidelines:

1. **Test your changes** - Make sure your changes work correctly before submitting
2. **Keep dependencies minimal** - Only add new dependencies when absolutely necessary
3. **Avoid caching volatile data** - Do not cache values that could move or change within kernel objects. Only cache stable references like:
   - Kallsyms location
   - `init_task` virtual address
   - BTF data

This project uses automated code quality checks to maintain consistency.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
