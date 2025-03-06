# mquire

mquire, a play on the `memory` and `inquire` words, is a memory querying tool inspired by [osquery](https://github.com/osquery/osquery).

It works by relying on the [BTF](https://www.kernel.org/doc/html/next/bpf/btf.html) debug symbols format, which is used by the Linux kernel for the code tracing features offered by BPF. This tool uses the [btfparse crate](https://github.com/alessandrogario/btfparse) (a rewrite in Rust of our previously released [C++ library](https://github.com/trailofbits/btfparse)) to acquire the required type information from the memory snapshot.

## Acquiring a memory snapshot

1. Compile the [LiME](https://github.com/504ensicsLabs/LiME) project
2. Acquire a raw memory snapshot by loading the built kernel module: `insmod ./lime-x.x.x-xx-generic.ko 'path=/path/to/memory/dump.bin format=padded'`

## Example output

### Task open files

```bash
mq \
  /home/alessandro/ubuntu2204.raw \
  'SELECT
    tasks.pid, tasks.binary_path, tasks.command_line,
    task_open_files.path
  FROM tasks
  JOIN task_open_files ON tasks.pid = task_open_files.pid
  WHERE path LIKE "/home/alessandro/%";'
```

```
...
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/alessandro/snap/firefox/common/.mozilla/firefox/8tljoy31.default/permissions.sqlite"
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/alessandro/snap/firefox/common/.mozilla/firefox/8tljoy31.default/places.sqlite"
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/alessandro/snap/firefox/common/.mozilla/firefox/8tljoy31.default/.parentlock"
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/alessandro/snap/firefox/common/.mozilla/firefox/8tljoy31.default/favicons.sqlite"
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/alessandro/snap/firefox/common/.mozilla/firefox/8tljoy31.default/cookies.sqlite"
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/alessandro/snap/firefox/common/.mozilla/firefox/8tljoy31.default/cert9.db"
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/alessandro/snap/firefox/common/.mozilla/firefox/8tljoy31.default/key4.db"
pid:"1982" binary_path:"/usr/lib/firefox/firefox" command_line:"/snap/firefox/2356/usr/lib/firefox/firefox" path:"/home/alessandro/snap/firefox/common/.mozilla/firefox/8tljoy31.default/storage.sqlite"
...
```

### System version

```bash
mq \
  /home/alessandro/ubuntu2204.raw \
  'SELECT * FROM os_version;'
```

```
arch:"x86_64" kernel_version:"6.2.0-39-generic" system_version:"#40~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Nov 16 10:53:04 UTC 2"
```

### System information

```bash
mq \
  /home/alessandro/ubuntu2204.raw \
  'SELECT * FROM system_info;'
```

```
domain:"(none)" hostname:"ubuntu2204-mquire" 
``````

### Running tasks

```bash
mq \
  /home/alessandro/ubuntu2204.raw \
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
