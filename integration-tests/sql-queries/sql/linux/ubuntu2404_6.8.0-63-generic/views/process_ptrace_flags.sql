SELECT pid, comm, flags, raw
FROM process_ptrace_flags
WHERE comm IN ('systemd', 'systemd-resolve', 'systemd-logind', 'upowerd', 'systemd-udevd')
ORDER BY pid, comm
