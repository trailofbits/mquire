SELECT pid, comm, effective, permitted, inheritable, ambient, bounding
FROM process_capabilities
WHERE comm IN ('systemd', 'systemd-resolve', 'systemd-logind', 'upowerd', 'systemd-udevd')
ORDER BY pid, comm
