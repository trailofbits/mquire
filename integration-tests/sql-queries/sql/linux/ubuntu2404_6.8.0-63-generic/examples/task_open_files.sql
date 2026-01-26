SELECT t.comm, t.pid, tof.fd, tof.path
FROM tasks t
JOIN task_open_files tof ON t.tgid = tof.tgid
WHERE t.comm LIKE '%systemd%'
