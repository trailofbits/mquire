SELECT t.comm, t.pid, nc.local_address, nc.local_port, nc.remote_address, nc.remote_port, nc.state
FROM tasks t
JOIN task_open_files tof ON t.tgid = tof.tgid
JOIN network_connections nc ON tof.inode = nc.inode
WHERE t.comm = 'sshd'
