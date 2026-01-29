WITH
  tasks_mat AS MATERIALIZED (
    SELECT tgid, pid, comm FROM tasks WHERE source = 'task_list' AND comm = 'sshd'
  ),
  task_open_files_mat AS MATERIALIZED (
    SELECT tgid, inode FROM task_open_files
  ),
  network_connections_mat AS MATERIALIZED (
    SELECT * FROM network_connections
  )
SELECT t.comm, t.pid, nc.local_address, nc.local_port, nc.remote_address, nc.remote_port, nc.state
FROM tasks_mat t
JOIN task_open_files_mat tof ON t.tgid = tof.tgid
JOIN network_connections_mat nc ON tof.inode = nc.inode
