-- Maps network connections to their owning processes by joining through file descriptors.
CREATE VIEW IF NOT EXISTS process_network_connections AS
WITH
  network_connections_mat AS MATERIALIZED (
    SELECT * FROM network_connections
  ),

  task_open_files_mat AS MATERIALIZED (
    SELECT * FROM task_open_files
  ),

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
