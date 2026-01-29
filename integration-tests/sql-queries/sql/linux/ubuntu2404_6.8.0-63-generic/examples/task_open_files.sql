WITH
  tasks_mat AS MATERIALIZED (
    SELECT virtual_address, tgid, pid, comm FROM tasks WHERE source = 'task_list' AND comm LIKE '%systemd%'
  ),
  task_open_files_mat AS MATERIALIZED (
    SELECT task, tgid, fd, path FROM task_open_files
  )
SELECT t.comm, t.pid, tof.fd, tof.path
FROM tasks_mat t
JOIN task_open_files_mat tof ON t.tgid = tof.tgid
