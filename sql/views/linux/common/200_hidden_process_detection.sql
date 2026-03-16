-- Detects processes visible in one discovery source but missing from another.
-- Rootkits often hide processes by unlinking them from the kernel's task list
-- while keeping them running.
--
-- Note: The task_list source aggressively follows pointers within task_struct
-- (e.g., parent, children, sibling, group_leader) to maximize process discovery.
-- This may occasionally yield invalid entries from corrupted or stale pointers.
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
