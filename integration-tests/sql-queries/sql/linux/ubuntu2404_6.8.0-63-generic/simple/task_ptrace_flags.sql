WITH target AS MATERIALIZED (
  SELECT virtual_address FROM tasks WHERE source = 'pid_ns' AND pid = 1
)
SELECT f.name, f.value
FROM target t
JOIN task_ptrace_flags f ON f.task = t.virtual_address
ORDER BY f.name
