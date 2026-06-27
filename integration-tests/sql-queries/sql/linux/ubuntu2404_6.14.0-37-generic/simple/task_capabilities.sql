WITH target AS MATERIALIZED (
  SELECT virtual_address FROM tasks WHERE source = 'pid_ns' AND pid = 1
)
SELECT c.name, c.effective, c.permitted, c.inheritable, c.bounding, c.ambient
FROM target t
JOIN task_capabilities c ON c.task = t.virtual_address
WHERE c.name IN ('CAP_CHOWN', 'CAP_NET_RAW', 'CAP_SYS_ADMIN', 'CAP_CHECKPOINT_RESTORE')
ORDER BY c.name
