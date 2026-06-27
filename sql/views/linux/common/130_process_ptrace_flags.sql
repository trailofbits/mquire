-- Quick-peek ptrace overview
CREATE VIEW IF NOT EXISTS process_ptrace_flags AS
WITH process_list AS MATERIALIZED (
  SELECT virtual_address, pid, comm FROM processes
)

SELECT
  p.pid,
  p.comm,
  p.virtual_address AS task,

  COALESCE(
    group_concat(
      CASE WHEN f.name NOT IN ('raw', 'unused') AND f.value = '1'
           THEN replace(f.name, 'PT_', '') END,
      ' '
    ),
    ''
  ) AS flags,

  MAX(CASE WHEN f.name = 'raw' THEN f.value END) AS raw

FROM process_list p

JOIN task_ptrace_flags f ON f.task = p.virtual_address

GROUP BY p.virtual_address
ORDER BY p.pid;
