-- Deduplicated process view across all discovery sources.
-- The tasks table may return the same task from multiple sources for rootkit detection.
-- This view provides a clean, single-row-per-process result by deduplicating across sources.
CREATE VIEW IF NOT EXISTS processes AS
WITH tasks_mat AS MATERIALIZED (
  SELECT * FROM tasks
  WHERE type = 'thread_group_leader'
    AND pid > 0
)
SELECT DISTINCT
  pid,
  ppid,
  tgid,
  comm,
  binary_path,
  command_line,
  environment,
  uid,
  gid,
  page_table,
  virtual_address,
  type,
  start_time,
  start_boottime
FROM tasks_mat;
