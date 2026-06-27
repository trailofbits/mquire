-- Lists the shared libraries loaded into each process, derived from file-backed
-- memory mappings ending in ".so" / ".so.<version>". Useful for spotting
-- unexpected or suspicious shared objects mapped into a process address space.
CREATE VIEW IF NOT EXISTS process_libraries AS
WITH process_list AS MATERIALIZED (
  SELECT virtual_address, pid, comm
  FROM processes
)

SELECT DISTINCT
  p.pid,
  p.comm,
  p.virtual_address AS task,
  mm.file_path AS library

FROM process_list p

JOIN memory_mappings mm ON mm.task = p.virtual_address
WHERE mm.file_path IS NOT NULL
  AND (mm.file_path LIKE '%.so' OR mm.file_path LIKE '%.so.%')

ORDER BY p.pid, library;
