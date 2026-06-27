-- Lists anonymous (non file-backed) memory regions that are both writable and
-- executable - a classic indicator of injected code, shellcode, or unpacked
-- payloads (the core of Volatility's "malfind").
--
-- Note: legitimate JIT runtimes (browsers, JVMs, .NET, etc.) also create W+X
-- anonymous regions, so treat hits as leads to triage rather than conclusive
-- findings. The `shared` column helps narrow results: private regions
-- (shared = 0) are the higher-signal case for injection.
CREATE VIEW IF NOT EXISTS process_anon_wx_regions AS
WITH process_list AS MATERIALIZED (
  SELECT virtual_address, pid, comm
  FROM processes
)

SELECT
  p.pid,
  p.comm,
  p.virtual_address AS task,
  mm.region_start,
  mm.region_end,
  mm.readable,
  mm.writable,
  mm.executable,
  mm.shared

FROM process_list p

JOIN memory_mappings mm ON mm.task = p.virtual_address
WHERE mm.writable = 1
  AND mm.executable = 1
  AND mm.file_path IS NULL;
