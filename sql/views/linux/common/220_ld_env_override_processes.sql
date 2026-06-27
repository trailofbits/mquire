-- Lists processes that override the dynamic linker through environment
-- variables commonly abused for userland code injection / library hijacking:
-- LD_PRELOAD, LD_AUDIT, and LD_LIBRARY_PATH.
--
-- The per-variable flag columns let you focus on the higher-signal cases
-- (LD_PRELOAD / LD_AUDIT). Note that these variables are also set legitimately
-- by sandboxes such as snap and flatpak (e.g. snap sets LD_PRELOAD to its own
-- bindtextdomain.so and LD_LIBRARY_PATH to its GL libs), so always inspect the
-- `environment` value to tell a benign loader path from an injected payload.
CREATE VIEW IF NOT EXISTS ld_env_override_processes AS
SELECT
  pid,
  comm,
  (environment LIKE '%LD_PRELOAD=%')      AS has_ld_preload,
  (environment LIKE '%LD_AUDIT=%')        AS has_ld_audit,
  (environment LIKE '%LD_LIBRARY_PATH=%') AS has_ld_library_path,
  environment

FROM processes

WHERE environment LIKE '%LD_PRELOAD=%'
   OR environment LIKE '%LD_AUDIT=%'
   OR environment LIKE '%LD_LIBRARY_PATH=%';
