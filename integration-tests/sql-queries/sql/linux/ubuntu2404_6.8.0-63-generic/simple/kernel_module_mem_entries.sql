WITH modules AS MATERIALIZED (
  SELECT virtual_address FROM kernel_modules WHERE name != ''
)
SELECT
  r.mem_type,
  COUNT(*) AS entry_count,
  SUM(CASE WHEN r.start = '0000000000000000' THEN 1 ELSE 0 END) AS unmapped_entries
FROM modules m
JOIN kernel_module_mem_entries r ON r.kernel_module = m.virtual_address
GROUP BY r.mem_type
ORDER BY r.mem_type
