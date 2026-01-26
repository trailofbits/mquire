SELECT * FROM memory_mappings WHERE file_path IS NOT NULL AND file_path <> '' ORDER BY region_start, file_path LIMIT 100
