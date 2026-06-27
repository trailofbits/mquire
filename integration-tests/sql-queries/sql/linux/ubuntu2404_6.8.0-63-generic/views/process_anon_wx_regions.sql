SELECT comm, count(*) AS rwx_regions FROM process_anon_wx_regions GROUP BY comm ORDER BY rwx_regions DESC, comm LIMIT 10
