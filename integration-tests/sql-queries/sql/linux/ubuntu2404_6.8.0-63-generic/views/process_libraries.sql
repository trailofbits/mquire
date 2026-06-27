SELECT comm, count(DISTINCT library) AS library_count FROM process_libraries GROUP BY comm ORDER BY library_count DESC, comm LIMIT 10
