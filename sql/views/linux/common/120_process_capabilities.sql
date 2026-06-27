-- Quick-peek capability overview
CREATE VIEW IF NOT EXISTS process_capabilities AS
WITH process_list AS MATERIALIZED (
  SELECT virtual_address, pid, comm FROM processes
)

SELECT
  p.pid,
  p.comm,
  p.virtual_address AS task,

  CASE
    WHEN COUNT(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' THEN c.effective END) = 0 THEN NULL
    WHEN SUM(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' AND c.effective = 1 THEN 1 ELSE 0 END)
       = COUNT(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' THEN c.effective END) THEN 'ALL'
    WHEN SUM(COALESCE(c.effective, 0)) = 0 THEN ''
    ELSE group_concat(CASE WHEN c.effective = 1 THEN replace(c.name, 'CAP_', '') END, ' ')
  END AS effective,

  CASE
    WHEN COUNT(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' THEN c.permitted END) = 0 THEN NULL
    WHEN SUM(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' AND c.permitted = 1 THEN 1 ELSE 0 END)
       = COUNT(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' THEN c.permitted END) THEN 'ALL'
    WHEN SUM(COALESCE(c.permitted, 0)) = 0 THEN ''
    ELSE group_concat(CASE WHEN c.permitted = 1 THEN replace(c.name, 'CAP_', '') END, ' ')
  END AS permitted,

  CASE
    WHEN COUNT(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' THEN c.inheritable END) = 0 THEN NULL
    WHEN SUM(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' AND c.inheritable = 1 THEN 1 ELSE 0 END)
       = COUNT(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' THEN c.inheritable END) THEN 'ALL'
    WHEN SUM(COALESCE(c.inheritable, 0)) = 0 THEN ''
    ELSE group_concat(CASE WHEN c.inheritable = 1 THEN replace(c.name, 'CAP_', '') END, ' ')
  END AS inheritable,

  CASE
    WHEN COUNT(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' THEN c.ambient END) = 0 THEN NULL
    WHEN SUM(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' AND c.ambient = 1 THEN 1 ELSE 0 END)
       = COUNT(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' THEN c.ambient END) THEN 'ALL'
    WHEN SUM(COALESCE(c.ambient, 0)) = 0 THEN ''
    ELSE group_concat(CASE WHEN c.ambient = 1 THEN replace(c.name, 'CAP_', '') END, ' ')
  END AS ambient,

  CASE
    WHEN COUNT(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' THEN c.bounding END) = 0 THEN NULL
    WHEN SUM(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' AND c.bounding = 1 THEN 1 ELSE 0 END)
       = COUNT(CASE WHEN c.name NOT LIKE 'CAP_UNKNOWN_BIT_%' THEN c.bounding END) THEN 'ALL'
    WHEN SUM(COALESCE(c.bounding, 0)) = 0 THEN ''
    ELSE group_concat(CASE WHEN c.bounding = 1 THEN replace(c.name, 'CAP_', '') END, ' ')
  END AS bounding

FROM process_list p

JOIN task_capabilities c ON c.task = p.virtual_address

GROUP BY p.virtual_address
ORDER BY p.pid;
