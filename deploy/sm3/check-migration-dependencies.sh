#!/usr/bin/env bash
# Read PostgreSQL catalogs only; no data restore and no foreign table queries.
set -euo pipefail
CONTAINER="${1:-postgres-13}"
PG_AUDIT_OPTIONS='-c default_transaction_read_only=on -c statement_timeout=60000'
dbs=$(docker exec --user postgres -e "PGOPTIONS=$PG_AUDIT_OPTIONS" "$CONTAINER" \
    psql -X -w -At -v ON_ERROR_STOP=1 -d postgres \
    -c 'SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname')
while IFS= read -r db; do
    printf '\nDatabase: %s\n' "$db"
    docker exec -i --user postgres -e "PGOPTIONS=$PG_AUDIT_OPTIONS" "$CONTAINER" \
        psql -X -w -P pager=off -v ON_ERROR_STOP=1 -d "$db" <<'SQL'
WITH RECURSIVE
edges AS (
  SELECT classid, objid, objsubid, refclassid, refobjid, refobjsubid
  FROM pg_depend
  UNION ALL
  SELECT 'pg_class'::regclass, r.ev_class, 0,
         'pg_rewrite'::regclass, r.oid, 0
  FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class
  WHERE c.relkind IN ('v','m')
),
extension_owned AS (
  SELECT classid, objid, objsubid FROM pg_depend
  WHERE refclassid = 'pg_extension'::regclass AND deptype = 'e'
  UNION
  SELECT d.classid, d.objid, d.objsubid
  FROM pg_depend d JOIN extension_owned o
    ON d.refclassid = o.classid AND d.refobjid = o.objid
   AND (o.objsubid = 0 OR d.refobjsubid = o.objsubid)
  WHERE d.deptype IN ('i','a')
),
seeds AS (
  SELECT 'pg_extension'::regclass::oid AS classid, oid AS objid, 0 AS objsubid
  FROM pg_extension WHERE extname <> 'plpgsql'
  UNION ALL
  SELECT 'pg_class'::regclass, oid, 0 FROM pg_class WHERE relkind = 'f'
),
affected AS (
  SELECT * FROM seeds
  UNION
  SELECT e.classid, e.objid, e.objsubid
  FROM edges e JOIN affected a
    ON e.refclassid = a.classid AND e.refobjid = a.objid
   AND (a.objsubid = 0 OR e.refobjsubid = a.objsubid)
)
SELECT CASE WHEN a.classid = 'pg_class'::regclass AND a.objsubid > 0
                 AND c.relkind IN ('r','p')
            THEN 'TABLE_COLUMN_REQUIRES_DECISION'
            WHEN c.relkind = 'f' THEN 'FOREIGN_TABLE_TO_EXCLUDE'
            ELSE 'DEFINITION_DEPENDENCY' END AS category,
       pg_describe_object(a.classid, a.objid, a.objsubid) AS dependent_object
FROM affected a
LEFT JOIN pg_class c ON a.classid = 'pg_class'::regclass AND c.oid = a.objid
LEFT JOIN pg_type t ON a.classid = 'pg_type'::regclass AND t.oid = a.objid
WHERE (a.classid IN ('pg_attrdef'::regclass, 'pg_constraint'::regclass,
                    'pg_rewrite'::regclass, 'pg_proc'::regclass, 'pg_trigger'::regclass)
       OR c.relkind IN ('r','p','i','I','v','m','f')
       OR (t.typtype = 'd'))
  AND NOT EXISTS (
    SELECT 1 FROM extension_owned o
    WHERE o.classid = a.classid AND o.objid = a.objid
      AND (o.objsubid = 0 OR o.objsubid = a.objsubid)
  )
ORDER BY category DESC, dependent_object;
SQL
done <<< "$dbs"
