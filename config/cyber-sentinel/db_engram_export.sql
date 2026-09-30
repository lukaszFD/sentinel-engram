-- ============================================================
-- Sentinel Engram — read-only export interface on Cyber Sentinel
-- ============================================================
-- Target:   Cyber Sentinel Postgres (postgres_db), DB cyber_intelligence.
-- Applied:  by Sentinel Engram playbook 07_cs_source_access.yml
--           (Jinja2 template: role name + password injected).
--
-- Design:
--   - Separate schema `engram_export`. Nothing in `cyber_sentinel`
--     or `cyber_sentinel_ai` is created, altered or granted.
--   - Role `{{ cs_pg_reader_user }}` has USAGE on `engram_export`
--     only. Views/functions are owned by `postgres`, so they read
--     the underlying CTI tables with owner rights — the reader never
--     gets a direct grant on any Cyber Sentinel table.
--   - Role is forced read-only at session level
--     (default_transaction_read_only) with a statement timeout, so
--     a runaway sync query cannot load the Pi.
--   - Idempotent: safe to re-run after every Cyber Sentinel deploy.
-- ============================================================

-- ------------------------------------------------------------
-- SECTION 1: Reader role
-- ------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{{ cs_pg_reader_user }}') THEN
        CREATE ROLE "{{ cs_pg_reader_user }}" LOGIN;
    END IF;
END
$$;

ALTER ROLE "{{ cs_pg_reader_user }}" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
    CONNECTION LIMIT 3
    PASSWORD '{{ vault_cs_pg_reader_password | replace("'", "''") }}';
ALTER ROLE "{{ cs_pg_reader_user }}" SET default_transaction_read_only = on;
ALTER ROLE "{{ cs_pg_reader_user }}" SET statement_timeout = '300s';
ALTER ROLE "{{ cs_pg_reader_user }}" SET search_path = engram_export;

GRANT CONNECT ON DATABASE cyber_intelligence TO "{{ cs_pg_reader_user }}";

-- ------------------------------------------------------------
-- SECTION 2: Export schema
-- ------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS engram_export AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA engram_export FROM PUBLIC;
GRANT USAGE ON SCHEMA engram_export TO "{{ cs_pg_reader_user }}";

-- ------------------------------------------------------------
-- SECTION 3: AI verdicts per indicator
-- ------------------------------------------------------------
-- One row per threat_indicators row. Simple (non-aggregated) view:
-- the worker's `WHERE last_scan > $watermark` pushes down to the
-- partitioned threat_indicators table and prunes partitions.
CREATE OR REPLACE VIEW engram_export.v_verdicts AS
SELECT
    ti.id                  AS indicator_id,
    ti.last_scan,
    ti.scan_count,
    lower(dq.domain)       AS fqdn,
    dq.record_type,
    dq.response_ip         AS observable_ip,
    ar.id                  AS analysis_id,
    ar.threat_score,
    ar.threat_label,
    tl.description         AS threat_level,
    tl.is_malicious_flag   AS is_malicious,
    ar.confidence_score,
    ar.analyzed_at,
    ARRAY(
        SELECT DISTINCT sp.name
        FROM cyber_sentinel.threat_indicator_details tid
        JOIN cyber_sentinel.dic_source_providers sp ON sp.id = tid.source_id
        WHERE tid.indicator_id = ti.id
        ORDER BY sp.name
    )                      AS providers
FROM cyber_sentinel.threat_indicators ti
JOIN cyber_sentinel.dns_queries        dq ON dq.id = ti.dns_query_id
JOIN cyber_sentinel.ai_analysis_results ar ON ar.id = ti.analysis_result_id
JOIN cyber_sentinel.dic_threat_levels  tl ON tl.score = ar.threat_score;

ALTER VIEW engram_export.v_verdicts OWNER TO postgres;
REVOKE ALL ON engram_export.v_verdicts FROM PUBLIC;
GRANT SELECT ON engram_export.v_verdicts TO "{{ cs_pg_reader_user }}";

-- ------------------------------------------------------------
-- SECTION 4: DNS resolutions seen on the home network
-- ------------------------------------------------------------
-- Function instead of a view: the time filter must be applied BEFORE
-- aggregation so dns_queries partitions are pruned. Aggregates per
-- (domain, response_ip) over the requested window.
-- SECURITY DEFINER + pinned search_path: runs as postgres, reader
-- only needs EXECUTE.
CREATE OR REPLACE FUNCTION engram_export.fn_dns_seen(p_since timestamp)
RETURNS TABLE (
    fqdn        text,
    response_ip text,
    first_seen  timestamp,
    last_seen   timestamp,
    hits        bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, cyber_sentinel
AS $fn$
    SELECT lower(dq.domain),
           dq.response_ip,
           min(dq.timestamp),
           max(dq.timestamp),
           count(*)
    FROM cyber_sentinel.dns_queries dq
    WHERE dq.timestamp >= p_since
    GROUP BY lower(dq.domain), dq.response_ip
$fn$;

ALTER FUNCTION engram_export.fn_dns_seen(timestamp) OWNER TO postgres;
REVOKE ALL ON FUNCTION engram_export.fn_dns_seen(timestamp) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION engram_export.fn_dns_seen(timestamp) TO "{{ cs_pg_reader_user }}";
