-- materialise.sql
-- Run via materialise.py (DuckDB).
-- Input:  labeled_audit.jsonl
-- Output: features.parquet (one row per audit event)

CREATE OR REPLACE TABLE raw AS
SELECT
    event_id,
    CAST(ts AS TIMESTAMP)                                        AS ts,
    COALESCE(CAST(session_id AS VARCHAR), '')                    AS session_id,
    user_token,
    sub,
    source_ip,
    source_geo.country                                           AS country,
    COALESCE(source_geo.asn, 0)::INTEGER                        AS asn,
    verb,
    endpoint,
    response_code,
    duration_ms,
    COALESCE(request_role, '')                                   AS request_role,
    label,
    -- epoch seconds for window arithmetic
    epoch(CAST(ts AS TIMESTAMP))::DOUBLE                         AS ts_epoch,
    -- high-privilege flag
    (request_role IN ('admin','cluster-admin'))::INTEGER         AS is_high_privilege_role,
    -- failed request flag
    (response_code >= 400)::INTEGER                              AS is_failed,
    -- read vs write
    (verb = 'GET')::INTEGER                                      AS is_read,
    (verb IN ('POST','PUT','PATCH','DELETE'))::INTEGER           AS is_write
FROM read_ndjson_auto('{{ input }}');

-- Lag features (previous event per user)
CREATE OR REPLACE TABLE with_lags AS
SELECT
    *,
    LAG(endpoint, 1) OVER w                         AS endpoint_lag1,
    LAG(endpoint, 2) OVER w                         AS endpoint_lag2,
    LAG(request_role, 1) OVER w                     AS role_lag1,
    ts_epoch - LAG(ts_epoch, 1) OVER w              AS delta_ts_t1_s
FROM raw
WINDOW w AS (PARTITION BY user_token ORDER BY ts);

-- Final feature table with window aggregates
COPY (
SELECT
    event_id,
    ts,
    session_id,
    user_token,
    sub,
    source_ip,
    -- encode country/endpoint/role as FNV-32a to match Go's hashStr()
    fnv32a(country)                                  AS country_hash,
    asn,
    fnv32a(endpoint)                                 AS endpoint_hash,
    COALESCE(fnv32a(endpoint_lag1), 0.0)             AS endpoint_lag1_hash,
    COALESCE(fnv32a(endpoint_lag2), 0.0)             AS endpoint_lag2_hash,
    fnv32a(request_role)                             AS role_hash,
    COALESCE(fnv32a(role_lag1), 0.0)                 AS role_lag1_hash,
    COALESCE(delta_ts_t1_s, -1)                      AS delta_ts_t1_s,
    is_high_privilege_role,
    -- session features
    ts_epoch - MIN(ts_epoch) OVER s                  AS session_age_s,
    ROW_NUMBER() OVER s                              AS session_total_actions,
    COUNT(DISTINCT endpoint) OVER s                  AS unique_endpoints,
    -- 1-min windows
    COUNT(*) OVER w1                                 AS req_count_1m,
    SUM(is_failed) OVER w1                           AS failed_req_count_1m,
    -- 5-min windows
    COUNT(*) OVER w5                                 AS req_count_5m,
    SUM(is_read) OVER w5                             AS reads_5m,
    SUM(is_write) OVER w5                            AS writes_5m,
    CASE WHEN SUM(is_write) OVER w5 = 0
         THEN SUM(is_read) OVER w5
         ELSE SUM(is_read) OVER w5::DOUBLE / SUM(is_write) OVER w5
    END                                              AS read_write_ratio_5m,
    AVG(delta_ts_t1_s) OVER w5                      AS interarrival_avg_5m,
    -- 15-min windows
    COUNT(*) OVER w15                                AS req_count_15m,
    -- role mismatch (request_role = 'admin' or 'cluster-admin' but not approved)
    SUM(is_high_privilege_role) OVER w5              AS role_mismatch_count_5m,
    -- geo: simultaneous IPs for same session in last 30s
    COUNT(DISTINCT source_ip) OVER s30               AS simultaneous_ip_count,
    -- mass listing score: GET /requests in last 5 min
    SUM(CASE WHEN verb='GET' AND endpoint='/requests' THEN 1 ELSE 0 END) OVER w5  AS mass_request_score,
    COUNT(DISTINCT request_role) OVER w5             AS unique_roles_requested_5m,
    -- circadian
    EXTRACT(hour FROM ts) + EXTRACT(minute FROM ts)/60.0  AS hour_of_day,
    SIN(2*PI()*(EXTRACT(hour FROM ts)/24.0))         AS hour_sin,
    COS(2*PI()*(EXTRACT(hour FROM ts)/24.0))         AS hour_cos,
    (EXTRACT(dow FROM ts) IN (0,6))::INTEGER         AS is_weekend,
    (EXTRACT(hour FROM ts) < 8 OR EXTRACT(hour FROM ts) >= 18)::INTEGER AS is_outside_hours,
    -- target
    label
FROM with_lags
WINDOW
    s   AS (PARTITION BY session_id ORDER BY ts ROWS UNBOUNDED PRECEDING),
    s30 AS (PARTITION BY session_id ORDER BY ts RANGE BETWEEN INTERVAL '30 seconds' PRECEDING AND CURRENT ROW),
    w1  AS (PARTITION BY user_token ORDER BY ts RANGE BETWEEN INTERVAL '1 minute'  PRECEDING AND CURRENT ROW),
    w5  AS (PARTITION BY user_token ORDER BY ts RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW),
    w15 AS (PARTITION BY user_token ORDER BY ts RANGE BETWEEN INTERVAL '15 minutes' PRECEDING AND CURRENT ROW)
) TO '{{ output }}' (FORMAT PARQUET, COMPRESSION SNAPPY);
