-- AppSec Greenplum PATCH v1.8
-- Бизнес-правило:
--   Устранено / Outflow / прогресс исправления = ТОЛЬКО status = fixed.
-- False Positive и Exclusion остаются отдельными статусами и не входят
-- в показатели устранения.
-- Python перезапускать не нужно.
-- Сырые таблицы не изменяются.

BEGIN;

CREATE OR REPLACE VIEW custom_ts_secure_development.repository_daily_flow AS
SELECT
    e.event_ts::DATE AS dt,
    ep.product_id,
    MAX(ep.product_name) AS product_name,
    e.repository_id,
    MAX(e.repository) AS repository,
    MAX(e.repository_slug) AS repository_slug,
    e.severity,
    COUNT(DISTINCT CASE WHEN e.new_status IN (
                            'new_issue', 'recurrent', 'reopened'
                        ) THEN e.issue_id ELSE NULL END)::INTEGER AS inflow_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'fixed'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS outflow_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'fixed'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS fixed_cnt
FROM custom_ts_secure_development.issue_status_events e
JOIN custom_ts_secure_development.issue_status_event_product ep
  ON ep.event_id = e.event_id
WHERE e.is_baseline = FALSE
  AND e.new_status <> 'check_required'
  AND ep.product_id NOT IN (
      'd569ed52-b01f-4222-948b-705b008ae64a',
      '1a16d04d-cd14-4894-b887-4ba7465c26aa'
  )
GROUP BY
    e.event_ts::DATE,
    ep.product_id,
    e.repository_id,
    e.severity;

CREATE OR REPLACE VIEW custom_ts_secure_development.security_debt_summary_by_product AS
WITH initial_counts AS (
    SELECT
        cp.product_id,
        MAX(cp.product_name) AS product_name,
        COUNT(DISTINCT c.issue_id)::INTEGER AS initial_total,
        COUNT(DISTINCT CASE WHEN c.severity = 'CRITICAL'
                            THEN c.issue_id ELSE NULL END)::INTEGER
            AS initial_critical,
        COUNT(DISTINCT CASE WHEN c.severity = 'HIGH'
                            THEN c.issue_id ELSE NULL END)::INTEGER
            AS initial_high
    FROM custom_ts_secure_development.security_debt_cohort c
    JOIN custom_ts_secure_development.security_debt_cohort_product cp
      ON cp.issue_id = c.issue_id
    LEFT JOIN custom_ts_secure_development.issues_current_all i
      ON i.issue_id = c.issue_id
    WHERE cp.product_id NOT IN (
          'd569ed52-b01f-4222-948b-705b008ae64a',
          '1a16d04d-cd14-4894-b887-4ba7465c26aa'
      )
      AND COALESCE(i.status, '') <> 'check_required'
    GROUP BY cp.product_id
),
current_counts AS (
    SELECT
        product_id,
        SUM(debt_remaining_int)::INTEGER AS current_remaining,
        SUM(CASE WHEN debt_remaining_int = 1 AND severity = 'CRITICAL'
                 THEN 1 ELSE 0 END)::INTEGER AS current_critical,
        SUM(CASE WHEN debt_remaining_int = 1 AND severity = 'HIGH'
                 THEN 1 ELSE 0 END)::INTEGER AS current_high,
        SUM(debt_fixed_current_int)::INTEGER AS fixed_current
    FROM custom_ts_secure_development.security_debt_current
    GROUP BY product_id
),
fixed_velocity AS (
    SELECT
        product_id,
        CASE
            WHEN MIN(dt) <= CURRENT_DATE - 27
            THEN SUM(
                CASE WHEN dt >= CURRENT_DATE - 27
                     THEN fixed_cnt ELSE 0 END
            ) / 28.0
            ELSE NULL
        END AS daily_velocity_28d,
        CASE
            WHEN MIN(dt) <= CURRENT_DATE - 89
            THEN SUM(
                CASE WHEN dt >= CURRENT_DATE - 89
                     THEN fixed_cnt ELSE 0 END
            ) / 90.0
            ELSE NULL
        END AS daily_velocity_90d
    FROM custom_ts_secure_development.security_debt_daily
    GROUP BY product_id
),
base AS (
    SELECT
        i.product_id,
        i.product_name,
        i.initial_total,
        i.initial_critical,
        i.initial_high,
        COALESCE(c.current_remaining, i.initial_total) AS current_remaining,
        COALESCE(c.current_critical, i.initial_critical) AS current_critical,
        COALESCE(c.current_high, i.initial_high) AS current_high,
        COALESCE(c.fixed_current, 0) AS fixed_current,
        v.daily_velocity_28d,
        v.daily_velocity_90d,
        (DATE '2027-01-01' - CURRENT_DATE)::INTEGER AS days_to_deadline
    FROM initial_counts i
    LEFT JOIN current_counts c
      ON c.product_id = i.product_id
    LEFT JOIN fixed_velocity v
      ON v.product_id = i.product_id
),
calculated AS (
    SELECT
        b.*,
        CASE WHEN days_to_deadline > 0
             THEN current_remaining / days_to_deadline::NUMERIC
             ELSE NULL END AS required_daily_velocity
    FROM base b
)
SELECT
    product_id,
    product_name,
    initial_total,
    initial_critical,
    initial_high,
    current_remaining,
    current_critical,
    current_high,
    fixed_current,
    fixed_current AS resolved_total,
    CASE WHEN initial_total > 0
         THEN ROUND(100.0 * fixed_current / initial_total, 2)
         ELSE 0 END AS progress_percent,
    NULL::INTEGER AS remaining_28d_ago,
    NULL::INTEGER AS remaining_90d_ago,
    daily_velocity_28d,
    daily_velocity_90d,
    daily_velocity_28d * 14.0 AS velocity_per_sprint_28d,
    daily_velocity_90d * 14.0 AS velocity_per_sprint_90d,
    days_to_deadline,
    required_daily_velocity,
    required_daily_velocity * 14.0 AS required_per_sprint,
    LEAST(
        initial_total,
        GREATEST(
            0,
            ROUND(
                current_remaining
                - COALESCE(daily_velocity_90d, 0)
                  * GREATEST(days_to_deadline, 0)
            )::INTEGER
        )
    ) AS forecast_remaining_at_deadline,
    CASE
        WHEN daily_velocity_90d IS NULL THEN 'NO DATA'
        WHEN days_to_deadline <= 0 THEN 'DEADLINE PASSED'
        WHEN daily_velocity_90d >= required_daily_velocity THEN 'ON TRACK'
        ELSE 'AT RISK'
    END AS forecast_status
FROM calculated;

CREATE OR REPLACE VIEW custom_ts_secure_development.effectiveness_by_product AS
WITH flow_28d AS (
    SELECT
        product_id,
        SUM(new_cnt + recurrent_cnt + reopened_cnt)::INTEGER AS inflow_28d,
        SUM(fixed_cnt)::INTEGER AS outflow_28d
    FROM custom_ts_secure_development.issues_daily_flow
    WHERE dt >= CURRENT_DATE - 27
    GROUP BY product_id
),
mttr AS (
    SELECT
        product_id,
        AVG(avg_mttr_days) AS avg_mttr_days,
        AVG(median_mttr_days) AS median_mttr_days
    FROM custom_ts_secure_development.mttr_by_product
    GROUP BY product_id
)
SELECT
    p.product_id,
    p.product_name,
    COALESCE(f.inflow_28d, 0) AS inflow_28d,
    COALESCE(f.outflow_28d, 0) AS outflow_28d,
    COALESCE(f.outflow_28d, 0) - COALESCE(f.inflow_28d, 0)
        AS net_reduction_28d,
    m.avg_mttr_days,
    m.median_mttr_days
FROM custom_ts_secure_development.dim_product p
LEFT JOIN flow_28d f
  ON f.product_id = p.product_id
LEFT JOIN mttr m
  ON m.product_id = p.product_id;

COMMIT;
