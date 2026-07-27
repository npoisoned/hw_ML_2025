-- AppSec Greenplum PATCH v1.9
-- Добавляет в исключения:
--   INSAPP_OLD  07f53607-7df1-42ae-b21b-b64d4c6e375e
--   UNUSED      f64b6ea9-a489-4129-92fe-dc459ce31e1f
--
-- Уже исключались:
--   TEST
--   Default product
--
-- Сырые таблицы не удаляются и не изменяются.
-- Обновляются только аналитические VIEW.
-- Python повторно запускать сразу после patch не обязательно.

BEGIN;

CREATE OR REPLACE VIEW custom_ts_secure_development.repository_product_current AS
SELECT *
FROM custom_ts_secure_development.repository_product_current_all
WHERE product_id IS NOT NULL
  AND product_id NOT IN (
      'd569ed52-b01f-4222-948b-705b008ae64a',
      '1a16d04d-cd14-4894-b887-4ba7465c26aa',
      '07f53607-7df1-42ae-b21b-b64d4c6e375e',
      'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
  );

CREATE OR REPLACE VIEW custom_ts_secure_development.dim_product AS
WITH latest_snapshot AS (
    SELECT MAX(ts) AS max_ts
    FROM custom_ts_secure_development.products_snapshot
),
ranked AS (
    SELECT
        p.*,
        ROW_NUMBER() OVER (
            PARTITION BY p.product_id
            ORDER BY p.ts DESC, p.product_name
        ) AS rn
    FROM custom_ts_secure_development.products_snapshot p
    JOIN latest_snapshot l
      ON l.max_ts = p.ts
    WHERE NULLIF(BTRIM(p.product_id), '') IS NOT NULL
)
SELECT
    product_id,
    product_name,
    product_slug,
    criticality,
    repos_count
FROM ranked
WHERE rn = 1
  AND product_id NOT IN (
      'd569ed52-b01f-4222-948b-705b008ae64a',
      '1a16d04d-cd14-4894-b887-4ba7465c26aa',
      '07f53607-7df1-42ae-b21b-b64d4c6e375e',
      'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
  );

CREATE OR REPLACE VIEW custom_ts_secure_development.issues_daily_flow_global AS
SELECT
    e.event_ts::DATE AS dt,
    e.severity,
    COUNT(DISTINCT CASE WHEN e.new_status = 'new_issue'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS new_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'recurrent'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS recurrent_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'reopened'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS reopened_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'confirmed'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS confirmed_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'risk_accepted'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS risk_accepted_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'security-debt'
                        THEN e.issue_id ELSE NULL END)::INTEGER
        AS security_debt_entered_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'fixed'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS fixed_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'false_positive'
                        THEN e.issue_id ELSE NULL END)::INTEGER
        AS false_positive_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'exclusion'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS exclusion_cnt
FROM custom_ts_secure_development.issue_status_events e
WHERE e.is_baseline = FALSE
  AND e.new_status <> 'check_required'
  AND EXISTS (
      SELECT 1
      FROM custom_ts_secure_development.issue_status_event_product ep
      WHERE ep.event_id = e.event_id
        AND ep.product_id NOT IN (
            'd569ed52-b01f-4222-948b-705b008ae64a',
            '1a16d04d-cd14-4894-b887-4ba7465c26aa',
            '07f53607-7df1-42ae-b21b-b64d4c6e375e',
            'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
        )
  )
GROUP BY e.event_ts::DATE, e.severity;

CREATE OR REPLACE VIEW custom_ts_secure_development.issues_daily_flow AS
SELECT
    e.event_ts::DATE AS dt,
    ep.product_id,
    MAX(ep.product_name) AS product_name,
    e.severity,
    COUNT(DISTINCT CASE WHEN e.new_status = 'new_issue'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS new_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'recurrent'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS recurrent_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'reopened'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS reopened_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'confirmed'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS confirmed_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'risk_accepted'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS risk_accepted_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'security-debt'
                        THEN e.issue_id ELSE NULL END)::INTEGER
        AS security_debt_entered_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'fixed'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS fixed_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'false_positive'
                        THEN e.issue_id ELSE NULL END)::INTEGER
        AS false_positive_cnt,
    COUNT(DISTINCT CASE WHEN e.new_status = 'exclusion'
                        THEN e.issue_id ELSE NULL END)::INTEGER AS exclusion_cnt
FROM custom_ts_secure_development.issue_status_events e
JOIN custom_ts_secure_development.issue_status_event_product ep
  ON ep.event_id = e.event_id
WHERE e.is_baseline = FALSE
  AND e.new_status <> 'check_required'
  AND ep.product_id NOT IN (
      'd569ed52-b01f-4222-948b-705b008ae64a',
      '1a16d04d-cd14-4894-b887-4ba7465c26aa',
      '07f53607-7df1-42ae-b21b-b64d4c6e375e',
      'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
  )
GROUP BY e.event_ts::DATE, ep.product_id, e.severity;

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
      '1a16d04d-cd14-4894-b887-4ba7465c26aa',
      '07f53607-7df1-42ae-b21b-b64d4c6e375e',
      'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
  )
GROUP BY
    e.event_ts::DATE,
    ep.product_id,
    e.repository_id,
    e.severity;

CREATE OR REPLACE VIEW custom_ts_secure_development.mttr_cycles AS
WITH cycle_starts AS (
    SELECT
        e.event_id AS start_event_id,
        e.issue_id,
        e.issue_title,
        e.repository_id,
        e.repository,
        e.repository_slug,
        e.severity,
        e.scanner,
        COALESCE(e.created_at, e.event_ts) AS cycle_started_at
    FROM custom_ts_secure_development.issue_status_events e
    WHERE e.new_status IN (
        'new_issue',
        'recurrent',
        'confirmed',
        'risk_accepted',
        'reopened',
        'security-debt'
    )
      AND (
          e.previous_status IS NULL
          OR e.previous_status IN (
              'fixed',
              'false_positive',
              'exclusion',
              'archive',
              'not-applicable',
              'wont-fix'
          )
          OR e.new_status = 'reopened'
      )
      AND EXISTS (
          SELECT 1
          FROM custom_ts_secure_development.issue_status_event_product ep
          WHERE ep.event_id = e.event_id
            AND ep.product_id NOT IN (
                'd569ed52-b01f-4222-948b-705b008ae64a',
                '1a16d04d-cd14-4894-b887-4ba7465c26aa',
                '07f53607-7df1-42ae-b21b-b64d4c6e375e',
                'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
            )
      )
),
fixed_after_start AS (
    SELECT
        s.start_event_id,
        MIN(f.event_ts) AS fixed_at
    FROM cycle_starts s
    JOIN custom_ts_secure_development.issue_status_events f
      ON f.issue_id = s.issue_id
     AND f.new_status = 'fixed'
     AND f.event_ts >= s.cycle_started_at
    GROUP BY s.start_event_id
)
SELECT
    s.start_event_id,
    s.issue_id,
    s.issue_title,
    s.repository_id,
    s.repository,
    s.repository_slug,
    s.severity,
    s.scanner,
    s.cycle_started_at,
    f.fixed_at,
    EXTRACT(EPOCH FROM (f.fixed_at - s.cycle_started_at)) / 86400.0
        AS mttr_days
FROM cycle_starts s
JOIN fixed_after_start f
  ON f.start_event_id = s.start_event_id
WHERE f.fixed_at > s.cycle_started_at;

CREATE OR REPLACE VIEW custom_ts_secure_development.mttr_by_product AS
SELECT
    ep.product_id,
    MAX(ep.product_name) AS product_name,
    c.severity,
    COUNT(*)::INTEGER AS fixed_cycles,
    AVG(c.mttr_days) AS avg_mttr_days,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY c.mttr_days)
        AS median_mttr_days,
    MIN(c.mttr_days) AS min_mttr_days,
    MAX(c.mttr_days) AS max_mttr_days
FROM custom_ts_secure_development.mttr_cycles c
JOIN custom_ts_secure_development.issue_status_event_product ep
  ON ep.event_id = c.start_event_id
WHERE ep.product_id NOT IN (
    'd569ed52-b01f-4222-948b-705b008ae64a',
    '1a16d04d-cd14-4894-b887-4ba7465c26aa',
    '07f53607-7df1-42ae-b21b-b64d4c6e375e',
    'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
)
GROUP BY ep.product_id, c.severity;

CREATE OR REPLACE VIEW custom_ts_secure_development.issues_daily_stock_summary AS
SELECT
    dt,
    product_id,
    MAX(product_name) AS product_name,
    SUM(CASE WHEN status IN (
                    'new_issue', 'recurrent', 'confirmed',
                    'risk_accepted', 'reopened', 'security-debt'
                ) THEN cnt ELSE 0 END)::INTEGER AS open_total,
    SUM(CASE WHEN status IN (
                    'new_issue', 'recurrent', 'confirmed',
                    'risk_accepted', 'reopened'
                ) THEN cnt ELSE 0 END)::INTEGER AS open_current_flow,
    SUM(CASE WHEN status = 'security-debt'
             THEN cnt ELSE 0 END)::INTEGER AS open_security_debt,
    SUM(CASE WHEN status IN (
                    'new_issue', 'recurrent', 'confirmed',
                    'risk_accepted', 'reopened', 'security-debt'
                ) AND severity = 'CRITICAL'
             THEN cnt ELSE 0 END)::INTEGER AS open_critical,
    SUM(CASE WHEN status IN (
                    'new_issue', 'recurrent', 'confirmed',
                    'risk_accepted', 'reopened', 'security-debt'
                ) AND severity = 'HIGH'
             THEN cnt ELSE 0 END)::INTEGER AS open_high,
    SUM(CASE WHEN status IN ('confirmed', 'reopened')
             THEN cnt ELSE 0 END)::INTEGER AS red_zone_total
FROM custom_ts_secure_development.issues_daily_stock
WHERE status <> 'check_required'
  AND product_id NOT IN (
      'd569ed52-b01f-4222-948b-705b008ae64a',
      '1a16d04d-cd14-4894-b887-4ba7465c26aa',
      '07f53607-7df1-42ae-b21b-b64d4c6e375e',
      'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
  )
GROUP BY dt, product_id;

CREATE OR REPLACE VIEW custom_ts_secure_development.security_debt_current AS
SELECT
    c.issue_id,
    c.issue_title,
    c.issue_url,
    c.repository_id,
    c.repository,
    c.repository_slug,
    c.severity,
    c.entered_at,
    cp.product_id,
    cp.product_name,
    i.status AS current_status,
    i.status_display AS current_status_display,
    CASE
        WHEN i.status IN (
            'fixed',
            'false_positive',
            'exclusion',
            'archive',
            'not-applicable',
            'wont-fix'
        ) THEN 0
        ELSE 1
    END AS debt_remaining_int,
    CASE WHEN i.status = 'fixed'
         THEN 1 ELSE 0 END AS debt_fixed_current_int
FROM custom_ts_secure_development.security_debt_cohort c
JOIN custom_ts_secure_development.security_debt_cohort_product cp
  ON cp.issue_id = c.issue_id
LEFT JOIN custom_ts_secure_development.issues_current_all i
  ON i.issue_id = c.issue_id
WHERE cp.product_id NOT IN (
      'd569ed52-b01f-4222-948b-705b008ae64a',
      '1a16d04d-cd14-4894-b887-4ba7465c26aa',
      '07f53607-7df1-42ae-b21b-b64d4c6e375e',
      'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
  )
  AND COALESCE(i.status, '') <> 'check_required';

CREATE OR REPLACE VIEW custom_ts_secure_development.security_debt_fixed_events AS
SELECT
    e.event_id,
    e.event_ts,
    e.issue_id,
    e.issue_title,
    e.repository_id,
    e.repository,
    e.repository_slug,
    e.severity,
    ep.product_id,
    ep.product_name
FROM custom_ts_secure_development.issue_status_events e
JOIN custom_ts_secure_development.security_debt_cohort c
  ON c.issue_id = e.issue_id
JOIN custom_ts_secure_development.issue_status_event_product ep
  ON ep.event_id = e.event_id
WHERE e.new_status = 'fixed'
  AND e.is_baseline = FALSE
  AND e.event_ts >= c.entered_at
  AND ep.product_id NOT IN (
      'd569ed52-b01f-4222-948b-705b008ae64a',
      '1a16d04d-cd14-4894-b887-4ba7465c26aa',
      '07f53607-7df1-42ae-b21b-b64d4c6e375e',
      'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
  );

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
          '1a16d04d-cd14-4894-b887-4ba7465c26aa',
          '07f53607-7df1-42ae-b21b-b64d4c6e375e',
          'f64b6ea9-a489-4129-92fe-dc459ce31e1f'
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

COMMIT;
