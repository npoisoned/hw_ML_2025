-- AppSec Greenplum PATCH v1.7
-- Исключает дефекты TEST / Default product также из global dashboard.
-- Сырые таблицы не изменяет. Python перезапускать не нужно.
-- Только CREATE OR REPLACE VIEW.

BEGIN;

CREATE OR REPLACE VIEW custom_ts_secure_development.issues_current AS
SELECT i.*
FROM custom_ts_secure_development.issues_current_all i
WHERE i.status <> 'check_required'
  AND i.repository_id IS NOT NULL
  AND EXISTS (
      SELECT 1
      FROM custom_ts_secure_development.repository_product_current rp
      WHERE rp.repository_id = i.repository_id
  );

CREATE OR REPLACE VIEW custom_ts_secure_development.issues_unmapped_current AS
SELECT i.*
FROM custom_ts_secure_development.issues_current_all i
WHERE i.status <> 'check_required'
  AND (
      i.repository_id IS NULL
      OR NOT EXISTS (
          SELECT 1
          FROM custom_ts_secure_development.repository_product_current rp
          WHERE rp.repository_id = i.repository_id
      )
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
            '1a16d04d-cd14-4894-b887-4ba7465c26aa'
        )
  )
GROUP BY e.event_ts::DATE, e.severity;

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
                '1a16d04d-cd14-4894-b887-4ba7465c26aa'
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

COMMIT;
