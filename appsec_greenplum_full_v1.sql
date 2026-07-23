-- =====================================================================
-- AppSec / Hexway Vampy -> Greenplum -> FineBI
-- Полная миграция аналитического слоя без удаления issues_snapshot
-- и products_snapshot.
--
-- Запуск: DBeaver -> Execute SQL Script
--
-- ВАЖНО:
-- 1. Скрипт не удаляет исторические снапшоты.
-- 2. Он создаёт/пересоздаёт аналитические views и служебные таблицы.
-- 3. После него Python-перекладчик нужно обновить, чтобы он:
--    - писал issue_title, issue_url, status_changed_at;
--    - добавлял реальные смены статусов в issue_status_events;
--    - поддерживал security_debt_cohort;
--    - обновлял issues_daily_stock и security_debt_daily.
-- 4. До обновления Python скрипт выполнит первичный backfill из накопленных
--    issues_snapshot.
-- =====================================================================

BEGIN;

SET TIME ZONE 'Europe/Moscow';

CREATE SCHEMA IF NOT EXISTS custom_ts_secure_development;

-- =====================================================================
-- 1. ОСНОВНЫЕ ТАБЛИЦЫ
-- =====================================================================

CREATE TABLE IF NOT EXISTS custom_ts_secure_development.issues_snapshot (
    ts               TIMESTAMP,
    issue_id         TEXT,
    product_id       TEXT,
    product_name     TEXT,
    repository       TEXT,
    severity         TEXT,
    status           TEXT,
    scanner          TEXT,
    is_security_debt BOOLEAN,
    is_active        BOOLEAN,
    created_at       TIMESTAMP,
    updated_at       TIMESTAMP,
    ra_deadline      TIMESTAMP
)
DISTRIBUTED BY (issue_id);

CREATE TABLE IF NOT EXISTS custom_ts_secure_development.products_snapshot (
    ts           TIMESTAMP,
    product_id   TEXT,
    product_name TEXT,
    repos_count  INTEGER
)
DISTRIBUTED BY (product_id);

-- Добавляем поля, необходимые для макетов FineBI.
DO LANGUAGE plpgsql $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'issue_title'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN issue_title TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'issue_url'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN issue_url TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'status_changed_at'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN status_changed_at TIMESTAMP;
    END IF;
END
$$;


-- =====================================================================
-- 2. СЛУЖЕБНЫЕ ТАБЛИЦЫ ДЛЯ АНАЛИТИКИ
-- =====================================================================

-- Одна строка = одна зафиксированная смена статуса.
CREATE TABLE IF NOT EXISTS custom_ts_secure_development.issue_status_events (
    event_id          TEXT,
    event_ts          TIMESTAMP NOT NULL,

    issue_id          TEXT NOT NULL,
    issue_title       TEXT,
    issue_url         TEXT,

    product_id        TEXT,
    product_name      TEXT,
    repository        TEXT,

    severity          TEXT,
    scanner           TEXT,

    previous_status   TEXT,
    new_status        TEXT NOT NULL,

    created_at        TIMESTAMP,
    ra_deadline       TIMESTAMP,

    -- Первая известная строка по issue из старой истории.
    -- Не считается новым поступлением.
    is_baseline       BOOLEAN DEFAULT FALSE
)
DISTRIBUTED BY (issue_id);


-- Историческая когорта Security Debt.
-- Дефект остаётся в ней даже после смены текущего статуса.
CREATE TABLE IF NOT EXISTS custom_ts_secure_development.security_debt_cohort (
    issue_id          TEXT NOT NULL,
    issue_title       TEXT,
    issue_url         TEXT,

    product_id        TEXT,
    product_name      TEXT,
    repository        TEXT,
    severity          TEXT,

    entered_at        TIMESTAMP NOT NULL
)
DISTRIBUTED BY (issue_id);


-- Остаток по статусам на конец каждого дня.
CREATE TABLE IF NOT EXISTS custom_ts_secure_development.issues_daily_stock (
    dt               DATE,
    product_id       TEXT,
    product_name     TEXT,
    severity         TEXT,
    status           TEXT,
    scanner          TEXT,
    is_security_debt BOOLEAN,
    cnt              INTEGER
)
DISTRIBUTED BY (product_id);


-- Дневная история Security Debt.
CREATE TABLE IF NOT EXISTS custom_ts_secure_development.security_debt_daily (
    dt              DATE,
    product_id      TEXT,
    product_name    TEXT,
    severity        TEXT,
    debt_remaining  INTEGER,
    fixed_cnt       INTEGER
)
DISTRIBUTED BY (product_id);


-- Разграничение доступа FineBI:
-- одна учётная запись может иметь несколько разрешённых продуктов.
CREATE TABLE IF NOT EXISTS custom_ts_secure_development.user_product_access (
    user_login  TEXT NOT NULL,
    product_id  TEXT NOT NULL
)
DISTRIBUTED BY (user_login);


-- =====================================================================
-- 3. УДАЛЕНИЕ СТАРЫХ / КОНФЛИКТУЮЩИХ VIEWS
-- =====================================================================

DROP VIEW IF EXISTS custom_ts_secure_development.security_debt_chart CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.security_debt_summary_by_product CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.security_debt_fixed_events CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.security_debt_current CASCADE;

DROP VIEW IF EXISTS custom_ts_secure_development.repository_daily_flow CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.mttr_by_product CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.mttr_cycles CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_daily_flow CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_daily_stock_summary CASCADE;

DROP VIEW IF EXISTS custom_ts_secure_development.products_comparison_current CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.products_full CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.products_current CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.appsec_summary CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.appsec_kpi_by_product CASCADE;

DROP VIEW IF EXISTS custom_ts_secure_development.red_zone CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_unmapped_current CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_current CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.dim_product CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_snapshot_normalized CASCADE;

DROP VIEW IF EXISTS custom_ts_secure_development.security_debt_progress CASCADE;
DROP VIEW IF EXISTS custom_ts_secure_development.effectiveness_by_product CASCADE;


-- =====================================================================
-- 4. НОРМАЛИЗОВАННЫЙ СЛОЙ СНАПШОТОВ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.issues_snapshot_normalized AS
SELECT
    ts,
    issue_id,
    issue_title,
    issue_url,

    NULLIF(BTRIM(product_id), '')                  AS product_id,
    NULLIF(BTRIM(product_name), '')                AS product_name,
    NULLIF(BTRIM(repository), '')                  AS repository,

    UPPER(BTRIM(COALESCE(severity, '')))           AS severity,
    LOWER(BTRIM(COALESCE(status, '')))             AS status,
    NULLIF(BTRIM(scanner), '')                     AS scanner,

    is_security_debt                               AS source_is_security_debt,
    is_active                                      AS source_is_active,

    created_at,
    status_changed_at,
    updated_at,
    ra_deadline
FROM custom_ts_secure_development.issues_snapshot;


-- =====================================================================
-- 5. ТЕКУЩИЙ СРЕЗ: ОДНА СТРОКА = ОДИН ISSUE
-- =====================================================================

CREATE VIEW custom_ts_secure_development.issues_current AS
WITH latest_snapshot AS (
    SELECT MAX(ts) AS max_ts
    FROM custom_ts_secure_development.issues_snapshot_normalized
),
deduplicated AS (
    SELECT
        i.*,
        ROW_NUMBER() OVER (
            PARTITION BY i.issue_id
            ORDER BY
                COALESCE(
                    i.status_changed_at,
                    i.updated_at,
                    i.created_at,
                    i.ts
                ) DESC,
                i.repository NULLS LAST
        ) AS rn
    FROM custom_ts_secure_development.issues_snapshot_normalized i
    JOIN latest_snapshot l
      ON i.ts = l.max_ts
)
SELECT
    ts,
    issue_id,
    issue_title,
    issue_url,

    product_id,
    product_name,
    repository,

    severity,
    status,
    scanner,

    created_at,
    status_changed_at,
    updated_at,
    ra_deadline,

    1 AS issue_cnt,

    -- Все нерешённые Critical / High, включая Security Debt.
    CASE
        WHEN status IN (
            'new_issue',
            'recurrent',
            'confirmed',
            'risk_accepted',
            'reopened',
            'security-debt'
        )
        THEN 1 ELSE 0
    END AS is_unresolved_int,

    -- Новый поток без исторического Security Debt.
    CASE
        WHEN status IN (
            'new_issue',
            'recurrent',
            'confirmed',
            'risk_accepted',
            'reopened'
        )
        THEN 1 ELSE 0
    END AS is_current_flow_int,

    CASE
        WHEN status = 'security-debt'
        THEN 1 ELSE 0
    END AS is_security_debt_current_int,

    -- FineBI ничего не переводит и не рассчитывает за Vampy.
    -- Красная зона строится по фактическому текущему статусу.
    CASE
        WHEN status IN ('confirmed', 'reopened')
         AND severity IN ('CRITICAL', 'HIGH')
        THEN 1 ELSE 0
    END AS is_red_zone_int,

    CASE
        WHEN status = 'confirmed'
         AND severity IN ('CRITICAL', 'HIGH')
        THEN 1 ELSE 0
    END AS is_confirmed_int,

    CASE
        WHEN status = 'reopened'
         AND severity IN ('CRITICAL', 'HIGH')
        THEN 1 ELSE 0
    END AS is_reopened_int,

    CASE
        WHEN status = 'risk_accepted'
        THEN 1 ELSE 0
    END AS is_risk_accepted_int,

    CASE
        WHEN status = 'fixed'
        THEN 1 ELSE 0
    END AS is_fixed_current_int,

    -- Пока Python не передаёт status_changed_at, используется fallback.
    FLOOR(
        EXTRACT(
            EPOCH FROM (
                NOW() -
                COALESCE(
                    status_changed_at,
                    updated_at,
                    created_at,
                    ts
                )
            )
        ) / 86400.0
    )::INTEGER AS days_in_status,

    -- Дата только визуализируется. FineBI не управляет SLA.
    CASE
        WHEN status = 'risk_accepted'
         AND ra_deadline IS NOT NULL
        THEN CEIL(
            EXTRACT(EPOCH FROM (ra_deadline - NOW())) / 86400.0
        )::INTEGER
        ELSE NULL
    END AS days_to_ra_deadline,

    CASE status
        WHEN 'new_issue'      THEN 'New'
        WHEN 'recurrent'      THEN 'Recurrent'
        WHEN 'confirmed'      THEN 'Confirmed'
        WHEN 'risk_accepted'  THEN 'Risk Accepted'
        WHEN 'reopened'       THEN 'Reopened'
        WHEN 'security-debt'  THEN 'Security Debt'
        WHEN 'fixed'          THEN 'Fixed'
        WHEN 'false_positive' THEN 'False Positive'
        WHEN 'exclusion'      THEN 'Exclusion'
        ELSE status
    END AS status_display,

    -- Укрупнённое поле для donut.
    CASE
        WHEN status IN ('new_issue', 'recurrent')
            THEN 'New / Recurrent'
        WHEN status = 'confirmed'
            THEN 'Confirmed'
        WHEN status = 'risk_accepted'
            THEN 'Risk Accepted'
        WHEN status = 'reopened'
            THEN 'Reopened'
        WHEN status = 'security-debt'
            THEN 'Security Debt'
        WHEN status = 'fixed'
            THEN 'Fixed'
        WHEN status = 'false_positive'
            THEN 'False Positive'
        WHEN status = 'exclusion'
            THEN 'Exclusion'
        ELSE status
    END AS status_group,

    CASE
        WHEN status = 'confirmed' AND severity = 'CRITICAL' THEN 1
        WHEN status = 'reopened'  AND severity = 'CRITICAL' THEN 2
        WHEN status = 'confirmed' AND severity = 'HIGH'     THEN 3
        WHEN status = 'reopened'  AND severity = 'HIGH'     THEN 4
        WHEN status = 'risk_accepted'
             AND severity = 'CRITICAL'                      THEN 5
        WHEN status IN ('new_issue', 'recurrent')
             AND severity = 'CRITICAL'                      THEN 6
        WHEN status = 'security-debt'
             AND severity = 'CRITICAL'                      THEN 7
        WHEN status = 'risk_accepted'
             AND severity = 'HIGH'                          THEN 20
        WHEN status IN ('new_issue', 'recurrent')
             AND severity = 'HIGH'                          THEN 21
        WHEN status = 'security-debt'
             AND severity = 'HIGH'                          THEN 22
        ELSE 99
    END AS priority_order

FROM deduplicated
WHERE rn = 1
  AND severity IN ('CRITICAL', 'HIGH');


-- Отдельный технический контроль: issues без product_id.
CREATE VIEW custom_ts_secure_development.issues_unmapped_current AS
SELECT *
FROM custom_ts_secure_development.issues_current
WHERE product_id IS NULL;


-- =====================================================================
-- 6. СПРАВОЧНИК ПРОДУКТОВ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.dim_product AS
WITH latest_snapshot AS (
    SELECT MAX(ts) AS max_ts
    FROM custom_ts_secure_development.products_snapshot
),
deduplicated AS (
    SELECT
        p.*,
        ROW_NUMBER() OVER (
            PARTITION BY p.product_id
            ORDER BY p.ts DESC, p.product_name
        ) AS rn
    FROM custom_ts_secure_development.products_snapshot p
    JOIN latest_snapshot l
      ON p.ts = l.max_ts
    WHERE NULLIF(BTRIM(p.product_id), '') IS NOT NULL
)
SELECT
    product_id,
    product_name,
    repos_count
FROM deduplicated
WHERE rn = 1;


-- =====================================================================
-- 7. КРАСНАЯ ЗОНА
-- =====================================================================

CREATE VIEW custom_ts_secure_development.red_zone AS
SELECT
    issue_id,
    issue_title,
    issue_url,

    product_id,
    product_name,
    repository,

    severity,
    status,
    status_display,
    scanner,

    created_at,
    status_changed_at,
    updated_at,
    ra_deadline,

    days_in_status,
    priority_order
FROM custom_ts_secure_development.issues_current
WHERE product_id IS NOT NULL
  AND is_red_zone_int = 1;


-- =====================================================================
-- 8. ТЕКУЩИЕ KPI ПО ПРОДУКТАМ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.appsec_kpi_by_product AS
WITH current_stats AS (
    SELECT
        product_id,

        SUM(is_unresolved_int) AS open_total,

        SUM(
            CASE WHEN is_unresolved_int = 1
                  AND severity = 'CRITICAL'
                 THEN 1 ELSE 0 END
        ) AS open_total_critical,

        SUM(
            CASE WHEN is_unresolved_int = 1
                  AND severity = 'HIGH'
                 THEN 1 ELSE 0 END
        ) AS open_total_high,

        SUM(is_current_flow_int) AS open_current_flow,

        SUM(
            CASE WHEN is_current_flow_int = 1
                  AND severity = 'CRITICAL'
                 THEN 1 ELSE 0 END
        ) AS open_critical_current_flow,

        SUM(
            CASE WHEN is_current_flow_int = 1
                  AND severity = 'HIGH'
                 THEN 1 ELSE 0 END
        ) AS open_high_current_flow,

        SUM(is_security_debt_current_int)
            AS security_debt_total,

        SUM(
            CASE WHEN is_security_debt_current_int = 1
                  AND severity = 'CRITICAL'
                 THEN 1 ELSE 0 END
        ) AS security_debt_critical,

        SUM(
            CASE WHEN is_security_debt_current_int = 1
                  AND severity = 'HIGH'
                 THEN 1 ELSE 0 END
        ) AS security_debt_high,

        SUM(is_red_zone_int)
            AS red_zone_total,

        SUM(is_confirmed_int)
            AS confirmed_total,

        SUM(is_reopened_int)
            AS reopened_total,

        SUM(is_risk_accepted_int)
            AS risk_accepted_total,

        MIN(
            CASE
                WHEN status = 'risk_accepted'
                THEN ra_deadline
                ELSE NULL
            END
        ) AS nearest_ra_deadline,

        SUM(
            CASE
                WHEN status = 'risk_accepted'
                 AND ra_deadline IS NOT NULL
                 AND ra_deadline >= NOW()
                 AND ra_deadline < NOW() + INTERVAL '7 days'
                THEN 1 ELSE 0
            END
        ) AS risk_accepted_due_7d,

        SUM(
            CASE
                WHEN status = 'risk_accepted'
                 AND ra_deadline IS NOT NULL
                 AND ra_deadline >= NOW()
                 AND ra_deadline < NOW() + INTERVAL '14 days'
                THEN 1 ELSE 0
            END
        ) AS risk_accepted_due_14d

    FROM custom_ts_secure_development.issues_current
    WHERE product_id IS NOT NULL
    GROUP BY product_id
),
last_load AS (
    SELECT MAX(ts) AS last_snapshot_ts
    FROM custom_ts_secure_development.issues_snapshot
)
SELECT
    d.product_id,
    d.product_name,
    d.repos_count,

    COALESCE(s.open_total, 0)                       AS open_total,
    COALESCE(s.open_total_critical, 0)              AS open_total_critical,
    COALESCE(s.open_total_high, 0)                  AS open_total_high,

    COALESCE(s.open_current_flow, 0)                AS open_current_flow,
    COALESCE(s.open_critical_current_flow, 0)       AS open_critical_current_flow,
    COALESCE(s.open_high_current_flow, 0)           AS open_high_current_flow,

    COALESCE(s.security_debt_total, 0)              AS security_debt_total,
    COALESCE(s.security_debt_critical, 0)           AS security_debt_critical,
    COALESCE(s.security_debt_high, 0)               AS security_debt_high,

    COALESCE(s.red_zone_total, 0)                   AS red_zone_total,
    COALESCE(s.confirmed_total, 0)                  AS confirmed_total,
    COALESCE(s.reopened_total, 0)                   AS reopened_total,

    COALESCE(s.risk_accepted_total, 0)              AS risk_accepted_total,
    s.nearest_ra_deadline,
    COALESCE(s.risk_accepted_due_7d, 0)             AS risk_accepted_due_7d,
    COALESCE(s.risk_accepted_due_14d, 0)            AS risk_accepted_due_14d,

    l.last_snapshot_ts

FROM custom_ts_secure_development.dim_product d
CROSS JOIN last_load l
LEFT JOIN current_stats s
       ON s.product_id = d.product_id;


CREATE VIEW custom_ts_secure_development.products_current AS
SELECT
    *,
    CASE
        WHEN red_zone_total > 0 THEN 1
        ELSE 0
    END AS has_red_zone
FROM custom_ts_secure_development.appsec_kpi_by_product;


CREATE VIEW custom_ts_secure_development.products_comparison_current AS
SELECT
    product_id,
    product_name,
    repos_count,

    open_total,
    open_total_critical,
    open_total_high,

    open_current_flow,
    open_critical_current_flow,
    open_high_current_flow,

    security_debt_total,
    security_debt_critical,
    security_debt_high,

    risk_accepted_total,
    nearest_ra_deadline,
    risk_accepted_due_7d,
    risk_accepted_due_14d,

    confirmed_total,
    reopened_total,
    red_zone_total,
    has_red_zone,

    last_snapshot_ts
FROM custom_ts_secure_development.products_current;


-- =====================================================================
-- 9. ПЕРВИЧНЫЙ BACKFILL СОБЫТИЙ СТАТУСОВ
-- =====================================================================
-- Первая известная строка каждого issue помечается is_baseline = TRUE
-- и не считается поступлением в issues_daily_flow.

WITH snap_dedup AS (
    SELECT *
    FROM (
        SELECT
            s.*,
            ROW_NUMBER() OVER (
                PARTITION BY s.issue_id, s.ts
                ORDER BY
                    COALESCE(
                        s.status_changed_at,
                        s.updated_at,
                        s.created_at,
                        s.ts
                    ) DESC,
                    s.repository NULLS LAST
            ) AS rn
        FROM custom_ts_secure_development.issues_snapshot_normalized s
        WHERE s.issue_id IS NOT NULL
          AND s.severity IN ('CRITICAL', 'HIGH')
    ) x
    WHERE rn = 1
),
ordered AS (
    SELECT
        s.*,
        LAG(s.status) OVER (
            PARTITION BY s.issue_id
            ORDER BY s.ts
        ) AS previous_status
    FROM snap_dedup s
),
transitions AS (
    SELECT
        MD5(
            COALESCE(issue_id, '')
            || '|'
            || TO_CHAR(ts, 'YYYY-MM-DD HH24:MI:SS.US')
            || '|'
            || COALESCE(previous_status, '')
            || '|'
            || COALESCE(status, '')
        ) AS event_id,

        ts AS event_ts,

        issue_id,
        issue_title,
        issue_url,

        product_id,
        product_name,
        repository,

        severity,
        scanner,

        previous_status,
        status AS new_status,

        created_at,
        ra_deadline,

        CASE
            WHEN previous_status IS NULL THEN TRUE
            ELSE FALSE
        END AS is_baseline

    FROM ordered
    WHERE previous_status IS DISTINCT FROM status
)
INSERT INTO custom_ts_secure_development.issue_status_events (
    event_id,
    event_ts,

    issue_id,
    issue_title,
    issue_url,

    product_id,
    product_name,
    repository,

    severity,
    scanner,

    previous_status,
    new_status,

    created_at,
    ra_deadline,
    is_baseline
)
SELECT
    t.event_id,
    t.event_ts,

    t.issue_id,
    t.issue_title,
    t.issue_url,

    t.product_id,
    t.product_name,
    t.repository,

    t.severity,
    t.scanner,

    t.previous_status,
    t.new_status,

    t.created_at,
    t.ra_deadline,
    t.is_baseline
FROM transitions t
WHERE NOT EXISTS (
    SELECT 1
    FROM custom_ts_secure_development.issue_status_events e
    WHERE e.event_id = t.event_id
);


-- =====================================================================
-- 10. ДНЕВНОЙ ПОТОК СОБЫТИЙ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.issues_daily_flow AS
SELECT
    event_ts::DATE AS dt,

    product_id,
    product_name,
    severity,
    scanner,

    SUM(CASE WHEN new_status = 'new_issue'
             THEN 1 ELSE 0 END) AS new_cnt,

    SUM(CASE WHEN new_status = 'recurrent'
             THEN 1 ELSE 0 END) AS recurrent_cnt,

    SUM(CASE WHEN new_status = 'reopened'
             THEN 1 ELSE 0 END) AS reopened_cnt,

    SUM(CASE WHEN new_status = 'fixed'
             THEN 1 ELSE 0 END) AS fixed_cnt,

    SUM(CASE WHEN new_status = 'false_positive'
             THEN 1 ELSE 0 END) AS false_positive_cnt,

    SUM(CASE WHEN new_status = 'exclusion'
             THEN 1 ELSE 0 END) AS exclusion_cnt,

    SUM(CASE WHEN new_status = 'risk_accepted'
             THEN 1 ELSE 0 END) AS risk_accepted_cnt,

    SUM(CASE WHEN new_status = 'confirmed'
             THEN 1 ELSE 0 END) AS confirmed_cnt,

    SUM(CASE WHEN new_status = 'security-debt'
             THEN 1 ELSE 0 END) AS security_debt_entered_cnt

FROM custom_ts_secure_development.issue_status_events
WHERE is_baseline = FALSE
  AND product_id IS NOT NULL
GROUP BY
    event_ts::DATE,
    product_id,
    product_name,
    severity,
    scanner;


CREATE VIEW custom_ts_secure_development.repository_daily_flow AS
SELECT
    event_ts::DATE AS dt,

    product_id,
    product_name,
    repository,
    severity,

    SUM(CASE WHEN new_status = 'new_issue'
             THEN 1 ELSE 0 END) AS new_cnt,

    SUM(CASE WHEN new_status = 'recurrent'
             THEN 1 ELSE 0 END) AS recurrent_cnt,

    SUM(CASE WHEN new_status = 'reopened'
             THEN 1 ELSE 0 END) AS reopened_cnt,

    SUM(CASE WHEN new_status = 'fixed'
             THEN 1 ELSE 0 END) AS fixed_cnt,

    SUM(CASE WHEN new_status = 'false_positive'
             THEN 1 ELSE 0 END) AS false_positive_cnt,

    SUM(CASE WHEN new_status = 'exclusion'
             THEN 1 ELSE 0 END) AS exclusion_cnt

FROM custom_ts_secure_development.issue_status_events
WHERE is_baseline = FALSE
  AND product_id IS NOT NULL
GROUP BY
    event_ts::DATE,
    product_id,
    product_name,
    repository,
    severity;


-- =====================================================================
-- 11. MTTR ПО ЦИКЛАМ
-- =====================================================================
-- Первый цикл: created_at -> fixed.
-- Повторный цикл: reopened -> следующий fixed.

CREATE VIEW custom_ts_secure_development.mttr_cycles AS
WITH ordered_events AS (
    SELECT
        e.*,

        MIN(e.event_ts) OVER (
            PARTITION BY e.issue_id
        ) AS first_seen_at,

        MAX(
            CASE
                WHEN e.new_status = 'reopened'
                THEN e.event_ts
                ELSE NULL
            END
        ) OVER (
            PARTITION BY e.issue_id
            ORDER BY e.event_ts
            ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) AS last_reopened_at

    FROM custom_ts_secure_development.issue_status_events e
),
fixed_cycles AS (
    SELECT
        event_id,

        issue_id,
        issue_title,
        issue_url,

        product_id,
        product_name,
        repository,

        severity,
        scanner,

        COALESCE(
            last_reopened_at,
            created_at,
            first_seen_at
        ) AS cycle_started_at,

        event_ts AS fixed_at

    FROM ordered_events
    WHERE new_status = 'fixed'
      AND is_baseline = FALSE
)
SELECT
    event_id AS fixed_event_id,

    issue_id,
    issue_title,
    issue_url,

    product_id,
    product_name,
    repository,

    severity,
    scanner,

    cycle_started_at,
    fixed_at,
    fixed_at::DATE AS fixed_dt,

    EXTRACT(
        EPOCH FROM (fixed_at - cycle_started_at)
    ) / 86400.0 AS mttr_days

FROM fixed_cycles
WHERE cycle_started_at IS NOT NULL
  AND fixed_at > cycle_started_at;


-- Удобная агрегированная витрина без жёсткого периода.
-- FineBI фильтрует fixed_dt и затем агрегирует по продукту.
CREATE VIEW custom_ts_secure_development.mttr_by_product AS
SELECT
    product_id,
    product_name,
    severity,
    fixed_dt,
    mttr_days,
    fixed_event_id,
    issue_id
FROM custom_ts_secure_development.mttr_cycles
WHERE product_id IS NOT NULL;


-- =====================================================================
-- 12. ДНЕВНОЙ ОСТАТОК ПО СТАТУСАМ
-- =====================================================================
-- Первичный rebuild из исторических снапшотов.
-- После обновления Python эту таблицу нужно обновлять каждым запуском.

TRUNCATE TABLE custom_ts_secure_development.issues_daily_stock;

WITH daily_last_snapshot AS (
    SELECT
        ts::DATE AS dt,
        MAX(ts) AS max_ts
    FROM custom_ts_secure_development.issues_snapshot_normalized
    GROUP BY ts::DATE
)
INSERT INTO custom_ts_secure_development.issues_daily_stock (
    dt,
    product_id,
    product_name,
    severity,
    status,
    scanner,
    is_security_debt,
    cnt
)
SELECT
    d.dt,
    i.product_id,
    i.product_name,
    i.severity,
    i.status,
    i.scanner,
    CASE WHEN i.status = 'security-debt' THEN TRUE ELSE FALSE END,
    COUNT(DISTINCT i.issue_id)::INTEGER
FROM daily_last_snapshot d
JOIN custom_ts_secure_development.issues_snapshot_normalized i
  ON i.ts = d.max_ts
WHERE i.product_id IS NOT NULL
  AND i.severity IN ('CRITICAL', 'HIGH')
GROUP BY
    d.dt,
    i.product_id,
    i.product_name,
    i.severity,
    i.status,
    i.scanner;


CREATE VIEW custom_ts_secure_development.issues_daily_stock_summary AS
SELECT
    dt,
    product_id,
    product_name,
    severity,

    SUM(
        CASE
            WHEN status IN (
                'new_issue',
                'recurrent',
                'confirmed',
                'risk_accepted',
                'reopened',
                'security-debt'
            )
            THEN cnt ELSE 0
        END
    ) AS open_total,

    SUM(
        CASE
            WHEN status IN (
                'new_issue',
                'recurrent',
                'confirmed',
                'risk_accepted',
                'reopened'
            )
            THEN cnt ELSE 0
        END
    ) AS open_current_flow,

    SUM(
        CASE
            WHEN status = 'security-debt'
            THEN cnt ELSE 0
        END
    ) AS open_security_debt,

    SUM(
        CASE
            WHEN status IN (
                'new_issue',
                'recurrent',
                'confirmed',
                'risk_accepted',
                'reopened',
                'security-debt'
            )
             AND severity = 'CRITICAL'
            THEN cnt ELSE 0
        END
    ) AS critical_open,

    SUM(
        CASE
            WHEN status IN (
                'new_issue',
                'recurrent',
                'confirmed',
                'risk_accepted',
                'reopened',
                'security-debt'
            )
             AND severity = 'HIGH'
            THEN cnt ELSE 0
        END
    ) AS high_open

FROM custom_ts_secure_development.issues_daily_stock
GROUP BY
    dt,
    product_id,
    product_name,
    severity;


-- =====================================================================
-- 13. BACKFILL КОГОРТЫ SECURITY DEBT
-- =====================================================================

WITH debt_rows AS (
    SELECT *
    FROM (
        SELECT
            s.*,
            ROW_NUMBER() OVER (
                PARTITION BY s.issue_id
                ORDER BY s.ts
            ) AS rn
        FROM custom_ts_secure_development.issues_snapshot_normalized s
        WHERE s.status = 'security-debt'
          AND s.issue_id IS NOT NULL
          AND s.severity IN ('CRITICAL', 'HIGH')
    ) x
    WHERE rn = 1
)
INSERT INTO custom_ts_secure_development.security_debt_cohort (
    issue_id,
    issue_title,
    issue_url,

    product_id,
    product_name,
    repository,
    severity,

    entered_at
)
SELECT
    d.issue_id,
    d.issue_title,
    d.issue_url,

    d.product_id,
    d.product_name,
    d.repository,
    d.severity,

    d.ts
FROM debt_rows d
WHERE NOT EXISTS (
    SELECT 1
    FROM custom_ts_secure_development.security_debt_cohort c
    WHERE c.issue_id = d.issue_id
);


-- =====================================================================
-- 14. ТЕКУЩЕЕ СОСТОЯНИЕ SECURITY DEBT
-- =====================================================================

CREATE VIEW custom_ts_secure_development.security_debt_current AS
SELECT
    c.issue_id,
    COALESCE(i.issue_title, c.issue_title) AS issue_title,
    COALESCE(i.issue_url, c.issue_url)     AS issue_url,

    c.product_id,
    c.product_name,
    c.repository,
    c.severity,
    c.entered_at,

    i.status          AS current_status,
    i.status_display  AS current_status_display,
    i.ra_deadline,
    i.days_in_status,

    CASE
        WHEN i.issue_id IS NULL THEN 1
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

    CASE
        WHEN i.status = 'fixed' THEN 1
        ELSE 0
    END AS debt_fixed_current_int,

    CASE
        WHEN i.issue_id IS NULL THEN 1
        ELSE 0
    END AS is_missing_from_current_int

FROM custom_ts_secure_development.security_debt_cohort c
LEFT JOIN custom_ts_secure_development.issues_current i
       ON i.issue_id = c.issue_id;


CREATE VIEW custom_ts_secure_development.security_debt_fixed_events AS
SELECT
    e.event_id,
    e.event_ts,
    e.event_ts::DATE AS fixed_dt,

    e.issue_id,
    COALESCE(e.issue_title, c.issue_title) AS issue_title,
    COALESCE(e.issue_url, c.issue_url)     AS issue_url,

    c.product_id,
    c.product_name,
    c.repository,
    c.severity,

    c.entered_at

FROM custom_ts_secure_development.issue_status_events e
JOIN custom_ts_secure_development.security_debt_cohort c
  ON c.issue_id = e.issue_id
WHERE e.new_status = 'fixed'
  AND e.is_baseline = FALSE
  AND e.event_ts >= c.entered_at;


-- =====================================================================
-- 15. ДНЕВНАЯ ИСТОРИЯ SECURITY DEBT
-- =====================================================================

TRUNCATE TABLE custom_ts_secure_development.security_debt_daily;

WITH daily_issue_state AS (
    SELECT *
    FROM (
        SELECT
            s.ts::DATE AS dt,

            c.issue_id,
            c.product_id,
            c.product_name,
            c.repository,
            c.severity,

            s.status,

            ROW_NUMBER() OVER (
                PARTITION BY c.issue_id, s.ts::DATE
                ORDER BY s.ts DESC
            ) AS rn

        FROM custom_ts_secure_development.security_debt_cohort c
        JOIN custom_ts_secure_development.issues_snapshot_normalized s
          ON s.issue_id = c.issue_id
         AND s.ts >= c.entered_at
    ) x
    WHERE rn = 1
),
remaining_by_day AS (
    SELECT
        dt,
        product_id,
        product_name,
        severity,

        SUM(
            CASE
                WHEN status IN (
                    'fixed',
                    'false_positive',
                    'exclusion',
                    'archive',
                    'not-applicable',
                    'wont-fix'
                )
                THEN 0 ELSE 1
            END
        )::INTEGER AS debt_remaining

    FROM daily_issue_state
    GROUP BY
        dt,
        product_id,
        product_name,
        severity
),
fixed_by_day AS (
    SELECT
        fixed_dt AS dt,
        product_id,
        product_name,
        severity,
        COUNT(*)::INTEGER AS fixed_cnt

    FROM custom_ts_secure_development.security_debt_fixed_events
    GROUP BY
        fixed_dt,
        product_id,
        product_name,
        severity
)
INSERT INTO custom_ts_secure_development.security_debt_daily (
    dt,
    product_id,
    product_name,
    severity,
    debt_remaining,
    fixed_cnt
)
SELECT
    COALESCE(r.dt, f.dt)                         AS dt,
    COALESCE(r.product_id, f.product_id)         AS product_id,
    COALESCE(r.product_name, f.product_name)     AS product_name,
    COALESCE(r.severity, f.severity)             AS severity,

    COALESCE(r.debt_remaining, 0)                AS debt_remaining,
    COALESCE(f.fixed_cnt, 0)                     AS fixed_cnt

FROM remaining_by_day r
FULL OUTER JOIN fixed_by_day f
  ON f.dt = r.dt
 AND f.product_id = r.product_id
 AND f.severity = r.severity;


-- =====================================================================
-- 16. SUMMARY И ПРОГНОЗ SECURITY DEBT ПО ПРОДУКТАМ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.security_debt_summary_by_product AS
WITH initial_counts AS (
    SELECT
        product_id,
        MAX(product_name) AS product_name,

        COUNT(*)::INTEGER AS initial_total,

        SUM(
            CASE WHEN severity = 'CRITICAL'
                 THEN 1 ELSE 0 END
        )::INTEGER AS initial_critical,

        SUM(
            CASE WHEN severity = 'HIGH'
                 THEN 1 ELSE 0 END
        )::INTEGER AS initial_high

    FROM custom_ts_secure_development.security_debt_cohort
    WHERE product_id IS NOT NULL
    GROUP BY product_id
),
current_counts AS (
    SELECT
        product_id,

        SUM(debt_remaining_int)::INTEGER
            AS current_remaining,

        SUM(
            CASE WHEN debt_remaining_int = 1
                   AND severity = 'CRITICAL'
                 THEN 1 ELSE 0 END
        )::INTEGER AS current_critical,

        SUM(
            CASE WHEN debt_remaining_int = 1
                   AND severity = 'HIGH'
                 THEN 1 ELSE 0 END
        )::INTEGER AS current_high,

        SUM(debt_fixed_current_int)::INTEGER
            AS fixed_current

    FROM custom_ts_secure_development.security_debt_current
    WHERE product_id IS NOT NULL
    GROUP BY product_id
),
historical_points AS (
    SELECT
        p.product_id,

        (
            SELECT SUM(d.debt_remaining)::INTEGER
            FROM custom_ts_secure_development.security_debt_daily d
            WHERE d.product_id = p.product_id
              AND d.dt = (
                  SELECT MAX(d2.dt)
                  FROM custom_ts_secure_development.security_debt_daily d2
                  WHERE d2.product_id = p.product_id
                    AND d2.dt <= CURRENT_DATE - 28
              )
        ) AS remaining_28d_ago,

        (
            SELECT SUM(d.debt_remaining)::INTEGER
            FROM custom_ts_secure_development.security_debt_daily d
            WHERE d.product_id = p.product_id
              AND d.dt = (
                  SELECT MAX(d2.dt)
                  FROM custom_ts_secure_development.security_debt_daily d2
                  WHERE d2.product_id = p.product_id
                    AND d2.dt <= CURRENT_DATE - 90
              )
        ) AS remaining_90d_ago

    FROM initial_counts p
),
base AS (
    SELECT
        i.product_id,
        i.product_name,

        i.initial_total,
        i.initial_critical,
        i.initial_high,

        COALESCE(c.current_remaining, i.initial_total)
            AS current_remaining,

        COALESCE(c.current_critical, i.initial_critical)
            AS current_critical,

        COALESCE(c.current_high, i.initial_high)
            AS current_high,

        COALESCE(c.fixed_current, 0)
            AS fixed_current,

        h.remaining_28d_ago,
        h.remaining_90d_ago,

        (DATE '2027-01-01' - CURRENT_DATE)::INTEGER
            AS days_to_deadline

    FROM initial_counts i
    LEFT JOIN current_counts c
           ON c.product_id = i.product_id
    LEFT JOIN historical_points h
           ON h.product_id = i.product_id
),
calculated AS (
    SELECT
        b.*,

        CASE
            WHEN remaining_28d_ago IS NOT NULL
            THEN (remaining_28d_ago - current_remaining) / 28.0
            ELSE NULL
        END AS daily_velocity_28d,

        CASE
            WHEN remaining_90d_ago IS NOT NULL
            THEN (remaining_90d_ago - current_remaining) / 90.0
            ELSE NULL
        END AS daily_velocity_90d,

        CASE
            WHEN days_to_deadline > 0
            THEN current_remaining / days_to_deadline::NUMERIC
            ELSE NULL
        END AS required_daily_velocity

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

    initial_total - current_remaining
        AS resolved_total,

    CASE
        WHEN initial_total > 0
        THEN ROUND(
            100.0 * (initial_total - current_remaining) / initial_total,
            2
        )
        ELSE 0
    END AS progress_percent,

    remaining_28d_ago,
    remaining_90d_ago,

    daily_velocity_28d,
    daily_velocity_90d,

    daily_velocity_28d * 14.0
        AS velocity_per_sprint_28d,

    daily_velocity_90d * 14.0
        AS velocity_per_sprint_90d,

    days_to_deadline,
    required_daily_velocity,
    required_daily_velocity * 14.0
        AS required_per_sprint,

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
        WHEN daily_velocity_90d IS NULL
            THEN 'NO DATA'
        WHEN days_to_deadline <= 0
            THEN 'DEADLINE PASSED'
        WHEN daily_velocity_90d >= required_daily_velocity
            THEN 'ON TRACK'
        ELSE 'AT RISK'
    END AS forecast_status

FROM calculated;


-- =====================================================================
-- 17. СЕРИЯ ДЛЯ ГРАФИКА SECURITY DEBT
-- =====================================================================

CREATE VIEW custom_ts_secure_development.security_debt_chart AS
WITH actual AS (
    SELECT
        dt,
        product_id,
        MAX(product_name) AS product_name,
        SUM(debt_remaining)::INTEGER AS actual_remaining,
        SUM(fixed_cnt)::INTEGER AS fixed_cnt
    FROM custom_ts_secure_development.security_debt_daily
    GROUP BY dt, product_id
),
product_start AS (
    SELECT
        s.product_id,
        s.product_name,
        s.initial_total,
        s.current_remaining,
        s.daily_velocity_90d,
        s.days_to_deadline,

        COALESCE(
            (
                SELECT MIN(a.dt)
                FROM actual a
                WHERE a.product_id = s.product_id
            ),
            CURRENT_DATE
        ) AS start_dt

    FROM custom_ts_secure_development.security_debt_summary_by_product s
),
calendar AS (
    SELECT
        p.product_id,
        p.product_name,
        p.initial_total,
        p.current_remaining,
        p.daily_velocity_90d,
        p.days_to_deadline,

        gs::DATE AS dt

    FROM product_start p
    CROSS JOIN LATERAL generate_series(
        p.start_dt::TIMESTAMP,
        DATE '2027-01-01'::TIMESTAMP,
        INTERVAL '1 day'
    ) gs
)
SELECT
    c.dt,
    c.product_id,
    c.product_name,

    a.actual_remaining,
    COALESCE(a.fixed_cnt, 0) AS fixed_cnt,

    CASE
        WHEN c.dt >= CURRENT_DATE
        THEN LEAST(
            c.initial_total,
            GREATEST(
                0,
                ROUND(
                    c.current_remaining
                    - COALESCE(c.daily_velocity_90d, 0)
                      * (c.dt - CURRENT_DATE)
                )::INTEGER
            )
        )
        ELSE NULL
    END AS forecast_remaining,

    CASE
        WHEN c.dt >= CURRENT_DATE
         AND DATE '2027-01-01' > CURRENT_DATE
        THEN GREATEST(
            0,
            ROUND(
                c.current_remaining
                * (
                    (DATE '2027-01-01' - c.dt)::NUMERIC
                    /
                    (DATE '2027-01-01' - CURRENT_DATE)::NUMERIC
                )
            )::INTEGER
        )
        ELSE NULL
    END AS target_remaining

FROM calendar c
LEFT JOIN actual a
       ON a.product_id = c.product_id
      AND a.dt = c.dt;


-- =====================================================================
-- 18. СВЕЖЕСТЬ ДАННЫХ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.data_freshness AS
SELECT
    MAX(ts) AS last_snapshot_ts,

    EXTRACT(
        EPOCH FROM (NOW() - MAX(ts))
    ) / 3600.0 AS hours_since_last_snapshot,

    CASE
        WHEN MAX(ts) IS NULL THEN 'NO DATA'
        WHEN NOW() - MAX(ts) > INTERVAL '6 hours'
            THEN 'STALE'
        ELSE 'OK'
    END AS freshness_status

FROM custom_ts_secure_development.issues_snapshot;


-- =====================================================================
-- 19. СТАТИСТИКА ДЛЯ ПЛАНИРОВЩИКА GREENPLUM
-- =====================================================================

ANALYZE custom_ts_secure_development.issues_snapshot;
ANALYZE custom_ts_secure_development.products_snapshot;
ANALYZE custom_ts_secure_development.issue_status_events;
ANALYZE custom_ts_secure_development.security_debt_cohort;
ANALYZE custom_ts_secure_development.issues_daily_stock;
ANALYZE custom_ts_secure_development.security_debt_daily;
ANALYZE custom_ts_secure_development.user_product_access;

COMMIT;


-- =====================================================================
-- 20. ПРОВЕРОЧНЫЕ ЗАПРОСЫ
-- Запускать после основного скрипта по одному или всем блоком.
-- =====================================================================

-- 1. Последний снапшот и свежесть:
SELECT *
FROM custom_ts_secure_development.data_freshness;

-- 2. Сколько строк в последнем срезе:
SELECT
    COUNT(*) AS current_issues,
    COUNT(DISTINCT issue_id) AS distinct_current_issues
FROM custom_ts_secure_development.issues_current;

-- Значения должны совпадать.

-- 3. Технически непривязанные issues:
SELECT COUNT(*) AS unmapped_issues
FROM custom_ts_secure_development.issues_unmapped_current;

-- 4. Общие KPI:
SELECT
    SUM(open_total)                       AS open_total,
    SUM(open_current_flow)                AS open_current_flow,
    SUM(security_debt_total)              AS security_debt_total,
    SUM(open_critical_current_flow)       AS critical_current_flow,
    SUM(red_zone_total)                   AS red_zone_total,
    SUM(confirmed_total)                  AS confirmed_total,
    SUM(reopened_total)                   AS reopened_total,
    SUM(risk_accepted_total)              AS risk_accepted_total
FROM custom_ts_secure_development.appsec_kpi_by_product;

-- 5. Все продукты:
SELECT
    product_name,
    repos_count,
    open_critical_current_flow,
    open_high_current_flow,
    security_debt_total,
    risk_accepted_total,
    confirmed_total,
    reopened_total,
    has_red_zone
FROM custom_ts_secure_development.products_comparison_current
ORDER BY
    open_critical_current_flow DESC,
    security_debt_total DESC,
    open_high_current_flow DESC;

-- 6. Красная зона:
SELECT
    product_name,
    repository,
    issue_title,
    severity,
    status_display,
    days_in_status
FROM custom_ts_secure_development.red_zone
ORDER BY priority_order, days_in_status DESC
LIMIT 20;

-- 7. События и дневной поток:
SELECT
    COUNT(*) AS event_count,
    SUM(CASE WHEN is_baseline THEN 1 ELSE 0 END) AS baseline_count,
    SUM(CASE WHEN NOT is_baseline THEN 1 ELSE 0 END) AS transition_count
FROM custom_ts_secure_development.issue_status_events;

SELECT *
FROM custom_ts_secure_development.issues_daily_flow
ORDER BY dt DESC, product_name
LIMIT 50;

-- 8. MTTR:
SELECT *
FROM custom_ts_secure_development.mttr_cycles
ORDER BY fixed_at DESC
LIMIT 20;

-- 9. Security Debt:
SELECT *
FROM custom_ts_secure_development.security_debt_summary_by_product
ORDER BY current_critical DESC, current_remaining DESC;

SELECT *
FROM custom_ts_secure_development.security_debt_chart
WHERE product_id = (
    SELECT product_id
    FROM custom_ts_secure_development.security_debt_summary_by_product
    ORDER BY current_remaining DESC
    LIMIT 1
)
ORDER BY dt
LIMIT 50;
