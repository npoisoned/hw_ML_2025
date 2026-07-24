-- =====================================================================
-- AppSec / Hexway Vampy -> Greenplum -> FineBI
-- Версия 1.6 FINAL
--
-- Источник истины:
--   issue -> repository_id -> one-or-many product_id
--
-- Правила аналитики:
--   * check_required сохраняется в raw, но отсутствует во всех dashboard views;
--   * TEST исключён по UUID d569ed52-b01f-4222-948b-705b008ae64a;
--   * Default product исключён по UUID 1a16d04d-cd14-4894-b887-4ba7465c26aa;
--   * глобальные показатели считают issue один раз;
--   * продуктовые показатели считают issue один раз внутри каждого продукта;
--   * один repository может принадлежать нескольким продуктам.
--
-- Безопасность миграции:
--   * не создаёт и не удаляет схемы;
--   * не использует DROP ... CASCADE;
--   * не удаляет raw-снапшоты;
--   * выполняется одной транзакцией.
--
-- После выполнения использовать только vampy_to_gp_final_v7.py.
-- =====================================================================

BEGIN;

DO LANGUAGE plpgsql $$
BEGIN
    IF current_database() <> 'gpdb' THEN
        RAISE EXCEPTION
            'Остановлено: подключение к БД %, ожидалась gpdb',
            current_database();
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_namespace
        WHERE nspname = 'custom_ts_secure_development'
    ) THEN
        RAISE EXCEPTION
            'Остановлено: схема custom_ts_secure_development не существует';
    END IF;
END
$$;

SET TIME ZONE 'Europe/Moscow';


-- =====================================================================
-- 1. RAW И СЛУЖЕБНЫЕ ТАБЛИЦЫ
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

-- Новые поля добавляются без потери существующей истории.
DO LANGUAGE plpgsql $$
BEGIN
    -- issues_snapshot
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'issue_title'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN issue_title TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'issue_url'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN issue_url TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'repository_id'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN repository_id TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'repository_slug'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN repository_slug TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'branch_id'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN branch_id TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'branch_slug'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN branch_slug TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'found_in_parsers'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN found_in_parsers TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'file_path'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN file_path TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'file_lineno'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN file_lineno INTEGER;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'library_name'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN library_name TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'library_version'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN library_version TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'cve_id'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN cve_id TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'cwe_id'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN cwe_id INTEGER;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'status_changed_at'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN status_changed_at TIMESTAMP;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issues_snapshot'
          AND column_name = 'completed_at'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issues_snapshot
            ADD COLUMN completed_at TIMESTAMP;
    END IF;

    -- products_snapshot
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'products_snapshot'
          AND column_name = 'product_slug'
    ) THEN
        ALTER TABLE custom_ts_secure_development.products_snapshot
            ADD COLUMN product_slug TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'products_snapshot'
          AND column_name = 'criticality'
    ) THEN
        ALTER TABLE custom_ts_secure_development.products_snapshot
            ADD COLUMN criticality TEXT;
    END IF;
END
$$;


-- Одна строка = одна проверенная связь repository -> product.
-- product_id = NULL означает: repository проверен, связей API не вернул.
CREATE TABLE IF NOT EXISTS custom_ts_secure_development.repository_product_snapshot (
    ts               TIMESTAMP NOT NULL,
    repository_id    TEXT NOT NULL,
    repository_name  TEXT,
    repository_slug  TEXT,
    product_id       TEXT,
    product_name     TEXT
)
DISTRIBUTED BY (repository_id);


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
    is_baseline       BOOLEAN DEFAULT FALSE
)
DISTRIBUTED BY (issue_id);

DO LANGUAGE plpgsql $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issue_status_events'
          AND column_name = 'repository_id'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issue_status_events
            ADD COLUMN repository_id TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issue_status_events'
          AND column_name = 'repository_slug'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issue_status_events
            ADD COLUMN repository_slug TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'issue_status_events'
          AND column_name = 'completed_at'
    ) THEN
        ALTER TABLE custom_ts_secure_development.issue_status_events
            ADD COLUMN completed_at TIMESTAMP;
    END IF;
END
$$;


-- Привязка события к продуктам в момент события.
CREATE TABLE IF NOT EXISTS custom_ts_secure_development.issue_status_event_product (
    event_id       TEXT NOT NULL,
    event_ts       TIMESTAMP NOT NULL,
    issue_id       TEXT NOT NULL,
    product_id     TEXT NOT NULL,
    product_name   TEXT
)
DISTRIBUTED BY (event_id);


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

DO LANGUAGE plpgsql $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'security_debt_cohort'
          AND column_name = 'repository_id'
    ) THEN
        ALTER TABLE custom_ts_secure_development.security_debt_cohort
            ADD COLUMN repository_id TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'custom_ts_secure_development'
          AND table_name = 'security_debt_cohort'
          AND column_name = 'repository_slug'
    ) THEN
        ALTER TABLE custom_ts_secure_development.security_debt_cohort
            ADD COLUMN repository_slug TEXT;
    END IF;
END
$$;


CREATE TABLE IF NOT EXISTS custom_ts_secure_development.security_debt_cohort_product (
    issue_id       TEXT NOT NULL,
    product_id     TEXT NOT NULL,
    product_name   TEXT,
    entered_at     TIMESTAMP NOT NULL
)
DISTRIBUTED BY (issue_id);


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

CREATE TABLE IF NOT EXISTS custom_ts_secure_development.security_debt_daily (
    dt              DATE,
    product_id      TEXT,
    product_name    TEXT,
    severity        TEXT,
    debt_remaining  INTEGER,
    fixed_cnt       INTEGER
)
DISTRIBUTED BY (product_id);

CREATE TABLE IF NOT EXISTS custom_ts_secure_development.user_product_access (
    user_login  TEXT NOT NULL,
    product_id  TEXT NOT NULL
)
DISTRIBUTED BY (user_login);


-- Старые product_id/product_name backfill в bridge, если они были заполнены.
INSERT INTO custom_ts_secure_development.issue_status_event_product (
    event_id,
    event_ts,
    issue_id,
    product_id,
    product_name
)
SELECT
    e.event_id,
    e.event_ts,
    e.issue_id,
    e.product_id,
    e.product_name
FROM custom_ts_secure_development.issue_status_events e
WHERE NULLIF(BTRIM(e.product_id), '') IS NOT NULL
  AND e.product_id NOT IN (
      'd569ed52-b01f-4222-948b-705b008ae64a',
      '1a16d04d-cd14-4894-b887-4ba7465c26aa'
  )
  AND NOT EXISTS (
      SELECT 1
      FROM custom_ts_secure_development.issue_status_event_product old
      WHERE old.event_id = e.event_id
        AND old.product_id = e.product_id
  );

INSERT INTO custom_ts_secure_development.security_debt_cohort_product (
    issue_id,
    product_id,
    product_name,
    entered_at
)
SELECT
    c.issue_id,
    c.product_id,
    c.product_name,
    c.entered_at
FROM custom_ts_secure_development.security_debt_cohort c
WHERE NULLIF(BTRIM(c.product_id), '') IS NOT NULL
  AND c.product_id NOT IN (
      'd569ed52-b01f-4222-948b-705b008ae64a',
      '1a16d04d-cd14-4894-b887-4ba7465c26aa'
  )
  AND NOT EXISTS (
      SELECT 1
      FROM custom_ts_secure_development.security_debt_cohort_product old
      WHERE old.issue_id = c.issue_id
        AND old.product_id = c.product_id
  );


-- Производные дневные таблицы пересобираются Python v7 с корректной M:N-связью.
TRUNCATE TABLE custom_ts_secure_development.issues_daily_stock;
TRUNCATE TABLE custom_ts_secure_development.security_debt_daily;


-- =====================================================================
-- 2. УДАЛЕНИЕ VIEWS В ПОРЯДКЕ ЗАВИСИМОСТЕЙ
-- =====================================================================

DROP VIEW IF EXISTS custom_ts_secure_development.products_comparison_access;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_current_by_product_access;
DROP VIEW IF EXISTS custom_ts_secure_development.data_freshness;
DROP VIEW IF EXISTS custom_ts_secure_development.security_debt_chart;
DROP VIEW IF EXISTS custom_ts_secure_development.security_debt_progress;
DROP VIEW IF EXISTS custom_ts_secure_development.security_debt_summary_by_product;
DROP VIEW IF EXISTS custom_ts_secure_development.security_debt_fixed_events;
DROP VIEW IF EXISTS custom_ts_secure_development.security_debt_current;
DROP VIEW IF EXISTS custom_ts_secure_development.effectiveness_by_product;
DROP VIEW IF EXISTS custom_ts_secure_development.mttr_by_product;
DROP VIEW IF EXISTS custom_ts_secure_development.mttr_cycles;
DROP VIEW IF EXISTS custom_ts_secure_development.repository_daily_flow;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_daily_flow;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_daily_flow_global;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_daily_stock_summary;
DROP VIEW IF EXISTS custom_ts_secure_development.products_comparison_current;
DROP VIEW IF EXISTS custom_ts_secure_development.products_full;
DROP VIEW IF EXISTS custom_ts_secure_development.products_current;
DROP VIEW IF EXISTS custom_ts_secure_development.appsec_summary;
DROP VIEW IF EXISTS custom_ts_secure_development.appsec_kpi_by_product;
DROP VIEW IF EXISTS custom_ts_secure_development.red_zone;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_unmapped_current;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_current_by_product;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_current;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_current_all;
DROP VIEW IF EXISTS custom_ts_secure_development.repository_product_current;
DROP VIEW IF EXISTS custom_ts_secure_development.repository_product_current_all;
DROP VIEW IF EXISTS custom_ts_secure_development.dim_product;
DROP VIEW IF EXISTS custom_ts_secure_development.issues_snapshot_normalized;


-- =====================================================================
-- 3. НОРМАЛИЗОВАННЫЕ RAW-ДАННЫЕ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.issues_snapshot_normalized AS
SELECT
    ts,
    NULLIF(BTRIM(issue_id), '')                    AS issue_id,
    NULLIF(BTRIM(issue_title), '')                 AS issue_title,
    NULLIF(BTRIM(issue_url), '')                   AS issue_url,

    NULLIF(BTRIM(repository_id), '')               AS repository_id,
    NULLIF(BTRIM(repository), '')                  AS repository,
    NULLIF(BTRIM(repository_slug), '')             AS repository_slug,
    NULLIF(BTRIM(branch_id), '')                   AS branch_id,
    NULLIF(BTRIM(branch_slug), '')                 AS branch_slug,

    UPPER(BTRIM(COALESCE(severity, '')))           AS severity,
    LOWER(BTRIM(COALESCE(status, '')))             AS status,
    NULLIF(BTRIM(scanner), '')                     AS scanner,
    NULLIF(BTRIM(found_in_parsers), '')            AS found_in_parsers,

    NULLIF(BTRIM(file_path), '')                   AS file_path,
    file_lineno,
    NULLIF(BTRIM(library_name), '')                AS library_name,
    NULLIF(BTRIM(library_version), '')             AS library_version,
    NULLIF(BTRIM(cve_id), '')                      AS cve_id,
    cwe_id,

    is_security_debt                               AS source_is_security_debt,
    is_active                                      AS source_is_active,

    created_at,
    status_changed_at,
    updated_at,
    completed_at,
    ra_deadline
FROM custom_ts_secure_development.issues_snapshot;


-- =====================================================================
-- 4. ТЕКУЩИЙ GLOBAL-СРЕЗ: ОДИН ISSUE = ОДНА СТРОКА
-- =====================================================================

CREATE VIEW custom_ts_secure_development.issues_current_all AS
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
                    i.completed_at,
                    i.updated_at,
                    i.created_at,
                    i.ts
                ) DESC,
                i.repository_id NULLS LAST
        ) AS rn
    FROM custom_ts_secure_development.issues_snapshot_normalized i
    JOIN latest_snapshot l
      ON i.ts = l.max_ts
    WHERE i.issue_id IS NOT NULL
)
SELECT
    ts,
    issue_id,
    issue_title,
    issue_url,

    repository_id,
    repository,
    repository_slug,
    branch_id,
    branch_slug,

    severity,
    status,
    scanner,
    found_in_parsers,

    file_path,
    file_lineno,
    library_name,
    library_version,
    cve_id,
    cwe_id,

    created_at,
    status_changed_at,
    updated_at,
    completed_at,
    ra_deadline,

    1 AS issue_cnt,

    CASE
        WHEN status IN (
            'new_issue',
            'recurrent',
            'confirmed',
            'check_required',
            'risk_accepted',
            'reopened',
            'security-debt'
        ) THEN 1 ELSE 0
    END AS is_unresolved_int,

    CASE
        WHEN status IN (
            'new_issue',
            'recurrent',
            'confirmed',
            'risk_accepted',
            'reopened'
        ) THEN 1 ELSE 0
    END AS is_current_flow_int,

    CASE WHEN status = 'security-debt'
         THEN 1 ELSE 0 END AS is_security_debt_current_int,

    CASE
        WHEN status IN ('confirmed', 'reopened')
         AND severity IN ('CRITICAL', 'HIGH')
        THEN 1 ELSE 0
    END AS is_red_zone_int,

    CASE WHEN status = 'confirmed'
         THEN 1 ELSE 0 END AS is_confirmed_int,

    CASE WHEN status = 'reopened'
         THEN 1 ELSE 0 END AS is_reopened_int,

    CASE WHEN status = 'risk_accepted'
         THEN 1 ELSE 0 END AS is_risk_accepted_int,

    CASE WHEN status = 'fixed'
         THEN 1 ELSE 0 END AS is_fixed_current_int,

    GREATEST(
        0,
        FLOOR(
            EXTRACT(
                EPOCH FROM (
                    NOW() - COALESCE(
                        status_changed_at,
                        completed_at,
                        updated_at,
                        created_at,
                        ts
                    )
                )
            ) / 86400.0
        )::INTEGER
    ) AS days_in_status,

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
        WHEN 'check_required' THEN 'Check Required'
        WHEN 'risk_accepted'  THEN 'Risk Accepted'
        WHEN 'reopened'       THEN 'Reopened'
        WHEN 'security-debt'  THEN 'Security Debt'
        WHEN 'fixed'          THEN 'Fixed'
        WHEN 'false_positive' THEN 'False Positive'
        WHEN 'exclusion'      THEN 'Exclusion'
        WHEN 'archive'        THEN 'Archive'
        WHEN 'not-applicable' THEN 'Not Applicable'
        WHEN 'wont-fix'       THEN 'Won''t Fix'
        ELSE status
    END AS status_display,

    CASE
        WHEN status IN ('new_issue', 'recurrent') THEN 'New / Recurrent'
        WHEN status = 'confirmed'                 THEN 'Confirmed'
        WHEN status = 'check_required'            THEN 'Check Required'
        WHEN status = 'risk_accepted'              THEN 'Risk Accepted'
        WHEN status = 'reopened'                   THEN 'Reopened'
        WHEN status = 'security-debt'              THEN 'Security Debt'
        WHEN status = 'fixed'                      THEN 'Fixed'
        WHEN status = 'false_positive'             THEN 'False Positive'
        WHEN status = 'exclusion'                  THEN 'Exclusion'
        ELSE status
    END AS status_group,

    CASE
        WHEN status = 'confirmed' AND severity = 'CRITICAL' THEN 1
        WHEN status = 'reopened'  AND severity = 'CRITICAL' THEN 2
        WHEN status = 'confirmed' AND severity = 'HIGH'     THEN 3
        WHEN status = 'reopened'  AND severity = 'HIGH'     THEN 4
        WHEN status = 'risk_accepted' AND severity = 'CRITICAL' THEN 5
        WHEN status IN ('new_issue', 'recurrent')
             AND severity = 'CRITICAL' THEN 6
        WHEN status = 'security-debt' AND severity = 'CRITICAL' THEN 7
        WHEN status = 'risk_accepted' AND severity = 'HIGH' THEN 20
        WHEN status IN ('new_issue', 'recurrent')
             AND severity = 'HIGH' THEN 21
        WHEN status = 'security-debt' AND severity = 'HIGH' THEN 22
        ELSE 99
    END AS priority_order
FROM deduplicated
WHERE rn = 1
  AND severity IN ('CRITICAL', 'HIGH');

-- Единственный global-источник для dashboard: check_required отсутствует.
CREATE VIEW custom_ts_secure_development.issues_current AS
SELECT *
FROM custom_ts_secure_development.issues_current_all
WHERE status <> 'check_required';


-- =====================================================================
-- 5. АКТУАЛЬНАЯ M:N-СВЯЗЬ REPOSITORY -> PRODUCT
-- =====================================================================

CREATE VIEW custom_ts_secure_development.repository_product_current_all AS
WITH latest AS (
    SELECT repository_id, MAX(ts) AS max_ts
    FROM custom_ts_secure_development.repository_product_snapshot
    GROUP BY repository_id
),
ranked AS (
    SELECT
        s.ts AS checked_at,
        s.repository_id,
        s.repository_name,
        s.repository_slug,
        NULLIF(BTRIM(s.product_id), '') AS product_id,
        NULLIF(BTRIM(s.product_name), '') AS product_name,
        ROW_NUMBER() OVER (
            PARTITION BY
                s.repository_id,
                COALESCE(NULLIF(BTRIM(s.product_id), ''), '<NULL>')
            ORDER BY s.ts DESC, s.product_name
        ) AS rn
    FROM custom_ts_secure_development.repository_product_snapshot s
    JOIN latest l
      ON l.repository_id = s.repository_id
     AND l.max_ts = s.ts
)
SELECT
    checked_at,
    repository_id,
    repository_name,
    repository_slug,
    product_id,
    product_name
FROM ranked
WHERE rn = 1;

CREATE VIEW custom_ts_secure_development.repository_product_current AS
SELECT *
FROM custom_ts_secure_development.repository_product_current_all
WHERE product_id IS NOT NULL
  AND product_id NOT IN (
      'd569ed52-b01f-4222-948b-705b008ae64a',
      '1a16d04d-cd14-4894-b887-4ba7465c26aa'
  );


-- =====================================================================
-- 6. СПРАВОЧНИК 37 РАБОЧИХ ПРОДУКТОВ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.dim_product AS
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
      '1a16d04d-cd14-4894-b887-4ba7465c26aa'
  );


-- =====================================================================
-- 7. PRODUCT-СРЕЗ: ОДИН ISSUE = ОДНА СТРОКА В КАЖДОМ ЕГО ПРОДУКТЕ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.issues_current_by_product AS
SELECT
    i.*,
    rp.product_id,
    COALESCE(d.product_name, rp.product_name) AS product_name,
    d.product_slug,
    d.criticality AS product_criticality,
    rp.checked_at AS repository_product_checked_at
FROM custom_ts_secure_development.issues_current i
JOIN custom_ts_secure_development.repository_product_current rp
  ON rp.repository_id = i.repository_id
LEFT JOIN custom_ts_secure_development.dim_product d
  ON d.product_id = rp.product_id;

CREATE VIEW custom_ts_secure_development.issues_unmapped_current AS
SELECT i.*
FROM custom_ts_secure_development.issues_current i
WHERE i.repository_id IS NULL
   OR NOT EXISTS (
       SELECT 1
       FROM custom_ts_secure_development.repository_product_current rp
       WHERE rp.repository_id = i.repository_id
   );


-- =====================================================================
-- 8. КРАСНАЯ ЗОНА И ТЕКУЩИЕ KPI
-- =====================================================================

CREATE VIEW custom_ts_secure_development.red_zone AS
SELECT
    issue_id,
    issue_title,
    issue_url,
    product_id,
    product_name,
    repository_id,
    repository,
    repository_slug,
    branch_slug,
    severity,
    status,
    status_display,
    scanner,
    found_in_parsers,
    file_path,
    file_lineno,
    library_name,
    library_version,
    cve_id,
    cwe_id,
    created_at,
    status_changed_at,
    updated_at,
    completed_at,
    ra_deadline,
    days_in_status,
    priority_order
FROM custom_ts_secure_development.issues_current_by_product
WHERE is_red_zone_int = 1;

CREATE VIEW custom_ts_secure_development.appsec_kpi_by_product AS
WITH current_stats AS (
    SELECT
        product_id,
        SUM(is_unresolved_int) AS open_total,
        SUM(CASE WHEN is_unresolved_int = 1 AND severity = 'CRITICAL'
                 THEN 1 ELSE 0 END) AS open_total_critical,
        SUM(CASE WHEN is_unresolved_int = 1 AND severity = 'HIGH'
                 THEN 1 ELSE 0 END) AS open_total_high,

        SUM(is_current_flow_int) AS open_current_flow,
        SUM(CASE WHEN is_current_flow_int = 1 AND severity = 'CRITICAL'
                 THEN 1 ELSE 0 END) AS open_critical_current_flow,
        SUM(CASE WHEN is_current_flow_int = 1 AND severity = 'HIGH'
                 THEN 1 ELSE 0 END) AS open_high_current_flow,

        SUM(is_security_debt_current_int) AS security_debt_total,
        SUM(CASE WHEN is_security_debt_current_int = 1
                  AND severity = 'CRITICAL' THEN 1 ELSE 0 END)
            AS security_debt_critical,
        SUM(CASE WHEN is_security_debt_current_int = 1
                  AND severity = 'HIGH' THEN 1 ELSE 0 END)
            AS security_debt_high,

        SUM(is_red_zone_int) AS red_zone_total,
        SUM(is_confirmed_int) AS confirmed_total,
        SUM(is_reopened_int) AS reopened_total,
        SUM(is_risk_accepted_int) AS risk_accepted_total,

        MIN(CASE WHEN status = 'risk_accepted'
                 THEN ra_deadline ELSE NULL END) AS nearest_ra_deadline,

        SUM(CASE WHEN status = 'risk_accepted'
                  AND ra_deadline IS NOT NULL
                  AND ra_deadline >= NOW()
                  AND ra_deadline < NOW() + INTERVAL '7 days'
                 THEN 1 ELSE 0 END) AS risk_accepted_due_7d,

        SUM(CASE WHEN status = 'risk_accepted'
                  AND ra_deadline IS NOT NULL
                  AND ra_deadline >= NOW()
                  AND ra_deadline < NOW() + INTERVAL '14 days'
                 THEN 1 ELSE 0 END) AS risk_accepted_due_14d
    FROM custom_ts_secure_development.issues_current_by_product
    GROUP BY product_id
),
last_load AS (
    SELECT MAX(ts) AS last_snapshot_ts
    FROM custom_ts_secure_development.issues_snapshot
)
SELECT
    d.product_id,
    d.product_name,
    d.product_slug,
    d.criticality,
    d.repos_count,

    COALESCE(s.open_total, 0) AS open_total,
    COALESCE(s.open_total_critical, 0) AS open_total_critical,
    COALESCE(s.open_total_high, 0) AS open_total_high,

    COALESCE(s.open_current_flow, 0) AS open_current_flow,
    COALESCE(s.open_critical_current_flow, 0)
        AS open_critical_current_flow,
    COALESCE(s.open_high_current_flow, 0)
        AS open_high_current_flow,

    COALESCE(s.security_debt_total, 0) AS security_debt_total,
    COALESCE(s.security_debt_critical, 0) AS security_debt_critical,
    COALESCE(s.security_debt_high, 0) AS security_debt_high,

    COALESCE(s.red_zone_total, 0) AS red_zone_total,
    COALESCE(s.confirmed_total, 0) AS confirmed_total,
    COALESCE(s.reopened_total, 0) AS reopened_total,
    COALESCE(s.risk_accepted_total, 0) AS risk_accepted_total,
    s.nearest_ra_deadline,
    COALESCE(s.risk_accepted_due_7d, 0) AS risk_accepted_due_7d,
    COALESCE(s.risk_accepted_due_14d, 0) AS risk_accepted_due_14d,
    l.last_snapshot_ts
FROM custom_ts_secure_development.dim_product d
CROSS JOIN last_load l
LEFT JOIN current_stats s
  ON s.product_id = d.product_id;

CREATE VIEW custom_ts_secure_development.products_current AS
SELECT
    *,
    CASE WHEN red_zone_total > 0 THEN 1 ELSE 0 END AS has_red_zone
FROM custom_ts_secure_development.appsec_kpi_by_product;

CREATE VIEW custom_ts_secure_development.products_comparison_current AS
SELECT *
FROM custom_ts_secure_development.products_current;

CREATE VIEW custom_ts_secure_development.products_full AS
SELECT *
FROM custom_ts_secure_development.products_current;

-- Global summary: issue не размножается из-за нескольких продуктов.
CREATE VIEW custom_ts_secure_development.appsec_summary AS
SELECT
    COUNT(*) AS issues_total,
    SUM(is_unresolved_int) AS open_total,
    SUM(CASE WHEN is_unresolved_int = 1 AND severity = 'CRITICAL'
             THEN 1 ELSE 0 END) AS open_critical,
    SUM(CASE WHEN is_unresolved_int = 1 AND severity = 'HIGH'
             THEN 1 ELSE 0 END) AS open_high,
    SUM(is_current_flow_int) AS open_current_flow,
    SUM(is_security_debt_current_int) AS security_debt_total,
    SUM(is_confirmed_int) AS confirmed_total,
    SUM(is_reopened_int) AS reopened_total,
    SUM(is_risk_accepted_int) AS risk_accepted_total,
    SUM(is_red_zone_int) AS red_zone_total,
    MAX(ts) AS last_snapshot_ts
FROM custom_ts_secure_development.issues_current;


-- =====================================================================
-- 9. ДНЕВНОЙ FLOW ПО СОБЫТИЯМ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.issues_daily_flow_global AS
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
GROUP BY e.event_ts::DATE, e.severity;

CREATE VIEW custom_ts_secure_development.issues_daily_flow AS
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
      '1a16d04d-cd14-4894-b887-4ba7465c26aa'
  )
GROUP BY e.event_ts::DATE, ep.product_id, e.severity;

CREATE VIEW custom_ts_secure_development.repository_daily_flow AS
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
    COUNT(DISTINCT CASE WHEN e.new_status IN (
                            'fixed', 'false_positive', 'exclusion'
                        ) THEN e.issue_id ELSE NULL END)::INTEGER AS outflow_cnt,
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


-- =====================================================================
-- 10. MTTR ПО ЗАФИКСИРОВАННЫМ ЦИКЛАМ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.mttr_cycles AS
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

CREATE VIEW custom_ts_secure_development.mttr_by_product AS
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
    '1a16d04d-cd14-4894-b887-4ba7465c26aa'
)
GROUP BY ep.product_id, c.severity;


-- =====================================================================
-- 11. ДНЕВНОЙ STOCK
-- =====================================================================

CREATE VIEW custom_ts_secure_development.issues_daily_stock_summary AS
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
      '1a16d04d-cd14-4894-b887-4ba7465c26aa'
  )
GROUP BY dt, product_id;


-- =====================================================================
-- 12. SECURITY DEBT
-- =====================================================================

CREATE VIEW custom_ts_secure_development.security_debt_current AS
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
      '1a16d04d-cd14-4894-b887-4ba7465c26aa'
  )
  AND COALESCE(i.status, '') <> 'check_required';

CREATE VIEW custom_ts_secure_development.security_debt_fixed_events AS
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
      '1a16d04d-cd14-4894-b887-4ba7465c26aa'
  );

CREATE VIEW custom_ts_secure_development.security_debt_summary_by_product AS
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
daily_product_debt AS (
    SELECT
        dt,
        product_id,
        SUM(debt_remaining)::INTEGER AS debt_remaining
    FROM custom_ts_secure_development.security_debt_daily
    GROUP BY dt, product_id
),
target_dates AS (
    SELECT
        i.product_id,
        MAX(CASE WHEN d.dt <= CURRENT_DATE - 28
                 THEN d.dt ELSE NULL END) AS target_dt_28,
        MAX(CASE WHEN d.dt <= CURRENT_DATE - 90
                 THEN d.dt ELSE NULL END) AS target_dt_90
    FROM initial_counts i
    LEFT JOIN daily_product_debt d
      ON d.product_id = i.product_id
    GROUP BY i.product_id
),
historical_points AS (
    SELECT
        t.product_id,
        MAX(CASE WHEN d.dt = t.target_dt_28
                 THEN d.debt_remaining ELSE NULL END)::INTEGER
            AS remaining_28d_ago,
        MAX(CASE WHEN d.dt = t.target_dt_90
                 THEN d.debt_remaining ELSE NULL END)::INTEGER
            AS remaining_90d_ago
    FROM target_dates t
    LEFT JOIN daily_product_debt d
      ON d.product_id = t.product_id
     AND d.dt IN (t.target_dt_28, t.target_dt_90)
    GROUP BY t.product_id
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
        h.remaining_28d_ago,
        h.remaining_90d_ago,
        (DATE '2027-01-01' - CURRENT_DATE)::INTEGER AS days_to_deadline
    FROM initial_counts i
    LEFT JOIN current_counts c
      ON c.product_id = i.product_id
    LEFT JOIN historical_points h
      ON h.product_id = i.product_id
),
calculated AS (
    SELECT
        b.*,
        CASE WHEN remaining_28d_ago IS NOT NULL
             THEN (remaining_28d_ago - current_remaining) / 28.0
             ELSE NULL END AS daily_velocity_28d,
        CASE WHEN remaining_90d_ago IS NOT NULL
             THEN (remaining_90d_ago - current_remaining) / 90.0
             ELSE NULL END AS daily_velocity_90d,
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
    initial_total - current_remaining AS resolved_total,
    CASE WHEN initial_total > 0
         THEN ROUND(
             100.0 * (initial_total - current_remaining) / initial_total,
             2
         ) ELSE 0 END AS progress_percent,
    remaining_28d_ago,
    remaining_90d_ago,
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

CREATE VIEW custom_ts_secure_development.security_debt_progress AS
SELECT *
FROM custom_ts_secure_development.security_debt_summary_by_product;

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
        COALESCE(
            MIN(a.dt),
            CURRENT_DATE
        ) AS start_dt
    FROM custom_ts_secure_development.security_debt_summary_by_product s
    LEFT JOIN actual a
      ON a.product_id = s.product_id
    GROUP BY
        s.product_id,
        s.product_name,
        s.initial_total,
        s.current_remaining,
        s.daily_velocity_90d
),
calendar AS (
    SELECT
        p.product_id,
        p.product_name,
        p.initial_total,
        p.current_remaining,
        p.daily_velocity_90d,
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
    CASE WHEN c.dt >= CURRENT_DATE
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
         ) ELSE NULL END AS forecast_remaining,
    CASE
        WHEN c.dt >= CURRENT_DATE
         AND DATE '2027-01-01' > CURRENT_DATE
        THEN GREATEST(
            0,
            ROUND(
                c.current_remaining
                * (
                    (DATE '2027-01-01' - c.dt)::NUMERIC
                    / (DATE '2027-01-01' - CURRENT_DATE)::NUMERIC
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
-- 13. ЭФФЕКТИВНОСТЬ ПО ПРОДУКТАМ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.effectiveness_by_product AS
WITH flow_28d AS (
    SELECT
        product_id,
        SUM(new_cnt + recurrent_cnt + reopened_cnt)::INTEGER AS inflow_28d,
        SUM(fixed_cnt + false_positive_cnt + exclusion_cnt)::INTEGER
            AS outflow_28d
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


-- =====================================================================
-- 14. ДОСТУП FINEBI
-- =====================================================================

-- Использовать эти views, когда FineBI умеет передавать текущий login.
CREATE VIEW custom_ts_secure_development.issues_current_by_product_access AS
SELECT
    a.user_login,
    i.*
FROM custom_ts_secure_development.user_product_access a
JOIN custom_ts_secure_development.issues_current_by_product i
  ON i.product_id = a.product_id;

CREATE VIEW custom_ts_secure_development.products_comparison_access AS
SELECT
    a.user_login,
    p.*
FROM custom_ts_secure_development.user_product_access a
JOIN custom_ts_secure_development.products_comparison_current p
  ON p.product_id = a.product_id;


-- =====================================================================
-- 15. СВЕЖЕСТЬ
-- =====================================================================

CREATE VIEW custom_ts_secure_development.data_freshness AS
SELECT
    MAX(ts) AS last_snapshot_ts,
    EXTRACT(EPOCH FROM (NOW() - MAX(ts))) / 3600.0
        AS hours_since_last_snapshot,
    CASE
        WHEN MAX(ts) IS NULL THEN 'NO DATA'
        WHEN NOW() - MAX(ts) > INTERVAL '6 hours' THEN 'STALE'
        ELSE 'OK'
    END AS freshness_status
FROM custom_ts_secure_development.issues_snapshot;


-- =====================================================================
-- 16. СТАТИСТИКА ПЛАНИРОВЩИКА
-- =====================================================================

ANALYZE custom_ts_secure_development.issues_snapshot;
ANALYZE custom_ts_secure_development.products_snapshot;
ANALYZE custom_ts_secure_development.repository_product_snapshot;
ANALYZE custom_ts_secure_development.issue_status_events;
ANALYZE custom_ts_secure_development.issue_status_event_product;
ANALYZE custom_ts_secure_development.security_debt_cohort;
ANALYZE custom_ts_secure_development.security_debt_cohort_product;
ANALYZE custom_ts_secure_development.issues_daily_stock;
ANALYZE custom_ts_secure_development.security_debt_daily;
ANALYZE custom_ts_secure_development.user_product_access;

COMMIT;


-- =====================================================================
-- ПРОВЕРКИ ПОСЛЕ ПЕРВОГО ЗАПУСКА PYTHON v7
-- =====================================================================

-- 1. Должно быть 37:
SELECT COUNT(*) AS products_count
FROM custom_ts_secure_development.dim_product;

-- 2. check_required отсутствует в dashboard source:
SELECT status, COUNT(*)
FROM custom_ts_secure_development.issues_current
WHERE status = 'check_required'
GROUP BY status;

-- 3. TEST и Default product отсутствуют:
SELECT product_id, product_name
FROM custom_ts_secure_development.dim_product
WHERE product_id IN (
    'd569ed52-b01f-4222-948b-705b008ae64a',
    '1a16d04d-cd14-4894-b887-4ba7465c26aa'
);

-- 4. Global issue не дублируется:
SELECT
    COUNT(*) AS rows_count,
    COUNT(DISTINCT issue_id) AS distinct_issues
FROM custom_ts_secure_development.issues_current;

-- 5. Проверка M:N-связей:
SELECT
    repository_id,
    MAX(repository_name) AS repository_name,
    COUNT(DISTINCT product_id) AS products_count
FROM custom_ts_secure_development.repository_product_current
GROUP BY repository_id
HAVING COUNT(DISTINCT product_id) > 1
ORDER BY products_count DESC
LIMIT 50;

-- 6. Непривязанные:
SELECT COUNT(*) AS unmapped_issues
FROM custom_ts_secure_development.issues_unmapped_current;

-- 7. Продуктовые KPI:
SELECT *
FROM custom_ts_secure_development.products_comparison_current
ORDER BY open_total_critical DESC, open_total_high DESC;

-- 8. Свежесть:
SELECT *
FROM custom_ts_secure_development.data_freshness;
