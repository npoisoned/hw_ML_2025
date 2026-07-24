Теперь прогоняем **только безопасные `SELECT`**, ничего они не меняют. Запускай по блокам и смотри результаты.

# 1. Свежесть и объём последней загрузки

```sql
SELECT *
FROM custom_ts_secure_development.data_freshness;
```

Ожидаем:

```text
freshness_status = OK
hours_since_last_snapshot < 6
```

Потом:

```sql
WITH latest AS (
    SELECT MAX(ts) AS max_ts
    FROM custom_ts_secure_development.issues_snapshot
)
SELECT
    l.max_ts,
    COUNT(*) AS snapshot_rows,
    COUNT(DISTINCT i.issue_id) AS unique_issue_ids,
    COUNT(*) - COUNT(DISTINCT i.issue_id) AS duplicate_rows
FROM custom_ts_secure_development.issues_snapshot i
CROSS JOIN latest l
WHERE i.ts = l.max_ts
GROUP BY l.max_ts;
```

Сравни `unique_issue_ids` с логом Python:

```text
Итого дефектов из API: N
Подготовлено уникальных issues: N
```

`duplicate_rows` желательно `0`. Если не ноль, `issues_current` всё равно дедуплицирует записи, но нужно посмотреть источник дублей.

# 2. Проверка `issues_current`

```sql
SELECT
    COUNT(*) AS current_rows,
    COUNT(DISTINCT issue_id) AS unique_current_issues,
    COUNT(*) - COUNT(DISTINCT issue_id) AS duplicates
FROM custom_ts_secure_development.issues_current;
```

Ожидаем:

```text
current_rows = unique_current_issues
duplicates = 0
```

Отдельно проверка:

```sql
SELECT
    issue_id,
    COUNT(*) AS cnt
FROM custom_ts_secure_development.issues_current
GROUP BY issue_id
HAVING COUNT(*) > 1
ORDER BY cnt DESC;
```

Должно вернуть **0 строк**.

# 3. Проверка реальных статусов

```sql
SELECT
    status,
    status_display,
    COUNT(*) AS cnt
FROM custom_ts_secure_development.issues_current
GROUP BY status, status_display
ORDER BY cnt DESC;
```

Ожидаемые значения `status`:

```text
new_issue
recurrent
confirmed
risk_accepted
reopened
security-debt
fixed
false_positive
exclusion
```

Если увидишь `Risk Accepted`, `Confirmed` или другие значения с заглавными буквами в поле `status`, значит где-то остались ненормализованные данные.

# 4. Проверка severity

```sql
SELECT
    severity,
    COUNT(*) AS cnt
FROM custom_ts_secure_development.issues_current
GROUP BY severity
ORDER BY severity;
```

Должны быть только:

```text
CRITICAL
HIGH
```

# 5. Проверка, что Risk Accepted и Security Debt нерешённые

```sql
SELECT
    status,
    COUNT(*) AS total,
    SUM(is_unresolved_int) AS unresolved,
    SUM(is_current_flow_int) AS current_flow,
    SUM(is_security_debt_current_int) AS security_debt
FROM custom_ts_secure_development.issues_current
WHERE status IN ('risk_accepted', 'security-debt')
GROUP BY status;
```

Ожидаем:

Для `risk_accepted`:

```text
unresolved = total
current_flow = total
security_debt = 0
```

Для `security-debt`:

```text
unresolved = total
current_flow = 0
security_debt = total
```

# 6. Проверка продуктов

```sql
SELECT
    COUNT(*) AS products_count,
    COUNT(DISTINCT product_id) AS unique_products
FROM custom_ts_secure_development.dim_product;
```

Ожидаем примерно:

```text
37
```

Проверка дублей:

```sql
SELECT
    product_id,
    COUNT(*) AS cnt
FROM custom_ts_secure_development.dim_product
GROUP BY product_id
HAVING COUNT(*) > 1;
```

Должно быть **0 строк**.

Проверка количества репозиториев:

```sql
SELECT
    product_id,
    product_name,
    repos_count
FROM custom_ts_secure_development.dim_product
ORDER BY repos_count DESC, product_name;
```

Здесь нужно визуально сравнить несколько продуктов с Vampy.

# 7. Дефекты без продукта

```sql
SELECT
    COUNT(*) AS unmapped_issues
FROM custom_ts_secure_development.issues_unmapped_current;
```

В идеале:

```text
0
```

Если не ноль:

```sql
SELECT
    issue_id,
    issue_title,
    repository,
    severity,
    status,
    scanner
FROM custom_ts_secure_development.issues_unmapped_current
ORDER BY severity, status
LIMIT 50;
```

Такие дефекты не попадут в продуктовые KPI.

# 8. Проверка основных KPI

```sql
SELECT
    SUM(open_total) AS open_total,
    SUM(open_current_flow) AS open_current_flow,
    SUM(security_debt_total) AS security_debt_total,

    SUM(open_total_critical) AS open_total_critical,
    SUM(open_total_high) AS open_total_high,

    SUM(open_critical_current_flow) AS critical_current_flow,
    SUM(open_high_current_flow) AS high_current_flow,

    SUM(confirmed_total) AS confirmed_total,
    SUM(reopened_total) AS reopened_total,
    SUM(risk_accepted_total) AS risk_accepted_total,
    SUM(red_zone_total) AS red_zone_total
FROM custom_ts_secure_development.appsec_kpi_by_product;
```

Проверь арифметику:

```text
open_total =
open_current_flow + security_debt_total
```

И:

```text
open_total =
open_total_critical + open_total_high
```

Можно проверить автоматически:

```sql
SELECT
    SUM(open_total) AS open_total,
    SUM(open_current_flow) + SUM(security_debt_total)
        AS calculated_open_total,
    SUM(open_total)
        - (
            SUM(open_current_flow)
            + SUM(security_debt_total)
          ) AS difference
FROM custom_ts_secure_development.appsec_kpi_by_product;
```

`difference` должно быть `0`.

# 9. Проверка красной зоны

```sql
SELECT
    status,
    severity,
    COUNT(*) AS cnt
FROM custom_ts_secure_development.red_zone
GROUP BY status, severity
ORDER BY severity, status;
```

По текущему ТЗ там должны быть только:

```text
confirmed
reopened
```

Посмотреть первые записи:

```sql
SELECT
    product_name,
    repository,
    issue_title,
    severity,
    status_display,
    days_in_status,
    priority_order
FROM custom_ts_secure_development.red_zone
ORDER BY priority_order, days_in_status DESC
LIMIT 20;
```

Если `days_in_status` выглядит странно, например тысячи дней или везде ноль, значит API не отдаёт корректное `status_changed_at`, и потребуется проверить реальные поля ответа.

# 10. Проверка названий и ссылок на дефекты

```sql
SELECT
    COUNT(*) AS total,
    COUNT(issue_title) AS with_title,
    COUNT(issue_url) AS with_url,
    COUNT(status_changed_at) AS with_status_changed_at,
    COUNT(ra_deadline) AS with_ra_deadline
FROM custom_ts_secure_development.issues_current;
```

Посмотри процент заполнения:

```sql
SELECT
    ROUND(
        100.0 * COUNT(issue_title) / NULLIF(COUNT(*), 0),
        2
    ) AS title_percent,

    ROUND(
        100.0 * COUNT(issue_url) / NULLIF(COUNT(*), 0),
        2
    ) AS url_percent,

    ROUND(
        100.0 * COUNT(status_changed_at) / NULLIF(COUNT(*), 0),
        2
    ) AS status_changed_percent
FROM custom_ts_secure_development.issues_current;
```

Если `issue_title`, `issue_url` или `status_changed_at` пустые почти у всех — это не ошибка Greenplum. Значит, мы ещё не угадали точные названия полей Vampy API.

# 11. Проверка событий статусов

```sql
SELECT
    COUNT(*) AS total_events,
    SUM(CASE WHEN is_baseline THEN 1 ELSE 0 END) AS baseline_events,
    SUM(CASE WHEN NOT is_baseline THEN 1 ELSE 0 END) AS real_transitions
FROM custom_ts_secure_development.issue_status_events;
```

Посмотреть последние события:

```sql
SELECT
    event_ts,
    issue_id,
    product_name,
    severity,
    previous_status,
    new_status,
    is_baseline
FROM custom_ts_secure_development.issue_status_events
ORDER BY event_ts DESC
LIMIT 50;
```

Проверка дублей событий:

```sql
SELECT
    event_id,
    COUNT(*) AS cnt
FROM custom_ts_secure_development.issue_status_events
GROUP BY event_id
HAVING COUNT(*) > 1;
```

Должно быть **0 строк**.

Если Python пока запускался только один раз и статусы не изменялись, отсутствие новых переходов нормально.

# 12. Дневной поток New / Reopened / Fixed

```sql
SELECT
    dt,
    SUM(new_cnt) AS new_cnt,
    SUM(recurrent_cnt) AS recurrent_cnt,
    SUM(reopened_cnt) AS reopened_cnt,
    SUM(fixed_cnt) AS fixed_cnt,
    SUM(false_positive_cnt) AS false_positive_cnt,
    SUM(exclusion_cnt) AS exclusion_cnt
FROM custom_ts_secure_development.issues_daily_flow
GROUP BY dt
ORDER BY dt DESC
LIMIT 30;
```

Если таблица пустая, проверь:

```sql
SELECT
    COUNT(*) AS non_baseline_events
FROM custom_ts_secure_development.issue_status_events
WHERE is_baseline = FALSE;
```

Если здесь `0`, пустой поток ожидаем: ещё не произошло зафиксированных смен статусов после baseline.

# 13. Проверка дневного остатка

```sql
SELECT
    dt,
    SUM(open_total) AS open_total,
    SUM(open_current_flow) AS open_current_flow,
    SUM(open_security_debt) AS security_debt
FROM custom_ts_secure_development.issues_daily_stock_summary
GROUP BY dt
ORDER BY dt DESC
LIMIT 30;
```

Последняя дата должна соответствовать сегодняшней дате по Москве.

Сравнение текущего остатка с дневным:

```sql
WITH current_kpi AS (
    SELECT
        SUM(open_total) AS current_open
    FROM custom_ts_secure_development.appsec_kpi_by_product
),
last_stock AS (
    SELECT
        SUM(open_total) AS stock_open
    FROM custom_ts_secure_development.issues_daily_stock_summary
    WHERE dt = (
        SELECT MAX(dt)
        FROM custom_ts_secure_development.issues_daily_stock_summary
    )
)
SELECT
    current_open,
    stock_open,
    current_open - stock_open AS difference
FROM current_kpi
CROSS JOIN last_stock;
```

`difference` желательно `0`.

# 14. Проверка Security Debt

```sql
SELECT
    COUNT(*) AS debt_cohort_size,
    COUNT(DISTINCT issue_id) AS unique_debt_issues
FROM custom_ts_secure_development.security_debt_cohort;
```

Значения должны совпадать.

```sql
SELECT
    current_status,
    debt_remaining_int,
    COUNT(*) AS cnt
FROM custom_ts_secure_development.security_debt_current
GROUP BY current_status, debt_remaining_int
ORDER BY current_status;
```

Потом сводка:

```sql
SELECT
    product_name,
    initial_total,
    current_remaining,
    current_critical,
    current_high,
    resolved_total,
    progress_percent,
    daily_velocity_28d,
    daily_velocity_90d,
    forecast_status
FROM custom_ts_secure_development.security_debt_summary_by_product
ORDER BY current_critical DESC, current_remaining DESC;
```

На первом этапе `daily_velocity_28d` и `daily_velocity_90d` могут быть `NULL`, если ещё нет истории на 28/90 дней. Это нормально.

# 15. Проверка MTTR

```sql
SELECT
    COUNT(*) AS mttr_cycles,
    MIN(mttr_days) AS min_mttr,
    MAX(mttr_days) AS max_mttr,
    PERCENTILE_CONT(0.5) WITHIN GROUP (
        ORDER BY mttr_days
    ) AS median_mttr
FROM custom_ts_secure_development.mttr_cycles;
```

Негативных значений быть не должно:

```sql
SELECT *
FROM custom_ts_secure_development.mttr_cycles
WHERE mttr_days < 0
   OR cycle_started_at IS NULL
   OR fixed_at <= cycle_started_at;
```

Должно быть **0 строк**.

---

## Самые важные результаты

Сначала пришли результаты вот этих пяти запросов:

```sql
SELECT * FROM custom_ts_secure_development.data_freshness;
```

```sql
SELECT
    COUNT(*) AS current_rows,
    COUNT(DISTINCT issue_id) AS unique_issues
FROM custom_ts_secure_development.issues_current;
```

```sql
SELECT status, COUNT(*)
FROM custom_ts_secure_development.issues_current
GROUP BY status
ORDER BY COUNT(*) DESC;
```

```sql
SELECT
    COUNT(*) AS products_count
FROM custom_ts_secure_development.dim_product;
```

```sql
SELECT
    COUNT(*) AS unmapped_issues
FROM custom_ts_secure_development.issues_unmapped_current;
```

По этим пяти сразу станет понятно, нормально ли перенеслись страницы API, статусы и продукты.
