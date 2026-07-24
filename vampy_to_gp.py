По логу сам запуск завершился нормально:

```text
issues = 33 027
дубли = 0
без repository_id = 0
репозиториев = 907
рабочих связей = 799
mapped repositories = 729
unmapped repositories = 178
events = 266
```

Главное сейчас — понять, **сколько дефектов сидит в 178 непривязанных репозиториях**, и проверить количество продуктов: API сейчас вернул уже **40**, а не 39.

Все запросы ниже только читают данные.

## 1. Последний снапшот: все ли 33 027 строк записались

```sql
WITH latest AS (
    SELECT MAX(ts) AS max_ts
    FROM custom_ts_secure_development.issues_snapshot
)
SELECT
    l.max_ts AS snapshot_ts,
    COUNT(*) AS snapshot_rows,
    COUNT(DISTINCT i.issue_id) AS unique_issues,
    COUNT(*) - COUNT(DISTINCT i.issue_id) AS duplicate_rows,
    COUNT(DISTINCT i.repository_id) AS repositories
FROM custom_ts_secure_development.issues_snapshot i
CROSS JOIN latest l
WHERE i.ts = l.max_ts
GROUP BY l.max_ts;
```

Ожидаем:

```text
snapshot_rows    = 33027
unique_issues    = 33027
duplicate_rows   = 0
repositories     = 907
```

## 2. Свежесть загрузки

```sql
SELECT *
FROM custom_ts_secure_development.data_freshness;
```

Сейчас должно быть:

```text
freshness_status = OK
```

## 3. Проверка количества продуктов

```sql
WITH latest AS (
    SELECT MAX(ts) AS max_ts
    FROM custom_ts_secure_development.products_snapshot
)
SELECT
    COUNT(*) AS raw_product_rows,
    COUNT(DISTINCT p.product_id) AS raw_unique_products,
    (
        SELECT COUNT(*)
        FROM custom_ts_secure_development.dim_product
    ) AS dashboard_products
FROM custom_ts_secure_development.products_snapshot p
CROSS JOIN latest l
WHERE p.ts = l.max_ts;
```

По логу ожидаем:

```text
raw_unique_products = 40
dashboard_products   = 38
```

Почему 38: из 40 исключаются `TEST` и `Default product`.

Раньше было 39 продуктов и ожидалось 37. Значит, в ASOC, похоже, появился ещё один продукт. Посмотри полный рабочий список:

```sql
SELECT
    product_id,
    product_name,
    product_slug,
    criticality,
    repos_count
FROM custom_ts_secure_development.dim_product
ORDER BY product_name;
```

Если по бизнес-логике продуктов должно быть строго 37, найдём в этом списке третий технический продукт и исключим его по UUID.

## 4. Проверка связи repository → product

```sql
WITH repositories AS (
    SELECT DISTINCT repository_id
    FROM custom_ts_secure_development.issues_current_all
    WHERE repository_id IS NOT NULL
),
mapped AS (
    SELECT DISTINCT repository_id
    FROM custom_ts_secure_development.repository_product_current
)
SELECT
    COUNT(*) AS total_repositories,
    SUM(
        CASE WHEN m.repository_id IS NOT NULL
             THEN 1 ELSE 0 END
    ) AS mapped_repositories,
    SUM(
        CASE WHEN m.repository_id IS NULL
             THEN 1 ELSE 0 END
    ) AS unmapped_repositories,
    (
        SELECT COUNT(*)
        FROM custom_ts_secure_development.repository_product_current
    ) AS working_relations
FROM repositories r
LEFT JOIN mapped m
  ON m.repository_id = r.repository_id;
```

Ожидаем по логу:

```text
total_repositories    = 907
mapped_repositories   = 729
unmapped_repositories = 178
working_relations     = 799
```

799 больше 729 — это нормально: некоторые репозитории относятся сразу к нескольким продуктам.

## 5. Сколько дефектов реально попало в продукты

Это сейчас самая важная проверка:

```sql
SELECT
    (
        SELECT COUNT(*)
        FROM custom_ts_secure_development.issues_current
    ) AS dashboard_issues,

    (
        SELECT COUNT(DISTINCT issue_id)
        FROM custom_ts_secure_development.issues_current_by_product
    ) AS mapped_distinct_issues,

    (
        SELECT COUNT(*)
        FROM custom_ts_secure_development.issues_unmapped_current
    ) AS unmapped_issues,

    (
        SELECT COUNT(*)
        FROM custom_ts_secure_development.issues_current_by_product
    ) AS product_issue_rows;
```

Проверяем равенство:

```text
dashboard_issues =
mapped_distinct_issues + unmapped_issues
```

`product_issue_rows` может быть больше `mapped_distinct_issues` — это правильно, потому что один дефект может отображаться в нескольких продуктах.

## 6. Почему 178 репозиториев остались без рабочего продукта

Этот запрос разделит их на две группы:

* репозиторий связан только с исключёнными `TEST`/`Default product`;
* API вообще не вернул продукт.

```sql
WITH unmapped AS (
    SELECT
        issue_id,
        repository_id,
        repository
    FROM custom_ts_secure_development.issues_unmapped_current
),
classified AS (
    SELECT
        u.*,
        CASE
            WHEN EXISTS (
                SELECT 1
                FROM custom_ts_secure_development.repository_product_current_all rp
                WHERE rp.repository_id = u.repository_id
                  AND rp.product_id IN (
                      'd569ed52-b01f-4222-948b-705b008ae64a',
                      '1a16d04d-cd14-4894-b887-4ba7465c26aa'
                  )
            )
            THEN 'ONLY TEST / DEFAULT PRODUCT'
            ELSE 'API RETURNED NO PRODUCT'
        END AS unmapped_reason
    FROM unmapped u
)
SELECT
    unmapped_reason,
    COUNT(DISTINCT repository_id) AS repositories,
    COUNT(DISTINCT issue_id) AS issues
FROM classified
GROUP BY unmapped_reason
ORDER BY unmapped_reason;
```

И топ непривязанных репозиториев:

```sql
SELECT
    repository_id,
    repository,
    COUNT(*) AS issues_count,
    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END)
        AS critical_count,
    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END)
        AS high_count
FROM custom_ts_secure_development.issues_unmapped_current
GROUP BY repository_id, repository
ORDER BY issues_count DESC
LIMIT 30;
```

Если большинство относится только к `TEST`/`Default product`, всё нормально. Если много строк в `API RETURNED NO PRODUCT`, часть данных действительно не попадёт в продуктовые дашборды.

## 7. Проверка исключений

```sql
SELECT
    (
        SELECT COUNT(*)
        FROM custom_ts_secure_development.issues_current_all
        WHERE status = 'check_required'
    ) AS check_required_in_raw,

    (
        SELECT COUNT(*)
        FROM custom_ts_secure_development.issues_current
        WHERE status = 'check_required'
    ) AS check_required_in_dashboard,

    (
        SELECT COUNT(*)
        FROM custom_ts_secure_development.dim_product
        WHERE product_id IN (
            'd569ed52-b01f-4222-948b-705b008ae64a',
            '1a16d04d-cd14-4894-b887-4ba7465c26aa'
        )
    ) AS excluded_products_in_dashboard;
```

Ожидаем:

```text
check_required_in_dashboard     = 0
excluded_products_in_dashboard  = 0
```

`check_required_in_raw` может быть больше нуля — так и задумано.

## 8. Нет ли дублей issue внутри одного продукта

```sql
SELECT
    issue_id,
    product_id,
    COUNT(*) AS cnt
FROM custom_ts_secure_development.issues_current_by_product
GROUP BY issue_id, product_id
HAVING COUNT(*) > 1
ORDER BY cnt DESC;
```

Должно быть **0 строк**.

## 9. Арифметика KPI по продуктам

```sql
SELECT
    product_id,
    product_name,
    open_total,
    open_total_critical,
    open_total_high,
    open_current_flow,
    security_debt_total
FROM custom_ts_secure_development.appsec_kpi_by_product
WHERE open_total <> open_total_critical + open_total_high
   OR open_total <> open_current_flow + security_debt_total;
```

Должно быть **0 строк**.

Посмотреть итоговую таблицу для FineBI:

```sql
SELECT
    product_name,
    repos_count,
    open_total,
    open_total_critical,
    open_total_high,
    confirmed_total,
    reopened_total,
    risk_accepted_total,
    security_debt_total,
    red_zone_total
FROM custom_ts_secure_development.products_comparison_current
ORDER BY red_zone_total DESC, open_total DESC;
```

Здесь уже должны быть ненулевые показатели.

## 10. Красная зона

```sql
SELECT
    (
        SELECT red_zone_total
        FROM custom_ts_secure_development.appsec_summary
    ) AS global_red_zone_issues,

    (
        SELECT COUNT(DISTINCT issue_id)
        FROM custom_ts_secure_development.red_zone
    ) AS mapped_red_zone_issues,

    (
        SELECT COUNT(*)
        FROM custom_ts_secure_development.red_zone
    ) AS product_red_zone_rows;
```

`product_red_zone_rows` может быть больше числа уникальных дефектов из-за связи одного репозитория с несколькими продуктами.

Посмотреть реальные строки:

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
LIMIT 50;
```

Теперь результат не должен быть пустым.

## 11. Проверка событий статусов

```sql
SELECT
    COUNT(*) AS total_events,
    COUNT(DISTINCT event_id) AS unique_events,
    SUM(CASE WHEN is_baseline THEN 1 ELSE 0 END) AS baseline_events,
    SUM(CASE WHEN NOT is_baseline THEN 1 ELSE 0 END) AS real_transitions,
    MAX(event_ts) AS latest_event_ts
FROM custom_ts_secure_development.issue_status_events;
```

Проверка дублей:

```sql
SELECT
    event_id,
    COUNT(*) AS cnt
FROM custom_ts_secure_development.issue_status_events
GROUP BY event_id
HAVING COUNT(*) > 1;
```

Должно быть **0 строк**.

## 12. Проверка заполненности важных полей

```sql
SELECT
    COUNT(*) AS total,
    COUNT(issue_title) AS with_title,
    COUNT(repository_id) AS with_repository_id,
    COUNT(issue_url) AS with_url,
    COUNT(status_changed_at) AS with_status_changed_at,
    COUNT(ra_deadline) AS with_ra_deadline
FROM custom_ts_secure_development.issues_current_all;
```

Ожидаем:

```text
with_title          = total
with_repository_id  = total
```

`with_url` и `with_status_changed_at` могут остаться нулевыми — API их в найденном ответе не отдавал. Основные KPI от этого работают, но кликабельная ссылка на дефект и точный возраст текущего статуса пока ограничены.

Сначала пришли результаты запросов **3, 5 и 6**. По ним сразу будет понятно, готовы ли продуктовые данные к подключению в FineBI или надо разобраться с частью 178 репозиториев.
