#!/usr/bin/env python3
"""
Выгружает данные из Vampy API в Greenplum (КХД 2.0)
Схема: custom_ts_secure_development

"""

import os
import logging
import asyncio
import aiohttp
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime, timezone

# ============================================================
# НАСТРОЙКИ — заполни в /etc/vampy-to-gp.env
# ============================================================
VAMPY_URL   = os.environ.get("VAMPY_URL",   "https://vampy.your-company.ru")
VAMPY_TOKEN = os.environ.get("VAMPY_TOKEN", "your-bot-token")
GP_HOST     = os.environ.get("GP_HOST",     "greenplum-host")
GP_PORT     = os.environ.get("GP_PORT",     "5432")
GP_DB       = os.environ.get("GP_DB",       "your-db-name")
GP_USER     = os.environ.get("GP_USER",     "SA-SSP-G0002")
GP_PASSWORD = os.environ.get("GP_PASSWORD", "your-password")
GP_SCHEMA   = "custom_ts_secure_development"

CLOSED_STATUSES = {"Fixed", "False Positive", "Exclusion"}

# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("vampy-to-gp")
HEADERS = {"Authentication": VAMPY_TOKEN, "Accept": "application/json"}


def normalize_status(raw: str) -> str:
    m = {
        "new":            "New",
        "recurrent":      "New",
        "confirmed":      "Confirmed",
        "risk_accepted":  "Risk Accepted",
        "risk accepted":  "Risk Accepted",
        "reopened":       "Reopened",
        "security_debt":  "Security Debt",
        "security debt":  "Security Debt",
        "fixed":          "Fixed",
        "false_positive": "False Positive",
        "false positive": "False Positive",
        "exclusion":      "Exclusion",
    }
    return m.get((raw or "").lower().strip(), raw or "")


def normalize_severity(raw: str) -> str:
    m = {"critical": "CRITICAL", "high": "HIGH"}
    return m.get((raw or "").lower(), (raw or "").upper())


def parse_dt(s) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


# ------------------------------------------------------------
# Дефекты: GET /ext/v1/scan_issues/export/
# Возвращает {"items": [...]} — всё одним запросом, без пагинации
# Фильтруем только critical,high на стороне Vampy
# ------------------------------------------------------------
async def fetch_issues(session: aiohttp.ClientSession) -> list:
    log.info("Запрашиваем дефекты /ext/v1/scan_issues/export/ ...")
    async with session.get(
        f"{VAMPY_URL}/ext/v1/scan_issues/export/",
        headers=HEADERS,
        params={
            "payload":    "INLINE",
            "formatter":  "JSON",
            "severities": "critical,high",  # только нужные severity
        },
        timeout=aiohttp.ClientTimeout(total=300)
    ) as r:
        if r.status != 200:
            text = await r.text()
            raise Exception(f"Ошибка API {r.status}: {text[:300]}")
        data = await r.json()

    items = data.get("items", [])
    log.info(f"Получено дефектов: {len(items)}")
    return items


# ------------------------------------------------------------
# Продукты: GET /ext/v1/products/
# Есть пагинация: limit + offset + hasNext
# Поля: id, name, slug, repositoriesCount, riskScore
# ------------------------------------------------------------
async def fetch_products(session: aiohttp.ClientSession) -> list:
    log.info("Запрашиваем продукты /ext/v1/products/ ...")
    all_products = []
    offset = 0
    limit  = 50

    while True:
        async with session.get(
            f"{VAMPY_URL}/ext/v1/products/",
            headers=HEADERS,
            params={"limit": limit, "offset": offset},
            timeout=aiohttp.ClientTimeout(total=60)
        ) as r:
            data = await r.json()

        items    = data.get("items", [])
        has_next = data.get("hasNext", False)
        total    = data.get("totalCount", "?")
        all_products.extend(items)

        log.info(f"Продукты: {len(all_products)} / {total}")

        if not has_next or not items:
            break
        offset += limit

    return all_products


# ------------------------------------------------------------
# Подготовка строк дефектов для INSERT
# Поля из API: id, severity, status, product (slug),
# repository (slug), parser, created, completed, sla
# ------------------------------------------------------------
def prepare_issue_rows(items: list, snapshot_ts: datetime) -> list:
    rows = []
    for item in items:
        status   = normalize_status(item.get("status", ""))
        severity = normalize_severity(item.get("severity", ""))
        is_debt  = (status == "Security Debt")
        is_active = (status not in CLOSED_STATUSES)

        rows.append((
            snapshot_ts,
            str(item.get("id", "")),
            str(item.get("product", "") or ""),     # product slug
            str(item.get("product", "") or ""),     # product name (slug, уточним из products)
            str(item.get("repository", "") or ""),  # repository slug
            severity,
            status,
            str(item.get("parser", "") or ""),      # тип сканера
            is_debt,
            is_active,
            parse_dt(item.get("created")),
            parse_dt(item.get("completed")),        # дата закрытия
            parse_dt(item.get("sla")),              # дедлайн RA
        ))
    return rows


# ------------------------------------------------------------
# Подготовка строк продуктов для INSERT
# Поля: id, name, slug, repositoriesCount
# ------------------------------------------------------------
def prepare_product_rows(products: list, snapshot_ts: datetime) -> list:
    rows = []
    for p in products:
        rows.append((
            snapshot_ts,
            str(p.get("id", "")),
            str(p.get("name", p.get("slug", ""))),
            int(p.get("repositoriesCount", 0)),
        ))
    return rows


# ------------------------------------------------------------
# Запись в Greenplum
# ------------------------------------------------------------
def save_to_greenplum(
    issue_rows: list,
    product_rows: list,
    snapshot_ts: datetime
):
    dsn = (
        f"host={GP_HOST} port={GP_PORT} dbname={GP_DB} "
        f"user={GP_USER} password={GP_PASSWORD}"
    )
    conn = psycopg2.connect(dsn)
    cur  = conn.cursor()
    cur.execute(f"SET search_path TO {GP_SCHEMA}")

    # -- Дефекты --
    log.info(f"Пишем {len(issue_rows)} дефектов в issues_snapshot...")
    execute_values(cur, f"""
        INSERT INTO {GP_SCHEMA}.issues_snapshot (
            ts, issue_id, product_id, product_name, repository,
            severity, status, scanner, is_security_debt, is_active,
            created_at, updated_at, ra_deadline
        ) VALUES %s
    """, issue_rows, page_size=500)

    # -- Продукты --
    if product_rows:
        log.info(f"Пишем {len(product_rows)} продуктов в products_snapshot...")
        execute_values(cur, f"""
            INSERT INTO {GP_SCHEMA}.products_snapshot (
                ts, product_id, product_name, repos_count
            ) VALUES %s
        """, product_rows)

    # -- Обновляем product_name в issues_snapshot по slug --
    # product в дефектах приходит как slug, обновляем на реальное название
    log.info("Обновляем названия продуктов в issues_snapshot...")
    cur.execute(f"""
        UPDATE {GP_SCHEMA}.issues_snapshot i
        SET product_name = p.product_name
        FROM {GP_SCHEMA}.products_snapshot p
        WHERE i.product_id = p.product_id
          AND i.ts = %s
          AND p.ts = %s
    """, (snapshot_ts, snapshot_ts))

    # -- Дневные агрегаты --
    today = snapshot_ts.date()
    log.info("Обновляем дневные агрегаты issues_daily...")
    cur.execute(
        f"DELETE FROM {GP_SCHEMA}.issues_daily WHERE dt = %s", (today,)
    )
    cur.execute(f"""
        INSERT INTO {GP_SCHEMA}.issues_daily (
            dt, product_id, product_name,
            severity, status, scanner, is_security_debt, cnt
        )
        SELECT
            DATE(ts),
            product_id, product_name,
            severity, status, scanner,
            is_security_debt,
            COUNT(DISTINCT issue_id)
        FROM {GP_SCHEMA}.issues_snapshot
        WHERE ts = (SELECT MAX(ts) FROM {GP_SCHEMA}.issues_snapshot)
        GROUP BY
            DATE(ts), product_id, product_name,
            severity, status, scanner, is_security_debt
    """)

    conn.commit()
    cur.close()
    conn.close()
    log.info("Greenplum обновлён.")


# ------------------------------------------------------------
# Главная функция
# ------------------------------------------------------------
async def main():
    snapshot_ts = datetime.now(timezone.utc)
    log.info(f"=== Старт: {snapshot_ts} ===")

    async with aiohttp.ClientSession() as session:
        issues, products = await asyncio.gather(
            fetch_issues(session),
            fetch_products(session),
        )

    if not issues:
        log.warning("Дефектов не получено — пропускаем.")
        return

    issue_rows   = prepare_issue_rows(issues, snapshot_ts)
    product_rows = prepare_product_rows(products, snapshot_ts)
    save_to_greenplum(issue_rows, product_rows, snapshot_ts)
    log.info("=== Готово ===")


if __name__ == "__main__":
    asyncio.run(main())