#!/usr/bin/env python3
"""
vampy_to_gp_final.py
Выгружает данные из Vampy API в Greenplum (КХД 2.0)
Читает настройки из /home/akhvostovets/vampy-to-gp/.env

Статусы хранятся как есть из Vampy — маппинг в FineBI/views
"""

import os
import logging
import asyncio
import aiohttp
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime, timezone
from pathlib import Path


def load_env(path: str = "/home/akhvostovets/vampy-to-gp/.env"):
    env_file = Path(path)
    if not env_file.exists():
        raise FileNotFoundError(f".env файл не найден: {path}")
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


load_env()

VAMPY_URL   = os.environ["VAMPY_URL"]
VAMPY_TOKEN = os.environ["VAMPY_TOKEN"]
GP_HOST     = os.environ["GP_HOST"]
GP_PORT     = os.environ.get("GP_PORT", "5050")
GP_DB       = os.environ["GP_DB"]
GP_USER     = os.environ["GP_USER"]
GP_PASSWORD = os.environ["GP_PASSWORD"]
GP_SCHEMA   = os.environ.get("GP_SCHEMA", "custom_ts_secure_development")
SPACE_ID    = os.environ.get("VAMPY_SPACE_ID", "")

# Закрытые статусы (для поля is_active)
# Оригинальные названия из Vampy API
CLOSED_STATUSES = {
    "fixed",
    "false_positive",
    "exclusion",
    "risk_accepted",
    "security-debt",
    "archive",
    "not-applicable",
    "wont-fix",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("vampy-to-gp")
HEADERS = {
    "Authentication": VAMPY_TOKEN,
    "Accept": "application/json",
    "Content-Type": "application/json",
}


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


async def fetch_issues(session: aiohttp.ClientSession) -> list:
    log.info("Запрашиваем дефекты POST /api/scan_issues/filter/ ...")
    all_issues = []
    offset = 0
    limit  = 60

    body = {"severities": ["CRITICAL", "HIGH"]}

    while True:
        async with session.post(
            f"{VAMPY_URL}/api/scan_issues/filter/",
            headers=HEADERS,
            params={
                "offset": offset,
                "limit":  limit,
                "order":  "-severity,created,filePath"
            },
            json=body,
            timeout=aiohttp.ClientTimeout(total=300)
        ) as r:
            if r.status != 200:
                text = await r.text()
                raise Exception(f"Ошибка API {r.status}: {text[:300]}")
            data = await r.json()

        items = data.get("items", [])
        all_issues.extend(items)

        total    = data.get("totalCount", data.get("total", len(all_issues)))
        has_next = len(all_issues) < total and len(items) == limit

        log.info(f"Дефектов: {len(all_issues)} / {total}")

        if not has_next or not items:
            break
        offset += limit

    log.info(f"Итого дефектов: {len(all_issues)}")
    return all_issues


async def fetch_products(session: aiohttp.ClientSession) -> list:
    if not SPACE_ID:
        log.warning("VAMPY_SPACE_ID не задан — продукты пропускаем")
        return []

    log.info(f"Запрашиваем продукты /api/spaces/{SPACE_ID}/products/ ...")
    all_products = []
    offset = 0
    limit  = 60

    while True:
        async with session.get(
            f"{VAMPY_URL}/api/spaces/{SPACE_ID}/products/",
            headers=HEADERS,
            params={"limit": limit, "offset": offset},
            timeout=aiohttp.ClientTimeout(total=60)
        ) as r:
            if r.status != 200:
                text = await r.text()
                log.error(f"Ошибка продуктов {r.status}: {text[:200]}")
                break
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


def prepare_issue_rows(items: list, snapshot_ts: datetime) -> list:
    rows = []
    for item in items:
        # Статус — храним как есть из Vampy
        raw_status = (item.get("status") or "").lower().strip()
        severity   = normalize_severity(item.get("severity", ""))

        # is_security_debt — статус security-debt
        is_debt   = (raw_status == "security-debt")

        # is_active — открытый или закрытый
        is_active = (raw_status not in CLOSED_STATUSES)

        # repository — объект
        repo = item.get("repository") or {}
        repo_name = repo.get("name", repo.get("slug", "")) if isinstance(repo, dict) else str(repo)

        # product — может быть null
        product = item.get("product") or {}
        if isinstance(product, dict) and product:
            product_id   = str(product.get("id", ""))
            product_name = product.get("name", product.get("slug", ""))
        else:
            product_id   = ""
            product_name = ""

        rows.append((
            snapshot_ts,
            str(item.get("id", "")),
            product_id,
            product_name,
            repo_name,
            severity,
            raw_status,              # оригинальный статус из Vampy
            str(item.get("parser", "") or ""),
            is_debt,
            is_active,
            parse_dt(item.get("created")),
            parse_dt(item.get("completed")),
            parse_dt(item.get("sla")),
        ))
    return rows


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


def save_to_greenplum(issue_rows: list, product_rows: list, snapshot_ts: datetime):
    dsn = (
        f"host={GP_HOST} port={GP_PORT} dbname={GP_DB} "
        f"user={GP_USER} password={GP_PASSWORD}"
    )
    conn = psycopg2.connect(dsn)
    cur  = conn.cursor()

    log.info(f"Пишем {len(issue_rows)} дефектов в issues_snapshot...")
    execute_values(cur, f"""
        INSERT INTO {GP_SCHEMA}.issues_snapshot (
            ts, issue_id, product_id, product_name, repository,
            severity, status, scanner, is_security_debt, is_active,
            created_at, updated_at, ra_deadline
        ) VALUES %s
    """, issue_rows, page_size=500)

    if product_rows:
        log.info(f"Пишем {len(product_rows)} продуктов в products_snapshot...")
        execute_values(cur, f"""
            INSERT INTO {GP_SCHEMA}.products_snapshot (
                ts, product_id, product_name, repos_count
            ) VALUES %s
        """, product_rows)

    log.info("Обновляем дневные агрегаты...")
    today = snapshot_ts.date()
    cur.execute(f"DELETE FROM {GP_SCHEMA}.issues_daily WHERE dt = %s", (today,))
    cur.execute(f"""
        INSERT INTO {GP_SCHEMA}.issues_daily (
            dt, product_id, product_name,
            severity, status, scanner, is_security_debt, cnt
        )
        SELECT
            DATE(ts), product_id, product_name,
            severity, status, scanner, is_security_debt,
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
