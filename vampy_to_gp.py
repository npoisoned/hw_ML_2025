#!/usr/bin/env python3
import os
import logging
import asyncio
import aiohttp
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# Загрузка .env файла
# ============================================================
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

# ============================================================
# НАСТРОЙКИ из .env
# ============================================================
VAMPY_URL   = os.environ["VAMPY_URL"]
VAMPY_TOKEN = os.environ["VAMPY_TOKEN"]
GP_HOST     = os.environ["GP_HOST"]
GP_PORT     = os.environ.get("GP_PORT", "5050")
GP_DB       = os.environ["GP_DB"]
GP_USER     = os.environ["GP_USER"]
GP_PASSWORD = os.environ["GP_PASSWORD"]
GP_SCHEMA   = os.environ.get("GP_SCHEMA", "custom_ts_secure_development")

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


async def fetch_issues(session: aiohttp.ClientSession) -> list:
    log.info("Запрашиваем дефекты /ext/v1/scan_issues/export/ ...")
    async with session.get(
        f"{VAMPY_URL}/ext/v1/scan_issues/export/",
        headers=HEADERS,
        params={
            "payload":    "INLINE",
            "formatter":  "JSON",
            "severities": "critical,high",
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


def prepare_issue_rows(items: list, snapshot_ts: datetime) -> list:
    rows = []
    for item in items:
        status    = normalize_status(item.get("status", ""))
        severity  = normalize_severity(item.get("severity", ""))
        is_debt   = (status == "Security Debt")
        is_active = (status not in CLOSED_STATUSES)
        rows.append((
            snapshot_ts,
            str(item.get("id", "")),
            str(item.get("product", "") or ""),
            str(item.get("product", "") or ""),
            str(item.get("repository", "") or ""),
            severity,
            status,
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

    log.info("Обновляем названия продуктов...")
    cur.execute(f"""
        UPDATE {GP_SCHEMA}.issues_snapshot i
        SET product_name = p.product_name
        FROM {GP_SCHEMA}.products_snapshot p
        WHERE i.product_id = p.product_id
          AND i.ts = %s
          AND p.ts = %s
    """, (snapshot_ts, snapshot_ts))

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
