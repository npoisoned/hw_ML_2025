#!/usr/bin/env python3
"""
vampy_to_gp_final_v6.py

Выгружает Critical/High из Hexway Vampy в Greenplum и поддерживает
аналитический слой для FineBI:

- issues_snapshot: полный текущий снапшот;
- products_snapshot: снапшот продуктов;
- issue_status_events: реальные изменения статусов между выгрузками;
- security_debt_cohort: историческая принадлежность к Security Debt;
- issues_daily_stock: остаток по статусам на конец дня;
- security_debt_daily: ежедневный остаток и погашение Security Debt.

ВАЖНО:
- defaultRelations=True сохранён намеренно: анализируются дефекты,
  связанные с дефолтными ветками.
- Workflow, SLA и переходы статусов выполняет Vampy.
- Скрипт только сохраняет фактическое состояние и изменения.
- Перед запуском выполнить appsec_greenplum_full_v1.sql.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import aiohttp
import psycopg2
from psycopg2 import sql
from psycopg2.extras import execute_values


ENV_PATH = "/home/akhvostovets/vampy-to-gp/.env"
MOSCOW_TZ = ZoneInfo("Europe/Moscow")

PAGE_SIZE = 60
REQUEST_RETRIES = 4
ISSUES_TIMEOUT_SECONDS = 300
PRODUCTS_TIMEOUT_SECONDS = 60

# Для аналитики эти состояния считаются нерешёнными.
# Это не управление workflow Vampy, а только признак для данных.
ACTIVE_STATUSES = {
    "new_issue",
    "recurrent",
    "confirmed",
    "risk_accepted",
    "reopened",
    "security-debt",
}

CLOSED_STATUSES = {
    "fixed",
    "false_positive",
    "exclusion",
    "archive",
    "not-applicable",
    "wont-fix",
}

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH"}


def load_env(path: str = ENV_PATH) -> None:
    env_file = Path(path)
    if not env_file.exists():
        raise FileNotFoundError(f".env файл не найден: {path}")

    with env_file.open(encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


load_env()

VAMPY_URL = os.environ["VAMPY_URL"].rstrip("/")
VAMPY_TOKEN = os.environ["VAMPY_TOKEN"]
SPACE_ID = os.environ.get("VAMPY_SPACE_ID", "").strip()

GP_HOST = os.environ["GP_HOST"]
GP_PORT = os.environ.get("GP_PORT", "5050")
GP_DB = os.environ["GP_DB"]
GP_USER = os.environ["GP_USER"]
GP_PASSWORD = os.environ["GP_PASSWORD"]
GP_SCHEMA = os.environ.get(
    "GP_SCHEMA",
    "custom_ts_secure_development",
).strip()

# Необязательный шаблон, только если API не отдаёт готовую ссылку.
# Пример значения в .env:
# VAMPY_ISSUE_URL_TEMPLATE=https://vampy.example/issues/{issue_id}
ISSUE_URL_TEMPLATE = os.environ.get("VAMPY_ISSUE_URL_TEMPLATE", "").strip()

# Пишет только названия ключей первого ответа, без значений.
DEBUG_API_KEYS = os.environ.get(
    "VAMPY_DEBUG_API_KEYS",
    "false",
).lower() in {"1", "true", "yes"}

if not GP_SCHEMA.replace("_", "").isalnum():
    raise ValueError(f"Недопустимое имя схемы: {GP_SCHEMA!r}")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("vampy-to-gp")

HEADERS = {
    "Authentication": VAMPY_TOKEN,
    "Accept": "application/json",
    "Content-Type": "application/json",
}


@dataclass(frozen=True)
class IssueRecord:
    snapshot_ts: datetime
    issue_id: str
    issue_title: str | None
    issue_url: str | None

    product_id: str | None
    product_name: str | None
    repository: str | None

    severity: str
    status: str
    scanner: str | None

    is_security_debt: bool
    is_active: bool

    created_at: datetime | None
    status_changed_at: datetime | None
    updated_at: datetime | None
    ra_deadline: datetime | None


@dataclass(frozen=True)
class PreviousIssue:
    issue_id: str
    status: str
    product_id: str | None
    product_name: str | None
    repository: str | None
    severity: str
    scanner: str | None
    created_at: datetime | None
    ra_deadline: datetime | None


def clean_text(value: Any) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    return text or None


def first_value(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def object_name(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, str):
        return clean_text(value)

    if isinstance(value, dict):
        candidate = first_value(
            value,
            "name",
            "title",
            "slug",
            "type",
            "code",
            "id",
        )
        return clean_text(candidate)

    return clean_text(value)


def normalize_status(raw: Any) -> str:
    return (clean_text(raw) or "").lower()


def normalize_severity(raw: Any) -> str:
    return (clean_text(raw) or "").upper()


def parse_api_dt(value: Any) -> datetime | None:
    """
    Возвращает aware datetime.

    Если API неожиданно прислал дату без offset/Z, считаем её UTC.
    """
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value).strip().replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def to_db_timestamp(value: datetime | None) -> datetime | None:
    """
    База из текущего SQL использует TIMESTAMP WITHOUT TIME ZONE.
    Сохраняем московское локальное время без tzinfo и задаём такую же
    timezone для соединения Greenplum.
    """
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(MOSCOW_TZ).replace(tzinfo=None)


def extract_relations(item: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Некоторые версии API могут возвращать relation/defaultRelations.
    Поле defaultRelations=True в запросе не меняем.
    """
    for key in (
        "defaultRelations",
        "default_relations",
        "relations",
    ):
        value = item.get(key)
        if isinstance(value, list):
            return [entry for entry in value if isinstance(entry, dict)]
        if isinstance(value, dict):
            return [value]

    return []


def extract_repository_object(item: dict[str, Any]) -> Any:
    repository = item.get("repository")
    if repository:
        return repository

    for relation in extract_relations(item):
        repository = relation.get("repository")
        if repository:
            return repository

        # Иногда relation сам содержит поля репозитория.
        if any(key in relation for key in ("name", "slug", "path")):
            return relation

    return None


def extract_repository_name(item: dict[str, Any]) -> str | None:
    repository = extract_repository_object(item)

    if isinstance(repository, dict):
        return clean_text(
            first_value(
                repository,
                "name",
                "slug",
                "path",
                "fullName",
                "full_name",
            )
        )

    return clean_text(repository)


def extract_product_object(item: dict[str, Any]) -> Any:
    product = item.get("product")
    if product:
        return product

    repository = extract_repository_object(item)
    if isinstance(repository, dict) and repository.get("product"):
        return repository["product"]

    for relation in extract_relations(item):
        if relation.get("product"):
            return relation["product"]

        relation_repository = relation.get("repository")
        if (
            isinstance(relation_repository, dict)
            and relation_repository.get("product")
        ):
            return relation_repository["product"]

    return None


def extract_product(item: dict[str, Any]) -> tuple[str | None, str | None]:
    product = extract_product_object(item)

    if not isinstance(product, dict):
        return None, clean_text(product)

    product_id = clean_text(
        first_value(product, "id", "uuid", "productId", "product_id")
    )
    product_name = clean_text(
        first_value(product, "name", "slug", "title")
    )
    return product_id, product_name


def extract_scanner(item: dict[str, Any]) -> str | None:
    return object_name(
        first_value(
            item,
            "parser",
            "scanner",
            "parserType",
            "parser_type",
            "scannerType",
            "scanner_type",
        )
    )


def extract_issue_title(item: dict[str, Any]) -> str | None:
    direct = first_value(
        item,
        "title",
        "name",
        "ruleName",
        "rule_name",
        "vulnerabilityName",
        "vulnerability_name",
    )
    if direct:
        return clean_text(direct)

    for nested_key in ("rule", "vulnerability", "issueType", "issue_type"):
        nested = item.get(nested_key)
        if isinstance(nested, dict):
            title = first_value(nested, "name", "title", "id")
            if title:
                return clean_text(title)

    return None


def extract_issue_url(item: dict[str, Any], issue_id: str) -> str | None:
    direct = first_value(
        item,
        "url",
        "webUrl",
        "web_url",
        "link",
        "issueUrl",
        "issue_url",
    )
    if direct:
        return clean_text(direct)

    if ISSUE_URL_TEMPLATE:
        try:
            return ISSUE_URL_TEMPLATE.format(issue_id=issue_id)
        except (KeyError, ValueError):
            log.warning(
                "Некорректный VAMPY_ISSUE_URL_TEMPLATE: %s",
                ISSUE_URL_TEMPLATE,
            )

    return None


def extract_status_changed_at(item: dict[str, Any]) -> datetime | None:
    """
    completed намеренно НЕ используется как дата смены статуса:
    без примера ответа API его семантика не подтверждена.
    """
    return parse_api_dt(
        first_value(
            item,
            "statusChangedAt",
            "status_changed_at",
            "statusUpdatedAt",
            "status_updated_at",
            "statusChanged",
            "status_changed",
        )
    )


def extract_updated_at(item: dict[str, Any]) -> datetime | None:
    return parse_api_dt(
        first_value(
            item,
            "updated",
            "updatedAt",
            "updated_at",
            "modified",
            "modifiedAt",
            "modified_at",
            "completed",
        )
    )


def make_event_id(
    issue_id: str,
    event_ts: datetime,
    previous_status: str | None,
    new_status: str,
) -> str:
    raw = "|".join(
        (
            issue_id,
            event_ts.isoformat(timespec="microseconds"),
            previous_status or "",
            new_status,
        )
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def request_json(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    timeout_seconds: int,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    last_error: Exception | None = None

    for attempt in range(1, REQUEST_RETRIES + 1):
        try:
            timeout = aiohttp.ClientTimeout(total=timeout_seconds)

            async with session.request(
                method,
                url,
                headers=HEADERS,
                params=params,
                json=json_body,
                timeout=timeout,
            ) as response:
                if response.status == 200:
                    payload = await response.json()
                    if not isinstance(payload, dict):
                        raise RuntimeError(
                            f"API вернул не объект JSON: {type(payload)!r}"
                        )
                    return payload

                text = await response.text()

                if response.status == 429 or 500 <= response.status < 600:
                    retry_after = response.headers.get("Retry-After")
                    delay = (
                        int(retry_after)
                        if retry_after and retry_after.isdigit()
                        else min(2 ** attempt, 30)
                    )
                    log.warning(
                        "API %s, попытка %s/%s, повтор через %s сек: %s",
                        response.status,
                        attempt,
                        REQUEST_RETRIES,
                        delay,
                        text[:300],
                    )
                    await asyncio.sleep(delay)
                    continue

                raise RuntimeError(
                    f"Ошибка API {response.status}: {text[:500]}"
                )

        except (
            aiohttp.ClientError,
            asyncio.TimeoutError,
            RuntimeError,
        ) as error:
            last_error = error
            if attempt == REQUEST_RETRIES:
                break

            delay = min(2 ** attempt, 30)
            log.warning(
                "Ошибка запроса, попытка %s/%s, повтор через %s сек: %s",
                attempt,
                REQUEST_RETRIES,
                delay,
                error,
            )
            await asyncio.sleep(delay)

    raise RuntimeError(
        f"Запрос не выполнен после {REQUEST_RETRIES} попыток: {url}"
    ) from last_error


async def fetch_issues(
    session: aiohttp.ClientSession,
) -> list[dict[str, Any]]:
    log.info(
        "Запрашиваем POST /api/scan_issues/filter/, "
        "defaultRelations=True"
    )

    all_issues: list[dict[str, Any]] = []
    offset = 0

    body = {
        "severities": ["CRITICAL", "HIGH"],

        # ОСТАВЛЯЕМ TRUE:
        # дашборд строится по дефолтным веткам.
        "defaultRelations": True,
    }

    while True:
        data = await request_json(
            session,
            "POST",
            f"{VAMPY_URL}/api/scan_issues/filter/",
            timeout_seconds=ISSUES_TIMEOUT_SECONDS,
            params={
                "offset": offset,
                "limit": PAGE_SIZE,
                "order": "-severity,created,filePath",
            },
            json_body=body,
        )

        items = data.get("items") or []
        if not isinstance(items, list):
            raise RuntimeError("Поле items в issues API не является списком")

        if DEBUG_API_KEYS and offset == 0 and items:
            first_item = items[0]
            if isinstance(first_item, dict):
                log.info(
                    "Ключи первого issue: %s",
                    sorted(first_item.keys()),
                )

        valid_items = [item for item in items if isinstance(item, dict)]
        all_issues.extend(valid_items)

        total_raw = data.get("totalCount", data.get("total"))
        total = (
            int(total_raw)
            if isinstance(total_raw, (int, str))
            and str(total_raw).isdigit()
            else None
        )

        has_next_api = data.get("hasNext")
        if isinstance(has_next_api, bool):
            has_next = has_next_api
        elif total is not None:
            has_next = len(all_issues) < total and len(items) == PAGE_SIZE
        else:
            has_next = len(items) == PAGE_SIZE

        log.info(
            "Дефектов получено: %s%s",
            len(all_issues),
            f" / {total}" if total is not None else "",
        )

        if not has_next or not items:
            break

        offset += PAGE_SIZE

    log.info("Итого дефектов из API: %s", len(all_issues))
    return all_issues


async def fetch_products(
    session: aiohttp.ClientSession,
) -> list[dict[str, Any]]:
    if not SPACE_ID:
        log.warning(
            "VAMPY_SPACE_ID не задан — products_snapshot не обновляется"
        )
        return []

    log.info(
        "Запрашиваем GET /api/spaces/%s/products/",
        SPACE_ID,
    )

    all_products: list[dict[str, Any]] = []
    offset = 0

    while True:
        data = await request_json(
            session,
            "GET",
            f"{VAMPY_URL}/api/spaces/{SPACE_ID}/products/",
            timeout_seconds=PRODUCTS_TIMEOUT_SECONDS,
            params={
                "limit": PAGE_SIZE,
                "offset": offset,
            },
        )

        items = data.get("items") or []
        if not isinstance(items, list):
            raise RuntimeError("Поле items в products API не является списком")

        if DEBUG_API_KEYS and offset == 0 and items:
            first_item = items[0]
            if isinstance(first_item, dict):
                log.info(
                    "Ключи первого product: %s",
                    sorted(first_item.keys()),
                )

        valid_items = [item for item in items if isinstance(item, dict)]
        all_products.extend(valid_items)

        total_raw = data.get("totalCount", data.get("total"))
        total = (
            int(total_raw)
            if isinstance(total_raw, (int, str))
            and str(total_raw).isdigit()
            else None
        )

        has_next_api = data.get("hasNext")
        if isinstance(has_next_api, bool):
            has_next = has_next_api
        elif total is not None:
            has_next = len(all_products) < total and len(items) == PAGE_SIZE
        else:
            has_next = len(items) == PAGE_SIZE

        log.info(
            "Продуктов получено: %s%s",
            len(all_products),
            f" / {total}" if total is not None else "",
        )

        if not has_next or not items:
            break

        offset += PAGE_SIZE

    return all_products


def prepare_issue_records(
    items: list[dict[str, Any]],
    snapshot_ts: datetime,
) -> list[IssueRecord]:
    records_by_id: dict[str, IssueRecord] = {}
    duplicates = 0
    missing_product = 0
    missing_repository = 0
    skipped = 0

    snapshot_db_ts = to_db_timestamp(snapshot_ts)
    assert snapshot_db_ts is not None

    for item in items:
        issue_id = clean_text(first_value(item, "id", "uuid"))
        if not issue_id:
            skipped += 1
            continue

        severity = normalize_severity(item.get("severity"))
        if severity not in ALLOWED_SEVERITIES:
            skipped += 1
            continue

        status = normalize_status(item.get("status"))
        product_id, product_name = extract_product(item)
        repository = extract_repository_name(item)
        scanner = extract_scanner(item)

        if not product_id:
            missing_product += 1
        if not repository:
            missing_repository += 1

        record = IssueRecord(
            snapshot_ts=snapshot_db_ts,
            issue_id=issue_id,
            issue_title=extract_issue_title(item),
            issue_url=extract_issue_url(item, issue_id),

            product_id=product_id,
            product_name=product_name,
            repository=repository,

            severity=severity,
            status=status,
            scanner=scanner,

            is_security_debt=(status == "security-debt"),
            is_active=(status in ACTIVE_STATUSES),

            created_at=to_db_timestamp(
                parse_api_dt(
                    first_value(item, "created", "createdAt", "created_at")
                )
            ),
            status_changed_at=to_db_timestamp(
                extract_status_changed_at(item)
            ),
            updated_at=to_db_timestamp(extract_updated_at(item)),
            ra_deadline=to_db_timestamp(
                parse_api_dt(
                    first_value(
                        item,
                        "sla",
                        "deadline",
                        "dueDate",
                        "due_date",
                    )
                )
            ),
        )

        previous = records_by_id.get(issue_id)
        if previous is not None:
            duplicates += 1

            # При перекрытии страниц/relations сохраняем более полную запись.
            previous_score = sum(
                value is not None
                for value in (
                    previous.product_id,
                    previous.repository,
                    previous.issue_title,
                    previous.issue_url,
                    previous.status_changed_at,
                )
            )
            current_score = sum(
                value is not None
                for value in (
                    record.product_id,
                    record.repository,
                    record.issue_title,
                    record.issue_url,
                    record.status_changed_at,
                )
            )
            if current_score > previous_score:
                records_by_id[issue_id] = record
        else:
            records_by_id[issue_id] = record

    log.info(
        "Подготовлено уникальных issues: %s; "
        "дубли API: %s; без product_id: %s; без repository: %s; "
        "пропущено: %s",
        len(records_by_id),
        duplicates,
        missing_product,
        missing_repository,
        skipped,
    )

    if duplicates:
        log.warning(
            "API вернул повторяющиеся issue_id. "
            "Скрипт дедуплицировал их. Проверьте, что "
            "defaultRelations=True действительно ограничивает нужные связи."
        )

    return list(records_by_id.values())


def prepare_product_rows(
    products: list[dict[str, Any]],
    snapshot_ts: datetime,
) -> list[tuple[Any, ...]]:
    snapshot_db_ts = to_db_timestamp(snapshot_ts)
    assert snapshot_db_ts is not None

    rows_by_id: dict[str, tuple[Any, ...]] = {}

    for product in products:
        product_id = clean_text(
            first_value(product, "id", "uuid", "productId", "product_id")
        )
        if not product_id:
            continue

        product_name = clean_text(
            first_value(product, "name", "slug", "title")
        ) or product_id

        repo_count_raw = first_value(
            product,
            "repositoriesCount",
            "repositories_count",
            "reposCount",
            "repos_count",
        )

        try:
            repos_count = int(repo_count_raw or 0)
        except (TypeError, ValueError):
            repos_count = 0

        rows_by_id[product_id] = (
            snapshot_db_ts,
            product_id,
            product_name,
            repos_count,
        )

    return list(rows_by_id.values())


def issue_insert_rows(
    records: list[IssueRecord],
) -> list[tuple[Any, ...]]:
    return [
        (
            record.snapshot_ts,
            record.issue_id,
            record.issue_title,
            record.issue_url,

            record.product_id,
            record.product_name,
            record.repository,

            record.severity,
            record.status,
            record.scanner,

            record.is_security_debt,
            record.is_active,

            record.created_at,
            record.status_changed_at,
            record.updated_at,
            record.ra_deadline,
        )
        for record in records
    ]


def load_previous_issues(
    cursor: Any,
    schema: sql.Identifier,
) -> tuple[bool, dict[str, PreviousIssue]]:
    cursor.execute(
        sql.SQL(
            """
            SELECT MAX(ts)
            FROM {}.issues_snapshot
            """
        ).format(schema)
    )
    previous_snapshot_ts = cursor.fetchone()[0]

    if previous_snapshot_ts is None:
        return False, {}

    cursor.execute(
        sql.SQL(
            """
            WITH ranked AS (
                SELECT
                    issue_id,
                    LOWER(BTRIM(COALESCE(status, ''))) AS status,

                    NULLIF(BTRIM(product_id), '') AS product_id,
                    NULLIF(BTRIM(product_name), '') AS product_name,
                    NULLIF(BTRIM(repository), '') AS repository,

                    UPPER(BTRIM(COALESCE(severity, ''))) AS severity,
                    NULLIF(BTRIM(scanner), '') AS scanner,

                    created_at,
                    ra_deadline,

                    ROW_NUMBER() OVER (
                        PARTITION BY issue_id
                        ORDER BY
                            COALESCE(
                                status_changed_at,
                                updated_at,
                                created_at,
                                ts
                            ) DESC,
                            repository NULLS LAST
                    ) AS rn
                FROM {}.issues_snapshot
                WHERE ts = %s
            )
            SELECT
                issue_id,
                status,
                product_id,
                product_name,
                repository,
                severity,
                scanner,
                created_at,
                ra_deadline
            FROM ranked
            WHERE rn = 1
            """
        ).format(schema),
        (previous_snapshot_ts,),
    )

    previous: dict[str, PreviousIssue] = {}

    for row in cursor.fetchall():
        issue = PreviousIssue(
            issue_id=row[0],
            status=row[1],
            product_id=row[2],
            product_name=row[3],
            repository=row[4],
            severity=row[5],
            scanner=row[6],
            created_at=row[7],
            ra_deadline=row[8],
        )
        previous[issue.issue_id] = issue

    return True, previous


def build_event_rows(
    records: list[IssueRecord],
    previous: dict[str, PreviousIssue],
    had_previous_snapshot: bool,
) -> list[tuple[Any, ...]]:
    events: list[tuple[Any, ...]] = []

    for record in records:
        old = previous.get(record.issue_id)

        if old is not None and old.status == record.status:
            continue

        previous_status = old.status if old is not None else None
        is_baseline = not had_previous_snapshot

        # Если API отдаёт реальную дату смены статуса — используем её.
        # Иначе фиксируем момент, когда изменение увидел перекладчик.
        event_ts = (
            record.status_changed_at
            or (
                record.created_at
                if old is None
                and record.status in {"new_issue", "recurrent"}
                else None
            )
            or record.snapshot_ts
        )

        event_id = make_event_id(
            record.issue_id,
            event_ts,
            previous_status,
            record.status,
        )

        events.append(
            (
                event_id,
                event_ts,

                record.issue_id,
                record.issue_title,
                record.issue_url,

                record.product_id,
                record.product_name,
                record.repository,

                record.severity,
                record.scanner,

                previous_status,
                record.status,

                record.created_at,
                record.ra_deadline,
                is_baseline,
            )
        )

    return events


def save_to_greenplum(
    issue_records: list[IssueRecord],
    product_rows: list[tuple[Any, ...]],
    snapshot_ts: datetime,
) -> None:
    dsn = (
        f"host={GP_HOST} port={GP_PORT} dbname={GP_DB} "
        f"user={GP_USER} password={GP_PASSWORD}"
    )

    schema = sql.Identifier(GP_SCHEMA)
    snapshot_db_ts = to_db_timestamp(snapshot_ts)
    assert snapshot_db_ts is not None
    today_moscow = snapshot_db_ts.date()

    connection = psycopg2.connect(dsn)

    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TIME ZONE 'Europe/Moscow'")

                had_previous_snapshot, previous = load_previous_issues(
                    cursor,
                    schema,
                )
                event_rows = build_event_rows(
                    issue_records,
                    previous,
                    had_previous_snapshot,
                )

                log.info(
                    "Пишем %s issues в issues_snapshot",
                    len(issue_records),
                )
                execute_values(
                    cursor,
                    sql.SQL(
                        """
                        INSERT INTO {}.issues_snapshot (
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

                            is_security_debt,
                            is_active,

                            created_at,
                            status_changed_at,
                            updated_at,
                            ra_deadline
                        )
                        VALUES %s
                        """
                    ).format(schema).as_string(connection),
                    issue_insert_rows(issue_records),
                    page_size=500,
                )

                if product_rows:
                    log.info(
                        "Пишем %s продуктов в products_snapshot",
                        len(product_rows),
                    )
                    execute_values(
                        cursor,
                        sql.SQL(
                            """
                            INSERT INTO {}.products_snapshot (
                                ts,
                                product_id,
                                product_name,
                                repos_count
                            )
                            VALUES %s
                            """
                        ).format(schema).as_string(connection),
                        product_rows,
                        page_size=500,
                    )

                if event_rows:
                    log.info(
                        "Фиксируем %s новых status events",
                        len(event_rows),
                    )
                    execute_values(
                        cursor,
                        sql.SQL(
                            """
                            INSERT INTO {}.issue_status_events (
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
                                v.event_id,
                                v.event_ts,

                                v.issue_id,
                                v.issue_title,
                                v.issue_url,

                                v.product_id,
                                v.product_name,
                                v.repository,

                                v.severity,
                                v.scanner,

                                v.previous_status,
                                v.new_status,

                                v.created_at,
                                v.ra_deadline,
                                v.is_baseline
                            FROM (VALUES %s) AS v (
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
                            WHERE NOT EXISTS (
                                SELECT 1
                                FROM {}.issue_status_events old
                                WHERE old.event_id = v.event_id
                            )
                            """
                        ).format(schema, schema).as_string(connection),
                        event_rows,
                        page_size=500,
                    )

                debt_rows = [
                    (
                        record.issue_id,
                        record.issue_title,
                        record.issue_url,

                        record.product_id,
                        record.product_name,
                        record.repository,
                        record.severity,

                        record.status_changed_at or record.snapshot_ts,
                    )
                    for record in issue_records
                    if record.status == "security-debt"
                ]

                if debt_rows:
                    log.info(
                        "Актуализируем Security Debt cohort: %s записей",
                        len(debt_rows),
                    )
                    execute_values(
                        cursor,
                        sql.SQL(
                            """
                            INSERT INTO {}.security_debt_cohort (
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
                                v.issue_id,
                                v.issue_title,
                                v.issue_url,

                                v.product_id,
                                v.product_name,
                                v.repository,
                                v.severity,

                                v.entered_at
                            FROM (VALUES %s) AS v (
                                issue_id,
                                issue_title,
                                issue_url,

                                product_id,
                                product_name,
                                repository,
                                severity,

                                entered_at
                            )
                            WHERE NOT EXISTS (
                                SELECT 1
                                FROM {}.security_debt_cohort old
                                WHERE old.issue_id = v.issue_id
                            )
                            """
                        ).format(schema, schema).as_string(connection),
                        debt_rows,
                        page_size=500,
                    )

                # -----------------------------------------------------
                # Остаток на конец текущего московского дня
                # -----------------------------------------------------
                cursor.execute(
                    sql.SQL(
                        """
                        DELETE FROM {}.issues_daily_stock
                        WHERE dt = %s
                        """
                    ).format(schema),
                    (today_moscow,),
                )

                cursor.execute(
                    sql.SQL(
                        """
                        INSERT INTO {}.issues_daily_stock (
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
                            %s AS dt,
                            product_id,
                            product_name,
                            UPPER(BTRIM(COALESCE(severity, ''))) AS severity,
                            LOWER(BTRIM(COALESCE(status, ''))) AS status,
                            scanner,

                            CASE
                                WHEN LOWER(BTRIM(COALESCE(status, '')))
                                     = 'security-debt'
                                THEN TRUE
                                ELSE FALSE
                            END AS is_security_debt,

                            COUNT(DISTINCT issue_id)::INTEGER AS cnt
                        FROM {}.issues_snapshot
                        WHERE ts = %s
                          AND NULLIF(BTRIM(product_id), '') IS NOT NULL
                          AND UPPER(BTRIM(COALESCE(severity, '')))
                              IN ('CRITICAL', 'HIGH')
                        GROUP BY
                            product_id,
                            product_name,
                            UPPER(BTRIM(COALESCE(severity, ''))),
                            LOWER(BTRIM(COALESCE(status, ''))),
                            scanner
                        """
                    ).format(schema, schema),
                    (today_moscow, snapshot_db_ts),
                )

                # -----------------------------------------------------
                # Ежедневный остаток и fixed Security Debt
                # -----------------------------------------------------
                cursor.execute(
                    sql.SQL(
                        """
                        DELETE FROM {}.security_debt_daily
                        WHERE dt = %s
                        """
                    ).format(schema),
                    (today_moscow,),
                )

                cursor.execute(
                    sql.SQL(
                        """
                        WITH current_ranked AS (
                            SELECT
                                issue_id,
                                LOWER(BTRIM(COALESCE(status, ''))) AS status,

                                ROW_NUMBER() OVER (
                                    PARTITION BY issue_id
                                    ORDER BY
                                        COALESCE(
                                            status_changed_at,
                                            updated_at,
                                            created_at,
                                            ts
                                        ) DESC,
                                        repository NULLS LAST
                                ) AS rn
                            FROM {}.issues_snapshot
                            WHERE ts = %s
                        ),
                        current_issue AS (
                            SELECT issue_id, status
                            FROM current_ranked
                            WHERE rn = 1
                        ),
                        remaining AS (
                            SELECT
                                c.product_id,
                                c.product_name,
                                c.severity,

                                SUM(
                                    CASE
                                        WHEN i.status IN (
                                            'fixed',
                                            'false_positive',
                                            'exclusion',
                                            'archive',
                                            'not-applicable',
                                            'wont-fix'
                                        )
                                        THEN 0
                                        ELSE 1
                                    END
                                )::INTEGER AS debt_remaining

                            FROM {}.security_debt_cohort c
                            LEFT JOIN current_issue i
                                   ON i.issue_id = c.issue_id
                            WHERE c.product_id IS NOT NULL
                            GROUP BY
                                c.product_id,
                                c.product_name,
                                c.severity
                        ),
                        fixed_today AS (
                            SELECT
                                c.product_id,
                                c.product_name,
                                c.severity,
                                COUNT(*)::INTEGER AS fixed_cnt

                            FROM {}.issue_status_events e
                            JOIN {}.security_debt_cohort c
                              ON c.issue_id = e.issue_id
                            WHERE e.new_status = 'fixed'
                              AND e.is_baseline = FALSE
                              AND e.event_ts::DATE = %s
                              AND e.event_ts >= c.entered_at
                            GROUP BY
                                c.product_id,
                                c.product_name,
                                c.severity
                        )
                        INSERT INTO {}.security_debt_daily (
                            dt,
                            product_id,
                            product_name,
                            severity,
                            debt_remaining,
                            fixed_cnt
                        )
                        SELECT
                            %s AS dt,

                            COALESCE(r.product_id, f.product_id)
                                AS product_id,

                            COALESCE(r.product_name, f.product_name)
                                AS product_name,

                            COALESCE(r.severity, f.severity)
                                AS severity,

                            COALESCE(r.debt_remaining, 0)
                                AS debt_remaining,

                            COALESCE(f.fixed_cnt, 0)
                                AS fixed_cnt

                        FROM remaining r
                        FULL OUTER JOIN fixed_today f
                          ON f.product_id = r.product_id
                         AND f.severity = r.severity
                        """
                    ).format(
                        schema,
                        schema,
                        schema,
                        schema,
                        schema,
                    ),
                    (
                        snapshot_db_ts,
                        today_moscow,
                        today_moscow,
                    ),
                )

                log.info(
                    "Greenplum обновлён: snapshot=%s, events=%s, date=%s",
                    len(issue_records),
                    len(event_rows),
                    today_moscow,
                )

    except Exception:
        connection.rollback()
        log.exception("Ошибка записи в Greenplum; транзакция отменена")
        raise
    finally:
        connection.close()


async def main() -> None:
    snapshot_ts = datetime.now(timezone.utc)
    log.info("=== Старт: %s ===", snapshot_ts.isoformat())

    async with aiohttp.ClientSession() as session:
        issues_task = fetch_issues(session)
        products_task = fetch_products(session)

        issues, products = await asyncio.gather(
            issues_task,
            products_task,
        )

    if not issues:
        log.warning(
            "Дефектов не получено — запись пропущена, "
            "чтобы не создать ложный пустой снапшот"
        )
        return

    issue_records = prepare_issue_records(issues, snapshot_ts)
    if not issue_records:
        log.warning(
            "После валидации не осталось Critical/High issues — "
            "запись пропущена"
        )
        return

    product_rows = prepare_product_rows(products, snapshot_ts)

    save_to_greenplum(
        issue_records,
        product_rows,
        snapshot_ts,
    )

    log.info("=== Готово ===")


if __name__ == "__main__":
    asyncio.run(main())
