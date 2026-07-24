#!/usr/bin/env python3
"""
vampy_to_gp_final_v7.py

Итоговый перекладчик Hexway Vampy -> Greenplum для FineBI.

Что делает:
1. Забирает все Critical/High issues из POST /api/scan_issues/filter/
   с defaultRelations=True и полной offset/limit-пагинацией.
2. Забирает продукты пространства.
3. Для каждого уникального repository_id определяет все связанные продукты:
   GET /api/spaces/{space_id}/products/?repositoryID={repository_id}
4. Поддерживает many-to-many:
   один репозиторий может относиться к нескольким продуктам.
5. Исключает TEST и Default product только из аналитики; сырые продукты
   и сырые связи сохраняются.
6. Сохраняет check_required в сырых снапшотах и событиях, но SQL-слой
   полностью скрывает этот статус от дашбордов.
7. Фиксирует смены статусов, Security Debt cohort и дневные остатки.
8. Кэширует repository -> products в Greenplum. Повторно спрашивает API
   только для новых или устаревших связей.

Перед запуском выполнить:
    appsec_greenplum_full_v1_6_final.sql

Python: 3.10+
Зависимости:
    pip install aiohttp psycopg2-binary
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import aiohttp
import psycopg2
from psycopg2 import sql
from psycopg2.extras import execute_values


ENV_PATH = "/home/akhvostovets/vampy-to-gp/.env"

# Москва с 2014 года постоянно UTC+3. Фиксированный offset не требует
# системной базы tzdata и не вызывает ZoneInfoNotFoundError.
MOSCOW_TZ = timezone(timedelta(hours=3), name="Europe/Moscow")

PAGE_SIZE = 60
REQUEST_RETRIES = 4
ISSUES_TIMEOUT_SECONDS = 300
PRODUCTS_TIMEOUT_SECONDS = 90

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH"}

# Сырые данные check_required сохраняются. SQL исключает этот статус
# из всех источников для FineBI.
WORKFLOW_ACTIVE_STATUSES = {
    "new_issue",
    "recurrent",
    "confirmed",
    "check_required",
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

EXCLUDED_PRODUCT_IDS = {
    # TEST
    "d569ed52-b01f-4222-948b-705b008ae64a",
    # Default product
    "1a16d04d-cd14-4894-b887-4ba7465c26aa",
}


def load_env(path: str = ENV_PATH) -> None:
    env_file = Path(path)
    if not env_file.exists():
        raise FileNotFoundError(f".env файл не найден: {path}")

    with env_file.open(encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, _, value = line.partition("=")
            value = value.strip()
            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in {"'", '"'}
            ):
                value = value[1:-1]
            os.environ.setdefault(key.strip(), value)


load_env()

VAMPY_URL = os.environ["VAMPY_URL"].rstrip("/")
VAMPY_TOKEN = os.environ["VAMPY_TOKEN"]
SPACE_ID = os.environ["VAMPY_SPACE_ID"].strip()

GP_HOST = os.environ["GP_HOST"]
GP_PORT = os.environ.get("GP_PORT", "5050")
GP_DB = os.environ["GP_DB"]
GP_USER = os.environ["GP_USER"]
GP_PASSWORD = os.environ["GP_PASSWORD"]
GP_SCHEMA = os.environ.get(
    "GP_SCHEMA",
    "custom_ts_secure_development",
).strip()

# Необязательно. Пример:
# VAMPY_ISSUE_URL_TEMPLATE=https://vampy.example/issues/{issue_id}
ISSUE_URL_TEMPLATE = os.environ.get("VAMPY_ISSUE_URL_TEMPLATE", "").strip()

DEBUG_API_KEYS = os.environ.get(
    "VAMPY_DEBUG_API_KEYS",
    "false",
).lower() in {"1", "true", "yes"}

MAPPING_REFRESH_HOURS = int(
    os.environ.get("VAMPY_REPOSITORY_MAPPING_REFRESH_HOURS", "24")
)
MAPPING_CONCURRENCY = max(
    1,
    int(os.environ.get("VAMPY_REPOSITORY_MAPPING_CONCURRENCY", "8")),
)

if not SPACE_ID:
    raise ValueError("VAMPY_SPACE_ID обязателен для связи repository -> product")
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
class ProductRef:
    product_id: str
    product_name: str


@dataclass(frozen=True)
class RepositoryRef:
    repository_id: str
    repository_name: str | None
    repository_slug: str | None


@dataclass(frozen=True)
class IssueRecord:
    snapshot_ts: datetime
    issue_id: str
    issue_title: str | None
    issue_url: str | None

    repository_id: str | None
    repository_name: str | None
    repository_slug: str | None

    branch_id: str | None
    branch_slug: str | None

    severity: str
    status: str
    scanner: str | None
    found_in_parsers: str | None

    file_path: str | None
    file_lineno: int | None
    library_name: str | None
    library_version: str | None
    cve_id: str | None
    cwe_id: int | None

    is_security_debt: bool
    is_active: bool

    created_at: datetime | None
    status_changed_at: datetime | None
    updated_at: datetime | None
    completed_at: datetime | None
    ra_deadline: datetime | None


@dataclass(frozen=True)
class PreviousIssue:
    issue_id: str
    status: str
    repository_id: str | None
    repository_name: str | None
    repository_slug: str | None
    severity: str
    scanner: str | None
    created_at: datetime | None
    completed_at: datetime | None
    ra_deadline: datetime | None


@dataclass(frozen=True)
class StatusEvent:
    event_id: str
    event_ts: datetime
    issue_id: str
    issue_title: str | None
    issue_url: str | None
    repository_id: str | None
    repository_name: str | None
    repository_slug: str | None
    severity: str
    scanner: str | None
    previous_status: str | None
    new_status: str
    created_at: datetime | None
    completed_at: datetime | None
    ra_deadline: datetime | None
    is_baseline: bool


@dataclass
class CachedRepositoryMapping:
    checked_at: datetime
    products: list[ProductRef]


@dataclass
class MappingFetchResult:
    repository: RepositoryRef
    products: list[ProductRef]
    refreshed: bool


# ---------------------------------------------------------------------
# Общие преобразования
# ---------------------------------------------------------------------


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


def int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_status(raw: Any) -> str:
    return (clean_text(raw) or "").lower()


def normalize_severity(raw: Any) -> str:
    return (clean_text(raw) or "").upper()


def parse_api_dt(value: Any) -> datetime | None:
    if not value or isinstance(value, (dict, list)):
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
    """TIMESTAMP WITHOUT TIME ZONE: московское локальное время."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(MOSCOW_TZ).replace(tzinfo=None)


def extract_datetime_from_object(
    value: Any,
    candidate_keys: Iterable[str],
    *,
    max_depth: int = 3,
) -> datetime | None:
    direct = parse_api_dt(value)
    if direct is not None:
        return direct

    if not isinstance(value, dict) or max_depth <= 0:
        return None

    for key in candidate_keys:
        if key in value:
            parsed = extract_datetime_from_object(
                value[key],
                candidate_keys,
                max_depth=max_depth - 1,
            )
            if parsed is not None:
                return parsed
    return None


def extract_sla_deadline(item: dict[str, Any]) -> datetime | None:
    keys = (
        "deadline",
        "dueDate",
        "due_date",
        "dueAt",
        "due_at",
        "endDate",
        "end_date",
        "endAt",
        "end_at",
        "expiresAt",
        "expires_at",
        "expiredAt",
        "expired_at",
        "date",
        "value",
    )

    for source in (
        item.get("sla"),
        item.get("deadline"),
        item.get("dueDate"),
        item.get("due_date"),
    ):
        parsed = extract_datetime_from_object(source, keys)
        if parsed is not None:
            return parsed
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


# ---------------------------------------------------------------------
# API
# ---------------------------------------------------------------------


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
                            f"API вернул не JSON object: {type(payload)!r}"
                        )
                    return payload

                text = await response.text()
                if response.status == 429 or 500 <= response.status < 600:
                    retry_after = response.headers.get("Retry-After")
                    delay = (
                        int(retry_after)
                        if retry_after and retry_after.isdigit()
                        else min(2**attempt, 30)
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

        except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError) as error:
            last_error = error
            if attempt == REQUEST_RETRIES:
                break
            delay = min(2**attempt, 30)
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


def pagination_has_next(
    data: dict[str, Any],
    *,
    received_count: int,
    page_items_count: int,
) -> tuple[bool, int | None]:
    total_raw = data.get("totalCount", data.get("total"))
    total = int_or_none(total_raw)

    has_next_api = data.get("hasNext")
    if isinstance(has_next_api, bool):
        return has_next_api, total
    if total is not None:
        return received_count < total and page_items_count == PAGE_SIZE, total
    return page_items_count == PAGE_SIZE, total


async def fetch_issues(
    session: aiohttp.ClientSession,
) -> list[dict[str, Any]]:
    log.info(
        "Запрашиваем POST /api/scan_issues/filter/, defaultRelations=True"
    )

    all_issues: list[dict[str, Any]] = []
    offset = 0
    body = {
        "severities": ["CRITICAL", "HIGH"],
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
                log.info("Ключи первого issue: %s", sorted(first_item.keys()))

        valid_items = [item for item in items if isinstance(item, dict)]
        all_issues.extend(valid_items)
        has_next, total = pagination_has_next(
            data,
            received_count=len(all_issues),
            page_items_count=len(items),
        )

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
    log.info("Запрашиваем продукты пространства %s", SPACE_ID)
    all_products: list[dict[str, Any]] = []
    offset = 0

    while True:
        data = await request_json(
            session,
            "GET",
            f"{VAMPY_URL}/api/spaces/{SPACE_ID}/products/",
            timeout_seconds=PRODUCTS_TIMEOUT_SECONDS,
            params={"limit": PAGE_SIZE, "offset": offset},
        )

        items = data.get("items") or []
        if not isinstance(items, list):
            raise RuntimeError("Поле items в products API не является списком")

        if DEBUG_API_KEYS and offset == 0 and items:
            first_item = items[0]
            if isinstance(first_item, dict):
                log.info("Ключи первого product: %s", sorted(first_item.keys()))

        all_products.extend(item for item in items if isinstance(item, dict))
        has_next, total = pagination_has_next(
            data,
            received_count=len(all_products),
            page_items_count=len(items),
        )

        log.info(
            "Продуктов получено: %s%s",
            len(all_products),
            f" / {total}" if total is not None else "",
        )

        if not has_next or not items:
            break
        offset += PAGE_SIZE

    return all_products


async def fetch_products_for_repository(
    session: aiohttp.ClientSession,
    repository: RepositoryRef,
) -> list[ProductRef]:
    products_by_id: dict[str, ProductRef] = {}
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
                "repositoryID": repository.repository_id,
            },
        )

        items = data.get("items") or []
        if not isinstance(items, list):
            raise RuntimeError(
                "Поле items в repository products API не является списком"
            )

        for product in items:
            if not isinstance(product, dict):
                continue
            product_id = clean_text(
                first_value(product, "id", "uuid", "productId", "product_id")
            )
            if not product_id:
                continue
            product_name = clean_text(
                first_value(product, "name", "slug", "title")
            ) or product_id
            products_by_id[product_id] = ProductRef(product_id, product_name)

        has_next, _ = pagination_has_next(
            data,
            received_count=len(products_by_id),
            page_items_count=len(items),
        )
        if not has_next or not items:
            break
        offset += PAGE_SIZE

    return sorted(products_by_id.values(), key=lambda value: value.product_id)


# ---------------------------------------------------------------------
# Подготовка данных
# ---------------------------------------------------------------------


def extract_repository(item: dict[str, Any]) -> RepositoryRef | None:
    repository = item.get("repository")
    if not isinstance(repository, dict):
        return None

    repository_id = clean_text(
        first_value(repository, "id", "uuid", "repositoryId", "repository_id")
    )
    if not repository_id:
        return None

    return RepositoryRef(
        repository_id=repository_id,
        repository_name=clean_text(
            first_value(repository, "name", "slug", "path")
        ),
        repository_slug=clean_text(
            first_value(repository, "slug", "path", "fullName", "full_name")
        ),
    )


def extract_branch(item: dict[str, Any]) -> tuple[str | None, str | None]:
    branch = item.get("repositoryBranch")
    if not isinstance(branch, dict):
        return None, None
    return (
        clean_text(first_value(branch, "id", "uuid")),
        clean_text(first_value(branch, "slug", "name")),
    )


def extract_scanner(item: dict[str, Any]) -> str | None:
    return clean_text(
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


def extract_found_in_parsers(item: dict[str, Any]) -> str | None:
    raw = item.get("foundInParsers")
    if not isinstance(raw, list):
        return None
    values = sorted({text for value in raw if (text := clean_text(value))})
    return ",".join(values) or None


def prepare_issue_records(
    items: list[dict[str, Any]],
    snapshot_ts: datetime,
) -> list[IssueRecord]:
    snapshot_db_ts = to_db_timestamp(snapshot_ts)
    assert snapshot_db_ts is not None

    records_by_id: dict[str, IssueRecord] = {}
    duplicates = 0
    skipped = 0
    missing_repository_id = 0

    for item in items:
        issue_id = clean_text(first_value(item, "id", "uuid"))
        severity = normalize_severity(item.get("severity"))
        if not issue_id or severity not in ALLOWED_SEVERITIES:
            skipped += 1
            continue

        status = normalize_status(item.get("status"))
        repository = extract_repository(item)
        if repository is None:
            missing_repository_id += 1

        branch_id, branch_slug = extract_branch(item)
        completed_at = to_db_timestamp(parse_api_dt(item.get("completed")))

        record = IssueRecord(
            snapshot_ts=snapshot_db_ts,
            issue_id=issue_id,
            issue_title=clean_text(first_value(item, "title", "name")),
            issue_url=extract_issue_url(item, issue_id),
            repository_id=(repository.repository_id if repository else None),
            repository_name=(repository.repository_name if repository else None),
            repository_slug=(repository.repository_slug if repository else None),
            branch_id=branch_id,
            branch_slug=branch_slug,
            severity=severity,
            status=status,
            scanner=extract_scanner(item),
            found_in_parsers=extract_found_in_parsers(item),
            file_path=clean_text(item.get("filePath")),
            file_lineno=int_or_none(item.get("fileLineno")),
            library_name=clean_text(item.get("libraryName")),
            library_version=clean_text(item.get("libraryVersion")),
            cve_id=clean_text(item.get("cveID")),
            cwe_id=int_or_none(item.get("cweID")),
            is_security_debt=(status == "security-debt"),
            is_active=(status in WORKFLOW_ACTIVE_STATUSES),
            created_at=to_db_timestamp(
                parse_api_dt(first_value(item, "created", "createdAt", "created_at"))
            ),
            status_changed_at=to_db_timestamp(extract_status_changed_at(item)),
            updated_at=to_db_timestamp(
                parse_api_dt(
                    first_value(
                        item,
                        "updated",
                        "updatedAt",
                        "updated_at",
                        "modified",
                        "modifiedAt",
                        "modified_at",
                    )
                )
            ) or completed_at,
            completed_at=completed_at,
            ra_deadline=to_db_timestamp(extract_sla_deadline(item)),
        )

        previous = records_by_id.get(issue_id)
        if previous is None:
            records_by_id[issue_id] = record
            continue

        duplicates += 1
        previous_score = sum(
            value is not None
            for value in (
                previous.repository_id,
                previous.issue_title,
                previous.status_changed_at,
                previous.completed_at,
                previous.ra_deadline,
            )
        )
        current_score = sum(
            value is not None
            for value in (
                record.repository_id,
                record.issue_title,
                record.status_changed_at,
                record.completed_at,
                record.ra_deadline,
            )
        )
        if current_score > previous_score:
            records_by_id[issue_id] = record

    log.info(
        "Подготовлено уникальных issues: %s; дубли API: %s; "
        "без repository_id: %s; пропущено: %s",
        len(records_by_id),
        duplicates,
        missing_repository_id,
        skipped,
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
        product_slug = clean_text(product.get("slug"))
        criticality = clean_text(product.get("criticality"))
        repos_count = int_or_none(
            first_value(
                product,
                "repositoriesCount",
                "repositories_count",
                "reposCount",
                "repos_count",
            )
        ) or 0

        rows_by_id[product_id] = (
            snapshot_db_ts,
            product_id,
            product_name,
            product_slug,
            criticality,
            repos_count,
        )

    return list(rows_by_id.values())


def collect_repositories(records: list[IssueRecord]) -> dict[str, RepositoryRef]:
    repositories: dict[str, RepositoryRef] = {}
    for record in records:
        if not record.repository_id:
            continue
        repositories[record.repository_id] = RepositoryRef(
            record.repository_id,
            record.repository_name,
            record.repository_slug,
        )
    return repositories


# ---------------------------------------------------------------------
# Greenplum mapping cache
# ---------------------------------------------------------------------


def gp_dsn() -> str:
    return (
        f"host={GP_HOST} port={GP_PORT} dbname={GP_DB} "
        f"user={GP_USER} password={GP_PASSWORD}"
    )


def load_repository_mapping_cache() -> dict[str, CachedRepositoryMapping]:
    schema = sql.Identifier(GP_SCHEMA)
    connection = psycopg2.connect(gp_dsn())
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET TIME ZONE 'Europe/Moscow'")
            cursor.execute(
                sql.SQL(
                    """
                    WITH latest AS (
                        SELECT repository_id, MAX(ts) AS max_ts
                        FROM {}.repository_product_snapshot
                        GROUP BY repository_id
                    )
                    SELECT
                        s.repository_id,
                        s.ts,
                        s.product_id,
                        s.product_name
                    FROM {}.repository_product_snapshot s
                    JOIN latest l
                      ON l.repository_id = s.repository_id
                     AND l.max_ts = s.ts
                    ORDER BY s.repository_id, s.product_id
                    """
                ).format(schema, schema)
            )

            cache: dict[str, CachedRepositoryMapping] = {}
            for repository_id, checked_at, product_id, product_name in cursor.fetchall():
                entry = cache.setdefault(
                    repository_id,
                    CachedRepositoryMapping(checked_at=checked_at, products=[]),
                )
                if product_id:
                    entry.products.append(
                        ProductRef(product_id, product_name or product_id)
                    )
            return cache
    except psycopg2.Error as error:
        raise RuntimeError(
            "Не удалось прочитать repository_product_snapshot. "
            "Сначала выполните appsec_greenplum_full_v1_6_final.sql"
        ) from error
    finally:
        connection.close()


async def resolve_repository_mappings(
    session: aiohttp.ClientSession,
    repositories: dict[str, RepositoryRef],
    cache: dict[str, CachedRepositoryMapping],
    snapshot_ts: datetime,
) -> tuple[
    dict[str, list[ProductRef]],
    list[tuple[Any, ...]],
]:
    snapshot_db_ts = to_db_timestamp(snapshot_ts)
    assert snapshot_db_ts is not None
    refresh_before = snapshot_db_ts - timedelta(hours=MAPPING_REFRESH_HOURS)

    current_map: dict[str, list[ProductRef]] = {}
    to_refresh: list[RepositoryRef] = []

    for repository_id, repository in repositories.items():
        cached = cache.get(repository_id)
        if (
            cached is not None
            and MAPPING_REFRESH_HOURS > 0
            and cached.checked_at >= refresh_before
        ):
            current_map[repository_id] = cached.products
        else:
            to_refresh.append(repository)

    log.info(
        "Repository mappings: всего=%s, из кэша=%s, обновить=%s",
        len(repositories),
        len(repositories) - len(to_refresh),
        len(to_refresh),
    )

    semaphore = asyncio.Semaphore(MAPPING_CONCURRENCY)

    async def fetch_one(repository: RepositoryRef) -> MappingFetchResult:
        async with semaphore:
            try:
                products = await fetch_products_for_repository(
                    session,
                    repository,
                )
                return MappingFetchResult(repository, products, True)
            except Exception:
                stale = cache.get(repository.repository_id)
                if stale is not None:
                    log.exception(
                        "Не удалось обновить mapping repository=%s; "
                        "используется устаревший кэш от %s",
                        repository.repository_id,
                        stale.checked_at,
                    )
                    return MappingFetchResult(repository, stale.products, False)
                raise

    refreshed_rows: list[tuple[Any, ...]] = []
    if to_refresh:
        tasks = [asyncio.create_task(fetch_one(repo)) for repo in to_refresh]
        completed = 0
        for future in asyncio.as_completed(tasks):
            result = await future
            completed += 1
            current_map[result.repository.repository_id] = result.products

            if result.refreshed:
                if result.products:
                    for product in result.products:
                        refreshed_rows.append(
                            (
                                snapshot_db_ts,
                                result.repository.repository_id,
                                result.repository.repository_name,
                                result.repository.repository_slug,
                                product.product_id,
                                product.product_name,
                            )
                        )
                else:
                    # NULL product — осознанный маркер, что репозиторий
                    # проверен и рабочих/любых продуктов API не вернул.
                    refreshed_rows.append(
                        (
                            snapshot_db_ts,
                            result.repository.repository_id,
                            result.repository.repository_name,
                            result.repository.repository_slug,
                            None,
                            None,
                        )
                    )

            if completed % 50 == 0 or completed == len(to_refresh):
                log.info(
                    "Repository mappings обновлено: %s / %s",
                    completed,
                    len(to_refresh),
                )

    # В аналитическую карту не включаем два служебных продукта.
    analytics_map = {
        repository_id: [
            product
            for product in products
            if product.product_id not in EXCLUDED_PRODUCT_IDS
        ]
        for repository_id, products in current_map.items()
    }

    mapped = sum(bool(products) for products in analytics_map.values())
    unmapped = len(analytics_map) - mapped
    relation_count = sum(len(products) for products in analytics_map.values())
    log.info(
        "Рабочие связи repository->product: relations=%s, "
        "mapped repositories=%s, unmapped repositories=%s",
        relation_count,
        mapped,
        unmapped,
    )

    return analytics_map, refreshed_rows


# ---------------------------------------------------------------------
# События
# ---------------------------------------------------------------------


def load_previous_issues(
    cursor: Any,
    schema: sql.Identifier,
) -> tuple[bool, dict[str, PreviousIssue]]:
    cursor.execute(sql.SQL("SELECT MAX(ts) FROM {}.issues_snapshot").format(schema))
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
                    NULLIF(BTRIM(repository_id), '') AS repository_id,
                    NULLIF(BTRIM(repository), '') AS repository_name,
                    NULLIF(BTRIM(repository_slug), '') AS repository_slug,
                    UPPER(BTRIM(COALESCE(severity, ''))) AS severity,
                    NULLIF(BTRIM(scanner), '') AS scanner,
                    created_at,
                    completed_at,
                    ra_deadline,
                    ROW_NUMBER() OVER (
                        PARTITION BY issue_id
                        ORDER BY
                            COALESCE(
                                status_changed_at,
                                completed_at,
                                updated_at,
                                created_at,
                                ts
                            ) DESC,
                            repository_id NULLS LAST
                    ) AS rn
                FROM {}.issues_snapshot
                WHERE ts = %s
            )
            SELECT
                issue_id,
                status,
                repository_id,
                repository_name,
                repository_slug,
                severity,
                scanner,
                created_at,
                completed_at,
                ra_deadline
            FROM ranked
            WHERE rn = 1
            """
        ).format(schema),
        (previous_snapshot_ts,),
    )

    previous: dict[str, PreviousIssue] = {}
    for row in cursor.fetchall():
        issue = PreviousIssue(*row)
        previous[issue.issue_id] = issue
    return True, previous


def build_events(
    records: list[IssueRecord],
    previous: dict[str, PreviousIssue],
    had_previous_snapshot: bool,
) -> list[StatusEvent]:
    events: list[StatusEvent] = []

    for record in records:
        old = previous.get(record.issue_id)
        if old is not None and old.status == record.status:
            continue

        previous_status = old.status if old is not None else None
        is_baseline = not had_previous_snapshot

        event_ts = (
            record.status_changed_at
            or (
                record.completed_at
                if record.status in CLOSED_STATUSES
                else None
            )
            or (
                record.created_at
                if old is None
                and record.status in {"new_issue", "recurrent"}
                else None
            )
            or record.snapshot_ts
        )

        events.append(
            StatusEvent(
                event_id=make_event_id(
                    record.issue_id,
                    event_ts,
                    previous_status,
                    record.status,
                ),
                event_ts=event_ts,
                issue_id=record.issue_id,
                issue_title=record.issue_title,
                issue_url=record.issue_url,
                repository_id=record.repository_id,
                repository_name=record.repository_name,
                repository_slug=record.repository_slug,
                severity=record.severity,
                scanner=record.scanner,
                previous_status=previous_status,
                new_status=record.status,
                created_at=record.created_at,
                completed_at=record.completed_at,
                ra_deadline=record.ra_deadline,
                is_baseline=is_baseline,
            )
        )

    return events


# ---------------------------------------------------------------------
# Запись
# ---------------------------------------------------------------------


def issue_insert_rows(records: list[IssueRecord]) -> list[tuple[Any, ...]]:
    return [
        (
            r.snapshot_ts,
            r.issue_id,
            r.issue_title,
            r.issue_url,
            r.repository_id,
            r.repository_name,
            r.repository_slug,
            r.branch_id,
            r.branch_slug,
            r.severity,
            r.status,
            r.scanner,
            r.found_in_parsers,
            r.file_path,
            r.file_lineno,
            r.library_name,
            r.library_version,
            r.cve_id,
            r.cwe_id,
            r.is_security_debt,
            r.is_active,
            r.created_at,
            r.status_changed_at,
            r.updated_at,
            r.completed_at,
            r.ra_deadline,
        )
        for r in records
    ]


def event_insert_rows(events: list[StatusEvent]) -> list[tuple[Any, ...]]:
    return [
        (
            e.event_id,
            e.event_ts,
            e.issue_id,
            e.issue_title,
            e.issue_url,
            e.repository_id,
            e.repository_name,
            e.repository_slug,
            e.severity,
            e.scanner,
            e.previous_status,
            e.new_status,
            e.created_at,
            e.completed_at,
            e.ra_deadline,
            e.is_baseline,
        )
        for e in events
    ]


def save_to_greenplum(
    issue_records: list[IssueRecord],
    product_rows: list[tuple[Any, ...]],
    refreshed_mapping_rows: list[tuple[Any, ...]],
    product_map: dict[str, list[ProductRef]],
    snapshot_ts: datetime,
) -> None:
    schema = sql.Identifier(GP_SCHEMA)
    snapshot_db_ts = to_db_timestamp(snapshot_ts)
    assert snapshot_db_ts is not None
    today_moscow = snapshot_db_ts.date()

    connection = psycopg2.connect(gp_dsn())
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TIME ZONE 'Europe/Moscow'")

                had_previous_snapshot, previous = load_previous_issues(
                    cursor,
                    schema,
                )
                events = build_events(
                    issue_records,
                    previous,
                    had_previous_snapshot,
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
                            is_security_debt,
                            is_active,
                            created_at,
                            status_changed_at,
                            updated_at,
                            completed_at,
                            ra_deadline
                        ) VALUES %s
                        """
                    ).format(schema).as_string(connection),
                    issue_insert_rows(issue_records),
                    page_size=500,
                )

                if product_rows:
                    execute_values(
                        cursor,
                        sql.SQL(
                            """
                            INSERT INTO {}.products_snapshot (
                                ts,
                                product_id,
                                product_name,
                                product_slug,
                                criticality,
                                repos_count
                            ) VALUES %s
                            """
                        ).format(schema).as_string(connection),
                        product_rows,
                        page_size=500,
                    )

                if refreshed_mapping_rows:
                    execute_values(
                        cursor,
                        sql.SQL(
                            """
                            INSERT INTO {}.repository_product_snapshot (
                                ts,
                                repository_id,
                                repository_name,
                                repository_slug,
                                product_id,
                                product_name
                            ) VALUES %s
                            """
                        ).format(schema).as_string(connection),
                        refreshed_mapping_rows,
                        page_size=500,
                    )

                if events:
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
                                repository_id,
                                repository,
                                repository_slug,
                                severity,
                                scanner,
                                previous_status,
                                new_status,
                                created_at,
                                completed_at,
                                ra_deadline,
                                is_baseline
                            )
                            SELECT v.*
                            FROM (VALUES %s) AS v (
                                event_id,
                                event_ts,
                                issue_id,
                                issue_title,
                                issue_url,
                                repository_id,
                                repository,
                                repository_slug,
                                severity,
                                scanner,
                                previous_status,
                                new_status,
                                created_at,
                                completed_at,
                                ra_deadline,
                                is_baseline
                            )
                            WHERE NOT EXISTS (
                                SELECT 1
                                FROM {} old
                                WHERE old.event_id = v.event_id
                            )
                            """
                        ).format(
                            schema,
                            sql.SQL("{}.issue_status_events").format(schema),
                        ).as_string(connection),
                        event_insert_rows(events),
                        page_size=500,
                    )

                    event_product_rows: list[tuple[Any, ...]] = []
                    for event in events:
                        if not event.repository_id:
                            continue
                        for product in product_map.get(event.repository_id, []):
                            event_product_rows.append(
                                (
                                    event.event_id,
                                    event.event_ts,
                                    event.issue_id,
                                    product.product_id,
                                    product.product_name,
                                )
                            )

                    if event_product_rows:
                        execute_values(
                            cursor,
                            sql.SQL(
                                """
                                INSERT INTO {}.issue_status_event_product (
                                    event_id,
                                    event_ts,
                                    issue_id,
                                    product_id,
                                    product_name
                                )
                                SELECT v.*
                                FROM (VALUES %s) AS v (
                                    event_id,
                                    event_ts,
                                    issue_id,
                                    product_id,
                                    product_name
                                )
                                WHERE NOT EXISTS (
                                    SELECT 1
                                    FROM {} old
                                    WHERE old.event_id = v.event_id
                                      AND old.product_id = v.product_id
                                )
                                """
                            ).format(
                                schema,
                                sql.SQL("{}.issue_status_event_product").format(schema),
                            ).as_string(connection),
                            event_product_rows,
                            page_size=500,
                        )

                debt_records = [
                    record
                    for record in issue_records
                    if record.status == "security-debt"
                ]
                if debt_records:
                    debt_rows = [
                        (
                            record.issue_id,
                            record.issue_title,
                            record.issue_url,
                            record.repository_id,
                            record.repository_name,
                            record.repository_slug,
                            record.severity,
                            record.status_changed_at or record.snapshot_ts,
                        )
                        for record in debt_records
                    ]
                    execute_values(
                        cursor,
                        sql.SQL(
                            """
                            INSERT INTO {}.security_debt_cohort (
                                issue_id,
                                issue_title,
                                issue_url,
                                repository_id,
                                repository,
                                repository_slug,
                                severity,
                                entered_at
                            )
                            SELECT v.*
                            FROM (VALUES %s) AS v (
                                issue_id,
                                issue_title,
                                issue_url,
                                repository_id,
                                repository,
                                repository_slug,
                                severity,
                                entered_at
                            )
                            WHERE NOT EXISTS (
                                SELECT 1
                                FROM {} old
                                WHERE old.issue_id = v.issue_id
                            )
                            """
                        ).format(
                            schema,
                            sql.SQL("{}.security_debt_cohort").format(schema),
                        ).as_string(connection),
                        debt_rows,
                        page_size=500,
                    )

                    debt_product_rows: list[tuple[Any, ...]] = []
                    for record in debt_records:
                        if not record.repository_id:
                            continue
                        entered_at = record.status_changed_at or record.snapshot_ts
                        for product in product_map.get(record.repository_id, []):
                            debt_product_rows.append(
                                (
                                    record.issue_id,
                                    product.product_id,
                                    product.product_name,
                                    entered_at,
                                )
                            )

                    if debt_product_rows:
                        execute_values(
                            cursor,
                            sql.SQL(
                                """
                                INSERT INTO {}.security_debt_cohort_product (
                                    issue_id,
                                    product_id,
                                    product_name,
                                    entered_at
                                )
                                SELECT v.*
                                FROM (VALUES %s) AS v (
                                    issue_id,
                                    product_id,
                                    product_name,
                                    entered_at
                                )
                                WHERE NOT EXISTS (
                                    SELECT 1
                                    FROM {} old
                                    WHERE old.issue_id = v.issue_id
                                      AND old.product_id = v.product_id
                                )
                                """
                            ).format(
                                schema,
                                sql.SQL("{}.security_debt_cohort_product").format(schema),
                            ).as_string(connection),
                            debt_product_rows,
                            page_size=500,
                        )

                # Текущий дневной остаток по продуктам.
                cursor.execute(
                    sql.SQL("DELETE FROM {}.issues_daily_stock WHERE dt = %s").format(schema),
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
                            %s,
                            product_id,
                            product_name,
                            severity,
                            status,
                            scanner,
                            CASE WHEN status = 'security-debt'
                                 THEN TRUE ELSE FALSE END,
                            COUNT(DISTINCT issue_id)::INTEGER
                        FROM {}.issues_current_by_product
                        GROUP BY
                            product_id,
                            product_name,
                            severity,
                            status,
                            scanner
                        """
                    ).format(schema, schema),
                    (today_moscow,),
                )

                # Security Debt daily.
                cursor.execute(
                    sql.SQL("DELETE FROM {}.security_debt_daily WHERE dt = %s").format(schema),
                    (today_moscow,),
                )
                cursor.execute(
                    sql.SQL(
                        """
                        WITH remaining AS (
                            SELECT
                                product_id,
                                MAX(product_name) AS product_name,
                                severity,
                                SUM(debt_remaining_int)::INTEGER AS debt_remaining
                            FROM {}.security_debt_current
                            GROUP BY product_id, severity
                        ),
                        fixed_today AS (
                            SELECT
                                product_id,
                                MAX(product_name) AS product_name,
                                severity,
                                COUNT(DISTINCT issue_id)::INTEGER AS fixed_cnt
                            FROM {}.security_debt_fixed_events
                            WHERE event_ts::DATE = %s
                            GROUP BY product_id, severity
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
                            %s,
                            COALESCE(r.product_id, f.product_id),
                            COALESCE(r.product_name, f.product_name),
                            COALESCE(r.severity, f.severity),
                            COALESCE(r.debt_remaining, 0),
                            COALESCE(f.fixed_cnt, 0)
                        FROM remaining r
                        FULL OUTER JOIN fixed_today f
                          ON f.product_id = r.product_id
                         AND f.severity = r.severity
                        """
                    ).format(schema, schema, schema),
                    (today_moscow, today_moscow),
                )

                log.info(
                    "Greenplum обновлён: issues=%s, products=%s, "
                    "mapping rows=%s, events=%s, date=%s",
                    len(issue_records),
                    len(product_rows),
                    len(refreshed_mapping_rows),
                    len(events),
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
        issues, products = await asyncio.gather(
            fetch_issues(session),
            fetch_products(session),
        )

        if not issues:
            log.warning(
                "Дефектов не получено — запись пропущена, чтобы не создать "
                "ложный пустой снапшот"
            )
            return

        issue_records = prepare_issue_records(issues, snapshot_ts)
        if not issue_records:
            log.warning("После валидации не осталось Critical/High issues")
            return

        repositories = collect_repositories(issue_records)
        mapping_cache = load_repository_mapping_cache()
        product_map, refreshed_mapping_rows = await resolve_repository_mappings(
            session,
            repositories,
            mapping_cache,
            snapshot_ts,
        )

    product_rows = prepare_product_rows(products, snapshot_ts)

    save_to_greenplum(
        issue_records,
        product_rows,
        refreshed_mapping_rows,
        product_map,
        snapshot_ts,
    )

    log.info("=== Готово ===")


if __name__ == "__main__":
    asyncio.run(main())
