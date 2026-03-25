from __future__ import annotations

import asyncio
import hashlib
import json
import random
import secrets
import time
from datetime import UTC, datetime
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiosqlite

from .config import config
from .log_store import RedisLogStore
from .logger import debug_logger
from .models import CaptchaConfig


class Database:
    SQLITE_BUSY_TIMEOUT_MS = 30000
    PERIODIC_LOG_VACUUM_ROW_THRESHOLD = 5000
    PERIODIC_LOG_VACUUM_MIN_INTERVAL_SECONDS = 1800

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or config.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = asyncio.Lock()
        self._redis_job_index_lock = asyncio.Lock()
        self._redis_log_store: Optional[RedisLogStore] = None
        self._log_cleanup_task: Optional[asyncio.Task] = None
        self._last_log_vacuum_monotonic = 0.0
        self._periodic_log_deleted_since_vacuum = 0

    @asynccontextmanager
    async def _connect(self):
        async with aiosqlite.connect(
            self.db_path,
            timeout=self.SQLITE_BUSY_TIMEOUT_MS / 1000,
        ) as db:
            await db.execute(f"PRAGMA busy_timeout = {self.SQLITE_BUSY_TIMEOUT_MS}")
            await db.execute("PRAGMA foreign_keys = ON")
            yield db

    @asynccontextmanager
    async def _write_connect(self):
        async with self._write_lock:
            async with self._connect() as db:
                yield db

    async def initialize_log_store(self):
        if not config.log_redis_enabled:
            return
        redis_url = config.log_redis_url
        if not redis_url:
            raise RuntimeError("已启用 Redis 日志存储，但未配置 log.redis_url / FCS_LOG_REDIS_URL")
        self._redis_log_store = RedisLogStore(
            redis_url=redis_url,
            key_prefix=config.log_redis_key_prefix,
            max_entries=config.log_redis_max_entries,
        )
        await self._redis_log_store.connect()
        rebuilt = await self._redis_log_store.ensure_job_log_indexes()
        if rebuilt:
            debug_logger.log_info("[RedisLogStore] rebuilt legacy job log indexes on startup")

    async def close(self):
        if self._log_cleanup_task and not self._log_cleanup_task.done():
            self._log_cleanup_task.cancel()
            try:
                await self._log_cleanup_task
            except asyncio.CancelledError:
                pass
        self._log_cleanup_task = None
        if self._redis_log_store is not None:
            await self._redis_log_store.close()
            self._redis_log_store = None
        self._last_log_vacuum_monotonic = 0.0
        self._periodic_log_deleted_since_vacuum = 0

    def _job_logs_use_redis(self) -> bool:
        return self._redis_log_store is not None and config.log_redis_enabled

    def _cluster_logs_use_redis(self) -> bool:
        return self._redis_log_store is not None and config.log_redis_enabled

    def _should_vacuum_periodic_logs(self, deleted_rows: int) -> bool:
        safe_deleted_rows = max(0, int(deleted_rows or 0))
        self._periodic_log_deleted_since_vacuum += safe_deleted_rows
        if self._periodic_log_deleted_since_vacuum < self.PERIODIC_LOG_VACUUM_ROW_THRESHOLD:
            return False
        now_monotonic = time.monotonic()
        if (
            self._last_log_vacuum_monotonic > 0
            and (now_monotonic - self._last_log_vacuum_monotonic) < self.PERIODIC_LOG_VACUUM_MIN_INTERVAL_SECONDS
        ):
            return False
        self._periodic_log_deleted_since_vacuum = 0
        self._last_log_vacuum_monotonic = now_monotonic
        return True

    @staticmethod
    def _normalize_optional_positive_int(value: Optional[int]) -> Optional[int]:
        try:
            normalized = int(value or 0)
        except (TypeError, ValueError):
            return None
        return normalized if normalized > 0 else None

    @staticmethod
    def _terminal_job_statuses() -> tuple[str, ...]:
        return (
            "finish:success",
            "finish:failed",
            "finish:cancelled",
            "finish:timeout",
            "error_reported",
        )

    async def _mark_session_complete_in_tx(
        self,
        db: aiosqlite.Connection,
        *,
        session_id: Optional[str],
        owner_type: str,
        owner_id: Optional[int],
        note: Optional[str] = None,
    ):
        normalized_session_id = str(session_id or "").strip()
        normalized_owner_id = int(owner_id or 0)
        if not normalized_session_id or normalized_owner_id <= 0:
            return
        await db.execute(
            """
            INSERT OR IGNORE INTO session_quota_events (session_id, owner_type, owner_id, event_type, note)
            VALUES (?, ?, ?, 'complete', ?)
            """,
            (normalized_session_id, owner_type, normalized_owner_id, (note or "")[:200] or None),
        )

    async def _backfill_session_completion_events_in_tx(self, db: aiosqlite.Connection) -> Dict[str, int]:
        terminal_statuses = self._terminal_job_statuses()
        placeholders = ",".join(["?"] * len(terminal_statuses))

        service_cursor = await db.execute(
            f"""
            INSERT OR IGNORE INTO session_quota_events (session_id, owner_type, owner_id, event_type, note)
            SELECT e.session_id, 'service_api_key', e.owner_id, 'complete', 'startup_backfill'
            FROM session_quota_events e
            WHERE e.owner_type = 'service_api_key'
              AND e.event_type = 'charge'
              AND NOT EXISTS (
                SELECT 1
                FROM session_quota_events c
                WHERE c.session_id = e.session_id
                  AND c.owner_type = e.owner_type
                  AND c.owner_id = e.owner_id
                  AND c.event_type = 'complete'
              )
              AND EXISTS (
                SELECT 1
                FROM captcha_jobs cj
                WHERE cj.api_key_id = e.owner_id
                  AND cj.session_id = e.session_id
                  AND cj.status IN ({placeholders})
              )
            """,
            terminal_statuses,
        )

        portal_cursor = await db.execute(
            f"""
            INSERT OR IGNORE INTO session_quota_events (session_id, owner_type, owner_id, event_type, note)
            SELECT e.session_id, 'portal_user', e.owner_id, 'complete', 'startup_backfill'
            FROM session_quota_events e
            WHERE e.owner_type = 'portal_user'
              AND e.event_type = 'charge'
              AND NOT EXISTS (
                SELECT 1
                FROM session_quota_events c
                WHERE c.session_id = e.session_id
                  AND c.owner_type = e.owner_type
                  AND c.owner_id = e.owner_id
                  AND c.event_type = 'complete'
              )
              AND (
                EXISTS (
                  SELECT 1
                  FROM portal_user_jobs pj
                  WHERE pj.portal_user_id = e.owner_id
                    AND pj.session_id = e.session_id
                    AND pj.status IN ({placeholders})
                )
                OR EXISTS (
                  SELECT 1
                  FROM captcha_jobs cj
                  WHERE cj.portal_user_id = e.owner_id
                    AND cj.session_id = e.session_id
                    AND cj.status IN ({placeholders})
                )
              )
            """,
            (*terminal_statuses, *terminal_statuses),
        )

        return {
            "service_api_key_complete": int(service_cursor.rowcount or 0),
            "portal_user_complete": int(portal_cursor.rowcount or 0),
        }

    async def _clear_log_tables_in_tx(
        self,
        db: aiosqlite.Connection,
        *,
        reset_sequences: bool,
        clear_cluster_node_last_error: bool,
    ) -> Dict[str, int]:
        captcha_cursor = await db.execute("DELETE FROM captcha_jobs")
        portal_cursor = await db.execute("DELETE FROM portal_user_jobs")
        heartbeat_cursor = await db.execute("DELETE FROM cluster_node_heartbeats")
        error_cursor = await db.execute("DELETE FROM cluster_node_errors")
        if clear_cluster_node_last_error:
            await db.execute(
                """
                UPDATE cluster_nodes
                SET last_error = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE last_error IS NOT NULL AND last_error <> ''
                """
            )
        if reset_sequences:
            await db.execute(
                """
                DELETE FROM sqlite_sequence
                WHERE name IN ('captcha_jobs', 'portal_user_jobs', 'cluster_node_heartbeats', 'cluster_node_errors')
                """
            )
        return {
            "captcha_jobs": int(captcha_cursor.rowcount or 0),
            "portal_user_jobs": int(portal_cursor.rowcount or 0),
            "cluster_node_heartbeats": int(heartbeat_cursor.rowcount or 0),
            "cluster_node_errors": int(error_cursor.rowcount or 0),
        }

    async def _checkpoint_and_vacuum_logs(self, *, reason: str, vacuum: bool):
        try:
            async with self._connect() as db:
                await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                await db.commit()
                if vacuum:
                    await db.execute("VACUUM")
                    self._last_log_vacuum_monotonic = time.monotonic()
                    self._periodic_log_deleted_since_vacuum = 0
        except Exception as exc:
            action = "VACUUM" if vacuum else "checkpoint"
            debug_logger.log_warning(f"[Database] {reason} {action} failed: {exc}")

    async def startup_log_maintenance(self) -> Dict[str, int]:
        if not config.log_startup_clear_on_boot:
            return {
                "captcha_jobs": 0,
                "portal_user_jobs": 0,
                "cluster_node_heartbeats": 0,
                "cluster_node_errors": 0,
                "backfilled_complete_events": 0,
            }

        async with self._write_connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            try:
                backfill = await self._backfill_session_completion_events_in_tx(db)
                cleanup_result = await self._clear_log_tables_in_tx(
                    db,
                    reset_sequences=True,
                    clear_cluster_node_last_error=True,
                )
                await db.commit()
            except Exception:
                await db.execute("ROLLBACK")
                raise

        await self._checkpoint_and_vacuum_logs(reason="startup", vacuum=True)

        return {
            "captcha_jobs": int(cleanup_result["captcha_jobs"]),
            "portal_user_jobs": int(cleanup_result["portal_user_jobs"]),
            "cluster_node_heartbeats": int(cleanup_result["cluster_node_heartbeats"]),
            "cluster_node_errors": int(cleanup_result["cluster_node_errors"]),
            "backfilled_complete_events": int(backfill["service_api_key_complete"]) + int(backfill["portal_user_complete"]),
        }

    async def start_periodic_log_cleanup(self):
        interval_minutes = int(config.log_auto_clear_interval_minutes or 0)
        if self._log_cleanup_task and not self._log_cleanup_task.done():
            self._log_cleanup_task.cancel()
            try:
                await self._log_cleanup_task
            except asyncio.CancelledError:
                pass
        self._log_cleanup_task = None
        if interval_minutes <= 0:
            return
        self._log_cleanup_task = asyncio.create_task(self._periodic_log_cleanup_loop(interval_minutes))

    async def clear_runtime_logs(self) -> Dict[str, int]:
        result = {"captcha_jobs": 0, "portal_user_jobs": 0, "cluster_node_heartbeats": 0, "cluster_node_errors": 0}

        if self._redis_log_store is not None and config.log_redis_enabled:
            redis_result = await self._redis_log_store.clear_job_logs_with_breakdown()
            result["captcha_jobs"] += int(redis_result.get("captcha_jobs") or 0)
            result["portal_user_jobs"] += int(redis_result.get("portal_user_jobs") or 0)

            nodes = await self.list_cluster_nodes()
            for node in nodes:
                node_id = int(node.get("id") or 0)
                if node_id <= 0:
                    continue
                result["cluster_node_heartbeats"] += await self._redis_log_store.clear_cluster_heartbeats(node_id=node_id)
                result["cluster_node_errors"] += await self._redis_log_store.clear_cluster_errors(node_id=node_id)

        async with self._write_connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            try:
                sqlite_result = await self._clear_log_tables_in_tx(
                    db,
                    reset_sequences=False,
                    clear_cluster_node_last_error=False,
                )
                await db.commit()
            except Exception:
                await db.execute("ROLLBACK")
                raise

        for key, value in sqlite_result.items():
            result[key] += int(value or 0)

        total_deleted = sum(int(result.get(key) or 0) for key in result)
        if total_deleted > 0:
            await self._checkpoint_and_vacuum_logs(
                reason="periodic",
                vacuum=self._should_vacuum_periodic_logs(total_deleted),
            )
        return result

    async def _periodic_log_cleanup_loop(self, interval_minutes: int):
        interval_seconds = max(60, int(interval_minutes) * 60)
        while True:
            try:
                await asyncio.sleep(interval_seconds)
                result = await self.clear_runtime_logs()
                total_deleted = sum(int(result.get(key) or 0) for key in result)
                if total_deleted > 0:
                    debug_logger.log_info(
                        "[log_cleanup] cleared logs "
                        f"captcha_jobs={int(result.get('captcha_jobs') or 0)} "
                        f"portal_user_jobs={int(result.get('portal_user_jobs') or 0)} "
                        f"cluster_node_heartbeats={int(result.get('cluster_node_heartbeats') or 0)} "
                        f"cluster_node_errors={int(result.get('cluster_node_errors') or 0)}"
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                debug_logger.log_warning(f"[log_cleanup] periodic cleanup failed: {exc}")

    async def _create_portal_user_job_log_in_tx(
        self,
        db: aiosqlite.Connection,
        *,
        portal_user_id: int,
        session_id: Optional[str],
        project_id: Optional[str],
        action: Optional[str],
        status: str,
        error_reason: Optional[str],
        duration_ms: Optional[int],
    ):
        await db.execute(
            """
            INSERT INTO portal_user_jobs (portal_user_id, session_id, project_id, action, status, error_reason, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (portal_user_id, session_id, project_id, action, status, error_reason, duration_ms),
        )

    async def _create_job_log_in_tx(
        self,
        db: aiosqlite.Connection,
        *,
        session_id: Optional[str],
        api_key_id: Optional[int],
        project_id: Optional[str],
        action: Optional[str],
        status: str,
        error_reason: Optional[str],
        duration_ms: Optional[int],
        portal_user_id: Optional[int] = None,
        portal_api_key_id: Optional[int] = None,
    ):
        normalized_api_key_id = self._normalize_optional_positive_int(api_key_id)
        normalized_portal_user_id = self._normalize_optional_positive_int(portal_user_id)
        normalized_portal_api_key_id = self._normalize_optional_positive_int(portal_api_key_id)

        if normalized_portal_user_id or normalized_portal_api_key_id:
            normalized_api_key_id = None

        await db.execute(
            """
            INSERT INTO captcha_jobs (session_id, api_key_id, project_id, action, status, error_reason, duration_ms, portal_user_id, portal_api_key_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                normalized_api_key_id,
                project_id,
                action,
                status,
                error_reason,
                duration_ms,
                normalized_portal_user_id,
                normalized_portal_api_key_id,
            ),
        )

    async def _refund_portal_user_quota_in_tx(
        self,
        db: aiosqlite.Connection,
        *,
        user_id: int,
        session_id: str,
        reason: str,
        portal_api_key_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT id
            FROM session_quota_events
            WHERE session_id = ? AND owner_type = 'portal_user' AND owner_id = ? AND event_type = 'charge'
            LIMIT 1
            """,
            (session_id, user_id),
        )
        charged = await cursor.fetchone()
        if not charged:
            return False, "未找到可返还的扣次记录"

        cursor = await db.execute(
            """
            INSERT OR IGNORE INTO session_quota_events (session_id, owner_type, owner_id, event_type, note)
            VALUES (?, 'portal_user', ?, 'refund', ?)
            """,
            (session_id, user_id, (reason or "")[:200] or None),
        )
        if int(cursor.rowcount or 0) <= 0:
            return True, "该会话已返还次数"

        await db.execute(
            """
            UPDATE portal_users
            SET quota_remaining = quota_remaining + 1,
                quota_used = MAX(quota_used - 1, 0),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (user_id,),
        )
        cursor = await db.execute("SELECT quota_remaining FROM portal_users WHERE id = ?", (user_id,))
        updated = await cursor.fetchone()
        balance_after = int(updated["quota_remaining"] or 0) if updated else 0
        await db.execute(
            """
            INSERT INTO portal_user_transactions (portal_user_id, change_amount, balance_after, source_type, source_ref, note)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                1,
                balance_after,
                "generation_refund",
                session_id,
                (reason or "生成失败返还次数")[:200],
            ),
        )
        if portal_api_key_id and int(portal_api_key_id) > 0:
            await db.execute(
                """
                UPDATE portal_user_api_keys
                SET quota_used = MAX(quota_used - 1, 0),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (int(portal_api_key_id),),
            )
        return True, "已返还 1 次"

    async def _refund_api_key_quota_in_tx(
        self,
        db: aiosqlite.Connection,
        *,
        api_key_id: int,
        session_id: str,
        reason: str,
    ) -> Tuple[bool, str]:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT id
            FROM session_quota_events
            WHERE session_id = ? AND owner_type = 'service_api_key' AND owner_id = ? AND event_type = 'charge'
            LIMIT 1
            """,
            (session_id, api_key_id),
        )
        charged = await cursor.fetchone()
        if not charged:
            return False, "未找到可返还的扣次记录"

        cursor = await db.execute(
            """
            INSERT OR IGNORE INTO session_quota_events (session_id, owner_type, owner_id, event_type, note)
            VALUES (?, 'service_api_key', ?, 'refund', ?)
            """,
            (session_id, api_key_id, (reason or "")[:200] or None),
        )
        if int(cursor.rowcount or 0) <= 0:
            return True, "该会话已返还次数"

        await db.execute(
            """
            UPDATE service_api_keys
            SET quota_remaining = CASE
                    WHEN quota_remaining IS NULL THEN NULL
                    ELSE quota_remaining + 1
                END,
                quota_used = MAX(quota_used - 1, 0),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (api_key_id,),
        )
        return True, "已返还 1 次"

    @staticmethod
    def _hash_secret(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _generate_cluster_key() -> str:
        return f"fcs_cluster_{secrets.token_urlsafe(24)}"

    @staticmethod
    def _generate_service_api_key() -> tuple[str, str, str]:
        raw_key = f"fcs_{secrets.token_urlsafe(32)}"
        return raw_key, Database._hash_secret(raw_key), raw_key[:12]

    async def init_db(self):
        async with self._write_connect() as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA journal_mode = WAL")
            await db.execute("PRAGMA synchronous = NORMAL")

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS captcha_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    browser_proxy_enabled BOOLEAN DEFAULT 0,
                    browser_proxy_url TEXT,
                    browser_count INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS service_admin (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS service_api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_prefix TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    quota_remaining INTEGER,
                    quota_used INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS portal_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT,
                    password_hash TEXT NOT NULL,
                    register_location TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    quota_remaining INTEGER DEFAULT 0,
                    quota_used INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login_at TIMESTAMP
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS portal_cdks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT NOT NULL UNIQUE,
                    quota_times INTEGER NOT NULL,
                    batch_prefix TEXT,
                    note TEXT,
                    enabled BOOLEAN DEFAULT 1,
                    redeemed_user_id INTEGER,
                    redeemed_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(redeemed_user_id) REFERENCES portal_users(id)
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS portal_user_api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    portal_user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_prefix TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    quota_used INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP,
                    FOREIGN KEY(portal_user_id) REFERENCES portal_users(id)
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS portal_user_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    portal_user_id INTEGER NOT NULL,
                    change_amount INTEGER NOT NULL,
                    balance_after INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    source_ref TEXT,
                    note TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(portal_user_id) REFERENCES portal_users(id)
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS session_quota_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    owner_type TEXT NOT NULL,
                    owner_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    note TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(session_id, owner_type, owner_id, event_type)
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS captcha_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    api_key_id INTEGER,
                    project_id TEXT,
                    action TEXT,
                    status TEXT,
                    error_reason TEXT,
                    duration_ms INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(api_key_id) REFERENCES service_api_keys(id)
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS portal_user_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    portal_user_id INTEGER NOT NULL,
                    session_id TEXT,
                    project_id TEXT,
                    action TEXT,
                    status TEXT,
                    error_reason TEXT,
                    duration_ms INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(portal_user_id) REFERENCES portal_users(id)
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS portal_user_checkins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    portal_user_id INTEGER NOT NULL,
                    checkin_date TEXT NOT NULL,
                    quota_granted INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(portal_user_id) REFERENCES portal_users(id),
                    UNIQUE(portal_user_id, checkin_date)
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS cluster_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    cluster_key TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS cluster_nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_name TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    node_api_key TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    healthy BOOLEAN DEFAULT 1,
                    active_sessions INTEGER DEFAULT 0,
                    cached_sessions INTEGER DEFAULT 0,
                    max_concurrency INTEGER DEFAULT 1,
                    weight INTEGER DEFAULT 100,
                    last_heartbeat_at TIMESTAMP,
                    last_error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # 历史版本把 node_name 设为 UNIQUE，会导致同名子节点覆盖；这里统一迁移为非唯一。
            await self._migrate_cluster_nodes_schema(db)
            await self._ensure_cluster_nodes_columns(db)
            await self._add_column_if_missing(db, "captcha_jobs", "portal_user_id", "INTEGER")
            await self._add_column_if_missing(db, "captcha_jobs", "portal_api_key_id", "INTEGER")
            await self._repair_captcha_jobs_owner_references(db)

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS cluster_node_heartbeats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    healthy BOOLEAN DEFAULT 1,
                    reason TEXT,
                    payload_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(node_id) REFERENCES cluster_nodes(id)
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS cluster_node_errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id INTEGER NOT NULL,
                    error_type TEXT NOT NULL,
                    error_message TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(node_id) REFERENCES cluster_nodes(id)
                )
                """
            )

            await db.execute("CREATE INDEX IF NOT EXISTS idx_captcha_jobs_created_at ON captcha_jobs(created_at DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_captcha_jobs_status ON captcha_jobs(status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_captcha_jobs_api_key_created ON captcha_jobs(api_key_id, created_at DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_portal_users_enabled ON portal_users(enabled)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_portal_users_last_login ON portal_users(last_login_at DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_portal_cdks_enabled ON portal_cdks(enabled)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_portal_cdks_redeemed_user_id ON portal_cdks(redeemed_user_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_portal_user_api_keys_user_id ON portal_user_api_keys(portal_user_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_portal_user_api_keys_enabled ON portal_user_api_keys(enabled)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_portal_user_transactions_user_created ON portal_user_transactions(portal_user_id, created_at DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_portal_user_jobs_user_created ON portal_user_jobs(portal_user_id, created_at DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_portal_user_jobs_status ON portal_user_jobs(status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_portal_user_checkins_user_date ON portal_user_checkins(portal_user_id, checkin_date DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_captcha_jobs_portal_user_created ON captcha_jobs(portal_user_id, created_at DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_session_quota_events_session ON session_quota_events(session_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_service_api_keys_enabled ON service_api_keys(enabled)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_cluster_nodes_enabled ON cluster_nodes(enabled)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_cluster_nodes_heartbeat ON cluster_nodes(last_heartbeat_at DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_cluster_nodes_base_url ON cluster_nodes(base_url)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_cluster_node_heartbeats_node_id ON cluster_node_heartbeats(node_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_cluster_node_heartbeats_created_at ON cluster_node_heartbeats(created_at DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_cluster_node_errors_node_id ON cluster_node_errors(node_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_cluster_node_errors_created_at ON cluster_node_errors(created_at DESC)")

            await db.commit()

        await self._ensure_defaults()

    async def _migrate_cluster_nodes_schema(self, db: aiosqlite.Connection):
        cursor = await db.execute("PRAGMA index_list(cluster_nodes)")
        indexes = await cursor.fetchall()

        has_node_name_unique = False
        for idx in indexes:
            idx_name = idx[1]
            is_unique = bool(idx[2])
            if not is_unique:
                continue

            idx_cursor = await db.execute(f"PRAGMA index_info('{idx_name}')")
            idx_columns = await idx_cursor.fetchall()
            if len(idx_columns) == 1 and str(idx_columns[0][2] or "") == "node_name":
                has_node_name_unique = True
                break

        if not has_node_name_unique:
            return

        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS cluster_nodes_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                node_api_key TEXT NOT NULL,
                enabled BOOLEAN DEFAULT 1,
                healthy BOOLEAN DEFAULT 1,
                active_sessions INTEGER DEFAULT 0,
                cached_sessions INTEGER DEFAULT 0,
                max_concurrency INTEGER DEFAULT 1,
                reported_browser_count INTEGER DEFAULT 1,
                reported_node_max_concurrency INTEGER DEFAULT 1,
                weight INTEGER DEFAULT 100,
                last_heartbeat_at TIMESTAMP,
                last_error TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await db.execute(
            """
            INSERT INTO cluster_nodes_v2 (
                id, node_name, base_url, node_api_key, enabled, healthy,
                active_sessions, cached_sessions, max_concurrency,
                reported_browser_count, reported_node_max_concurrency, weight,
                last_heartbeat_at, last_error, created_at, updated_at
            )
            SELECT
                id, node_name, base_url, node_api_key, enabled, healthy,
                active_sessions, cached_sessions, max_concurrency,
                max_concurrency, max_concurrency, weight,
                last_heartbeat_at, last_error, created_at, updated_at
            FROM cluster_nodes
            ORDER BY id ASC
            """
        )
        await db.execute("DROP TABLE cluster_nodes")
        await db.execute("ALTER TABLE cluster_nodes_v2 RENAME TO cluster_nodes")

    async def _ensure_cluster_nodes_columns(self, db: aiosqlite.Connection):
        await self._add_column_if_missing(db, "cluster_nodes", "reported_browser_count", "INTEGER DEFAULT 1")
        await self._add_column_if_missing(db, "cluster_nodes", "reported_node_max_concurrency", "INTEGER DEFAULT 1")

    async def _add_column_if_missing(
        self,
        db: aiosqlite.Connection,
        table_name: str,
        column_name: str,
        column_definition: str,
    ):
        cursor = await db.execute(f"PRAGMA table_info({table_name})")
        columns = await cursor.fetchall()
        existing = {str(col[1]) for col in columns}
        if column_name in existing:
            return
        await db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")

    async def _repair_captcha_jobs_owner_references(self, db: aiosqlite.Connection):
        cursor = await db.execute(
            """
            SELECT COUNT(*)
            FROM captcha_jobs j
            LEFT JOIN service_api_keys k ON k.id = j.api_key_id
            WHERE j.api_key_id IS NOT NULL
              AND j.api_key_id > 0
              AND k.id IS NULL
            """
        )
        row = await cursor.fetchone()
        invalid_before = int(row[0] or 0) if row else 0
        if invalid_before <= 0:
            return

        remap_portal_key_cursor = await db.execute(
            """
            UPDATE captcha_jobs
            SET portal_api_key_id = api_key_id
            WHERE (portal_api_key_id IS NULL OR portal_api_key_id <= 0)
              AND api_key_id IS NOT NULL
              AND api_key_id > 0
              AND NOT EXISTS (SELECT 1 FROM service_api_keys k WHERE k.id = captcha_jobs.api_key_id)
              AND EXISTS (SELECT 1 FROM portal_user_api_keys pk WHERE pk.id = captcha_jobs.api_key_id)
            """
        )
        remap_portal_key_count = int(remap_portal_key_cursor.rowcount or 0)

        fill_portal_user_cursor = await db.execute(
            """
            UPDATE captcha_jobs
            SET portal_user_id = (
                SELECT pk.portal_user_id
                FROM portal_user_api_keys pk
                WHERE pk.id = captcha_jobs.portal_api_key_id
            )
            WHERE (portal_user_id IS NULL OR portal_user_id <= 0)
              AND portal_api_key_id IS NOT NULL
              AND portal_api_key_id > 0
              AND EXISTS (SELECT 1 FROM portal_user_api_keys pk WHERE pk.id = captcha_jobs.portal_api_key_id)
            """
        )
        fill_portal_user_count = int(fill_portal_user_cursor.rowcount or 0)

        clear_portal_owner_api_key_cursor = await db.execute(
            """
            UPDATE captcha_jobs
            SET api_key_id = NULL
            WHERE api_key_id IS NOT NULL
              AND (
                    (portal_user_id IS NOT NULL AND portal_user_id > 0)
                 OR (portal_api_key_id IS NOT NULL AND portal_api_key_id > 0)
              )
            """
        )
        clear_portal_owner_api_key_count = int(clear_portal_owner_api_key_cursor.rowcount or 0)

        clear_invalid_api_key_cursor = await db.execute(
            """
            UPDATE captcha_jobs
            SET api_key_id = NULL
            WHERE api_key_id IS NOT NULL
              AND (
                    api_key_id <= 0
                 OR NOT EXISTS (SELECT 1 FROM service_api_keys k WHERE k.id = captcha_jobs.api_key_id)
              )
            """
        )
        clear_invalid_api_key_count = int(clear_invalid_api_key_cursor.rowcount or 0)

        cursor = await db.execute(
            """
            SELECT COUNT(*)
            FROM captcha_jobs j
            LEFT JOIN service_api_keys k ON k.id = j.api_key_id
            WHERE j.api_key_id IS NOT NULL
              AND j.api_key_id > 0
              AND k.id IS NULL
            """
        )
        row = await cursor.fetchone()
        invalid_after = int(row[0] or 0) if row else 0

        debug_logger.log_info(
            "[Database] captcha_jobs owner repair "
            f"invalid_before={invalid_before} remap_portal_key={remap_portal_key_count} "
            f"fill_portal_user={fill_portal_user_count} clear_portal_owner_api_key={clear_portal_owner_api_key_count} "
            f"clear_invalid_api_key={clear_invalid_api_key_count} invalid_after={invalid_after}"
        )

    async def _ensure_defaults(self):
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row

            cursor = await db.execute("SELECT id FROM captcha_config WHERE id = 1")
            row = await cursor.fetchone()
            if not row:
                await db.execute(
                    """
                    INSERT INTO captcha_config (id, browser_proxy_enabled, browser_proxy_url, browser_count)
                    VALUES (1, ?, ?, ?)
                    """,
                    (1 if config.browser_proxy_enabled else 0, config.browser_proxy_url or None, config.browser_count),
                )

            cursor = await db.execute("SELECT id FROM service_admin WHERE id = 1")
            row = await cursor.fetchone()
            if not row:
                await db.execute(
                    """
                    INSERT INTO service_admin (id, username, password_hash)
                    VALUES (1, ?, ?)
                    """,
                    (config.admin_username, self._hash_secret(config.admin_password)),
                )

            cursor = await db.execute("SELECT id FROM cluster_settings WHERE id = 1")
            row = await cursor.fetchone()
            if not row:
                await db.execute(
                    """
                    INSERT INTO cluster_settings (id, cluster_key)
                    VALUES (1, ?)
                    """,
                    (self._generate_cluster_key(),),
                )

            await db.commit()

    async def verify_admin_credentials(self, username: str, password: str) -> bool:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT username, password_hash FROM service_admin WHERE id = 1"
            )
            row = await cursor.fetchone()
            if not row:
                return False
            if row["username"] != username:
                return False
            return row["password_hash"] == self._hash_secret(password)

    async def get_admin_profile(self) -> Dict[str, Any]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT username, created_at, updated_at FROM service_admin WHERE id = 1"
            )
            row = await cursor.fetchone()
            if not row:
                return {
                    "username": config.admin_username,
                    "created_at": None,
                    "updated_at": None,
                }
            return dict(row)

    async def update_admin_credentials(
        self,
        current_password: str,
        new_username: Optional[str] = None,
        new_password: Optional[str] = None,
    ) -> tuple[bool, str, Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT username, password_hash, created_at, updated_at FROM service_admin WHERE id = 1"
            )
            row = await cursor.fetchone()
            if not row:
                return False, "管理员账号不存在", {}

            if row["password_hash"] != self._hash_secret(current_password):
                return False, "当前密码错误", {}

            username = (new_username or row["username"] or "").strip()
            if not username:
                return False, "用户名不能为空", {}

            password_hash = row["password_hash"]
            if new_password:
                password_hash = self._hash_secret(new_password)

            await db.execute(
                """
                UPDATE service_admin
                SET username = ?,
                    password_hash = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
                """,
                (username, password_hash),
            )
            await db.commit()

        profile = await self.get_admin_profile()
        return True, "管理员账号更新成功", profile

    async def get_portal_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, username, display_name, register_location, enabled,
                       quota_remaining, quota_used, created_at, updated_at, last_login_at
                FROM portal_users
                WHERE id = ?
                """,
                (user_id,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_portal_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        normalized = str(username or "").strip()
        if not normalized:
            return None

        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, username, display_name, register_location, enabled,
                       quota_remaining, quota_used, created_at, updated_at, last_login_at,
                       password_hash
                FROM portal_users
                WHERE username = ?
                """,
                (normalized,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def create_portal_user(
        self,
        username: str,
        password: str,
        register_location: str,
        display_name: Optional[str] = None,
        initial_quota: int = 0,
    ) -> tuple[bool, str, Optional[Dict[str, Any]]]:
        normalized_username = str(username or "").strip()
        normalized_location = str(register_location or "").strip()
        normalized_display_name = str(display_name or normalized_username).strip() or normalized_username
        if not normalized_username:
            return False, "用户名不能为空", None
        if not normalized_location:
            return False, "注册位置不能为空", None
        existing = await self.get_portal_user_by_username(normalized_username)
        if existing:
            return False, "该用户名已经注册", None

        async with self._connect() as db:
            cursor = await db.execute(
                """
                INSERT INTO portal_users (username, display_name, password_hash, register_location, enabled, quota_remaining, quota_used)
                VALUES (?, ?, ?, ?, 1, 0, 0)
                """,
                (normalized_username, normalized_display_name, self._hash_secret(password), normalized_location),
            )
            user_id = int(cursor.lastrowid or 0)
            if int(initial_quota or 0) > 0:
                await db.execute(
                    """
                    UPDATE portal_users
                    SET quota_remaining = quota_remaining + ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (int(initial_quota), user_id),
                )
            await db.commit()

        if int(initial_quota or 0) > 0:
            user = await self.get_portal_user(user_id)
            await self.create_portal_user_transaction(
                portal_user_id=user_id,
                change_amount=int(initial_quota),
                balance_after=int(user.get("quota_remaining") or 0) if user else int(initial_quota),
                source_type="register_bonus",
                source_ref=str(user_id),
                note="注册赠送额度",
            )
        return True, "注册成功", await self.get_portal_user(user_id)

    async def verify_portal_user_credentials(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        user = await self.get_portal_user_by_username(username)
        if not user:
            return None
        if user.get("password_hash") != self._hash_secret(password):
            return None
        return await self.get_portal_user(int(user["id"]))

    async def mark_portal_user_login(self, user_id: int):
        async with self._connect() as db:
            await db.execute(
                "UPDATE portal_users SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,),
            )
            await db.commit()

    async def list_portal_users(self) -> List[Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, username, display_name, register_location, enabled,
                       quota_remaining, quota_used, created_at, updated_at, last_login_at
                FROM portal_users
                ORDER BY id DESC
                """
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def update_portal_user(
        self,
        user_id: int,
        username: Optional[str] = None,
        enabled: Optional[bool] = None,
        display_name: Optional[str] = None,
        quota_remaining_delta: Optional[int] = None,
        quota_remaining: Optional[int] = None,
        quota_used: Optional[int] = None,
        new_password: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        current = await self.get_portal_user(user_id)
        if not current:
            return None

        current_username = str(current.get("username") or "").strip()
        new_username = str(username or current_username).strip()
        if not new_username:
            raise ValueError("用户名不能为空")
        if new_username != current_username:
            existing_user = await self.get_portal_user_by_username(new_username)
            if existing_user and int(existing_user.get("id") or 0) != int(user_id):
                raise ValueError("该账号已存在")

        new_enabled = int(bool(enabled)) if enabled is not None else int(bool(current["enabled"]))
        if display_name is not None:
            new_display_name = str(display_name or "").strip() or new_username
        else:
            new_display_name = str(current.get("display_name") or "").strip() or new_username

        current_quota_remaining = int(current.get("quota_remaining") or 0)
        if quota_remaining is not None:
            new_quota_remaining = max(0, int(quota_remaining))
        else:
            delta = int(quota_remaining_delta or 0)
            new_quota_remaining = max(current_quota_remaining + delta, 0)
        effective_delta = new_quota_remaining - current_quota_remaining
        new_quota_used = max(0, int(quota_used)) if quota_used is not None else int(current.get("quota_used") or 0)
        new_password_hash = self._hash_secret(new_password) if new_password else None

        async with self._write_connect() as db:
            if new_password_hash:
                await db.execute(
                    """
                    UPDATE portal_users
                    SET username = ?,
                        enabled = ?,
                        display_name = ?,
                        quota_remaining = ?,
                        quota_used = ?,
                        password_hash = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        new_username,
                        new_enabled,
                        new_display_name,
                        new_quota_remaining,
                        new_quota_used,
                        new_password_hash,
                        user_id,
                    ),
                )
            else:
                await db.execute(
                    """
                    UPDATE portal_users
                    SET username = ?,
                        enabled = ?,
                        display_name = ?,
                        quota_remaining = ?,
                        quota_used = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        new_username,
                        new_enabled,
                        new_display_name,
                        new_quota_remaining,
                        new_quota_used,
                        user_id,
                    ),
                )
            await db.commit()

        updated = await self.get_portal_user(user_id)
        if updated is None:
            return None
        if effective_delta != 0:
            await self.create_portal_user_transaction(
                portal_user_id=user_id,
                change_amount=effective_delta,
                balance_after=int(updated.get("quota_remaining") or 0),
                source_type="admin_adjust",
                source_ref=str(user_id),
                note="管理员调整剩余次数" if quota_remaining is None else "管理员设置剩余次数",
            )
        if enabled is False:
            await self.set_portal_user_api_keys_enabled(user_id, False)
        return updated

    async def ensure_portal_user_available(self, user_id: int) -> Tuple[bool, str]:
        user = await self.get_portal_user(user_id)
        if not user:
            return False, "用户不存在"
        if not bool(user.get("enabled")):
            return False, "用户已禁用"
        if int(user.get("quota_remaining") or 0) <= 0:
            return False, "剩余次数不足"
        return True, ""

    async def consume_portal_user_quota(
        self,
        user_id: int,
        source_type: str = "solve_success",
        source_ref: Optional[str] = None,
        note: Optional[str] = None,
        portal_api_key_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        async with self._write_connect() as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            try:
                cursor = await db.execute(
                    "SELECT enabled, quota_remaining, quota_used FROM portal_users WHERE id = ?",
                    (user_id,),
                )
                row = await cursor.fetchone()
                if not row:
                    await db.execute("ROLLBACK")
                    return False, "用户不存在"
                if not bool(row["enabled"]):
                    await db.execute("ROLLBACK")
                    return False, "用户已禁用"
                if int(row["quota_remaining"] or 0) <= 0:
                    await db.execute("ROLLBACK")
                    return False, "剩余次数不足"

                await db.execute(
                    """
                    UPDATE portal_users
                    SET quota_remaining = quota_remaining - 1,
                        quota_used = quota_used + 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND quota_remaining > 0
                    """,
                    (user_id,),
                )
                cursor = await db.execute("SELECT quota_remaining FROM portal_users WHERE id = ?", (user_id,))
                updated = await cursor.fetchone()
                balance_after = int(updated["quota_remaining"] or 0) if updated else 0
                await db.execute(
                    """
                    INSERT INTO portal_user_transactions (portal_user_id, change_amount, balance_after, source_type, source_ref, note)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, -1, balance_after, (source_type or "solve_success")[:80], source_ref, note),
                )
                normalized_ref = str(source_ref or "").strip()
                if normalized_ref:
                    await db.execute(
                        """
                        INSERT OR IGNORE INTO session_quota_events (session_id, owner_type, owner_id, event_type, note)
                        VALUES (?, 'portal_user', ?, 'charge', ?)
                        """,
                        (normalized_ref, user_id, (note or "")[:200] or None),
                    )
                if portal_api_key_id and int(portal_api_key_id) > 0:
                    await db.execute(
                        """
                        UPDATE portal_user_api_keys
                        SET quota_used = quota_used + 1,
                            last_used_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        (int(portal_api_key_id),),
                    )
                await db.commit()
                return True, ""
            except Exception:
                await db.execute("ROLLBACK")
                raise

    async def refund_portal_user_quota(
        self,
        user_id: int,
        session_id: str,
        reason: str,
        portal_api_key_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        normalized_session_id = str(session_id or "").strip()
        if not normalized_session_id:
            return False, "session_id 不能为空"

        async with self._write_connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            try:
                refunded, message = await self._refund_portal_user_quota_in_tx(
                    db,
                    user_id=user_id,
                    session_id=normalized_session_id,
                    reason=reason,
                    portal_api_key_id=portal_api_key_id,
                )
                await db.commit()
                return refunded, message
            except Exception:
                await db.execute("ROLLBACK")
                raise

    async def create_portal_user_job_log(
        self,
        portal_user_id: int,
        session_id: Optional[str],
        project_id: Optional[str],
        action: Optional[str],
        status: str,
        error_reason: Optional[str],
        duration_ms: Optional[int],
    ):
        if self._job_logs_use_redis():
            await self._redis_log_store.append_job_log(
                {
                    "log_scope": "portal_user_jobs",
                    "portal_user_id": int(portal_user_id),
                    "session_id": session_id,
                    "project_id": project_id,
                    "action": action,
                    "status": status,
                    "error_reason": error_reason,
                    "duration_ms": duration_ms,
                }
            )
            return
        async with self._write_connect() as db:
            await self._create_portal_user_job_log_in_tx(
                db,
                portal_user_id=portal_user_id,
                session_id=session_id,
                project_id=project_id,
                action=action,
                status=status,
                error_reason=error_reason,
                duration_ms=duration_ms,
            )
            await db.commit()

    def _normalize_redis_job_log(self, raw: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(raw, dict):
            return None
        item = dict(raw)
        item["id"] = int(item.get("id") or 0)
        item["api_key_id"] = self._normalize_optional_positive_int(item.get("api_key_id"))
        item["portal_user_id"] = self._normalize_optional_positive_int(item.get("portal_user_id"))
        item["portal_api_key_id"] = self._normalize_optional_positive_int(item.get("portal_api_key_id"))
        try:
            item["duration_ms"] = int(item["duration_ms"]) if item.get("duration_ms") is not None else None
        except (TypeError, ValueError):
            item["duration_ms"] = None
        item["log_scope"] = str(item.get("log_scope") or "captcha_jobs").strip() or "captcha_jobs"
        return item

    async def _get_redis_job_logs(self, *, limit: Optional[int] = None, offset: int = 0) -> List[Dict[str, Any]]:
        if self._redis_log_store is None:
            return []
        if limit is None:
            items = await self._redis_log_store.list_all_job_logs()
        else:
            safe_limit = max(1, int(limit or 1))
            safe_offset = max(0, int(offset or 0))
            items = await self._redis_log_store.list_job_logs(limit=safe_limit, offset=safe_offset)
        normalized: List[Dict[str, Any]] = []
        for raw in items:
            item = self._normalize_redis_job_log(raw)
            if item is not None:
                normalized.append(item)
        if limit is None:
            normalized.sort(key=lambda item: (str(item.get("created_at") or ""), int(item.get("id") or 0)), reverse=True)
        return normalized

    async def _get_all_redis_job_logs(self) -> List[Dict[str, Any]]:
        return await self._get_redis_job_logs(limit=None, offset=0)

    async def _ensure_redis_job_log_indexes(self):
        if self._redis_log_store is None:
            return
        async with self._redis_job_index_lock:
            if await self._redis_log_store.job_log_indexes_ready():
                return
            await self._redis_log_store.ensure_job_log_indexes()

    async def _get_redis_job_logs_by_scope(
        self,
        *,
        scope: str,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if self._redis_log_store is None:
            return []
        normalized_scope = str(scope or "captcha_jobs").strip() or "captcha_jobs"
        if await self._redis_log_store.job_log_scope_index_exists(scope=normalized_scope):
            if limit is None:
                items = await self._redis_log_store.list_all_job_logs_by_scope(scope=normalized_scope)
            else:
                items = await self._redis_log_store.list_job_logs_by_scope(
                    scope=normalized_scope,
                    limit=max(1, int(limit or 1)),
                    offset=max(0, int(offset or 0)),
                )
            return [item for item in (self._normalize_redis_job_log(raw) for raw in items) if item is not None]
        if await self._redis_log_store.job_log_indexes_ready():
            return []
        await self._ensure_redis_job_log_indexes()
        if await self._redis_log_store.job_log_scope_index_exists(scope=normalized_scope):
            return await self._get_redis_job_logs_by_scope(scope=normalized_scope, limit=limit, offset=offset)
        return []

    async def _count_redis_job_logs_by_scope(self, *, scope: str) -> int:
        if self._redis_log_store is None:
            return 0
        normalized_scope = str(scope or "captcha_jobs").strip() or "captcha_jobs"
        if await self._redis_log_store.job_log_scope_index_exists(scope=normalized_scope):
            return await self._redis_log_store.count_job_logs_by_scope(scope=normalized_scope)
        if await self._redis_log_store.job_log_indexes_ready():
            return 0
        await self._ensure_redis_job_log_indexes()
        if await self._redis_log_store.job_log_scope_index_exists(scope=normalized_scope):
            return await self._redis_log_store.count_job_logs_by_scope(scope=normalized_scope)
        return 0

    async def _get_redis_job_logs_by_api_key(
        self,
        *,
        api_key_id: int,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if self._redis_log_store is None:
            return []
        normalized_api_key_id = int(api_key_id or 0)
        if normalized_api_key_id <= 0:
            return []
        if await self._redis_log_store.job_log_api_key_index_exists(api_key_id=normalized_api_key_id):
            if limit is None:
                items = await self._redis_log_store.list_all_job_logs_by_api_key(api_key_id=normalized_api_key_id)
            else:
                items = await self._redis_log_store.list_job_logs_by_api_key(
                    api_key_id=normalized_api_key_id,
                    limit=max(1, int(limit or 1)),
                    offset=max(0, int(offset or 0)),
                )
            return [item for item in (self._normalize_redis_job_log(raw) for raw in items) if item is not None]
        if await self._redis_log_store.job_log_indexes_ready():
            return []
        await self._ensure_redis_job_log_indexes()
        if await self._redis_log_store.job_log_api_key_index_exists(api_key_id=normalized_api_key_id):
            return await self._get_redis_job_logs_by_api_key(
                api_key_id=normalized_api_key_id,
                limit=limit,
                offset=offset,
            )
        return []

    async def _count_redis_job_logs_by_api_key(self, *, api_key_id: int) -> int:
        if self._redis_log_store is None:
            return 0
        normalized_api_key_id = int(api_key_id or 0)
        if normalized_api_key_id <= 0:
            return 0
        if await self._redis_log_store.job_log_api_key_index_exists(api_key_id=normalized_api_key_id):
            return await self._redis_log_store.count_job_logs_by_api_key(api_key_id=normalized_api_key_id)
        if await self._redis_log_store.job_log_indexes_ready():
            return 0
        await self._ensure_redis_job_log_indexes()
        if await self._redis_log_store.job_log_api_key_index_exists(api_key_id=normalized_api_key_id):
            return await self._redis_log_store.count_job_logs_by_api_key(api_key_id=normalized_api_key_id)
        return 0

    async def _get_redis_job_logs_by_portal_user(
        self,
        *,
        portal_user_id: int,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if self._redis_log_store is None:
            return []
        normalized_portal_user_id = int(portal_user_id or 0)
        if normalized_portal_user_id <= 0:
            return []
        if await self._redis_log_store.job_log_portal_user_index_exists(portal_user_id=normalized_portal_user_id):
            if limit is None:
                items = await self._redis_log_store.list_all_job_logs_by_portal_user(portal_user_id=normalized_portal_user_id)
            else:
                items = await self._redis_log_store.list_job_logs_by_portal_user(
                    portal_user_id=normalized_portal_user_id,
                    limit=max(1, int(limit or 1)),
                    offset=max(0, int(offset or 0)),
                )
            return [item for item in (self._normalize_redis_job_log(raw) for raw in items) if item is not None]
        if await self._redis_log_store.job_log_indexes_ready():
            return []
        await self._ensure_redis_job_log_indexes()
        if await self._redis_log_store.job_log_portal_user_index_exists(portal_user_id=normalized_portal_user_id):
            return await self._get_redis_job_logs_by_portal_user(
                portal_user_id=normalized_portal_user_id,
                limit=limit,
                offset=offset,
            )
        return []

    async def _count_redis_job_logs_by_portal_user(self, *, portal_user_id: int) -> int:
        if self._redis_log_store is None:
            return 0
        normalized_portal_user_id = int(portal_user_id or 0)
        if normalized_portal_user_id <= 0:
            return 0
        if await self._redis_log_store.job_log_portal_user_index_exists(portal_user_id=normalized_portal_user_id):
            return await self._redis_log_store.count_job_logs_by_portal_user(portal_user_id=normalized_portal_user_id)
        if await self._redis_log_store.job_log_indexes_ready():
            return 0
        await self._ensure_redis_job_log_indexes()
        if await self._redis_log_store.job_log_portal_user_index_exists(portal_user_id=normalized_portal_user_id):
            return await self._redis_log_store.count_job_logs_by_portal_user(portal_user_id=normalized_portal_user_id)
        return 0

    @staticmethod
    def _parse_timestamp(value: Any) -> Optional[datetime]:
        text = str(value or "").strip()
        if not text:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None

    async def list_portal_user_jobs(
        self,
        portal_user_id: int,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if self._job_logs_use_redis():
            safe_limit = max(1, min(int(limit), 200))
            safe_offset = max(0, int(offset))
            normalized_status = str(status or "").strip()
            normalized_project_id = str(project_id or "").strip()
            portal_key_cache: Dict[int, Optional[Dict[str, Any]]] = {}
            items: List[Dict[str, Any]] = []
            for entry in await self._get_redis_job_logs_by_portal_user(
                portal_user_id=portal_user_id,
                limit=None,
                offset=0,
            ):
                if normalized_status and str(entry.get("status") or "").strip() != normalized_status:
                    continue
                if normalized_project_id and str(entry.get("project_id") or "").strip() != normalized_project_id:
                    continue
                item = {
                    "id": int(entry.get("id") or 0),
                    "portal_user_id": int(entry.get("portal_user_id") or 0),
                    "session_id": entry.get("session_id"),
                    "project_id": entry.get("project_id"),
                    "action": entry.get("action"),
                    "status": entry.get("status"),
                    "error_reason": entry.get("error_reason"),
                    "duration_ms": entry.get("duration_ms"),
                    "created_at": entry.get("created_at"),
                    "source": "portal" if entry.get("log_scope") == "portal_user_jobs" else "api",
                    "api_key_name": None,
                    "api_key_prefix": None,
                }
                portal_api_key_id = int(entry.get("portal_api_key_id") or 0)
                if portal_api_key_id > 0 and item["source"] == "api":
                    if portal_api_key_id not in portal_key_cache:
                        portal_key_cache[portal_api_key_id] = await self.get_portal_user_api_key(portal_api_key_id)
                    portal_key = portal_key_cache.get(portal_api_key_id) or {}
                    item["api_key_name"] = portal_key.get("name")
                    item["api_key_prefix"] = portal_key.get("key_prefix")
                items.append(item)
            return items[safe_offset:safe_offset + safe_limit]

        safe_limit = max(1, min(int(limit), 200))
        safe_offset = max(0, int(offset))
        filters: List[str] = []
        params: List[Any] = [portal_user_id, portal_user_id]

        if str(status or "").strip():
            filters.append("status = ?")
            params.append(str(status).strip())
        if str(project_id or "").strip():
            filters.append("project_id = ?")
            params.append(str(project_id).strip())

        where_sql = f"WHERE {' AND '.join(filters)}" if filters else ""
        params.extend([safe_limit, safe_offset])
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                f"""
                SELECT *
                FROM (
                    SELECT id, portal_user_id, session_id, project_id, action, status, error_reason, duration_ms, created_at,
                           NULL AS api_key_name, NULL AS api_key_prefix, 'portal' AS source
                    FROM portal_user_jobs
                    WHERE portal_user_id = ?
                    UNION ALL
                    SELECT j.id, j.portal_user_id, j.session_id, j.project_id, j.action, j.status, j.error_reason, j.duration_ms, j.created_at,
                           pk.name AS api_key_name, pk.key_prefix AS api_key_prefix, 'api' AS source
                    FROM captcha_jobs j
                    LEFT JOIN portal_user_api_keys pk ON pk.id = j.portal_api_key_id
                    WHERE j.portal_user_id = ?
                ) merged
                {where_sql}
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                params,
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def count_portal_user_jobs(
        self,
        portal_user_id: int,
        status: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> int:
        if self._job_logs_use_redis():
            normalized_status = str(status or "").strip()
            normalized_project_id = str(project_id or "").strip()
            if not normalized_status and not normalized_project_id:
                return await self._count_redis_job_logs_by_portal_user(portal_user_id=portal_user_id)
            total = 0
            for entry in await self._get_redis_job_logs_by_portal_user(
                portal_user_id=portal_user_id,
                limit=None,
                offset=0,
            ):
                if normalized_status and str(entry.get("status") or "").strip() != normalized_status:
                    continue
                if normalized_project_id and str(entry.get("project_id") or "").strip() != normalized_project_id:
                    continue
                total += 1
            return total

        filters: List[str] = []
        params: List[Any] = [portal_user_id, portal_user_id]

        if str(status or "").strip():
            filters.append("status = ?")
            params.append(str(status).strip())
        if str(project_id or "").strip():
            filters.append("project_id = ?")
            params.append(str(project_id).strip())

        where_sql = f"WHERE {' AND '.join(filters)}" if filters else ""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM (
                    SELECT status, project_id
                    FROM portal_user_jobs
                    WHERE portal_user_id = ?
                    UNION ALL
                    SELECT status, project_id
                    FROM captcha_jobs
                    WHERE portal_user_id = ?
                ) merged
                {where_sql}
                """,
                params,
            )
            row = await cursor.fetchone()
            return int(row["total"] or 0) if row else 0

    async def refund_stale_session_quotas(
        self,
        stale_seconds: int,
        limit: int = 100,
    ) -> Dict[str, int]:
        safe_stale = max(60, int(stale_seconds or 60))
        safe_limit = max(1, min(int(limit or 100), 500))
        result = {
            "portal_refunded": 0,
            "service_refunded": 0,
            "timeout_logs_created": 0,
        }

        async with self._connect() as db:
            db.row_factory = aiosqlite.Row

            portal_cursor = await db.execute(
                """
                SELECT
                    e.session_id,
                    e.owner_id AS portal_user_id,
                    CASE
                        WHEN EXISTS (
                            SELECT 1
                            FROM captcha_jobs cj
                            WHERE cj.portal_user_id = e.owner_id
                              AND cj.session_id = e.session_id
                            LIMIT 1
                        ) THEN 'api'
                        ELSE 'portal'
                    END AS source_kind,
                    COALESCE(
                        (
                            SELECT cj.project_id
                            FROM captcha_jobs cj
                            WHERE cj.portal_user_id = e.owner_id
                              AND cj.session_id = e.session_id
                            ORDER BY cj.id DESC
                            LIMIT 1
                        ),
                        (
                            SELECT pj.project_id
                            FROM portal_user_jobs pj
                            WHERE pj.portal_user_id = e.owner_id
                              AND pj.session_id = e.session_id
                            ORDER BY pj.id DESC
                            LIMIT 1
                        )
                    ) AS project_id,
                    COALESCE(
                        (
                            SELECT cj.action
                            FROM captcha_jobs cj
                            WHERE cj.portal_user_id = e.owner_id
                              AND cj.session_id = e.session_id
                            ORDER BY cj.id DESC
                            LIMIT 1
                        ),
                        (
                            SELECT pj.action
                            FROM portal_user_jobs pj
                            WHERE pj.portal_user_id = e.owner_id
                              AND pj.session_id = e.session_id
                            ORDER BY pj.id DESC
                            LIMIT 1
                        )
                    ) AS action,
                    COALESCE(
                        (
                            SELECT cj.api_key_id
                            FROM captcha_jobs cj
                            WHERE cj.portal_user_id = e.owner_id
                              AND cj.session_id = e.session_id
                            ORDER BY cj.id DESC
                            LIMIT 1
                        ),
                        0
                    ) AS api_key_id,
                    COALESCE(
                        (
                            SELECT cj.portal_api_key_id
                            FROM captcha_jobs cj
                            WHERE cj.portal_user_id = e.owner_id
                              AND cj.session_id = e.session_id
                            ORDER BY cj.id DESC
                            LIMIT 1
                        ),
                        0
                    ) AS portal_api_key_id
                FROM session_quota_events e
                WHERE e.owner_type = 'portal_user'
                  AND e.event_type = 'charge'
                  AND e.created_at < datetime('now', '-' || ? || ' seconds')
                  AND NOT EXISTS (
                    SELECT 1
                    FROM session_quota_events r
                    WHERE r.session_id = e.session_id
                      AND r.owner_type = e.owner_type
                      AND r.owner_id = e.owner_id
                      AND r.event_type = 'refund'
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM session_quota_events c
                    WHERE c.session_id = e.session_id
                      AND c.owner_type = e.owner_type
                      AND c.owner_id = e.owner_id
                      AND c.event_type = 'complete'
                  )
                ORDER BY e.id ASC
                LIMIT ?
                """,
                (safe_stale, safe_limit),
            )
            portal_candidates = [dict(row) for row in await portal_cursor.fetchall()]

            service_cursor = await db.execute(
                """
                SELECT
                    e.session_id,
                    e.owner_id AS api_key_id,
                    (
                        SELECT cj.project_id
                        FROM captcha_jobs cj
                        WHERE cj.api_key_id = e.owner_id
                          AND cj.session_id = e.session_id
                        ORDER BY cj.id DESC
                        LIMIT 1
                    ) AS project_id,
                    (
                        SELECT cj.action
                        FROM captcha_jobs cj
                        WHERE cj.api_key_id = e.owner_id
                          AND cj.session_id = e.session_id
                        ORDER BY cj.id DESC
                        LIMIT 1
                    ) AS action
                FROM session_quota_events e
                WHERE e.owner_type = 'service_api_key'
                  AND e.event_type = 'charge'
                  AND e.created_at < datetime('now', '-' || ? || ' seconds')
                  AND NOT EXISTS (
                    SELECT 1
                    FROM session_quota_events r
                    WHERE r.session_id = e.session_id
                      AND r.owner_type = e.owner_type
                      AND r.owner_id = e.owner_id
                      AND r.event_type = 'refund'
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM session_quota_events c
                    WHERE c.session_id = e.session_id
                      AND c.owner_type = e.owner_type
                      AND c.owner_id = e.owner_id
                      AND c.event_type = 'complete'
                  )
                ORDER BY e.id ASC
                LIMIT ?
                """,
                (safe_stale, safe_limit),
            )
            service_candidates = [dict(row) for row in await service_cursor.fetchall()]

        for item in portal_candidates:
            refunded, message = await self.refund_portal_user_quota(
                user_id=int(item["portal_user_id"]),
                session_id=str(item["session_id"] or ""),
                reason="session_timeout",
                portal_api_key_id=int(item.get("portal_api_key_id") or 0) or None,
            )
            if not refunded or message != "已返还 1 次":
                continue

            result["portal_refunded"] += 1
            if str(item.get("source_kind") or "portal") == "api":
                await self.create_job_log(
                    session_id=str(item.get("session_id") or "") or None,
                    api_key_id=int(item.get("api_key_id") or 0),
                    project_id=item.get("project_id"),
                    action=item.get("action"),
                    status="finish:timeout",
                    error_reason="session_timeout",
                    duration_ms=None,
                    portal_user_id=int(item["portal_user_id"]),
                    portal_api_key_id=int(item.get("portal_api_key_id") or 0) or None,
                )
            else:
                await self.create_portal_user_job_log(
                    portal_user_id=int(item["portal_user_id"]),
                    session_id=str(item.get("session_id") or "") or None,
                    project_id=item.get("project_id"),
                    action=item.get("action"),
                    status="finish:timeout",
                    error_reason="session_timeout",
                    duration_ms=None,
                )
            result["timeout_logs_created"] += 1

        for item in service_candidates:
            refunded, message = await self.refund_api_key_quota(
                api_key_id=int(item["api_key_id"]),
                session_id=str(item["session_id"] or ""),
                reason="session_timeout",
            )
            if not refunded or message != "已返还 1 次":
                continue

            result["service_refunded"] += 1
            await self.create_job_log(
                session_id=str(item.get("session_id") or "") or None,
                api_key_id=int(item["api_key_id"]),
                project_id=item.get("project_id"),
                action=item.get("action"),
                status="finish:timeout",
                error_reason="session_timeout",
                duration_ms=None,
            )
            result["timeout_logs_created"] += 1

        return result

    async def get_portal_user_usage_summary(self, user_id: int) -> Optional[Dict[str, Any]]:
        user = await self.get_portal_user(user_id)
        if not user:
            return None

        if self._job_logs_use_redis():
            now = datetime.now(UTC).replace(tzinfo=None)
            request_statuses = {"success", "success_master_dispatch", "failed"}
            failed_statuses = {"failed", "error_reported", "finish:failed", "finish:cancelled", "finish:timeout"}
            items = await self._get_redis_job_logs_by_portal_user(portal_user_id=user_id, limit=None, offset=0)
            request_total = 0
            solve_success_total = 0
            solve_failed_total = 0
            finish_total = 0
            error_total = 0
            recent_24h_total = 0
            recent_7d_total = 0
            duration_values: List[int] = []
            last_request_at: Optional[str] = None
            latest_session_id: Optional[str] = None
            project_totals: Dict[str, int] = {}

            for entry in items:
                status_name = str(entry.get("status") or "").strip()
                created_at = str(entry.get("created_at") or "").strip() or None
                created_dt = self._parse_timestamp(created_at)
                if status_name in request_statuses:
                    request_total += 1
                    project_id_value = str(entry.get("project_id") or "").strip()
                    if project_id_value:
                        project_totals[project_id_value] = project_totals.get(project_id_value, 0) + 1
                if status_name == "finish:success":
                    solve_success_total += 1
                if status_name in failed_statuses:
                    solve_failed_total += 1
                if status_name.startswith("finish:"):
                    finish_total += 1
                if status_name == "error_reported":
                    error_total += 1
                if created_dt is not None:
                    age_seconds = (now - created_dt).total_seconds()
                    if age_seconds <= 24 * 3600:
                        recent_24h_total += 1
                    if age_seconds <= 7 * 24 * 3600:
                        recent_7d_total += 1
                if entry.get("duration_ms") is not None:
                    duration_values.append(int(entry["duration_ms"]))
                if created_at and (last_request_at is None or created_at > last_request_at):
                    last_request_at = created_at
                session_id_value = str(entry.get("session_id") or "").strip()
                if session_id_value and latest_session_id is None:
                    latest_session_id = session_id_value

            top_projects = [
                {"project_id": project_id, "total": total}
                for project_id, total in sorted(project_totals.items(), key=lambda item: (-item[1], item[0]))[:5]
            ]

            async with self._connect() as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(
                    """
                    SELECT checkin_date, quota_granted, created_at
                    FROM portal_user_checkins
                    WHERE portal_user_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (user_id,),
                )
                latest_checkin = await cursor.fetchone()

            solve_total = solve_success_total + solve_failed_total
            return {
                "user": user,
                "usage": {
                    "request_total": request_total,
                    "solve_success_total": solve_success_total,
                    "solve_failed_total": solve_failed_total,
                    "solve_total": solve_total,
                    "finish_total": finish_total,
                    "error_total": error_total,
                    "recent_24h_total": recent_24h_total,
                    "recent_7d_total": recent_7d_total,
                    "avg_duration_ms": int(sum(duration_values) / len(duration_values)) if duration_values else None,
                    "last_request_at": last_request_at,
                    "latest_session_id": latest_session_id,
                    "success_rate": round((solve_success_total / solve_total) * 100, 2) if solve_total > 0 else 0.0,
                    "top_projects": top_projects,
                    "latest_checkin": dict(latest_checkin) if latest_checkin else None,
                },
            }

        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT
                    SUM(CASE WHEN status IN ('success', 'success_master_dispatch', 'failed') THEN 1 ELSE 0 END) AS request_total,
                    SUM(CASE WHEN status = 'finish:success' THEN 1 ELSE 0 END) AS solve_success_total,
                    SUM(CASE WHEN status IN ('failed', 'error_reported', 'finish:failed', 'finish:cancelled', 'finish:timeout') THEN 1 ELSE 0 END) AS solve_failed_total,
                    SUM(CASE WHEN status LIKE 'finish:%' THEN 1 ELSE 0 END) AS finish_total,
                    SUM(CASE WHEN status = 'error_reported' THEN 1 ELSE 0 END) AS error_total,
                    SUM(CASE WHEN created_at >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS recent_24h_total,
                    SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS recent_7d_total,
                    AVG(CASE WHEN duration_ms IS NOT NULL THEN duration_ms END) AS avg_duration_ms,
                    MAX(created_at) AS last_request_at
                FROM (
                    SELECT status, duration_ms, created_at FROM portal_user_jobs WHERE portal_user_id = ?
                    UNION ALL
                    SELECT status, duration_ms, created_at FROM captcha_jobs WHERE portal_user_id = ?
                ) merged
                """,
                (user_id, user_id),
            )
            summary = await cursor.fetchone()

            cursor = await db.execute(
                """
                SELECT project_id, COUNT(*) AS total
                FROM (
                    SELECT project_id
                    FROM portal_user_jobs
                    WHERE portal_user_id = ? AND status IN ('success', 'success_master_dispatch', 'failed')
                    UNION ALL
                    SELECT project_id
                    FROM captcha_jobs
                    WHERE portal_user_id = ? AND status IN ('success', 'success_master_dispatch', 'failed')
                ) merged
                WHERE project_id IS NOT NULL AND project_id <> ''
                GROUP BY project_id
                ORDER BY total DESC, project_id ASC
                LIMIT 5
                """,
                (user_id, user_id),
            )
            top_projects = [dict(row) for row in await cursor.fetchall()]

            cursor = await db.execute(
                """
                SELECT session_id
                FROM (
                    SELECT id, session_id FROM portal_user_jobs WHERE portal_user_id = ?
                    UNION ALL
                    SELECT id, session_id FROM captcha_jobs WHERE portal_user_id = ?
                ) merged
                WHERE session_id IS NOT NULL AND session_id <> ''
                ORDER BY id DESC
                LIMIT 1
                """,
                (user_id, user_id),
            )
            latest_session = await cursor.fetchone()

            cursor = await db.execute(
                """
                SELECT checkin_date, quota_granted, created_at
                FROM portal_user_checkins
                WHERE portal_user_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (user_id,),
            )
            latest_checkin = await cursor.fetchone()

        solve_success_total = int(summary["solve_success_total"] or 0)
        solve_failed_total = int(summary["solve_failed_total"] or 0)
        solve_total = solve_success_total + solve_failed_total
        return {
            "user": user,
            "usage": {
                "request_total": int(summary["request_total"] or 0),
                "solve_success_total": solve_success_total,
                "solve_failed_total": solve_failed_total,
                "solve_total": solve_total,
                "finish_total": int(summary["finish_total"] or 0),
                "error_total": int(summary["error_total"] or 0),
                "recent_24h_total": int(summary["recent_24h_total"] or 0),
                "recent_7d_total": int(summary["recent_7d_total"] or 0),
                "avg_duration_ms": int(float(summary["avg_duration_ms"] or 0)) if summary["avg_duration_ms"] is not None else None,
                "last_request_at": summary["last_request_at"],
                "latest_session_id": latest_session["session_id"] if latest_session else None,
                "success_rate": round((solve_success_total / solve_total) * 100, 2) if solve_total > 0 else 0.0,
                "top_projects": top_projects,
                "latest_checkin": dict(latest_checkin) if latest_checkin else None,
            },
        }

    async def get_portal_user_checkin_status(self, user_id: int) -> Dict[str, Any]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT checkin_date, quota_granted, created_at
                FROM portal_user_checkins
                WHERE portal_user_id = ? AND checkin_date = date('now', 'localtime')
                LIMIT 1
                """,
                (user_id,),
            )
            today = await cursor.fetchone()
        return {
            "checked_in_today": bool(today),
            "today_reward": int(today["quota_granted"] or 0) if today else 0,
            "checkin_date": today["checkin_date"] if today else None,
            "checked_in_at": today["created_at"] if today else None,
        }

    async def claim_portal_user_checkin(self, user_id: int, min_quota: int, max_quota: int) -> Tuple[bool, str, Dict[str, Any]]:
        safe_min = max(0, int(min_quota or 0))
        safe_max = max(safe_min, int(max_quota or 0))
        if safe_max <= 0:
            return False, "当前未开启签到奖励", {"granted_quota": 0}

        granted_quota = random.randint(safe_min, safe_max)
        async with self._write_connect() as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            try:
                cursor = await db.execute(
                    "SELECT enabled, quota_remaining FROM portal_users WHERE id = ?",
                    (user_id,),
                )
                user = await cursor.fetchone()
                if not user:
                    await db.execute("ROLLBACK")
                    return False, "用户不存在", {"granted_quota": 0}
                if not bool(user["enabled"]):
                    await db.execute("ROLLBACK")
                    return False, "用户已禁用", {"granted_quota": 0}

                cursor = await db.execute(
                    """
                    INSERT OR IGNORE INTO portal_user_checkins (portal_user_id, checkin_date, quota_granted)
                    VALUES (?, date('now', 'localtime'), ?)
                    """,
                    (user_id, granted_quota),
                )
                if int(cursor.rowcount or 0) <= 0:
                    cursor = await db.execute(
                        """
                        SELECT checkin_date, quota_granted, created_at
                        FROM portal_user_checkins
                        WHERE portal_user_id = ? AND checkin_date = date('now', 'localtime')
                        LIMIT 1
                        """,
                        (user_id,),
                    )
                    existing = await cursor.fetchone()
                    await db.execute("ROLLBACK")
                    return False, "今天已经签到过了", {
                        "granted_quota": int(existing["quota_granted"] or 0) if existing else 0,
                        "checkin_date": existing["checkin_date"] if existing else None,
                        "checked_in_at": existing["created_at"] if existing else None,
                    }

                await db.execute(
                    """
                    UPDATE portal_users
                    SET quota_remaining = quota_remaining + ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (granted_quota, user_id),
                )
                cursor = await db.execute("SELECT quota_remaining FROM portal_users WHERE id = ?", (user_id,))
                updated_user = await cursor.fetchone()
                balance_after = int(updated_user["quota_remaining"] or 0) if updated_user else granted_quota
                await db.execute(
                    """
                    INSERT INTO portal_user_transactions (portal_user_id, change_amount, balance_after, source_type, source_ref, note)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, granted_quota, balance_after, "daily_checkin", None, "每日签到奖励"),
                )
                await db.commit()
                return True, "签到成功", {
                    "granted_quota": granted_quota,
                    "balance_after": balance_after,
                    "checkin_date": None,
                    "checked_in_at": None,
                }
            except Exception:
                await db.execute("ROLLBACK")
                raise

    async def get_portal_usage_leaderboard(self, limit: int = 10) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit or 10), 50))
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT
                    u.id,
                    u.username,
                    u.display_name,
                    u.quota_used,
                    COUNT(m.status) AS request_total,
                    SUM(CASE WHEN m.status = 'finish:success' THEN 1 ELSE 0 END) AS solve_success_total,
                    SUM(CASE WHEN m.created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS recent_7d_total
                FROM portal_users u
                LEFT JOIN (
                    SELECT portal_user_id, status, created_at FROM portal_user_jobs
                    UNION ALL
                    SELECT portal_user_id, status, created_at FROM captcha_jobs WHERE portal_user_id IS NOT NULL
                ) m ON m.portal_user_id = u.id
                WHERE u.enabled = 1
                GROUP BY u.id, u.username, u.display_name, u.quota_used
                ORDER BY request_total DESC, solve_success_total DESC, u.quota_used DESC, u.id ASC
                LIMIT ?
                """,
                (safe_limit,),
            )
            rows = await cursor.fetchall()
            return [
                {
                    "rank": index + 1,
                    "user_id": int(row["id"] or 0),
                    "username": row["username"] or "",
                    "display_name": row["display_name"] or row["username"] or "",
                    "request_total": int(row["request_total"] or 0),
                    "solve_success_total": int(row["solve_success_total"] or 0),
                    "recent_7d_total": int(row["recent_7d_total"] or 0),
                    "quota_used": int(row["quota_used"] or 0),
                }
                for index, row in enumerate(rows)
            ]

    async def create_portal_cdks_batch(
        self,
        count: int,
        quota_times: int,
        prefix: Optional[str] = None,
        note: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        safe_count = max(1, min(int(count), 500))
        safe_quota = max(1, int(quota_times))
        normalized_prefix = str(prefix or "CDK").strip().upper()[:20] or "CDK"
        normalized_note = str(note or "").strip()[:200] or None

        created: List[Dict[str, Any]] = []
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            for _ in range(safe_count):
                while True:
                    code = f"{normalized_prefix}-{secrets.token_urlsafe(8).replace('-', '').replace('_', '').upper()[:10]}"
                    cursor = await db.execute("SELECT id FROM portal_cdks WHERE code = ?", (code,))
                    if not await cursor.fetchone():
                        break
                cursor = await db.execute(
                    """
                    INSERT INTO portal_cdks (code, quota_times, batch_prefix, note, enabled)
                    VALUES (?, ?, ?, ?, 1)
                    """,
                    (code, safe_quota, normalized_prefix, normalized_note),
                )
                created.append(
                    {
                        "id": int(cursor.lastrowid or 0),
                        "code": code,
                        "quota_times": safe_quota,
                        "batch_prefix": normalized_prefix,
                        "note": normalized_note,
                        "enabled": True,
                    }
                )
            await db.commit()
        return created

    async def list_portal_cdks(self, limit: int = 500) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 1000))
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT c.id, c.code, c.quota_times, c.batch_prefix, c.note, c.enabled,
                       c.redeemed_user_id, u.username AS redeemed_username, c.redeemed_at, c.created_at
                FROM portal_cdks c
                LEFT JOIN portal_users u ON u.id = c.redeemed_user_id
                ORDER BY c.id DESC
                LIMIT ?
                """,
                (safe_limit,),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def update_portal_cdk(self, cdk_id: int, enabled: Optional[bool] = None) -> Optional[Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM portal_cdks WHERE id = ?", (cdk_id,))
            current = await cursor.fetchone()
            if not current:
                return None
            new_enabled = int(bool(enabled)) if enabled is not None else int(bool(current["enabled"]))
            await db.execute(
                "UPDATE portal_cdks SET enabled = ? WHERE id = ?",
                (new_enabled, cdk_id),
            )
            await db.commit()

        items = await self.list_portal_cdks(limit=1000)
        return next((item for item in items if int(item.get("id") or 0) == int(cdk_id)), None)

    async def list_portal_user_cdk_redeems(self, user_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 100))
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT c.id, c.code, c.quota_times, c.batch_prefix, c.note, c.redeemed_at, c.created_at
                FROM portal_cdks c
                WHERE c.redeemed_user_id = ?
                ORDER BY c.redeemed_at DESC, c.id DESC
                LIMIT ?
                """,
                (user_id, safe_limit),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def redeem_portal_cdk(self, user_id: int, code: str) -> tuple[bool, str, Optional[Dict[str, Any]]]:
        normalized_code = str(code or "").strip().upper()
        if not normalized_code:
            return False, "兑换码不能为空", None

        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            try:
                cursor = await db.execute("SELECT * FROM portal_cdks WHERE code = ?", (normalized_code,))
                cdk = await cursor.fetchone()
                if not cdk:
                    await db.execute("ROLLBACK")
                    return False, "兑换码不存在", None
                if not bool(cdk["enabled"]):
                    await db.execute("ROLLBACK")
                    return False, "兑换码已禁用", None
                if cdk["redeemed_user_id"] is not None:
                    await db.execute("ROLLBACK")
                    return False, "兑换码已被使用", None

                cursor = await db.execute("SELECT enabled FROM portal_users WHERE id = ?", (user_id,))
                user = await cursor.fetchone()
                if not user:
                    await db.execute("ROLLBACK")
                    return False, "用户不存在", None
                if not bool(user["enabled"]):
                    await db.execute("ROLLBACK")
                    return False, "用户已禁用", None

                await db.execute(
                    "UPDATE portal_users SET quota_remaining = quota_remaining + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (int(cdk["quota_times"] or 0), user_id),
                )
                await db.execute(
                    "UPDATE portal_cdks SET redeemed_user_id = ?, redeemed_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (user_id, int(cdk["id"])),
                )
                cursor = await db.execute("SELECT quota_remaining FROM portal_users WHERE id = ?", (user_id,))
                updated_user_balance = await cursor.fetchone()
                await db.execute(
                    """
                    INSERT INTO portal_user_transactions (portal_user_id, change_amount, balance_after, source_type, source_ref, note)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        int(cdk["quota_times"] or 0),
                        int(updated_user_balance["quota_remaining"] or 0) if updated_user_balance else 0,
                        "cdk_redeem",
                        str(cdk["id"]),
                        str(cdk["code"] or ""),
                    ),
                )
                await db.commit()
            except Exception:
                await db.execute("ROLLBACK")
                raise

        updated_user = await self.get_portal_user(user_id)
        cdks = await self.list_portal_cdks(limit=1000)
        redeemed = next((item for item in cdks if str(item.get("code") or "") == normalized_code), None)
        return True, "兑换成功", {"user": updated_user, "cdk": redeemed}

    async def create_portal_user_transaction(
        self,
        portal_user_id: int,
        change_amount: int,
        balance_after: int,
        source_type: str,
        source_ref: Optional[str] = None,
        note: Optional[str] = None,
    ):
        async with self._connect() as db:
            await db.execute(
                """
                INSERT INTO portal_user_transactions (portal_user_id, change_amount, balance_after, source_type, source_ref, note)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (portal_user_id, int(change_amount), int(balance_after), (source_type or "unknown")[:80], source_ref, note),
            )
            await db.commit()

    async def count_portal_user_transactions(self, portal_user_id: int) -> int:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT COUNT(*) AS total
                FROM portal_user_transactions
                WHERE portal_user_id = ?
                """,
                (portal_user_id,),
            )
            row = await cursor.fetchone()
            return int(row["total"] or 0) if row else 0

    async def list_portal_user_transactions(
        self,
        portal_user_id: int,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 200))
        safe_offset = max(0, int(offset))
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, portal_user_id, change_amount, balance_after, source_type, source_ref, note, created_at
                FROM portal_user_transactions
                WHERE portal_user_id = ?
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (portal_user_id, safe_limit, safe_offset),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def _delete_portal_user_in_tx(self, db: aiosqlite.Connection, user_id: int) -> bool:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT id FROM portal_users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        if not row:
            return False

        await db.execute(
            "UPDATE portal_cdks SET redeemed_user_id = NULL, redeemed_at = NULL WHERE redeemed_user_id = ?",
            (user_id,),
        )
        await db.execute(
            "DELETE FROM session_quota_events WHERE owner_type = 'portal_user' AND owner_id = ?",
            (user_id,),
        )
        await db.execute("DELETE FROM captcha_jobs WHERE portal_user_id = ?", (user_id,))
        await db.execute("DELETE FROM portal_user_jobs WHERE portal_user_id = ?", (user_id,))
        await db.execute("DELETE FROM portal_user_transactions WHERE portal_user_id = ?", (user_id,))
        await db.execute("DELETE FROM portal_user_checkins WHERE portal_user_id = ?", (user_id,))
        await db.execute("DELETE FROM portal_user_api_keys WHERE portal_user_id = ?", (user_id,))
        await db.execute("DELETE FROM portal_users WHERE id = ?", (user_id,))
        return True

    async def delete_portal_user(self, user_id: int) -> bool:
        async with self._write_connect() as db:
            deleted = await self._delete_portal_user_in_tx(db, int(user_id))
            await db.commit()
            return deleted

    async def delete_portal_users(self, user_ids: List[int]) -> List[int]:
        normalized_ids: List[int] = []
        seen: set[int] = set()
        for raw_id in user_ids or []:
            user_id = int(raw_id or 0)
            if user_id <= 0 or user_id in seen:
                continue
            seen.add(user_id)
            normalized_ids.append(user_id)

        if not normalized_ids:
            return []

        deleted_ids: List[int] = []
        async with self._write_connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            try:
                for user_id in normalized_ids:
                    if await self._delete_portal_user_in_tx(db, user_id):
                        deleted_ids.append(user_id)
                await db.commit()
            except Exception:
                await db.execute("ROLLBACK")
                raise
        return deleted_ids

    async def create_portal_user_api_key(self, portal_user_id: int, name: str) -> Tuple[str, Dict[str, Any]]:
        raw_key, key_hash, key_prefix = self._generate_service_api_key()
        normalized_name = str(name or "").strip() or f"key-{portal_user_id}"
        async with self._connect() as db:
            cursor = await db.execute(
                """
                INSERT INTO portal_user_api_keys (portal_user_id, name, key_hash, key_prefix, enabled)
                VALUES (?, ?, ?, ?, 1)
                """,
                (portal_user_id, normalized_name, key_hash, key_prefix),
            )
            api_key_id = int(cursor.lastrowid or 0)
            await db.commit()
        item = await self.get_portal_user_api_key(api_key_id, portal_user_id=portal_user_id)
        return raw_key, item or {}

    async def get_portal_user_api_key(self, api_key_id: int, portal_user_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            sql = """
                SELECT id, portal_user_id, name, key_prefix, enabled, quota_used, created_at, updated_at, last_used_at
                FROM portal_user_api_keys
                WHERE id = ?
            """
            params: List[Any] = [api_key_id]
            if portal_user_id is not None:
                sql += " AND portal_user_id = ?"
                params.append(portal_user_id)
            cursor = await db.execute(sql, params)
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def list_portal_user_api_keys(self, portal_user_id: int) -> List[Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, portal_user_id, name, key_prefix, enabled, quota_used, created_at, updated_at, last_used_at
                FROM portal_user_api_keys
                WHERE portal_user_id = ?
                ORDER BY id DESC
                """,
                (portal_user_id,),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def update_portal_user_api_key(
        self,
        api_key_id: int,
        portal_user_id: int,
        name: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> Optional[Dict[str, Any]]:
        current = await self.get_portal_user_api_key(api_key_id, portal_user_id=portal_user_id)
        if not current:
            return None
        new_name = str(name or current.get("name") or "").strip() or str(current.get("name") or "")
        new_enabled = int(bool(enabled)) if enabled is not None else int(bool(current.get("enabled")))
        async with self._connect() as db:
            await db.execute(
                """
                UPDATE portal_user_api_keys
                SET name = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND portal_user_id = ?
                """,
                (new_name, new_enabled, api_key_id, portal_user_id),
            )
            await db.commit()
        return await self.get_portal_user_api_key(api_key_id, portal_user_id=portal_user_id)

    async def set_portal_user_api_keys_enabled(self, portal_user_id: int, enabled: bool):
        async with self._connect() as db:
            await db.execute(
                "UPDATE portal_user_api_keys SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE portal_user_id = ?",
                (1 if enabled else 0, portal_user_id),
            )
            await db.commit()

    async def resolve_portal_user_api_key(self, raw_key: str) -> Optional[Dict[str, Any]]:
        key_hash = self._hash_secret(raw_key)
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, portal_user_id, name, key_prefix, enabled, quota_used, created_at, updated_at, last_used_at
                FROM portal_user_api_keys
                WHERE key_hash = ?
                """,
                (key_hash,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def list_portal_user_api_call_logs(
        self,
        portal_user_id: int,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if self._job_logs_use_redis():
            safe_limit = max(1, min(int(limit), 200))
            safe_offset = max(0, int(offset))
            normalized_status = str(status or "").strip()
            normalized_project_id = str(project_id or "").strip()
            portal_key_cache: Dict[int, Optional[Dict[str, Any]]] = {}
            items: List[Dict[str, Any]] = []
            for entry in await self._get_redis_job_logs_by_portal_user(
                portal_user_id=portal_user_id,
                limit=None,
                offset=0,
            ):
                if entry.get("log_scope") != "captcha_jobs":
                    continue
                if int(entry.get("portal_user_id") or 0) != int(portal_user_id):
                    continue
                if normalized_status and str(entry.get("status") or "").strip() != normalized_status:
                    continue
                if normalized_project_id and str(entry.get("project_id") or "").strip() != normalized_project_id:
                    continue
                portal_api_key_id = int(entry.get("portal_api_key_id") or 0)
                if portal_api_key_id > 0 and portal_api_key_id not in portal_key_cache:
                    portal_key_cache[portal_api_key_id] = await self.get_portal_user_api_key(portal_api_key_id)
                portal_key = portal_key_cache.get(portal_api_key_id) or {}
                items.append(
                    {
                        "id": int(entry.get("id") or 0),
                        "session_id": entry.get("session_id"),
                        "project_id": entry.get("project_id"),
                        "action": entry.get("action"),
                        "status": entry.get("status"),
                        "error_reason": entry.get("error_reason"),
                        "duration_ms": entry.get("duration_ms"),
                        "created_at": entry.get("created_at"),
                        "api_key_name": portal_key.get("name"),
                        "api_key_prefix": portal_key.get("key_prefix"),
                    }
                )
            return items[safe_offset:safe_offset + safe_limit]

        safe_limit = max(1, min(int(limit), 200))
        safe_offset = max(0, int(offset))
        conditions = ["j.portal_user_id = ?"]
        params: List[Any] = [portal_user_id]
        if str(status or "").strip():
            conditions.append("j.status = ?")
            params.append(str(status).strip())
        if str(project_id or "").strip():
            conditions.append("j.project_id = ?")
            params.append(str(project_id).strip())
        params.extend([safe_limit, safe_offset])
        where_sql = " AND ".join(conditions)
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                f"""
                SELECT j.id, j.session_id, j.project_id, j.action, j.status, j.error_reason, j.duration_ms, j.created_at,
                       pk.name AS api_key_name, pk.key_prefix AS api_key_prefix
                FROM captcha_jobs j
                LEFT JOIN portal_user_api_keys pk ON pk.id = j.portal_api_key_id
                WHERE {where_sql}
                ORDER BY j.id DESC
                LIMIT ? OFFSET ?
                """,
                params,
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_captcha_config(self) -> CaptchaConfig:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM captcha_config WHERE id = 1")
            row = await cursor.fetchone()
            if not row:
                return CaptchaConfig()
            return CaptchaConfig(
                id=row["id"],
                browser_proxy_enabled=bool(row["browser_proxy_enabled"]),
                browser_proxy_url=row["browser_proxy_url"],
                browser_count=max(1, int(row["browser_count"] or 1)),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    async def update_captcha_config(
        self,
        browser_proxy_enabled: bool,
        browser_proxy_url: Optional[str],
        browser_count: int,
    ):
        async with self._connect() as db:
            await db.execute(
                """
                UPDATE captcha_config
                SET browser_proxy_enabled = ?,
                    browser_proxy_url = ?,
                    browser_count = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
                """,
                (1 if browser_proxy_enabled else 0, browser_proxy_url, max(1, int(browser_count))),
            )
            await db.commit()

    async def create_api_key(self, name: str, quota_remaining: Optional[int]) -> Tuple[str, Dict[str, Any]]:
        raw_key = f"fcs_{secrets.token_urlsafe(32)}"
        key_hash = self._hash_secret(raw_key)
        key_prefix = raw_key[:12]

        async with self._connect() as db:
            cursor = await db.execute(
                """
                INSERT INTO service_api_keys (name, key_hash, key_prefix, enabled, quota_remaining)
                VALUES (?, ?, ?, 1, ?)
                """,
                (name, key_hash, key_prefix, quota_remaining),
            )
            api_key_id = cursor.lastrowid
            await db.commit()

        row = await self.get_api_key(api_key_id)
        return raw_key, row

    async def get_api_key(self, api_key_id: int) -> Optional[Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, name, key_prefix, enabled, quota_remaining, quota_used,
                       created_at, updated_at, last_used_at
                FROM service_api_keys
                WHERE id = ?
                """,
                (api_key_id,),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return dict(row)

    async def list_api_keys(self) -> List[Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, name, key_prefix, enabled, quota_remaining, quota_used,
                       created_at, updated_at, last_used_at
                FROM service_api_keys
                ORDER BY id ASC
                """
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def update_api_key(
        self,
        api_key_id: int,
        name: Optional[str] = None,
        enabled: Optional[bool] = None,
        quota_remaining: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        current = await self.get_api_key(api_key_id)
        if not current:
            return None

        new_name = name if name is not None else current["name"]
        new_enabled = int(enabled) if enabled is not None else int(bool(current["enabled"]))
        new_quota = quota_remaining if quota_remaining is not None else current["quota_remaining"]

        async with self._connect() as db:
            await db.execute(
                """
                UPDATE service_api_keys
                SET name = ?, enabled = ?, quota_remaining = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (new_name, new_enabled, new_quota, api_key_id),
            )
            await db.commit()

        return await self.get_api_key(api_key_id)

    async def resolve_service_api_key(self, raw_key: str) -> Optional[Dict[str, Any]]:
        key_hash = self._hash_secret(raw_key)
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, name, key_prefix, enabled, quota_remaining, quota_used,
                       created_at, updated_at, last_used_at
                FROM service_api_keys
                WHERE key_hash = ?
                """,
                (key_hash,),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return dict(row)

    async def ensure_api_key_available(self, api_key_id: int) -> Tuple[bool, str]:
        if api_key_id <= 0:
            return True, ""

        api_key = await self.get_api_key(api_key_id)
        if not api_key:
            return False, "API Key 不存在"

        if not bool(api_key["enabled"]):
            return False, "API Key 已禁用"

        quota_remaining = api_key["quota_remaining"]
        if quota_remaining is not None and int(quota_remaining) <= 0:
            return False, "API Key 可用次数已耗尽"

        return True, ""

    async def consume_api_key_quota(self, api_key_id: int, session_id: Optional[str] = None) -> Tuple[bool, str]:
        if api_key_id <= 0:
            return True, ""

        async with self._write_connect() as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            try:
                cursor = await db.execute(
                    "SELECT enabled, quota_remaining, quota_used FROM service_api_keys WHERE id = ?",
                    (api_key_id,),
                )
                row = await cursor.fetchone()
                if not row:
                    await db.execute("ROLLBACK")
                    return False, "API Key 不存在"

                if not bool(row["enabled"]):
                    await db.execute("ROLLBACK")
                    return False, "API Key 已禁用"

                quota_remaining = row["quota_remaining"]
                if quota_remaining is None:
                    await db.execute(
                        """
                        UPDATE service_api_keys
                        SET quota_used = quota_used + 1,
                            last_used_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        (api_key_id,),
                    )
                else:
                    if int(quota_remaining) <= 0:
                        await db.execute("ROLLBACK")
                        return False, "API Key 可用次数已耗尽"
                    await db.execute(
                        """
                        UPDATE service_api_keys
                        SET quota_remaining = quota_remaining - 1,
                            quota_used = quota_used + 1,
                            last_used_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ? AND quota_remaining > 0
                        """,
                        (api_key_id,),
                    )
                normalized_session_id = str(session_id or "").strip()
                if normalized_session_id:
                    await db.execute(
                        """
                        INSERT OR IGNORE INTO session_quota_events (session_id, owner_type, owner_id, event_type)
                        VALUES (?, 'service_api_key', ?, 'charge')
                        """,
                        (normalized_session_id, api_key_id),
                    )
                await db.commit()
                return True, ""
            except Exception:
                await db.execute("ROLLBACK")
                raise

    async def refund_api_key_quota(
        self,
        api_key_id: int,
        session_id: str,
        reason: str,
    ) -> Tuple[bool, str]:
        normalized_session_id = str(session_id or "").strip()
        if api_key_id <= 0:
            return False, "API Key 无效"
        if not normalized_session_id:
            return False, "session_id 不能为空"

        async with self._write_connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            try:
                refunded, message = await self._refund_api_key_quota_in_tx(
                    db,
                    api_key_id=api_key_id,
                    session_id=normalized_session_id,
                    reason=reason,
                )
                await db.commit()
                return refunded, message
            except Exception:
                await db.execute("ROLLBACK")
                raise

    async def create_job_log(
        self,
        session_id: Optional[str],
        api_key_id: Optional[int],
        project_id: Optional[str],
        action: Optional[str],
        status: str,
        error_reason: Optional[str],
        duration_ms: Optional[int],
        portal_user_id: Optional[int] = None,
        portal_api_key_id: Optional[int] = None,
    ):
        if self._job_logs_use_redis():
            await self._redis_log_store.append_job_log(
                {
                    "log_scope": "captcha_jobs",
                    "session_id": session_id,
                    "api_key_id": api_key_id,
                    "project_id": project_id,
                    "action": action,
                    "status": status,
                    "error_reason": error_reason,
                    "duration_ms": duration_ms,
                    "portal_user_id": portal_user_id,
                    "portal_api_key_id": portal_api_key_id,
                }
            )
            return
        async with self._write_connect() as db:
            await self._create_job_log_in_tx(
                db,
                session_id=session_id,
                api_key_id=api_key_id,
                project_id=project_id,
                action=action,
                status=status,
                error_reason=error_reason,
                duration_ms=duration_ms,
                portal_user_id=portal_user_id,
                portal_api_key_id=portal_api_key_id,
            )
            await db.commit()

    async def finalize_service_session(
        self,
        *,
        session_id: Optional[str],
        api_key_id: Optional[int],
        project_id: Optional[str],
        action: Optional[str],
        status: str,
        error_reason: Optional[str],
        portal_user_id: Optional[int] = None,
        portal_api_key_id: Optional[int] = None,
        refund_reason: Optional[str] = None,
    ):
        normalized_session_id = str(session_id or "").strip() or None
        normalized_refund_reason = str(refund_reason or "").strip() or None

        async with self._write_connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            try:
                if normalized_session_id and normalized_refund_reason:
                    if int(portal_user_id or 0) > 0:
                        await self._refund_portal_user_quota_in_tx(
                            db,
                            user_id=int(portal_user_id),
                            session_id=normalized_session_id,
                            reason=normalized_refund_reason,
                            portal_api_key_id=int(portal_api_key_id or 0) or None,
                        )
                    elif int(api_key_id or 0) > 0:
                        await self._refund_api_key_quota_in_tx(
                            db,
                            api_key_id=int(api_key_id),
                            session_id=normalized_session_id,
                            reason=normalized_refund_reason,
                        )

                if int(portal_user_id or 0) > 0:
                    await self._mark_session_complete_in_tx(
                        db,
                        session_id=normalized_session_id,
                        owner_type="portal_user",
                        owner_id=int(portal_user_id),
                        note=status,
                    )
                elif int(api_key_id or 0) > 0:
                    await self._mark_session_complete_in_tx(
                        db,
                        session_id=normalized_session_id,
                        owner_type="service_api_key",
                        owner_id=int(api_key_id),
                        note=status,
                    )

                if not self._job_logs_use_redis():
                    await self._create_job_log_in_tx(
                        db,
                        session_id=normalized_session_id,
                        api_key_id=api_key_id,
                        project_id=project_id,
                        action=action,
                        status=status,
                        error_reason=error_reason,
                        duration_ms=None,
                        portal_user_id=portal_user_id,
                        portal_api_key_id=portal_api_key_id,
                    )
                await db.commit()
            except Exception:
                await db.execute("ROLLBACK")
                raise
        if self._job_logs_use_redis():
            await self._redis_log_store.append_job_log(
                {
                    "log_scope": "captcha_jobs",
                    "session_id": normalized_session_id,
                    "api_key_id": api_key_id,
                    "project_id": project_id,
                    "action": action,
                    "status": status,
                    "error_reason": error_reason,
                    "duration_ms": None,
                    "portal_user_id": portal_user_id,
                    "portal_api_key_id": portal_api_key_id,
                }
            )

    async def finalize_portal_user_session(
        self,
        *,
        portal_user_id: int,
        session_id: Optional[str],
        project_id: Optional[str],
        action: Optional[str],
        status: str,
        error_reason: Optional[str],
        refund_reason: Optional[str] = None,
    ):
        normalized_session_id = str(session_id or "").strip() or None
        normalized_refund_reason = str(refund_reason or "").strip() or None

        async with self._write_connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            try:
                if normalized_session_id and normalized_refund_reason:
                    await self._refund_portal_user_quota_in_tx(
                        db,
                        user_id=int(portal_user_id),
                        session_id=normalized_session_id,
                        reason=normalized_refund_reason,
                    )

                await self._mark_session_complete_in_tx(
                    db,
                    session_id=normalized_session_id,
                    owner_type="portal_user",
                    owner_id=int(portal_user_id),
                    note=status,
                )

                if not self._job_logs_use_redis():
                    await self._create_portal_user_job_log_in_tx(
                        db,
                        portal_user_id=int(portal_user_id),
                        session_id=normalized_session_id,
                        project_id=project_id,
                        action=action,
                        status=status,
                        error_reason=error_reason,
                        duration_ms=None,
                    )
                await db.commit()
            except Exception:
                await db.execute("ROLLBACK")
                raise
        if self._job_logs_use_redis():
            await self._redis_log_store.append_job_log(
                {
                    "log_scope": "portal_user_jobs",
                    "portal_user_id": int(portal_user_id),
                    "session_id": normalized_session_id,
                    "project_id": project_id,
                    "action": action,
                    "status": status,
                    "error_reason": error_reason,
                    "duration_ms": None,
                }
            )

    async def list_job_logs(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        if self._job_logs_use_redis():
            safe_limit = max(1, min(int(limit), 500))
            safe_offset = max(0, int(offset))
            items = await self._get_redis_job_logs(limit=safe_limit, offset=safe_offset)
            service_key_cache: Dict[int, Optional[Dict[str, Any]]] = {}
            result: List[Dict[str, Any]] = []
            for entry in items:
                item = {
                    "id": int(entry.get("id") or 0),
                    "session_id": entry.get("session_id"),
                    "api_key_id": entry.get("api_key_id"),
                    "api_key_name": None,
                    "key_prefix": None,
                    "project_id": entry.get("project_id"),
                    "action": entry.get("action"),
                    "status": entry.get("status"),
                    "error_reason": entry.get("error_reason"),
                    "duration_ms": entry.get("duration_ms"),
                    "created_at": entry.get("created_at"),
                    "portal_user_id": entry.get("portal_user_id"),
                    "portal_api_key_id": entry.get("portal_api_key_id"),
                }
                api_key_id = int(entry.get("api_key_id") or 0)
                if api_key_id > 0:
                    if api_key_id not in service_key_cache:
                        service_key_cache[api_key_id] = await self.get_api_key(api_key_id)
                    api_key = service_key_cache.get(api_key_id) or {}
                    item["api_key_name"] = api_key.get("name")
                    item["key_prefix"] = api_key.get("key_prefix")
                result.append(item)
            return result

        safe_limit = max(1, min(int(limit), 500))
        safe_offset = max(0, int(offset))
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT *
                FROM (
                    SELECT
                        j.id,
                        j.session_id,
                        j.api_key_id,
                        k.name AS api_key_name,
                        k.key_prefix,
                        j.project_id,
                        j.action,
                        j.status,
                        j.error_reason,
                        j.duration_ms,
                        j.created_at,
                        j.portal_user_id,
                        j.portal_api_key_id
                    FROM captcha_jobs j
                    LEFT JOIN service_api_keys k ON k.id = j.api_key_id
                    UNION ALL
                    SELECT
                        p.id,
                        p.session_id,
                        NULL AS api_key_id,
                        NULL AS api_key_name,
                        NULL AS key_prefix,
                        p.project_id,
                        p.action,
                        p.status,
                        p.error_reason,
                        p.duration_ms,
                        p.created_at,
                        p.portal_user_id,
                        NULL AS portal_api_key_id
                    FROM portal_user_jobs p
                ) merged
                ORDER BY created_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (safe_limit, safe_offset),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def count_job_logs(self) -> int:
        if self._job_logs_use_redis():
            return await self._redis_log_store.count_job_logs()
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM captcha_jobs) +
                    (SELECT COUNT(*) FROM portal_user_jobs) AS total
                """
            )
            row = await cursor.fetchone()
            return int(row["total"] or 0) if row else 0

    async def clear_job_logs(self) -> Dict[str, int]:
        if self._job_logs_use_redis():
            redis_result = await self._redis_log_store.clear_job_logs_with_breakdown()
            result = {
                "captcha_jobs": int(redis_result.get("captcha_jobs") or 0),
                "portal_user_jobs": int(redis_result.get("portal_user_jobs") or 0),
            }
            async with self._write_connect() as db:
                captcha_cursor = await db.execute("DELETE FROM captcha_jobs")
                portal_cursor = await db.execute("DELETE FROM portal_user_jobs")
                await db.commit()
            result["captcha_jobs"] += int(captcha_cursor.rowcount or 0)
            result["portal_user_jobs"] += int(portal_cursor.rowcount or 0)
            return result
        async with self._write_connect() as db:
            captcha_cursor = await db.execute("DELETE FROM captcha_jobs")
            portal_cursor = await db.execute("DELETE FROM portal_user_jobs")
            await db.commit()
            return {
                "captcha_jobs": int(captcha_cursor.rowcount or 0),
                "portal_user_jobs": int(portal_cursor.rowcount or 0),
            }


    async def list_job_logs_by_api_key(
        self,
        api_key_id: int,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if self._job_logs_use_redis():
            safe_limit = max(1, min(int(limit), 200))
            safe_offset = max(0, int(offset))
            normalized_status = str(status or "").strip()
            normalized_project = str(project_id or "").strip()
            api_key = await self.get_api_key(api_key_id)
            items: List[Dict[str, Any]] = []
            for entry in await self._get_redis_job_logs_by_api_key(
                api_key_id=api_key_id,
                limit=None,
                offset=0,
            ):
                if normalized_status and str(entry.get("status") or "").strip() != normalized_status:
                    continue
                if normalized_project and str(entry.get("project_id") or "").strip() != normalized_project:
                    continue
                items.append(
                    {
                        "id": int(entry.get("id") or 0),
                        "session_id": entry.get("session_id"),
                        "api_key_id": api_key_id,
                        "api_key_name": (api_key or {}).get("name"),
                        "key_prefix": (api_key or {}).get("key_prefix"),
                        "project_id": entry.get("project_id"),
                        "action": entry.get("action"),
                        "status": entry.get("status"),
                        "error_reason": entry.get("error_reason"),
                        "duration_ms": entry.get("duration_ms"),
                        "created_at": entry.get("created_at"),
                    }
                )
            return items[safe_offset:safe_offset + safe_limit]

        safe_limit = max(1, min(int(limit), 200))
        safe_offset = max(0, int(offset))

        conditions = ["j.api_key_id = ?"]
        params: list[Any] = [api_key_id]

        normalized_status = str(status or "").strip()
        if normalized_status:
            conditions.append("j.status = ?")
            params.append(normalized_status)

        normalized_project = str(project_id or "").strip()
        if normalized_project:
            conditions.append("j.project_id = ?")
            params.append(normalized_project)

        where_sql = " AND ".join(conditions)
        params.extend([safe_limit, safe_offset])

        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                f"""
                SELECT j.id, j.session_id, j.api_key_id, k.name AS api_key_name, k.key_prefix,
                       j.project_id, j.action, j.status, j.error_reason, j.duration_ms, j.created_at
                FROM captcha_jobs j
                LEFT JOIN service_api_keys k ON k.id = j.api_key_id
                WHERE {where_sql}
                ORDER BY j.id DESC
                LIMIT ? OFFSET ?
                """,
                params,
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


    async def get_api_key_usage_summary(self, api_key_id: int) -> Optional[Dict[str, Any]]:
        api_key = await self.get_api_key(api_key_id)
        if not api_key:
            return None

        if self._job_logs_use_redis():
            now = datetime.now(UTC).replace(tzinfo=None)
            request_statuses = {"success", "success_master_dispatch", "failed"}
            failed_statuses = {"failed", "error_reported", "finish:failed", "finish:cancelled", "finish:timeout"}
            items = await self._get_redis_job_logs_by_api_key(api_key_id=api_key_id, limit=None, offset=0)
            request_total = 0
            solve_success_total = 0
            solve_failed_total = 0
            finish_total = 0
            error_total = 0
            recent_24h_total = 0
            recent_7d_total = 0
            duration_values: List[int] = []
            last_request_at: Optional[str] = None
            latest_session_id: Optional[str] = None
            project_summary: Dict[str, Dict[str, Any]] = {}
            action_totals: Dict[str, int] = {}

            for entry in items:
                status_name = str(entry.get("status") or "").strip()
                created_at = str(entry.get("created_at") or "").strip() or None
                created_dt = self._parse_timestamp(created_at)
                if status_name in request_statuses:
                    request_total += 1
                    project_id_value = str(entry.get("project_id") or "").strip()
                    if project_id_value:
                        project_item = project_summary.setdefault(
                            project_id_value,
                            {
                                "project_id": project_id_value,
                                "total": 0,
                                "solve_success": 0,
                                "solve_failed": 0,
                                "last_used_at": None,
                            },
                        )
                        project_item["total"] += 1
                        if status_name == "finish:success":
                            project_item["solve_success"] += 1
                        if status_name in failed_statuses:
                            project_item["solve_failed"] += 1
                        if created_at and (
                            project_item["last_used_at"] is None or created_at > project_item["last_used_at"]
                        ):
                            project_item["last_used_at"] = created_at
                    action_name = str(entry.get("action") or "").strip()
                    if action_name:
                        action_totals[action_name] = action_totals.get(action_name, 0) + 1
                if status_name == "finish:success":
                    solve_success_total += 1
                if status_name in failed_statuses:
                    solve_failed_total += 1
                if status_name.startswith("finish:"):
                    finish_total += 1
                if status_name == "error_reported":
                    error_total += 1
                if created_dt is not None:
                    age_seconds = (now - created_dt).total_seconds()
                    if age_seconds <= 24 * 3600:
                        recent_24h_total += 1
                    if age_seconds <= 7 * 24 * 3600:
                        recent_7d_total += 1
                if entry.get("duration_ms") is not None:
                    duration_values.append(int(entry["duration_ms"]))
                if created_at and (last_request_at is None or created_at > last_request_at):
                    last_request_at = created_at
                session_id_value = str(entry.get("session_id") or "").strip()
                if session_id_value and latest_session_id is None:
                    latest_session_id = session_id_value

            solve_total = solve_success_total + solve_failed_total
            top_projects = sorted(
                project_summary.values(),
                key=lambda item: (-int(item["total"]), str(item["project_id"])),
            )[:5]
            top_actions = [
                {"action": action_name, "total": total}
                for action_name, total in sorted(action_totals.items(), key=lambda item: (-item[1], item[0]))[:5]
            ]

            return {
                "api_key": api_key,
                "usage": {
                    "request_total": request_total,
                    "solve_success_total": solve_success_total,
                    "solve_failed_total": solve_failed_total,
                    "solve_total": solve_total,
                    "finish_total": finish_total,
                    "error_total": error_total,
                    "recent_24h_total": recent_24h_total,
                    "recent_7d_total": recent_7d_total,
                    "avg_duration_ms": int(sum(duration_values) / len(duration_values)) if duration_values else None,
                    "last_request_at": last_request_at,
                    "latest_session_id": latest_session_id,
                    "success_rate": round((solve_success_total / solve_total) * 100, 2) if solve_total > 0 else 0.0,
                    "top_projects": top_projects,
                    "top_actions": top_actions,
                },
            }

        async with self._connect() as db:
            db.row_factory = aiosqlite.Row

            cursor = await db.execute(
                """
                SELECT
                    SUM(CASE WHEN status IN ('success', 'success_master_dispatch', 'failed') THEN 1 ELSE 0 END) AS request_total,
                    SUM(CASE WHEN status = 'finish:success' THEN 1 ELSE 0 END) AS solve_success_total,
                    SUM(CASE WHEN status IN ('failed', 'error_reported', 'finish:failed', 'finish:cancelled', 'finish:timeout') THEN 1 ELSE 0 END) AS solve_failed_total,
                    SUM(CASE WHEN status LIKE 'finish:%' THEN 1 ELSE 0 END) AS finish_total,
                    SUM(CASE WHEN status = 'error_reported' THEN 1 ELSE 0 END) AS error_total,
                    SUM(CASE WHEN created_at >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS recent_24h_total,
                    SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS recent_7d_total,
                    AVG(CASE WHEN duration_ms IS NOT NULL THEN duration_ms END) AS avg_duration_ms,
                    MAX(created_at) AS last_request_at
                FROM captcha_jobs
                WHERE api_key_id = ?
                """,
                (api_key_id,),
            )
            summary = await cursor.fetchone()

            cursor = await db.execute(
                """
                SELECT session_id
                FROM captcha_jobs
                WHERE api_key_id = ? AND session_id IS NOT NULL AND session_id <> ''
                ORDER BY id DESC
                LIMIT 1
                """,
                (api_key_id,),
            )
            latest_session = await cursor.fetchone()

            cursor = await db.execute(
                """
                SELECT project_id,
                       COUNT(*) AS total,
                       SUM(CASE WHEN status = 'finish:success' THEN 1 ELSE 0 END) AS solve_success,
                       SUM(CASE WHEN status IN ('failed', 'error_reported', 'finish:failed', 'finish:cancelled', 'finish:timeout') THEN 1 ELSE 0 END) AS solve_failed,
                       MAX(created_at) AS last_used_at
                FROM captcha_jobs
                WHERE api_key_id = ?
                  AND project_id IS NOT NULL
                  AND project_id <> ''
                  AND status IN ('success', 'success_master_dispatch', 'failed')
                GROUP BY project_id
                ORDER BY total DESC, project_id ASC
                LIMIT 5
                """,
                (api_key_id,),
            )
            top_projects = [dict(row) for row in await cursor.fetchall()]

            cursor = await db.execute(
                """
                SELECT action,
                       COUNT(*) AS total
                FROM captcha_jobs
                WHERE api_key_id = ?
                  AND action IS NOT NULL
                  AND action <> ''
                  AND status IN ('success', 'success_master_dispatch', 'failed')
                GROUP BY action
                ORDER BY total DESC, action ASC
                LIMIT 5
                """,
                (api_key_id,),
            )
            top_actions = [dict(row) for row in await cursor.fetchall()]

        solve_success_total = int(summary["solve_success_total"] or 0)
        solve_failed_total = int(summary["solve_failed_total"] or 0)
        solve_total = solve_success_total + solve_failed_total

        return {
            "api_key": api_key,
            "usage": {
                "request_total": int(summary["request_total"] or 0),
                "solve_success_total": solve_success_total,
                "solve_failed_total": solve_failed_total,
                "solve_total": solve_total,
                "finish_total": int(summary["finish_total"] or 0),
                "error_total": int(summary["error_total"] or 0),
                "recent_24h_total": int(summary["recent_24h_total"] or 0),
                "recent_7d_total": int(summary["recent_7d_total"] or 0),
                "avg_duration_ms": int(float(summary["avg_duration_ms"] or 0)) if summary["avg_duration_ms"] is not None else None,
                "last_request_at": summary["last_request_at"],
                "latest_session_id": latest_session["session_id"] if latest_session else None,
                "success_rate": round((solve_success_total / solve_total) * 100, 2) if solve_total > 0 else 0.0,
                "top_projects": top_projects,
                "top_actions": top_actions,
            },
        }

    async def get_service_stats(self) -> Dict[str, Any]:
        if self._job_logs_use_redis():
            request_statuses = {"success", "success_master_dispatch", "failed"}
            failed_statuses = {"failed", "error_reported", "finish:failed", "finish:cancelled", "finish:timeout"}
            job_items = await self._get_redis_job_logs_by_scope(scope="captcha_jobs", limit=None, offset=0)
            summary = {
                "total": 0,
                "success": 0,
                "failed": 0,
                "finish_total": 0,
                "error_report_total": 0,
            }
            for entry in job_items:
                status_name = str(entry.get("status") or "").strip()
                if status_name in request_statuses:
                    summary["total"] += 1
                if status_name == "finish:success":
                    summary["success"] += 1
                if status_name in failed_statuses:
                    summary["failed"] += 1
                if status_name.startswith("finish:"):
                    summary["finish_total"] += 1
                if status_name == "error_reported":
                    summary["error_report_total"] += 1

            async with self._connect() as db:
                db.row_factory = aiosqlite.Row

                cursor = await db.execute(
                    """
                    SELECT
                        COUNT(*) AS key_count,
                        SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS key_enabled_count
                    FROM service_api_keys
                    """
                )
                key_summary = await cursor.fetchone()

                cursor = await db.execute(
                    """
                    SELECT
                        COUNT(*) AS node_count,
                        SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS node_enabled_count
                    FROM cluster_nodes
                    """
                )
                node_summary = await cursor.fetchone()

                cursor = await db.execute(
                    """
                    SELECT
                        COUNT(*) AS portal_user_total,
                        SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS portal_user_enabled_total
                    FROM portal_users
                    """
                )
                portal_user_summary = await cursor.fetchone()

                cursor = await db.execute(
                    """
                    SELECT
                        COUNT(*) AS portal_cdk_total,
                        SUM(CASE WHEN redeemed_user_id IS NULL THEN 1 ELSE 0 END) AS portal_cdk_unused_total
                    FROM portal_cdks
                    """
                )
                portal_cdk_summary = await cursor.fetchone()

            return {
                "jobs_total": int(summary["total"] or 0),
                "jobs_success": int(summary["success"] or 0),
                "jobs_failed": int(summary["failed"] or 0),
                "jobs_solve_total": int(summary["success"] or 0) + int(summary["failed"] or 0),
                "jobs_finish_total": int(summary["finish_total"] or 0),
                "jobs_error_report_total": int(summary["error_report_total"] or 0),
                "api_key_total": int(key_summary["key_count"] or 0),
                "api_key_enabled_total": int(key_summary["key_enabled_count"] or 0),
                "cluster_node_total": int(node_summary["node_count"] or 0),
                "cluster_node_enabled_total": int(node_summary["node_enabled_count"] or 0),
                "portal_user_total": int(portal_user_summary["portal_user_total"] or 0),
                "portal_user_enabled_total": int(portal_user_summary["portal_user_enabled_total"] or 0),
                "portal_cdk_total": int(portal_cdk_summary["portal_cdk_total"] or 0),
                "portal_cdk_unused_total": int(portal_cdk_summary["portal_cdk_unused_total"] or 0),
            }

        async with self._connect() as db:
            db.row_factory = aiosqlite.Row

            cursor = await db.execute(
                """
                SELECT
                    SUM(CASE WHEN status IN ('success', 'success_master_dispatch', 'failed') THEN 1 ELSE 0 END) AS total,
                    SUM(CASE WHEN status = 'finish:success' THEN 1 ELSE 0 END) AS success,
                    SUM(CASE WHEN status IN ('failed', 'error_reported', 'finish:failed', 'finish:cancelled', 'finish:timeout') THEN 1 ELSE 0 END) AS failed,
                    SUM(CASE WHEN status LIKE 'finish:%' THEN 1 ELSE 0 END) AS finish_total,
                    SUM(CASE WHEN status = 'error_reported' THEN 1 ELSE 0 END) AS error_report_total
                FROM captcha_jobs
                """
            )
            summary = await cursor.fetchone()

            cursor = await db.execute(
                """
                SELECT
                    COUNT(*) AS key_count,
                    SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS key_enabled_count
                FROM service_api_keys
                """
            )
            key_summary = await cursor.fetchone()

            cursor = await db.execute(
                """
                SELECT
                    COUNT(*) AS node_count,
                    SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS node_enabled_count
                FROM cluster_nodes
                """
            )
            node_summary = await cursor.fetchone()

            cursor = await db.execute(
                """
                SELECT
                    COUNT(*) AS portal_user_total,
                    SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS portal_user_enabled_total
                FROM portal_users
                """
            )
            portal_user_summary = await cursor.fetchone()

            cursor = await db.execute(
                """
                SELECT
                    COUNT(*) AS portal_cdk_total,
                    SUM(CASE WHEN redeemed_user_id IS NULL THEN 1 ELSE 0 END) AS portal_cdk_unused_total
                FROM portal_cdks
                """
            )
            portal_cdk_summary = await cursor.fetchone()

            return {
                "jobs_total": int(summary["total"] or 0),
                "jobs_success": int(summary["success"] or 0),
                "jobs_failed": int(summary["failed"] or 0),
                "jobs_solve_total": int(summary["success"] or 0) + int(summary["failed"] or 0),
                "jobs_finish_total": int(summary["finish_total"] or 0),
                "jobs_error_report_total": int(summary["error_report_total"] or 0),
                "api_key_total": int(key_summary["key_count"] or 0),
                "api_key_enabled_total": int(key_summary["key_enabled_count"] or 0),
                "cluster_node_total": int(node_summary["node_count"] or 0),
                "cluster_node_enabled_total": int(node_summary["node_enabled_count"] or 0),
                "portal_user_total": int(portal_user_summary["portal_user_total"] or 0),
                "portal_user_enabled_total": int(portal_user_summary["portal_user_enabled_total"] or 0),
                "portal_cdk_total": int(portal_cdk_summary["portal_cdk_total"] or 0),
                "portal_cdk_unused_total": int(portal_cdk_summary["portal_cdk_unused_total"] or 0),
            }

    async def get_cluster_key(self) -> str:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT cluster_key FROM cluster_settings WHERE id = 1")
            row = await cursor.fetchone()
            if row and row["cluster_key"]:
                return row["cluster_key"]

        new_key = self._generate_cluster_key()
        async with self._connect() as db:
            await db.execute(
                "INSERT OR REPLACE INTO cluster_settings (id, cluster_key, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)",
                (new_key,),
            )
            await db.commit()
        return new_key

    async def rotate_cluster_key(self) -> str:
        new_key = self._generate_cluster_key()
        async with self._connect() as db:
            await db.execute(
                "UPDATE cluster_settings SET cluster_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
                (new_key,),
            )
            await db.commit()
        return new_key

    async def validate_cluster_key(self, raw_key: str) -> bool:
        current = await self.get_cluster_key()
        return bool(raw_key) and secrets.compare_digest(raw_key, current)

    async def upsert_cluster_node(
        self,
        node_name: str,
        base_url: str,
        node_api_key: str,
        weight: int,
        max_concurrency: int,
        reported_browser_count: int,
        reported_node_max_concurrency: int,
        active_sessions: int,
        cached_sessions: int,
        healthy: bool,
    ) -> Dict[str, Any]:
        normalized_name = node_name.strip()
        normalized_url = base_url.strip().rstrip("/")

        async with self._write_connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT id FROM cluster_nodes WHERE base_url = ? ORDER BY id ASC LIMIT 1",
                (normalized_url,),
            )
            row = await cursor.fetchone()

            if row:
                node_id = int(row["id"])
                await db.execute(
                    """
                    UPDATE cluster_nodes
                    SET node_name = ?, node_api_key = ?, weight = ?, max_concurrency = ?,
                        reported_browser_count = ?, reported_node_max_concurrency = ?,
                        active_sessions = ?, cached_sessions = ?, healthy = ?,
                        last_error = NULL,
                        last_heartbeat_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        normalized_name,
                        node_api_key,
                        max(1, int(weight)),
                        max(1, int(max_concurrency)),
                        max(1, int(reported_browser_count)),
                        max(1, int(reported_node_max_concurrency)),
                        max(0, int(active_sessions)),
                        max(0, int(cached_sessions)),
                        1 if healthy else 0,
                        node_id,
                    ),
                )
            else:
                cursor = await db.execute(
                    """
                    INSERT INTO cluster_nodes (
                        node_name, base_url, node_api_key, enabled, healthy,
                        active_sessions, cached_sessions, max_concurrency,
                        reported_browser_count, reported_node_max_concurrency, weight,
                        last_heartbeat_at
                    )
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (
                        normalized_name,
                        normalized_url,
                        node_api_key,
                        1 if healthy else 0,
                        max(0, int(active_sessions)),
                        max(0, int(cached_sessions)),
                        max(1, int(max_concurrency)),
                        max(1, int(reported_browser_count)),
                        max(1, int(reported_node_max_concurrency)),
                        max(1, int(weight)),
                    ),
                )
                node_id = int(cursor.lastrowid)

            await db.execute(
                "DELETE FROM cluster_nodes WHERE base_url = ? AND id <> ?",
                (normalized_url, node_id),
            )
            await db.commit()

        node = await self.get_cluster_node(node_id)
        if not node:
            raise RuntimeError("节点保存失败")
        return node

    async def heartbeat_cluster_node(
        self,
        node_name: str,
        base_url: str,
        max_concurrency: int,
        reported_browser_count: int,
        reported_node_max_concurrency: int,
        active_sessions: int,
        cached_sessions: int,
        healthy: bool,
    ) -> Optional[Dict[str, Any]]:
        normalized_name = node_name.strip()
        normalized_url = base_url.strip().rstrip("/")
        async with self._write_connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT id FROM cluster_nodes WHERE base_url = ? ORDER BY id ASC LIMIT 1",
                (normalized_url,),
            )
            row = await cursor.fetchone()
            if not row:
                return None

            node_id = int(row["id"])
            await db.execute(
                """
                UPDATE cluster_nodes
                SET node_name = ?,
                    max_concurrency = ?,
                    reported_browser_count = ?,
                    reported_node_max_concurrency = ?,
                    active_sessions = ?,
                    cached_sessions = ?,
                    healthy = ?,
                    last_error = NULL,
                    last_heartbeat_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    normalized_name,
                    max(1, int(max_concurrency)),
                    max(1, int(reported_browser_count)),
                    max(1, int(reported_node_max_concurrency)),
                    max(0, int(active_sessions)),
                    max(0, int(cached_sessions)),
                    1 if healthy else 0,
                    node_id,
                ),
            )
            await db.execute(
                "DELETE FROM cluster_nodes WHERE base_url = ? AND id <> ?",
                (normalized_url, node_id),
            )
            await db.commit()

        return await self.get_cluster_node(node_id)

    async def list_cluster_nodes(self) -> List[Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, node_name, base_url, enabled, healthy,
                       active_sessions, cached_sessions, max_concurrency,
                       reported_browser_count, reported_node_max_concurrency, weight,
                       last_heartbeat_at, last_error, created_at, updated_at
                FROM cluster_nodes
                ORDER BY id ASC
                """
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_cluster_node(self, node_id: int) -> Optional[Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM cluster_nodes WHERE id = ?", (node_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_cluster_node_by_name(self, node_name: str) -> Optional[Dict[str, Any]]:
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM cluster_nodes WHERE node_name = ?", (node_name,))
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_cluster_node_by_base_url(self, base_url: str) -> Optional[Dict[str, Any]]:
        normalized_url = base_url.strip().rstrip("/")
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM cluster_nodes WHERE base_url = ? ORDER BY id ASC LIMIT 1",
                (normalized_url,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def update_cluster_node(
        self,
        node_id: int,
        enabled: Optional[bool] = None,
        weight: Optional[int] = None,
        max_concurrency: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        current = await self.get_cluster_node(node_id)
        if not current:
            return None

        new_enabled = int(enabled) if enabled is not None else int(bool(current["enabled"]))
        new_weight = max(1, int(weight)) if weight is not None else max(1, int(current["weight"] or 100))
        new_max = (
            max(1, int(max_concurrency))
            if max_concurrency is not None
            else max(1, int(current["max_concurrency"] or 1))
        )

        async with self._write_connect() as db:
            await db.execute(
                """
                UPDATE cluster_nodes
                SET enabled = ?,
                    weight = ?,
                    max_concurrency = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (new_enabled, new_weight, new_max, node_id),
            )
            await db.commit()

        return await self.get_cluster_node(node_id)

    async def delete_cluster_node(self, node_id: int) -> bool:
        if self._cluster_logs_use_redis():
            await self._redis_log_store.clear_cluster_heartbeats(node_id=node_id)
            await self._redis_log_store.clear_cluster_errors(node_id=node_id)
        async with self._connect() as db:
            await db.execute("DELETE FROM cluster_node_heartbeats WHERE node_id = ?", (node_id,))
            await db.execute("DELETE FROM cluster_node_errors WHERE node_id = ?", (node_id,))
            cursor = await db.execute("DELETE FROM cluster_nodes WHERE id = ?", (node_id,))
            await db.commit()
            return (cursor.rowcount or 0) > 0

    async def mark_cluster_node_error(self, node_id: int, error_message: str, error_type: str = "runtime"):
        async with self._write_connect() as db:
            await db.execute(
                """
                UPDATE cluster_nodes
                SET last_error = ?,
                    healthy = 0,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (error_message[:500], node_id),
            )
            if not self._cluster_logs_use_redis():
                await db.execute(
                    """
                    INSERT INTO cluster_node_errors (node_id, error_type, error_message)
                    VALUES (?, ?, ?)
                    """,
                    (node_id, (error_type or "runtime")[:60], (error_message or "")[:500]),
                )
            await db.commit()
        if self._cluster_logs_use_redis():
            await self._redis_log_store.append_cluster_error(
                int(node_id),
                {
                    "node_id": int(node_id),
                    "error_type": (error_type or "runtime")[:60],
                    "error_message": (error_message or "")[:500],
                },
            )

    async def adjust_cluster_node_sessions(
        self,
        node_id: int,
        *,
        active_delta: int = 0,
        cached_delta: int = 0,
    ):
        """在心跳之间，快速修正 master 侧节点会话计数，降低调度滞后。"""
        if node_id <= 0:
            return

        active_delta = int(active_delta or 0)
        cached_delta = int(cached_delta or 0)
        if active_delta == 0 and cached_delta == 0:
            return

        async with self._write_connect() as db:
            await db.execute(
                """
                UPDATE cluster_nodes
                SET active_sessions = MAX(active_sessions + ?, 0),
                    cached_sessions = MAX(cached_sessions + ?, 0),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (active_delta, cached_delta, node_id),
            )
            await db.commit()

    async def record_cluster_node_heartbeat(
        self,
        node_id: int,
        event_type: str,
        payload: Dict[str, Any],
        healthy: bool,
        reason: Optional[str] = None,
    ):
        safe_payload = payload if isinstance(payload, dict) else {}
        if self._cluster_logs_use_redis():
            await self._redis_log_store.append_cluster_heartbeat(
                int(node_id),
                {
                    "node_id": int(node_id),
                    "event_type": (event_type or "heartbeat")[:32],
                    "healthy": bool(healthy),
                    "reason": (reason or "")[:300] or None,
                    "payload": safe_payload,
                },
            )
            return
        async with self._write_connect() as db:
            await db.execute(
                """
                INSERT INTO cluster_node_heartbeats (node_id, event_type, healthy, reason, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    node_id,
                    (event_type or "heartbeat")[:32],
                    1 if healthy else 0,
                    (reason or "")[:300] or None,
                    json.dumps(safe_payload, ensure_ascii=False),
                ),
            )
            await db.commit()

    async def list_cluster_node_heartbeats(self, node_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        if self._cluster_logs_use_redis():
            safe_limit = min(max(1, int(limit or 20)), 100)
            items = await self._redis_log_store.list_cluster_heartbeats(node_id=node_id, limit=safe_limit)
            for item in items:
                item["id"] = int(item.get("id") or 0)
                item["node_id"] = int(item.get("node_id") or node_id)
                item["healthy"] = bool(item.get("healthy"))
                if not isinstance(item.get("payload"), dict):
                    item["payload"] = {}
            return items
        safe_limit = min(max(1, int(limit or 20)), 100)
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, node_id, event_type, healthy, reason, payload_json, created_at
                FROM cluster_node_heartbeats
                WHERE node_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (node_id, safe_limit),
            )
            rows = await cursor.fetchall()

        items: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            raw_payload = item.pop("payload_json", None)
            parsed_payload: Dict[str, Any] = {}
            if raw_payload:
                try:
                    loaded = json.loads(str(raw_payload))
                    if isinstance(loaded, dict):
                        parsed_payload = loaded
                except json.JSONDecodeError:
                    parsed_payload = {"raw": str(raw_payload)}
            item["payload"] = parsed_payload
            item["healthy"] = bool(item.get("healthy"))
            items.append(item)
        return items

    async def list_cluster_node_errors(self, node_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        if self._cluster_logs_use_redis():
            safe_limit = min(max(1, int(limit or 20)), 100)
            items = await self._redis_log_store.list_cluster_errors(node_id=node_id, limit=safe_limit)
            for item in items:
                item["id"] = int(item.get("id") or 0)
                item["node_id"] = int(item.get("node_id") or node_id)
            return items
        safe_limit = min(max(1, int(limit or 20)), 100)
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, node_id, error_type, error_message, created_at
                FROM cluster_node_errors
                WHERE node_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (node_id, safe_limit),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def clear_cluster_node_logs(
        self,
        node_id: int,
        *,
        clear_heartbeats: bool = False,
        clear_errors: bool = False,
    ) -> Dict[str, int]:
        if not clear_heartbeats and not clear_errors:
            return {"heartbeats": 0, "errors": 0}

        if self._cluster_logs_use_redis():
            node = await self.get_cluster_node(node_id)
            if not node:
                raise ValueError("节点不存在")
            result = {"heartbeats": 0, "errors": 0}
            if clear_heartbeats:
                result["heartbeats"] = await self._redis_log_store.clear_cluster_heartbeats(node_id=node_id)
            if clear_errors:
                result["errors"] = await self._redis_log_store.clear_cluster_errors(node_id=node_id)
                async with self._write_connect() as db:
                    await db.execute(
                        """
                        UPDATE cluster_nodes
                        SET last_error = NULL,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        (node_id,),
                    )
                    await db.commit()
            return result

        async with self._write_connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT id FROM cluster_nodes WHERE id = ?", (node_id,))
            row = await cursor.fetchone()
            if not row:
                raise ValueError("节点不存在")

            result = {"heartbeats": 0, "errors": 0}
            if clear_heartbeats:
                heartbeat_cursor = await db.execute("DELETE FROM cluster_node_heartbeats WHERE node_id = ?", (node_id,))
                result["heartbeats"] = int(heartbeat_cursor.rowcount or 0)
            if clear_errors:
                error_cursor = await db.execute("DELETE FROM cluster_node_errors WHERE node_id = ?", (node_id,))
                result["errors"] = int(error_cursor.rowcount or 0)
                await db.execute(
                    """
                    UPDATE cluster_nodes
                    SET last_error = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (node_id,),
                )
            await db.commit()
            return result

    async def get_available_cluster_nodes(self, stale_seconds: int) -> List[Dict[str, Any]]:
        stale_seconds = max(10, int(stale_seconds))
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT *
                FROM cluster_nodes
                WHERE enabled = 1
                  AND healthy = 1
                  AND last_heartbeat_at IS NOT NULL
                  AND last_heartbeat_at >= datetime('now', '-' || ? || ' seconds')
                ORDER BY id ASC
                """,
                (stale_seconds,),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_token(self, token_id: int):
        """兼容 browser_captcha.py 的调用；独立打码服务默认不维护业务 token。"""
        return None

