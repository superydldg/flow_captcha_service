from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiosqlite

from .config import config
from .models import CaptchaConfig


class Database:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or config.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

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
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

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
            await db.execute("CREATE INDEX IF NOT EXISTS idx_captcha_jobs_portal_user_created ON captcha_jobs(portal_user_id, created_at DESC)")
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

    async def _ensure_defaults(self):
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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

        async with aiosqlite.connect(self.db_path) as db:
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

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO portal_users (username, display_name, password_hash, register_location, enabled, quota_remaining, quota_used)
                VALUES (?, ?, ?, ?, 1, 0, 0)
                """,
                (normalized_username, normalized_display_name, self._hash_secret(password), normalized_location),
            )
            user_id = int(cursor.lastrowid or 0)
            await db.commit()

        return True, "注册成功", await self.get_portal_user(user_id)

    async def verify_portal_user_credentials(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        user = await self.get_portal_user_by_username(username)
        if not user:
            return None
        if user.get("password_hash") != self._hash_secret(password):
            return None
        return await self.get_portal_user(int(user["id"]))

    async def mark_portal_user_login(self, user_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE portal_users SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,),
            )
            await db.commit()

    async def list_portal_users(self) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
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
        enabled: Optional[bool] = None,
        display_name: Optional[str] = None,
        quota_remaining_delta: Optional[int] = None,
        new_password: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        current = await self.get_portal_user(user_id)
        if not current:
            return None

        new_enabled = int(bool(enabled)) if enabled is not None else int(bool(current["enabled"]))
        new_display_name = str(display_name or current.get("display_name") or current.get("username") or "").strip()
        delta = int(quota_remaining_delta or 0)
        new_password_hash = self._hash_secret(new_password) if new_password else None

        async with aiosqlite.connect(self.db_path) as db:
            if new_password_hash:
                await db.execute(
                    """
                    UPDATE portal_users
                    SET enabled = ?,
                        display_name = ?,
                        quota_remaining = MAX(COALESCE(quota_remaining, 0) + ?, 0),
                        password_hash = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (new_enabled, new_display_name, delta, new_password_hash, user_id),
                )
            else:
                await db.execute(
                    """
                    UPDATE portal_users
                    SET enabled = ?,
                        display_name = ?,
                        quota_remaining = MAX(COALESCE(quota_remaining, 0) + ?, 0),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (new_enabled, new_display_name, delta, user_id),
                )
            await db.commit()

        updated = await self.get_portal_user(user_id)
        if updated is None:
            return None
        if delta != 0:
            await self.create_portal_user_transaction(
                portal_user_id=user_id,
                change_amount=delta,
                balance_after=int(updated.get("quota_remaining") or 0),
                source_type="admin_adjust",
                source_ref=str(user_id),
                note="??????",
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
    ) -> Tuple[bool, str]:
        async with aiosqlite.connect(self.db_path) as db:
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
                await db.commit()
                return True, ""
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
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO portal_user_jobs (portal_user_id, session_id, project_id, action, status, error_reason, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (portal_user_id, session_id, project_id, action, status, error_reason, duration_ms),
            )
            await db.commit()

    async def list_portal_user_jobs(
        self,
        portal_user_id: int,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
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
        async with aiosqlite.connect(self.db_path) as db:
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

    async def get_portal_user_usage_summary(self, user_id: int) -> Optional[Dict[str, Any]]:
        user = await self.get_portal_user(user_id)
        if not user:
            return None

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT
                    COUNT(*) AS request_total,
                    SUM(CASE WHEN status IN ('success', 'success_master_dispatch') THEN 1 ELSE 0 END) AS solve_success_total,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS solve_failed_total,
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
                    SELECT project_id FROM portal_user_jobs WHERE portal_user_id = ?
                    UNION ALL
                    SELECT project_id FROM captcha_jobs WHERE portal_user_id = ?
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
            },
        }

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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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

        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO portal_user_transactions (portal_user_id, change_amount, balance_after, source_type, source_ref, note)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (portal_user_id, int(change_amount), int(balance_after), (source_type or "unknown")[:80], source_ref, note),
            )
            await db.commit()

    async def list_portal_user_transactions(self, portal_user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 200))
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT id, portal_user_id, change_amount, balance_after, source_type, source_ref, note, created_at
                FROM portal_user_transactions
                WHERE portal_user_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (portal_user_id, safe_limit),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def create_portal_user_api_key(self, portal_user_id: int, name: str) -> Tuple[str, Dict[str, Any]]:
        raw_key, key_hash, key_prefix = self._generate_service_api_key()
        normalized_name = str(name or "").strip() or f"key-{portal_user_id}"
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE portal_user_api_keys SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE portal_user_id = ?",
                (1 if enabled else 0, portal_user_id),
            )
            await db.commit()

    async def resolve_portal_user_api_key(self, raw_key: str) -> Optional[Dict[str, Any]]:
        key_hash = self._hash_secret(raw_key)
        async with aiosqlite.connect(self.db_path) as db:
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

    async def touch_portal_user_api_key_usage(self, api_key_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE portal_user_api_keys
                SET quota_used = quota_used + 1,
                    last_used_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (api_key_id,),
            )
            await db.commit()

    async def list_portal_user_api_call_logs(
        self,
        portal_user_id: int,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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

        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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

        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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

    async def consume_api_key_quota(self, api_key_id: int) -> Tuple[bool, str]:
        if api_key_id <= 0:
            return True, ""

        async with aiosqlite.connect(self.db_path) as db:
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
                await db.commit()
                return True, ""
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
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO captcha_jobs (session_id, api_key_id, project_id, action, status, error_reason, duration_ms, portal_user_id, portal_api_key_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, api_key_id, project_id, action, status, error_reason, duration_ms, portal_user_id, portal_api_key_id),
            )
            await db.commit()

    async def list_job_logs(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 500))
        safe_offset = max(0, int(offset))
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT j.id, j.session_id, j.api_key_id, k.name AS api_key_name, k.key_prefix,
                       j.project_id, j.action, j.status, j.error_reason, j.duration_ms, j.created_at,
                       j.portal_user_id, j.portal_api_key_id
                FROM captcha_jobs j
                LEFT JOIN service_api_keys k ON k.id = j.api_key_id
                ORDER BY j.id DESC
                LIMIT ? OFFSET ?
                """,
                (safe_limit, safe_offset),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


    async def list_job_logs_by_api_key(
        self,
        api_key_id: int,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
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

        async with aiosqlite.connect(self.db_path) as db:
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

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            cursor = await db.execute(
                """
                SELECT
                    COUNT(*) AS request_total,
                    SUM(CASE WHEN status IN ('success', 'success_master_dispatch') THEN 1 ELSE 0 END) AS solve_success_total,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS solve_failed_total,
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
                       SUM(CASE WHEN status IN ('success', 'success_master_dispatch') THEN 1 ELSE 0 END) AS solve_success,
                       SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS solve_failed,
                       MAX(created_at) AS last_used_at
                FROM captcha_jobs
                WHERE api_key_id = ? AND project_id IS NOT NULL AND project_id <> ''
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
                WHERE api_key_id = ? AND action IS NOT NULL AND action <> ''
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
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            cursor = await db.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status IN ('success', 'success_master_dispatch') THEN 1 ELSE 0 END) AS success,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
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
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT cluster_key FROM cluster_settings WHERE id = 1")
            row = await cursor.fetchone()
            if row and row["cluster_key"]:
                return row["cluster_key"]

        new_key = self._generate_cluster_key()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO cluster_settings (id, cluster_key, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)",
                (new_key,),
            )
            await db.commit()
        return new_key

    async def rotate_cluster_key(self) -> str:
        new_key = self._generate_cluster_key()
        async with aiosqlite.connect(self.db_path) as db:
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

        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM cluster_nodes WHERE id = ?", (node_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_cluster_node_by_name(self, node_name: str) -> Optional[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM cluster_nodes WHERE node_name = ?", (node_name,))
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_cluster_node_by_base_url(self, base_url: str) -> Optional[Dict[str, Any]]:
        normalized_url = base_url.strip().rstrip("/")
        async with aiosqlite.connect(self.db_path) as db:
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

        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM cluster_node_heartbeats WHERE node_id = ?", (node_id,))
            await db.execute("DELETE FROM cluster_node_errors WHERE node_id = ?", (node_id,))
            cursor = await db.execute("DELETE FROM cluster_nodes WHERE id = ?", (node_id,))
            await db.commit()
            return (cursor.rowcount or 0) > 0

    async def mark_cluster_node_error(self, node_id: int, error_message: str, error_type: str = "runtime"):
        async with aiosqlite.connect(self.db_path) as db:
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
            await db.execute(
                """
                INSERT INTO cluster_node_errors (node_id, error_type, error_message)
                VALUES (?, ?, ?)
                """,
                (node_id, (error_type or "runtime")[:60], (error_message or "")[:500]),
            )
            await db.commit()

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

        async with aiosqlite.connect(self.db_path) as db:
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
        async with aiosqlite.connect(self.db_path) as db:
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
        safe_limit = min(max(1, int(limit or 20)), 100)
        async with aiosqlite.connect(self.db_path) as db:
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
        safe_limit = min(max(1, int(limit or 20)), 100)
        async with aiosqlite.connect(self.db_path) as db:
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

    async def get_available_cluster_nodes(self, stale_seconds: int) -> List[Dict[str, Any]]:
        stale_seconds = max(10, int(stale_seconds))
        async with aiosqlite.connect(self.db_path) as db:
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
