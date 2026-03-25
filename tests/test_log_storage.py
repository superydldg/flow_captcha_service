import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import aiosqlite

from src.core.database import Database


class FakeRedisLogStore:
    def __init__(self):
        self.job_logs = []
        self._seq = 0
        self._heartbeats = {}
        self._errors = {}
        self._job_logs_by_scope = {}
        self._job_logs_by_api_key = {}
        self._job_logs_by_portal_user = {}
        self._job_log_indexes_ready = True
        self.ensure_job_log_indexes_calls = 0

    async def close(self):
        return None

    def _clone(self, item):
        return dict(item)

    def _reset_indexes(self):
        self._job_logs_by_scope = {}
        self._job_logs_by_api_key = {}
        self._job_logs_by_portal_user = {}

    def _append_indexes(self, payload):
        scope = str(payload.get("log_scope") or "captcha_jobs").strip() or "captcha_jobs"
        self._job_logs_by_scope.setdefault(scope, []).insert(0, self._clone(payload))

        api_key_id = int(payload.get("api_key_id") or 0)
        if api_key_id > 0:
            self._job_logs_by_api_key.setdefault(api_key_id, []).insert(0, self._clone(payload))

        portal_user_id = int(payload.get("portal_user_id") or 0)
        if portal_user_id > 0:
            self._job_logs_by_portal_user.setdefault(portal_user_id, []).insert(0, self._clone(payload))

    def _rebuild_indexes(self):
        self._reset_indexes()
        for item in reversed(self.job_logs):
            self._append_indexes(item)

    async def append_job_log(self, entry):
        self._seq += 1
        payload = dict(entry)
        payload["id"] = self._seq
        payload["created_at"] = payload.get("created_at") or datetime.now(UTC).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
        self.job_logs.insert(0, payload)
        self._append_indexes(payload)
        return payload

    async def list_all_job_logs(self):
        return [dict(item) for item in self.job_logs]

    async def list_job_logs(self, *, limit: int, offset: int):
        safe_limit = max(1, int(limit or 1))
        safe_offset = max(0, int(offset or 0))
        return [dict(item) for item in self.job_logs[safe_offset:safe_offset + safe_limit]]

    async def list_job_logs_by_scope(self, *, scope: str, limit: int, offset: int = 0):
        safe_limit = max(1, int(limit or 1))
        safe_offset = max(0, int(offset or 0))
        normalized_scope = str(scope or "captcha_jobs").strip() or "captcha_jobs"
        items = [dict(item) for item in self._job_logs_by_scope.get(normalized_scope, [])]
        return items[safe_offset:safe_offset + safe_limit]

    async def list_all_job_logs_by_scope(self, *, scope: str):
        normalized_scope = str(scope or "captcha_jobs").strip() or "captcha_jobs"
        return [dict(item) for item in self._job_logs_by_scope.get(normalized_scope, [])]

    async def list_job_logs_by_api_key(self, *, api_key_id: int, limit: int, offset: int = 0):
        safe_limit = max(1, int(limit or 1))
        safe_offset = max(0, int(offset or 0))
        normalized_api_key_id = int(api_key_id or 0)
        items = [dict(item) for item in self._job_logs_by_api_key.get(normalized_api_key_id, [])]
        return items[safe_offset:safe_offset + safe_limit]

    async def list_all_job_logs_by_api_key(self, *, api_key_id: int):
        normalized_api_key_id = int(api_key_id or 0)
        return [dict(item) for item in self._job_logs_by_api_key.get(normalized_api_key_id, [])]

    async def count_job_logs(self):
        return len(self.job_logs)

    async def count_job_logs_by_scope(self, *, scope: str):
        normalized_scope = str(scope or "captcha_jobs").strip() or "captcha_jobs"
        return len(self._job_logs_by_scope.get(normalized_scope, []))

    async def count_job_logs_by_api_key(self, *, api_key_id: int):
        normalized_api_key_id = int(api_key_id or 0)
        return len(self._job_logs_by_api_key.get(normalized_api_key_id, []))

    async def list_job_logs_by_portal_user(self, *, portal_user_id: int, limit: int, offset: int = 0):
        safe_limit = max(1, int(limit or 1))
        safe_offset = max(0, int(offset or 0))
        normalized_portal_user_id = int(portal_user_id or 0)
        items = [dict(item) for item in self._job_logs_by_portal_user.get(normalized_portal_user_id, [])]
        return items[safe_offset:safe_offset + safe_limit]

    async def list_all_job_logs_by_portal_user(self, *, portal_user_id: int):
        normalized_portal_user_id = int(portal_user_id or 0)
        return [dict(item) for item in self._job_logs_by_portal_user.get(normalized_portal_user_id, [])]

    async def count_job_logs_by_portal_user(self, *, portal_user_id: int):
        normalized_portal_user_id = int(portal_user_id or 0)
        return len(self._job_logs_by_portal_user.get(normalized_portal_user_id, []))

    async def job_log_scope_index_exists(self, *, scope: str):
        normalized_scope = str(scope or "captcha_jobs").strip() or "captcha_jobs"
        return normalized_scope in self._job_logs_by_scope

    async def job_log_api_key_index_exists(self, *, api_key_id: int):
        return int(api_key_id or 0) in self._job_logs_by_api_key

    async def job_log_portal_user_index_exists(self, *, portal_user_id: int):
        return int(portal_user_id or 0) in self._job_logs_by_portal_user

    async def job_log_indexes_ready(self):
        return bool(self._job_log_indexes_ready)

    async def ensure_job_log_indexes(self, *, batch_size: int = 500):
        _ = batch_size
        self.ensure_job_log_indexes_calls += 1
        self._rebuild_indexes()
        self._job_log_indexes_ready = True
        return True

    async def clear_job_logs(self):
        total = len(self.job_logs)
        self.job_logs = []
        self._reset_indexes()
        self._job_log_indexes_ready = False
        return total

    async def clear_job_logs_with_breakdown(self):
        captcha_jobs = 0
        portal_user_jobs = 0
        for item in self.job_logs:
            scope = str(item.get("log_scope") or "captcha_jobs").strip() or "captcha_jobs"
            if scope == "portal_user_jobs":
                portal_user_jobs += 1
            else:
                captcha_jobs += 1
        total = len(self.job_logs)
        self.job_logs = []
        self._reset_indexes()
        self._job_log_indexes_ready = False
        return {
            "total": total,
            "captcha_jobs": captcha_jobs,
            "portal_user_jobs": portal_user_jobs,
        }

    async def append_cluster_heartbeat(self, node_id: int, entry):
        self._heartbeats.setdefault(int(node_id), []).insert(0, dict(entry))
        return dict(entry)

    async def list_cluster_heartbeats(self, *, node_id: int, limit: int):
        safe_limit = max(1, int(limit or 1))
        return [dict(item) for item in self._heartbeats.get(int(node_id), [])[:safe_limit]]

    async def clear_cluster_heartbeats(self, *, node_id: int):
        items = self._heartbeats.pop(int(node_id), [])
        return len(items)

    async def append_cluster_error(self, node_id: int, entry):
        self._errors.setdefault(int(node_id), []).insert(0, dict(entry))
        return dict(entry)

    async def list_cluster_errors(self, *, node_id: int, limit: int):
        safe_limit = max(1, int(limit or 1))
        return [dict(item) for item in self._errors.get(int(node_id), [])[:safe_limit]]

    async def clear_cluster_errors(self, *, node_id: int):
        items = self._errors.pop(int(node_id), [])
        return len(items)


class LogStorageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.db = Database(self.db_path)
        await self.db.init_db()

    async def asyncTearDown(self):
        await self.db.close()
        self.temp_dir.cleanup()

    async def test_startup_cleanup_backfills_completion_and_clears_sqlite_logs(self):
        _, api_key = await self.db.create_api_key("cleanup-key", 10)
        await self.db.consume_api_key_quota(int(api_key["id"]), session_id="sess-cleanup")
        await self.db.create_job_log(
            session_id="sess-cleanup",
            api_key_id=int(api_key["id"]),
            project_id="proj-a",
            action="IMAGE_GENERATION",
            status="finish:success",
            error_reason=None,
            duration_ms=123,
        )

        node = await self.db.upsert_cluster_node(
            node_name="node-1",
            base_url="http://node-1:8060",
            node_api_key="node-key",
            weight=100,
            max_concurrency=1,
            reported_browser_count=1,
            reported_node_max_concurrency=1,
            active_sessions=0,
            cached_sessions=0,
            healthy=True,
        )
        await self.db.record_cluster_node_heartbeat(
            node_id=int(node["id"]),
            event_type="heartbeat",
            payload={"healthy": True},
            healthy=True,
        )
        await self.db.mark_cluster_node_error(int(node["id"]), "boom", error_type="dispatch")

        result = await self.db.startup_log_maintenance()

        self.assertEqual(result["captcha_jobs"], 1)
        self.assertEqual(result["portal_user_jobs"], 0)
        self.assertEqual(result["cluster_node_heartbeats"], 1)
        self.assertEqual(result["cluster_node_errors"], 1)
        self.assertEqual(result["backfilled_complete_events"], 1)
        self.assertEqual(await self.db.count_job_logs(), 0)
        self.assertEqual(await self.db.list_cluster_node_heartbeats(int(node["id"]), limit=20), [])
        self.assertEqual(await self.db.list_cluster_node_errors(int(node["id"]), limit=20), [])

        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(
                """
                SELECT COUNT(*) AS total
                FROM session_quota_events
                WHERE session_id = ? AND owner_type = 'service_api_key' AND owner_id = ? AND event_type = 'complete'
                """,
                ("sess-cleanup", int(api_key["id"])),
            )
            row = await cursor.fetchone()
            self.assertEqual(int(row["total"] or 0), 1)

            cursor = await conn.execute("SELECT last_error FROM cluster_nodes WHERE id = ?", (int(node["id"]),))
            node_row = await cursor.fetchone()
            self.assertTrue(node_row is not None)
            self.assertIn(node_row["last_error"], (None, ""))

    async def test_redis_job_log_backend_supports_create_list_summary_and_clear(self):
        fake_store = FakeRedisLogStore()
        self.db._redis_log_store = fake_store

        _, api_key = await self.db.create_api_key("redis-key", 10)
        api_key_id = int(api_key["id"])

        with patch.object(self.db, "_job_logs_use_redis", return_value=True):
            await self.db.create_job_log(
                session_id="sess-redis",
                api_key_id=api_key_id,
                project_id="proj-redis",
                action="IMAGE_GENERATION",
                status="success",
                error_reason=None,
                duration_ms=45,
            )
            await self.db.finalize_service_session(
                session_id="sess-redis",
                api_key_id=api_key_id,
                project_id="proj-redis",
                action="IMAGE_GENERATION",
                status="finish:success",
                error_reason=None,
            )

            total = await self.db.count_job_logs()
            logs = await self.db.list_job_logs(limit=10, offset=0)
            api_logs = await self.db.list_job_logs_by_api_key(api_key_id=api_key_id, limit=10, offset=0)
            summary = await self.db.get_api_key_usage_summary(api_key_id)
            cleared = await self.db.clear_job_logs()

        self.assertEqual(total, 2)
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]["status"], "finish:success")
        self.assertEqual(logs[0]["api_key_name"], "redis-key")
        self.assertEqual(len(api_logs), 2)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["usage"]["request_total"], 1)
        self.assertEqual(summary["usage"]["solve_success_total"], 1)
        self.assertEqual(summary["usage"]["solve_total"], 1)
        self.assertEqual(summary["usage"]["latest_session_id"], "sess-redis")
        self.assertEqual(cleared["captcha_jobs"], 2)
        self.assertEqual(cleared["portal_user_jobs"], 0)
        self.assertEqual(await self.db.count_job_logs(), 0)

    async def test_redis_legacy_logs_backfill_indexes_before_filtered_reads(self):
        fake_store = FakeRedisLogStore()
        fake_store._job_log_indexes_ready = False
        self.db._redis_log_store = fake_store

        _, api_key = await self.db.create_api_key("legacy-redis-key", 10)
        api_key_id = int(api_key["id"])

        fake_store.job_logs = [
            {
                "id": 2,
                "api_key_id": api_key_id,
                "project_id": "proj-legacy",
                "action": "IMAGE_GENERATION",
                "status": "finish:success",
                "error_reason": None,
                "duration_ms": 88,
                "session_id": "legacy-session",
                "created_at": "2026-03-25 10:00:01",
                "log_scope": "captcha_jobs",
            },
            {
                "id": 1,
                "api_key_id": api_key_id,
                "project_id": "proj-legacy",
                "action": "IMAGE_GENERATION",
                "status": "success",
                "error_reason": None,
                "duration_ms": 66,
                "session_id": "legacy-session",
                "created_at": "2026-03-25 10:00:00",
                "log_scope": "captcha_jobs",
            },
        ]

        with patch.object(fake_store, "list_all_job_logs", side_effect=AssertionError("should not full-scan legacy logs")):
            with patch.object(self.db, "_job_logs_use_redis", return_value=True):
                api_logs = await self.db.list_job_logs_by_api_key(api_key_id=api_key_id, limit=10, offset=0)
                summary = await self.db.get_api_key_usage_summary(api_key_id)

        self.assertEqual(fake_store.ensure_job_log_indexes_calls, 1)
        self.assertEqual(len(api_logs), 2)
        self.assertEqual(api_logs[0]["status"], "finish:success")
        self.assertEqual(summary["usage"]["request_total"], 1)
        self.assertEqual(summary["usage"]["solve_success_total"], 1)
        self.assertEqual(summary["usage"]["latest_session_id"], "legacy-session")

    async def test_periodic_log_cleanup_only_clears_logs_without_touching_quota_or_node_state(self):
        _, api_key = await self.db.create_api_key("periodic-cleanup-key", 10)
        api_key_id = int(api_key["id"])
        await self.db.consume_api_key_quota(api_key_id, session_id="sess-periodic")
        await self.db.create_job_log(
            session_id="sess-periodic",
            api_key_id=api_key_id,
            project_id="proj-periodic",
            action="IMAGE_GENERATION",
            status="success",
            error_reason=None,
            duration_ms=66,
        )

        node = await self.db.upsert_cluster_node(
            node_name="node-periodic",
            base_url="http://node-periodic:8060",
            node_api_key="node-periodic-key",
            weight=100,
            max_concurrency=1,
            reported_browser_count=1,
            reported_node_max_concurrency=1,
            active_sessions=0,
            cached_sessions=0,
            healthy=True,
        )
        await self.db.record_cluster_node_heartbeat(
            node_id=int(node["id"]),
            event_type="heartbeat",
            payload={"healthy": True},
            healthy=True,
        )
        await self.db.mark_cluster_node_error(int(node["id"]), "boom", error_type="dispatch")

        result = await self.db.clear_runtime_logs()

        self.assertEqual(result["captcha_jobs"], 1)
        self.assertEqual(result["portal_user_jobs"], 0)
        self.assertEqual(result["cluster_node_heartbeats"], 1)
        self.assertEqual(result["cluster_node_errors"], 1)
        self.assertEqual(await self.db.count_job_logs(), 0)
        self.assertEqual(await self.db.list_cluster_node_heartbeats(int(node["id"]), limit=20), [])
        self.assertEqual(await self.db.list_cluster_node_errors(int(node["id"]), limit=20), [])

        updated_api_key = await self.db.get_api_key(api_key_id)
        self.assertIsNotNone(updated_api_key)
        self.assertEqual(int(updated_api_key["quota_used"] or 0), 1)
        self.assertEqual(int(updated_api_key["quota_remaining"] or 0), 9)

        updated_node = await self.db.get_cluster_node(int(node["id"]))
        self.assertIsNotNone(updated_node)
        self.assertEqual(updated_node["last_error"], "boom")


if __name__ == "__main__":
    unittest.main()
