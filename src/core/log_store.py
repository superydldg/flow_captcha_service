from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

try:
    import redis.asyncio as redis
except ImportError:  # pragma: no cover - exercised only when optional dep is missing
    redis = None


def _utc_now_text() -> str:
    return datetime.now(UTC).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")


class RedisLogStore:
    def __init__(
        self,
        *,
        redis_url: str,
        key_prefix: str,
        max_entries: int,
    ):
        self.redis_url = str(redis_url or "").strip()
        self.key_prefix = str(key_prefix or "fcs").strip() or "fcs"
        self.max_entries = max(100, int(max_entries or 20000))
        self._client: Optional[Any] = None
        self._job_log_index_lock = asyncio.Lock()

    def _key(self, suffix: str) -> str:
        return f"{self.key_prefix}:{suffix}"

    async def _get_client(self):
        if redis is None:
            raise RuntimeError("redis 依赖未安装，无法启用 Redis 日志存储")
        if self._client is None:
            self._client = redis.from_url(self.redis_url, decode_responses=True)
        return self._client

    async def connect(self):
        client = await self._get_client()
        await client.ping()

    async def close(self):
        if self._client is None:
            return
        await self._client.aclose()
        self._client = None

    async def _next_id(self, suffix: str) -> int:
        client = await self._get_client()
        return int(await client.incr(self._key(suffix)) or 0)

    async def _append_list_entry(self, *, list_key: str, entry: Dict[str, Any], seq_key: str) -> Dict[str, Any]:
        payload = dict(entry)
        payload["id"] = int(payload.get("id") or await self._next_id(seq_key))
        payload["created_at"] = str(payload.get("created_at") or _utc_now_text())
        await self._append_payload_to_lists(payload=payload, list_keys=[list_key])
        return payload

    async def _append_payload_to_lists(self, *, payload: Dict[str, Any], list_keys: List[str]):
        client = await self._get_client()
        encoded = json.dumps(payload, ensure_ascii=False)
        unique_keys = []
        seen: set[str] = set()
        for list_key in list_keys:
            normalized = str(list_key or "").strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            unique_keys.append(self._key(normalized))
        if not unique_keys:
            return
        async with client.pipeline(transaction=True) as pipe:
            for key in unique_keys:
                pipe.lpush(key, encoded)
                pipe.ltrim(key, 0, self.max_entries - 1)
            await pipe.execute()

    async def _list_entries(self, *, list_key: str, start: int, stop: int) -> List[Dict[str, Any]]:
        client = await self._get_client()
        raw_items = await client.lrange(self._key(list_key), start, stop)
        items: List[Dict[str, Any]] = []
        for raw in raw_items or []:
            try:
                parsed = json.loads(str(raw))
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                items.append(parsed)
        return items

    async def _count_list(self, *, list_key: str) -> int:
        client = await self._get_client()
        return int(await client.llen(self._key(list_key)) or 0)

    async def _clear_list(self, *, list_key: str) -> int:
        client = await self._get_client()
        key = self._key(list_key)
        total = int(await client.llen(key) or 0)
        await client.delete(key)
        return total

    async def _list_exists(self, *, list_key: str) -> bool:
        client = await self._get_client()
        return bool(await client.exists(self._key(list_key)))

    async def _scan_keys(self, *, pattern: str) -> List[str]:
        client = await self._get_client()
        cursor = 0
        keys: List[str] = []
        match_pattern = self._key(pattern)
        while True:
            cursor, batch = await client.scan(cursor=cursor, match=match_pattern, count=200)
            keys.extend(batch or [])
            if int(cursor or 0) == 0:
                break
        return keys

    async def _delete_keys(self, keys: List[str]):
        if not keys:
            return
        client = await self._get_client()
        unique_keys = []
        seen: set[str] = set()
        for key in keys:
            normalized = str(key or "").strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            unique_keys.append(normalized)
        if not unique_keys:
            return
        chunk_size = 200
        for index in range(0, len(unique_keys), chunk_size):
            await client.delete(*unique_keys[index:index + chunk_size])

    def _job_log_index_key_for_scope(self, scope: str) -> str:
        normalized_scope = str(scope or "captcha_jobs").strip() or "captcha_jobs"
        return f"logs:jobs:scope:{normalized_scope}"

    def _job_log_index_key_for_api_key(self, api_key_id: int) -> str:
        return f"logs:jobs:api_key:{int(api_key_id)}"

    def _job_log_index_key_for_portal_user(self, portal_user_id: int) -> str:
        return f"logs:jobs:portal_user:{int(portal_user_id)}"

    def _job_log_index_ready_key(self) -> str:
        return "logs:jobs:indexes:ready:v1"

    async def job_log_indexes_ready(self) -> bool:
        return await self._list_exists(list_key=self._job_log_index_ready_key())

    async def _set_job_log_indexes_ready(self):
        client = await self._get_client()
        await client.set(self._key(self._job_log_index_ready_key()), "1")

    async def _job_log_index_keys(self) -> List[str]:
        keys: List[str] = []
        keys.extend(await self._scan_keys(pattern="logs:jobs:scope:*"))
        keys.extend(await self._scan_keys(pattern="logs:jobs:api_key:*"))
        keys.extend(await self._scan_keys(pattern="logs:jobs:portal_user:*"))
        return keys

    async def ensure_job_log_indexes(self, *, batch_size: int = 500) -> bool:
        client = await self._get_client()
        safe_batch_size = max(100, min(int(batch_size or 500), self.max_entries))
        aggregate_key = self._key("logs:jobs")

        async with self._job_log_index_lock:
            if await self.job_log_indexes_ready():
                return False

            total = int(await client.llen(aggregate_key) or 0)
            existing_index_keys = await self._job_log_index_keys()
            if existing_index_keys:
                await self._delete_keys(existing_index_keys)

            if total <= 0:
                await self._set_job_log_indexes_ready()
                return False

            for start in range(0, total, safe_batch_size):
                stop = min(total - 1, start + safe_batch_size - 1)
                raw_items = await client.lrange(aggregate_key, start, stop)
                if not raw_items:
                    continue

                bucketed_entries: Dict[str, List[str]] = {}
                for raw in raw_items:
                    try:
                        parsed = json.loads(str(raw))
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(parsed, dict):
                        continue

                    scope = str(parsed.get("log_scope") or "captcha_jobs").strip() or "captcha_jobs"
                    scope_key = self._job_log_index_key_for_scope(scope)
                    bucketed_entries.setdefault(scope_key, []).append(str(raw))

                    api_key_id = int(parsed.get("api_key_id") or 0)
                    if api_key_id > 0:
                        api_key = self._job_log_index_key_for_api_key(api_key_id)
                        bucketed_entries.setdefault(api_key, []).append(str(raw))

                    portal_user_id = int(parsed.get("portal_user_id") or 0)
                    if portal_user_id > 0:
                        portal_key = self._job_log_index_key_for_portal_user(portal_user_id)
                        bucketed_entries.setdefault(portal_key, []).append(str(raw))

                if not bucketed_entries:
                    continue

                async with client.pipeline(transaction=True) as pipe:
                    for list_key, entries in bucketed_entries.items():
                        pipe.rpush(self._key(list_key), *entries)
                    await pipe.execute()

            await self._set_job_log_indexes_ready()
            return True

    async def append_job_log(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        async with self._job_log_index_lock:
            payload = dict(entry)
            payload["id"] = int(payload.get("id") or await self._next_id("seq:jobs"))
            payload["created_at"] = str(payload.get("created_at") or _utc_now_text())
            scope = str(payload.get("log_scope") or "captcha_jobs").strip() or "captcha_jobs"
            list_keys = ["logs:jobs", self._job_log_index_key_for_scope(scope)]

            api_key_id = int(payload.get("api_key_id") or 0)
            if api_key_id > 0:
                list_keys.append(self._job_log_index_key_for_api_key(api_key_id))

            portal_user_id = int(payload.get("portal_user_id") or 0)
            if portal_user_id > 0:
                list_keys.append(self._job_log_index_key_for_portal_user(portal_user_id))

            await self._append_payload_to_lists(payload=payload, list_keys=list_keys)
            return payload

    async def list_job_logs(self, *, limit: int, offset: int) -> List[Dict[str, Any]]:
        safe_limit = max(1, int(limit or 1))
        safe_offset = max(0, int(offset or 0))
        return await self._list_entries(
            list_key="logs:jobs",
            start=safe_offset,
            stop=safe_offset + safe_limit - 1,
        )

    async def list_all_job_logs(self) -> List[Dict[str, Any]]:
        return await self._list_entries(
            list_key="logs:jobs",
            start=0,
            stop=self.max_entries - 1,
        )

    async def list_job_logs_by_scope(self, *, scope: str, limit: int, offset: int = 0) -> List[Dict[str, Any]]:
        safe_limit = max(1, int(limit or 1))
        safe_offset = max(0, int(offset or 0))
        return await self._list_entries(
            list_key=self._job_log_index_key_for_scope(scope),
            start=safe_offset,
            stop=safe_offset + safe_limit - 1,
        )

    async def list_all_job_logs_by_scope(self, *, scope: str) -> List[Dict[str, Any]]:
        return await self._list_entries(
            list_key=self._job_log_index_key_for_scope(scope),
            start=0,
            stop=self.max_entries - 1,
        )

    async def count_job_logs(self) -> int:
        return await self._count_list(list_key="logs:jobs")

    async def count_job_logs_by_scope(self, *, scope: str) -> int:
        return await self._count_list(list_key=self._job_log_index_key_for_scope(scope))

    async def job_log_scope_index_exists(self, *, scope: str) -> bool:
        return await self._list_exists(list_key=self._job_log_index_key_for_scope(scope))

    async def list_job_logs_by_api_key(self, *, api_key_id: int, limit: int, offset: int = 0) -> List[Dict[str, Any]]:
        safe_limit = max(1, int(limit or 1))
        safe_offset = max(0, int(offset or 0))
        return await self._list_entries(
            list_key=self._job_log_index_key_for_api_key(api_key_id),
            start=safe_offset,
            stop=safe_offset + safe_limit - 1,
        )

    async def list_all_job_logs_by_api_key(self, *, api_key_id: int) -> List[Dict[str, Any]]:
        return await self._list_entries(
            list_key=self._job_log_index_key_for_api_key(api_key_id),
            start=0,
            stop=self.max_entries - 1,
        )

    async def count_job_logs_by_api_key(self, *, api_key_id: int) -> int:
        return await self._count_list(list_key=self._job_log_index_key_for_api_key(api_key_id))

    async def job_log_api_key_index_exists(self, *, api_key_id: int) -> bool:
        return await self._list_exists(list_key=self._job_log_index_key_for_api_key(api_key_id))

    async def list_job_logs_by_portal_user(self, *, portal_user_id: int, limit: int, offset: int = 0) -> List[Dict[str, Any]]:
        safe_limit = max(1, int(limit or 1))
        safe_offset = max(0, int(offset or 0))
        return await self._list_entries(
            list_key=self._job_log_index_key_for_portal_user(portal_user_id),
            start=safe_offset,
            stop=safe_offset + safe_limit - 1,
        )

    async def list_all_job_logs_by_portal_user(self, *, portal_user_id: int) -> List[Dict[str, Any]]:
        return await self._list_entries(
            list_key=self._job_log_index_key_for_portal_user(portal_user_id),
            start=0,
            stop=self.max_entries - 1,
        )

    async def count_job_logs_by_portal_user(self, *, portal_user_id: int) -> int:
        return await self._count_list(list_key=self._job_log_index_key_for_portal_user(portal_user_id))

    async def job_log_portal_user_index_exists(self, *, portal_user_id: int) -> bool:
        return await self._list_exists(list_key=self._job_log_index_key_for_portal_user(portal_user_id))

    async def clear_job_logs(self) -> int:
        result = await self.clear_job_logs_with_breakdown()
        return int(result.get("total") or 0)

    async def clear_job_logs_with_breakdown(self) -> Dict[str, int]:
        client = await self._get_client()
        aggregate_key = self._key("logs:jobs")
        captcha_key = self._key(self._job_log_index_key_for_scope("captcha_jobs"))
        portal_key = self._key(self._job_log_index_key_for_scope("portal_user_jobs"))
        ready_key = self._key(self._job_log_index_ready_key())

        async with self._job_log_index_lock:
            async with client.pipeline(transaction=True) as pipe:
                pipe.llen(aggregate_key)
                pipe.llen(captcha_key)
                pipe.llen(portal_key)
                pipe.exists(ready_key)
                counts = await pipe.execute()

            total = int(counts[0] or 0)
            captcha_jobs = int(counts[1] or 0)
            portal_user_jobs = int(counts[2] or 0)
            indexes_ready = bool(counts[3])

            if total > 0 and captcha_jobs + portal_user_jobs == 0 and not indexes_ready:
                safe_batch_size = max(100, min(500, self.max_entries))
                for start in range(0, total, safe_batch_size):
                    stop = min(total - 1, start + safe_batch_size - 1)
                    raw_items = await client.lrange(aggregate_key, start, stop)
                    for raw in raw_items or []:
                        try:
                            entry = json.loads(str(raw))
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(entry, dict):
                            continue
                        scope = str(entry.get("log_scope") or "captcha_jobs").strip() or "captcha_jobs"
                        if scope == "portal_user_jobs":
                            portal_user_jobs += 1
                        else:
                            captcha_jobs += 1

            keys_to_delete = [
                aggregate_key,
                captcha_key,
                portal_key,
                ready_key,
                self._key("seq:jobs"),
            ]
            keys_to_delete.extend(await self._job_log_index_keys())
            await self._delete_keys(keys_to_delete)

        return {
            "total": max(total, captcha_jobs + portal_user_jobs),
            "captcha_jobs": captcha_jobs,
            "portal_user_jobs": portal_user_jobs,
        }

    async def append_cluster_heartbeat(self, node_id: int, entry: Dict[str, Any]) -> Dict[str, Any]:
        return await self._append_list_entry(
            list_key=f"cluster:nodes:{int(node_id)}:heartbeats",
            entry=entry,
            seq_key="seq:cluster:heartbeats",
        )

    async def list_cluster_heartbeats(self, *, node_id: int, limit: int) -> List[Dict[str, Any]]:
        safe_limit = max(1, int(limit or 1))
        return await self._list_entries(
            list_key=f"cluster:nodes:{int(node_id)}:heartbeats",
            start=0,
            stop=safe_limit - 1,
        )

    async def clear_cluster_heartbeats(self, *, node_id: int) -> int:
        return await self._clear_list(list_key=f"cluster:nodes:{int(node_id)}:heartbeats")

    async def append_cluster_error(self, node_id: int, entry: Dict[str, Any]) -> Dict[str, Any]:
        return await self._append_list_entry(
            list_key=f"cluster:nodes:{int(node_id)}:errors",
            entry=entry,
            seq_key="seq:cluster:errors",
        )

    async def list_cluster_errors(self, *, node_id: int, limit: int) -> List[Dict[str, Any]]:
        safe_limit = max(1, int(limit or 1))
        return await self._list_entries(
            list_key=f"cluster:nodes:{int(node_id)}:errors",
            start=0,
            stop=safe_limit - 1,
        )

    async def clear_cluster_errors(self, *, node_id: int) -> int:
        return await self._clear_list(list_key=f"cluster:nodes:{int(node_id)}:errors")
