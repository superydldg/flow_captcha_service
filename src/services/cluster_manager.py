from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from curl_cffi.requests import AsyncSession

from ..core.config import config
from ..core.database import Database
from ..core.logger import debug_logger


class ClusterManager:
    def __init__(self, db: Database, runtime):
        self.db = db
        self.runtime = runtime
        self._heartbeat_task: Optional[asyncio.Task] = None

    async def start(self):
        if config.cluster_role == "subnode":
            if self._heartbeat_task is None or self._heartbeat_task.done():
                self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def close(self):
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

    async def dispatch_solve(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        nodes = await self._select_candidate_nodes()
        if not nodes:
            raise RuntimeError("暂无可用子节点")

        last_error = ""
        for node in nodes[:2]:
            try:
                result = await self._post_to_node(
                    node=node,
                    path="/api/v1/solve",
                    json_payload=request_payload,
                    timeout=config.cluster_master_dispatch_timeout_seconds,
                )
                child_session = str(result.get("session_id") or "").strip()
                token = str(result.get("token") or "").strip()
                if not child_session or not token:
                    raise RuntimeError("子节点响应缺少 session_id/token")

                result["session_id"] = f"{node['id']}:{child_session}"
                result["node_name"] = node["node_name"]
                return result
            except Exception as e:
                last_error = str(e)
                await self.db.mark_cluster_node_error(int(node["id"]), last_error)
                debug_logger.log_warning(f"[ClusterManager] dispatch solve node={node['node_name']} failed: {last_error}")

        raise RuntimeError(f"子节点打码失败: {last_error or 'unknown'}")

    async def dispatch_finish(self, routed_session_id: str, status: str) -> Dict[str, Any]:
        node, child_session = await self._resolve_routed_session(routed_session_id)
        payload = {"status": status}
        return await self._post_to_node(
            node=node,
            path=f"/api/v1/sessions/{child_session}/finish",
            json_payload=payload,
            timeout=20,
        )

    async def dispatch_error(self, routed_session_id: str, error_reason: str) -> Dict[str, Any]:
        node, child_session = await self._resolve_routed_session(routed_session_id)
        payload = {"error_reason": error_reason}
        return await self._post_to_node(
            node=node,
            path=f"/api/v1/sessions/{child_session}/error",
            json_payload=payload,
            timeout=20,
        )

    async def dispatch_custom_score(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        nodes = await self._select_candidate_nodes()
        if not nodes:
            raise RuntimeError("暂无可用子节点")

        last_error = ""
        for node in nodes[:2]:
            try:
                return await self._post_to_node(
                    node=node,
                    path="/api/v1/custom-score",
                    json_payload=request_payload,
                    timeout=config.cluster_master_dispatch_timeout_seconds,
                )
            except Exception as e:
                last_error = str(e)
                await self.db.mark_cluster_node_error(int(node["id"]), last_error)
                debug_logger.log_warning(f"[ClusterManager] dispatch custom-score node={node['node_name']} failed: {last_error}")

        raise RuntimeError(f"子节点分数校验失败: {last_error or 'unknown'}")

    async def register_node(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        node = await self.db.upsert_cluster_node(
            node_name=payload["node_name"],
            base_url=payload["base_url"],
            node_api_key=payload["node_api_key"],
            weight=int(payload.get("weight") or 100),
            max_concurrency=int(payload.get("max_concurrency") or 1),
            active_sessions=int(payload.get("active_sessions") or 0),
            cached_sessions=int(payload.get("cached_sessions") or 0),
            healthy=bool(payload.get("healthy", True)),
        )
        return {
            "success": True,
            "node": node,
            "cluster_role": config.cluster_role,
        }

    async def heartbeat_node(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        node = await self.db.heartbeat_cluster_node(
            node_name=payload["node_name"],
            base_url=payload["base_url"],
            active_sessions=int(payload.get("active_sessions") or 0),
            cached_sessions=int(payload.get("cached_sessions") or 0),
            healthy=bool(payload.get("healthy", True)),
        )
        if not node:
            return {
                "success": False,
                "message": "node_not_registered",
            }
        return {
            "success": True,
            "node": node,
        }

    async def _resolve_routed_session(self, routed_session_id: str) -> Tuple[Dict[str, Any], str]:
        raw = (routed_session_id or "").strip()
        if ":" not in raw:
            raise RuntimeError("master 模式 session_id 必须为 nodeId:childSessionId")
        node_part, child_session = raw.split(":", 1)
        if not node_part.isdigit() or not child_session:
            raise RuntimeError("session_id 路由格式无效")

        node_id = int(node_part)
        node = await self.db.get_cluster_node(node_id)
        if not node:
            raise RuntimeError("路由节点不存在")
        if not bool(node.get("enabled", 0)):
            raise RuntimeError("路由节点已禁用")

        return node, child_session

    async def _select_candidate_nodes(self) -> List[Dict[str, Any]]:
        nodes = await self.db.get_available_cluster_nodes(config.cluster_master_node_stale_seconds)
        if not nodes:
            return []

        def _score(node: Dict[str, Any]) -> tuple[float, int]:
            active = max(0, int(node.get("active_sessions") or 0))
            max_concurrency = max(1, int(node.get("max_concurrency") or 1))
            weight = max(1, int(node.get("weight") or 100))
            load = active / max_concurrency
            weighted = load / (weight / 100.0)
            return weighted, int(node.get("id") or 0)

        return sorted(nodes, key=_score)

    async def _post_to_node(
        self,
        node: Dict[str, Any],
        path: str,
        json_payload: Dict[str, Any],
        timeout: int,
    ) -> Dict[str, Any]:
        base_url = str(node.get("base_url") or "").rstrip("/")
        api_key = str(node.get("node_api_key") or "").strip()
        if not base_url or not api_key:
            raise RuntimeError("节点配置缺少 base_url 或 node_api_key")

        url = f"{base_url}{path}"
        headers = {"Authorization": f"Bearer {api_key}"}
        async with AsyncSession() as session:
            response = await session.post(url, headers=headers, json=json_payload, timeout=timeout)
            try:
                payload = response.json()
            except Exception:
                payload = {"detail": response.text[:300]}

            if response.status_code >= 400:
                detail = payload.get("detail") if isinstance(payload, dict) else None
                raise RuntimeError(f"HTTP {response.status_code}: {detail or payload}")

            if isinstance(payload, dict):
                return payload
            raise RuntimeError("子节点响应不是 JSON 对象")

    async def _heartbeat_loop(self):
        debug_logger.log_info("[ClusterManager] subnode heartbeat loop started")
        while True:
            try:
                await self._send_subnode_heartbeat()
            except asyncio.CancelledError:
                return
            except Exception as e:
                debug_logger.log_warning(f"[ClusterManager] heartbeat error: {e}")

            await asyncio.sleep(config.cluster_heartbeat_interval_seconds)

    async def _send_subnode_heartbeat(self):
        master_base = config.cluster_master_base_url
        cluster_key = config.cluster_master_cluster_key
        node_api_key = config.node_api_key

        if not master_base or not cluster_key or not node_api_key:
            debug_logger.log_warning(
                "[ClusterManager] subnode mode 缺少 master_base_url/master_cluster_key/node_api_key，跳过心跳"
            )
            return

        public_base_url = config.cluster_node_public_base_url
        if not public_base_url:
            public_base_url = f"http://{config.server_host}:{config.server_port}"

        runtime_stats = await self.runtime.get_stats()
        active_sessions = int(runtime_stats.get("active_sessions") or 0)
        cached_sessions = int(runtime_stats.get("cached_sessions") or 0)

        register_payload = {
            "node_name": config.node_name,
            "base_url": public_base_url,
            "node_api_key": node_api_key,
            "weight": config.cluster_node_weight,
            "max_concurrency": config.cluster_node_max_concurrency,
            "active_sessions": active_sessions,
            "cached_sessions": cached_sessions,
            "healthy": True,
        }
        heartbeat_payload = {
            "node_name": config.node_name,
            "base_url": public_base_url,
            "active_sessions": active_sessions,
            "cached_sessions": cached_sessions,
            "healthy": True,
        }

        headers = {"X-Cluster-Key": cluster_key}

        async with AsyncSession() as session:
            register_url = f"{master_base}/api/cluster/register"
            hb_url = f"{master_base}/api/cluster/heartbeat"

            register_resp = await session.post(register_url, headers=headers, json=register_payload, timeout=20)
            if register_resp.status_code >= 400:
                detail = register_resp.text[:200]
                raise RuntimeError(f"register failed: {register_resp.status_code}, {detail}")

            hb_resp = await session.post(hb_url, headers=headers, json=heartbeat_payload, timeout=20)
            if hb_resp.status_code >= 400:
                detail = hb_resp.text[:200]
                raise RuntimeError(f"heartbeat failed: {hb_resp.status_code}, {detail}")

    async def get_cluster_runtime_summary(self) -> Dict[str, Any]:
        nodes = await self.db.list_cluster_nodes()
        return {
            "role": config.cluster_role,
            "node_name": config.node_name,
            "node_count": len(nodes),
            "nodes": nodes,
        }
