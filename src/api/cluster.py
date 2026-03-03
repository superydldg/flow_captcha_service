from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from ..core.auth import verify_cluster_key
from ..core.config import config
from ..core.database import Database
from ..core.models import ClusterHeartbeatRequest, ClusterRegisterRequest
from ..services.cluster_manager import ClusterManager

router = APIRouter(prefix="/api/cluster", tags=["cluster-internal"])

_db: Optional[Database] = None
_cluster: Optional[ClusterManager] = None


def set_dependencies(db: Database, cluster_manager: ClusterManager):
    global _db, _cluster
    _db = db
    _cluster = cluster_manager


@router.post("/register")
async def register_node(
    request: ClusterRegisterRequest,
    cluster_key: str = Depends(verify_cluster_key),
):
    if config.cluster_role != "master":
        raise HTTPException(status_code=400, detail="当前节点不是 master")
    if _cluster is None:
        raise HTTPException(status_code=500, detail="cluster manager 未初始化")

    result = await _cluster.register_node(request.model_dump())
    return result


@router.post("/heartbeat")
async def heartbeat_node(
    request: ClusterHeartbeatRequest,
    cluster_key: str = Depends(verify_cluster_key),
):
    if config.cluster_role != "master":
        raise HTTPException(status_code=400, detail="当前节点不是 master")
    if _cluster is None:
        raise HTTPException(status_code=500, detail="cluster manager 未初始化")

    result = await _cluster.heartbeat_node(request.model_dump())
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("message") or "node_not_registered")
    return result
