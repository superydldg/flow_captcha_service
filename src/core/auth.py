from __future__ import annotations

import secrets
from typing import Optional

from fastapi import Header, HTTPException

from .config import config
from .database import Database


_db: Optional[Database] = None
_active_admin_tokens: set[str] = set()


def set_database(db: Database):
    global _db
    _db = db


def _extract_bearer(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="缺少 Authorization 头")
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        raise HTTPException(status_code=401, detail="Authorization 必须使用 Bearer Token")
    token = authorization[len(prefix):].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Token 不能为空")
    return token


async def verify_service_api_key(authorization: Optional[str] = Header(default=None)) -> dict:
    if _db is None:
        raise HTTPException(status_code=500, detail="数据库未初始化")

    raw_key = _extract_bearer(authorization)
    if config.cluster_role == "subnode" and config.node_api_key and secrets.compare_digest(raw_key, config.node_api_key):
        return {
            "id": -1,
            "name": "cluster_subnode_internal",
            "enabled": True,
            "quota_remaining": None,
            "quota_used": 0,
            "is_internal": True,
        }

    api_key = await _db.resolve_service_api_key(raw_key)
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key 无效")

    if not bool(api_key["enabled"]):
        raise HTTPException(status_code=403, detail="API Key 已禁用")

    return api_key


def issue_admin_token() -> str:
    token = f"admin_{secrets.token_urlsafe(24)}"
    _active_admin_tokens.add(token)
    return token


def revoke_admin_token(token: str):
    _active_admin_tokens.discard(token)


async def verify_admin_token(authorization: Optional[str] = Header(default=None)) -> str:
    token = _extract_bearer(authorization)
    if token not in _active_admin_tokens:
        raise HTTPException(status_code=401, detail="管理员会话无效或已过期")
    return token


async def verify_cluster_key(x_cluster_key: Optional[str] = Header(default=None)) -> str:
    if _db is None:
        raise HTTPException(status_code=500, detail="数据库未初始化")
    if not x_cluster_key:
        raise HTTPException(status_code=401, detail="缺少 X-Cluster-Key")
    is_valid = await _db.validate_cluster_key(x_cluster_key.strip())
    if not is_valid:
        raise HTTPException(status_code=401, detail="Cluster Key 无效")
    return x_cluster_key
