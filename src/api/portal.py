from __future__ import annotations

import time
import urllib.parse
from typing import Any, Dict, Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, Response

from ..core.auth import (
    issue_portal_user_token,
    revoke_portal_user_token,
    verify_portal_user_token,
    verify_service_api_key,
)
from ..core.config import config
from ..core.database import Database
from ..core.models import (
    CustomScoreRequest,
    ErrorRequest,
    FinishRequest,
    LoginRequest,
    PortalRedeemRequest,
    PortalRegisterRequest,
    PortalUserApiKeyCreateRequest,
    PortalUserApiKeyUpdateRequest,
    SolveRequest,
    SolveResponse,
)
from ..services.captcha_runtime import CaptchaRuntime
from ..services.cluster_manager import ClusterManager

router = APIRouter(prefix="/api/portal", tags=["portal"])

_db: Optional[Database] = None
_runtime: Optional[CaptchaRuntime] = None
_cluster: Optional[ClusterManager] = None


def set_dependencies(db: Database, runtime: CaptchaRuntime, cluster_manager: ClusterManager):
    global _db, _runtime, _cluster
    _db = db
    _runtime = runtime
    _cluster = cluster_manager


def _assert_portal_public_role(feature_name: str):
    if config.cluster_role == "subnode":
        raise HTTPException(status_code=400, detail=f"当前 subnode 角色不开放：{feature_name}")


def _build_runtime_summary(runtime_stats: Dict[str, Any]) -> Dict[str, Any]:
    browser_stats = runtime_stats.get("browser") if isinstance(runtime_stats.get("browser"), dict) else {}
    return {
        "node_name": runtime_stats.get("node_name", config.node_name),
        "role": runtime_stats.get("role", config.cluster_role),
        "active_sessions": int(runtime_stats.get("active_sessions") or 0),
        "pending_sessions": int(runtime_stats.get("pending_sessions") or 0),
        "cached_sessions": int(runtime_stats.get("cached_sessions") or 0),
        "local_solve_enabled": bool(runtime_stats.get("local_solve_enabled", config.cluster_role != "master")),
        "browser": {
            "configured_browser_count": int(browser_stats.get("configured_browser_count") or 0),
            "busy_browser_count": int(browser_stats.get("busy_browser_count") or 0),
            "idle_browser_count": int(browser_stats.get("idle_browser_count") or 0),
            "total_solve_count": int(browser_stats.get("total_solve_count") or 0),
            "total_error_count": int(browser_stats.get("total_error_count") or 0),
            "risk_403_count": int(browser_stats.get("risk_403_count") or 0),
            "thread_total": int(browser_stats.get("thread_total") or 0),
            "thread_active": int(browser_stats.get("thread_active") or 0),
            "thread_idle": int(browser_stats.get("thread_idle") or 0),
        },
    }


def _build_cluster_summary(cluster_stats: Dict[str, Any]) -> Dict[str, Any]:
    if config.cluster_role != "master":
        return {
            "enabled": False,
            "role": config.cluster_role,
            "node_count": 0,
            "healthy_node_count": 0,
            "total_thread_capacity": 0,
            "total_active_capacity": 0,
            "total_idle_capacity": 0,
            "nodes": [],
            "message": "当前角色不是 master，用户端不展示子节点调度看板。",
        }

    nodes: list[Dict[str, Any]] = []
    for node in cluster_stats.get("nodes", []) or []:
        nodes.append(
            {
                "id": int(node.get("id") or 0),
                "node_name": node.get("node_name") or "unknown",
                "enabled": bool(node.get("enabled", True)),
                "healthy": bool(node.get("is_healthy", node.get("healthy", False))),
                "health_reason": node.get("health_reason") or "未知",
                "thread_total": int(node.get("thread_total") or 0),
                "thread_active": int(node.get("thread_active") or 0),
                "thread_idle": int(node.get("thread_idle") or 0),
                "active_sessions": int(node.get("active_sessions") or 0),
                "cached_sessions": int(node.get("cached_sessions") or 0),
                "heartbeat_age_seconds": node.get("heartbeat_age_seconds"),
                "weight": int(node.get("weight") or 0),
                "effective_capacity": int(node.get("effective_capacity") or 0),
            }
        )

    return {
        "enabled": True,
        "role": config.cluster_role,
        "node_count": int(cluster_stats.get("node_count") or len(nodes)),
        "healthy_node_count": int(cluster_stats.get("healthy_node_count") or 0),
        "total_thread_capacity": int(cluster_stats.get("total_thread_capacity") or 0),
        "total_active_capacity": int(cluster_stats.get("total_active_capacity") or 0),
        "total_idle_capacity": int(cluster_stats.get("total_idle_capacity") or 0),
        "nodes": nodes,
        "message": "仅展示用户侧只读摘要，不包含管理员敏感配置。",
    }


def _build_quickstart(base_url: str) -> Dict[str, Any]:
    return {
        "base_url": base_url,
        "auth_scheme": "Portal User Token / Service API Key",
        "console_actions": ["solve", "finish", "error", "custom-score"],
        "endpoints": [
            {"name": "用户注册", "method": "POST", "path": "/api/portal/auth/register", "description": "用户自注册，校验注册位置与重复用户名。"},
            {"name": "用户登录", "method": "POST", "path": "/api/portal/auth/login", "description": "登录后拿到 portal token，用户端打码不必暴露管理员数据。"},
            {"name": "兑换 CDK", "method": "POST", "path": "/api/portal/cdks/redeem", "description": "成功兑换后增加可用打码次数。"},
            {"name": "用户打码", "method": "POST", "path": "/api/portal/user/solve", "description": "打码成功才扣 1 次；失败不扣。"},
            {"name": "高级 API 调试", "method": "POST", "path": "/api/v1/solve", "description": "高级接入仍支持 API Key 直连模式。"},
        ],
    }


def _resolve_register_location(request: Request, register_location: str) -> str:
    normalized_location = str(register_location or "").strip().lower()
    allowed_locations = {"master-portal", "partner-channel", "private-cluster", "/", "/portal"}
    if normalized_location not in allowed_locations:
        raise HTTPException(status_code=400, detail="注册位置无效")

    referer = str(request.headers.get("referer") or "").strip()
    if referer:
        parsed = urllib.parse.urlparse(referer)
        referer_path = (parsed.path or "").strip() or "/portal"
        if referer_path not in {"/", "/portal"}:
            raise HTTPException(status_code=400, detail="注册位置校验失败")

    return normalized_location


async def _build_portal_user_workspace_payload(user_id: int) -> Dict[str, Any]:
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    summary = await _db.get_portal_user_usage_summary(user_id)
    if not summary:
        raise HTTPException(status_code=404, detail="用户不存在")

    recent_sessions = await _db.list_portal_user_api_call_logs(portal_user_id=user_id, limit=20, offset=0)
    recent_redeems = await _db.list_portal_user_cdk_redeems(user_id=user_id, limit=12)
    recent_transactions = await _db.list_portal_user_transactions(portal_user_id=user_id, limit=20)
    api_keys = await _db.list_portal_user_api_keys(portal_user_id=user_id)
    return {
        "success": True,
        "user": summary["user"],
        "usage": summary["usage"],
        "recent_sessions": recent_sessions,
        "recent_redeems": recent_redeems,
        "recent_transactions": recent_transactions,
        "api_keys": api_keys,
    }


async def _cleanup_portal_success_result(result: Optional[Dict[str, Any]]):
    if not result:
        return
    session_id = str(result.get("session_id") or "").strip()
    if not session_id:
        return

    if config.cluster_role == "master" and _cluster is not None:
        try:
            await _cluster.dispatch_error(session_id, "quota_conflict")
        except Exception:
            pass
    elif _runtime is not None:
        try:
            await _runtime.mark_error(session_id, "quota_conflict")
        except Exception:
            pass


@router.get("/overview")
async def get_portal_overview(request: Request):
    if _db is None or _runtime is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    db_stats = await _db.get_service_stats()
    runtime_stats = await _runtime.get_stats()
    cluster_stats = await _cluster.get_cluster_runtime_summary() if (_cluster and config.cluster_role == "master") else {}

    solve_total = int(db_stats.get("jobs_solve_total") or 0)
    solve_success = int(db_stats.get("jobs_success") or 0)
    base_url = str(request.base_url).rstrip("/")

    return {
        "success": True,
        "meta": {
            "service": "flow_captcha_service",
            "node_name": config.node_name,
            "role": config.cluster_role,
            "portal_path": "/portal",
            "admin_path": "/admin",
        },
        "service": {
            "name": "flow_captcha_service",
            "node_name": config.node_name,
            "role": config.cluster_role,
            "local_solve_enabled": config.cluster_role != "master",
        },
        "health": {
            "status": "ok",
            "local_solve_enabled": config.cluster_role != "master",
        },
        "capabilities": {
            "user_portal": True,
            "self_register": config.cluster_role != "subnode",
            "user_login": config.cluster_role != "subnode",
            "cdk_redeem": config.cluster_role != "subnode",
            "api_console": True,
            "session_center": True,
            "public_cluster_board": config.cluster_role == "master",
            "actions": ["solve", "finish", "error", "custom-score"],
        },
        "stats": {
            **db_stats,
            "jobs_success_rate": round((solve_success / solve_total) * 100, 2) if solve_total > 0 else 0.0,
        },
        "runtime": _build_runtime_summary(runtime_stats),
        "cluster": {
            **_build_cluster_summary(cluster_stats),
            "dispatch_available": int(cluster_stats.get("total_idle_capacity") or 0) > 0,
        },
        "quickstart": _build_quickstart(base_url),
    }


@router.get("/summary")
async def get_portal_summary(request: Request):
    return await get_portal_overview(request)


@router.post("/auth/register")
async def portal_user_register(request: PortalRegisterRequest, raw_request: Request, response: Response):
    _assert_portal_public_role("用户自注册")
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    confirm_password = getattr(request, "confirm_password", None)
    if confirm_password and request.password != confirm_password:
        raise HTTPException(status_code=400, detail="两次密码输入不一致")
    register_location = _resolve_register_location(raw_request, request.register_location)
    ok, message, user = await _db.create_portal_user(
        username=request.username,
        password=request.password,
        register_location=register_location,
        display_name=request.display_name or request.username,
    )
    if not ok or not user:
        raise HTTPException(status_code=409, detail=message)

    await _db.mark_portal_user_login(int(user["id"]))
    token = issue_portal_user_token(int(user["id"]))
    response.set_cookie("portal_session", token, path="/", samesite="lax", httponly=True)
    payload = await _build_portal_user_workspace_payload(int(user["id"]))
    return {
        "success": True,
        "message": message,
        "authenticated": True,
        "token": token,
        "token": token,
        **payload,
    }


@router.post("/auth/login")
async def portal_user_login(request: LoginRequest, response: Response):
    _assert_portal_public_role("用户登录")
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    user = await _db.verify_portal_user_credentials(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")

    await _db.mark_portal_user_login(int(user["id"]))
    token = issue_portal_user_token(int(user["id"]))
    response.set_cookie("portal_session", token, path="/", samesite="lax", httponly=True)
    payload = await _build_portal_user_workspace_payload(int(user["id"]))
    return {
        "success": True,
        "message": "登录成功",
        "authenticated": True,
        "token": token,
    }


@router.post("/auth/logout")
async def portal_user_logout(response: Response, user: dict = Depends(verify_portal_user_token)):
    revoke_portal_user_token(str(user.get("token") or ""))
    response.delete_cookie("portal_session", path="/")
    return {"success": True}


@router.get("/auth/me")
async def portal_user_me(
    authorization: Optional[str] = Header(default=None),
    portal_session: Optional[str] = Cookie(default=None),
):
    try:
        user = await verify_portal_user_token(authorization=authorization, portal_session=portal_session)
    except HTTPException:
        return {"success": True, "authenticated": False, "user": None}
    payload = await _build_portal_user_workspace_payload(int(user["id"]))
    payload["authenticated"] = True
    return payload


@router.get("/auth/check")
async def portal_check_username(username: str = Query(min_length=1, max_length=60)):
    _assert_portal_public_role("注册检查")
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    user = await _db.get_portal_user_by_username(username)
    if not user:
        return {"success": True, "registered": False, "message": "该用户名尚未注册"}

    return {
        "success": True,
        "registered": True,
        "message": "该用户名已注册，请直接登录",
        "user": {
            "username": user.get("username"),
            "register_location": user.get("register_location"),
            "enabled": bool(user.get("enabled", True)),
            "created_at": user.get("created_at"),
        },
    }


@router.get("/user/api-keys")
async def list_portal_user_api_keys(user: dict = Depends(verify_portal_user_token)):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")
    items = await _db.list_portal_user_api_keys(int(user["id"]))
    return {"success": True, "items": items}


@router.post("/user/api-keys")
async def create_portal_user_api_key(
    request: PortalUserApiKeyCreateRequest,
    user: dict = Depends(verify_portal_user_token),
):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")
    raw_key, item = await _db.create_portal_user_api_key(int(user["id"]), request.name)
    return {"success": True, "api_key": raw_key, "item": item, "message": "仅本次返回完整 API Key，请立即保存"}


@router.patch("/user/api-keys/{api_key_id}")
async def update_portal_user_api_key(
    api_key_id: int,
    request: PortalUserApiKeyUpdateRequest,
    user: dict = Depends(verify_portal_user_token),
):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")
    item = await _db.update_portal_user_api_key(
        api_key_id=api_key_id,
        portal_user_id=int(user["id"]),
        name=request.name,
        enabled=request.enabled,
    )
    if not item:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    return {"success": True, "item": item}


@router.delete("/user/api-keys/{api_key_id}")
async def soft_delete_portal_user_api_key(api_key_id: int, user: dict = Depends(verify_portal_user_token)):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")
    item = await _db.update_portal_user_api_key(
        api_key_id=api_key_id,
        portal_user_id=int(user["id"]),
        enabled=False,
    )
    if not item:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    return {"success": True, "item": item, "message": f"API Key #{api_key_id} 已软删除（已禁用）"}


@router.get("/user/transactions")
async def list_portal_user_transactions(user: dict = Depends(verify_portal_user_token)):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")
    items = await _db.list_portal_user_transactions(int(user["id"]), limit=50)
    return {"success": True, "items": items}


@router.post("/redeem")
@router.post("/cdks/redeem")
async def portal_redeem_cdk(request: PortalRedeemRequest, user: dict = Depends(verify_portal_user_token)):
    _assert_portal_public_role("CDK 兑换")
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    ok, message, payload = await _db.redeem_portal_cdk(int(user["id"]), request.code)
    if not ok:
        raise HTTPException(status_code=400, detail=message)

    workspace = await _build_portal_user_workspace_payload(int(user["id"]))
    return {
        "success": True,
        "message": message,
        "redeem": payload,
        "redeemed_code": (payload or {}).get("cdk"),
        **workspace,
    }


@router.get("/user/overview")
@router.get("/user/workspace")
async def get_portal_user_workspace(user: dict = Depends(verify_portal_user_token)):
    return await _build_portal_user_workspace_payload(int(user["id"]))


@router.get("/user/logs")
@router.get("/user/sessions")
async def list_portal_user_sessions(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None, max_length=80),
    project_id: Optional[str] = Query(default=None, max_length=120),
    user: dict = Depends(verify_portal_user_token),
):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    items = await _db.list_portal_user_jobs(
        portal_user_id=int(user["id"]),
        limit=limit,
        offset=offset,
        status=status,
        project_id=project_id,
    )
    return {
        "success": True,
        "items": items,
        "limit": limit,
        "offset": offset,
        "filters": {"status": status, "project_id": project_id},
    }


@router.post("/user/solve", response_model=SolveResponse)
async def portal_user_solve(request: SolveRequest, user: dict = Depends(verify_portal_user_token)):
    _assert_portal_public_role("用户打码")
    if _db is None or _runtime is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    user_id = int(user["id"])
    available, message = await _db.ensure_portal_user_available(user_id)
    if not available:
        raise HTTPException(status_code=403, detail=message)

    started = time.perf_counter()
    result: Optional[Dict[str, Any]] = None
    try:
        if config.cluster_role == "master":
            if _cluster is None:
                raise RuntimeError("cluster manager 未初始化")
            result = await _cluster.dispatch_solve(request.model_dump())
            log_status = "success_master_dispatch"
        else:
            result = await _runtime.solve(
                project_id=request.project_id,
                action=request.action,
                token_id=request.token_id,
                api_key_id=0,
            )
            log_status = "success"

        consumed, consume_message = await _db.consume_portal_user_quota(user_id)
        if not consumed:
            await _cleanup_portal_success_result(result)
            raise HTTPException(status_code=403, detail=consume_message)

        elapsed = int((time.perf_counter() - started) * 1000)
        await _db.create_portal_user_job_log(
            portal_user_id=user_id,
            session_id=result.get("session_id") if result else None,
            project_id=request.project_id,
            action=request.action,
            status=log_status,
            error_reason=None,
            duration_ms=elapsed,
        )
        return SolveResponse(**(result or {}))
    except HTTPException:
        raise
    except Exception as e:
        elapsed = int((time.perf_counter() - started) * 1000)
        await _db.create_portal_user_job_log(
            portal_user_id=user_id,
            session_id=result.get("session_id") if result else None,
            project_id=request.project_id,
            action=request.action,
            status="failed",
            error_reason=str(e),
            duration_ms=elapsed,
        )
        raise HTTPException(status_code=500, detail=f"打码失败: {e}")


@router.post("/user/sessions/{session_id}/finish")
async def portal_user_finish_session(
    session_id: str,
    request: FinishRequest,
    user: dict = Depends(verify_portal_user_token),
):
    if _db is None or _runtime is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    entry = None
    if config.cluster_role == "master" and ":" in session_id:
        if _cluster is None:
            raise HTTPException(status_code=500, detail="cluster manager 未初始化")
        try:
            await _cluster.dispatch_finish(session_id, request.status)
            message = "ok"
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"finish 转发失败: {e}")
    else:
        ok, message, entry = await _runtime.finish(session_id)
        if not ok:
            raise HTTPException(status_code=404, detail=message)

    await _db.create_portal_user_job_log(
        portal_user_id=int(user["id"]),
        session_id=session_id,
        project_id=entry.project_id if entry else None,
        action=entry.action if entry else None,
        status=f"finish:{request.status}",
        error_reason=None,
        duration_ms=None,
    )
    return {"success": True, "message": message}


@router.post("/user/sessions/{session_id}/error")
async def portal_user_report_error(
    session_id: str,
    request: ErrorRequest,
    user: dict = Depends(verify_portal_user_token),
):
    if _db is None or _runtime is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    entry = None
    if config.cluster_role == "master" and ":" in session_id:
        if _cluster is None:
            raise HTTPException(status_code=500, detail="cluster manager 未初始化")
        try:
            await _cluster.dispatch_error(session_id, request.error_reason)
            message = "ok"
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"error 转发失败: {e}")
    else:
        ok, message, entry = await _runtime.mark_error(session_id, request.error_reason)
        if not ok:
            raise HTTPException(status_code=404, detail=message)

    await _db.create_portal_user_job_log(
        portal_user_id=int(user["id"]),
        session_id=session_id,
        project_id=entry.project_id if entry else None,
        action=entry.action if entry else None,
        status="error_reported",
        error_reason=request.error_reason,
        duration_ms=None,
    )
    return {"success": True, "message": message}


@router.post("/user/custom-score")
async def portal_user_custom_score(
    request: CustomScoreRequest,
    user: dict = Depends(verify_portal_user_token),
):
    _assert_portal_public_role("自定义 score 调试")
    if _db is None or _runtime is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    user_id = int(user["id"])
    available, message = await _db.ensure_portal_user_available(user_id)
    if not available:
        raise HTTPException(status_code=403, detail=message)

    started = time.perf_counter()
    try:
        if config.cluster_role == "master":
            if _cluster is None:
                raise RuntimeError("cluster manager 未初始化")
            payload = await _cluster.dispatch_custom_score(request.model_dump())
            log_status = "success_master_dispatch"
        else:
            payload = await _runtime.custom_score(
                website_url=request.website_url,
                website_key=request.website_key,
                verify_url=request.verify_url,
                action=request.action,
                enterprise=request.enterprise,
            )
            log_status = "success"

        consumed, consume_message = await _db.consume_portal_user_quota(user_id)
        if not consumed:
            raise HTTPException(status_code=403, detail=consume_message)

        elapsed = int((time.perf_counter() - started) * 1000)
        await _db.create_portal_user_job_log(
            portal_user_id=user_id,
            session_id=None,
            project_id=request.website_url,
            action=f"CUSTOM_SCORE:{request.action}",
            status=log_status,
            error_reason=None,
            duration_ms=elapsed,
        )

        verify_result = payload.get("verify_result") or payload
        token_value = payload.get("token")
        if not token_value and isinstance(verify_result, dict):
            token_value = verify_result.get("token") or verify_result.get("gRecaptchaResponse")

        return {
            "success": bool(payload.get("success", True)),
            "captcha_method": "remote_browser",
            "node_name": payload.get("node_name", config.node_name),
            "token": token_value,
            "token_elapsed_ms": payload.get("token_elapsed_ms"),
            "verify_elapsed_ms": payload.get("verify_elapsed_ms"),
            "verify_http_status": payload.get("verify_http_status"),
            "verify_mode": payload.get("verify_mode"),
            "fingerprint": payload.get("fingerprint"),
            "verify_result": verify_result,
            "message": payload.get("message", "ok"),
            "raw": payload,
        }
    except HTTPException:
        raise
    except Exception as e:
        elapsed = int((time.perf_counter() - started) * 1000)
        await _db.create_portal_user_job_log(
            portal_user_id=user_id,
            session_id=None,
            project_id=request.website_url,
            action=f"CUSTOM_SCORE:{request.action}",
            status="failed",
            error_reason=str(e),
            duration_ms=elapsed,
        )
        raise HTTPException(status_code=500, detail=f"custom-score 失败: {e}")


@router.get("/workspace")
async def get_portal_workspace(api_key: dict = Depends(verify_service_api_key)):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    api_key_id = int(api_key.get("id") or 0)
    if api_key_id <= 0:
        return {
            "success": True,
            "api_key": api_key,
            "usage": {
                "request_total": 0,
                "solve_success_total": 0,
                "solve_failed_total": 0,
                "solve_total": 0,
                "finish_total": 0,
                "error_total": 0,
                "recent_24h_total": 0,
                "recent_7d_total": 0,
                "avg_duration_ms": None,
                "last_request_at": None,
                "latest_session_id": None,
                "success_rate": 0.0,
                "top_projects": [],
                "top_actions": [],
            },
            "recent_sessions": [],
        }

    summary = await _db.get_api_key_usage_summary(api_key_id)
    recent_sessions = await _db.list_job_logs_by_api_key(api_key_id=api_key_id, limit=8, offset=0)
    if not summary:
        raise HTTPException(status_code=404, detail="API Key 不存在")

    return {
        "success": True,
        "api_key": summary["api_key"],
        "usage": summary["usage"],
        "recent_sessions": recent_sessions,
    }


@router.get("/me/overview")
async def get_portal_me_overview(api_key: dict = Depends(verify_service_api_key)):
    return await get_portal_workspace(api_key)


@router.get("/sessions")
async def list_portal_sessions(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None, max_length=80),
    project_id: Optional[str] = Query(default=None, max_length=120),
    api_key: dict = Depends(verify_service_api_key),
):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    api_key_id = int(api_key.get("id") or 0)
    if api_key_id <= 0:
        return {
            "success": True,
            "items": [],
            "limit": limit,
            "offset": offset,
            "filters": {"status": status, "project_id": project_id},
        }

    items = await _db.list_job_logs_by_api_key(
        api_key_id=api_key_id,
        limit=limit,
        offset=offset,
        status=status,
        project_id=project_id,
    )
    return {
        "success": True,
        "items": items,
        "limit": limit,
        "offset": offset,
        "filters": {"status": status, "project_id": project_id},
    }


@router.get("/me/logs")
async def get_portal_me_logs(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None, max_length=80),
    project_id: Optional[str] = Query(default=None, max_length=120),
    api_key: dict = Depends(verify_service_api_key),
):
    return await list_portal_sessions(
        limit=limit,
        offset=offset,
        status=status,
        project_id=project_id,
        api_key=api_key,
    )
