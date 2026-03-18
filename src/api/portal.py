from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
import urllib.parse
import urllib.request
from hashlib import sha256
from typing import Any, Dict, Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse

from ..core.auth import (
    issue_portal_user_token,
    revoke_portal_user_token,
    verify_portal_user_token,
    verify_service_api_key,
)
from ..core.config import config
from ..core.database import Database
from ..core.diagnostics import diag_label
from ..core.logger import debug_logger
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
PORTAL_OIDC_STATE_COOKIE = "portal_oidc_state"


def set_dependencies(db: Database, runtime: CaptchaRuntime, cluster_manager: ClusterManager):
    global _db, _runtime, _cluster
    _db = db
    _runtime = runtime
    _cluster = cluster_manager


def _assert_portal_public_role(feature_name: str):
    if config.cluster_role == "subnode":
        raise HTTPException(status_code=400, detail=f"当前 subnode 角色不开放：{feature_name}")


def _assert_local_portal_auth_enabled(feature_name: str):
    if config.portal_oauth_only:
        raise HTTPException(status_code=400, detail=f"当前仅允许 OAuth/OIDC 登录，已关闭：{feature_name}")


def _get_oidc_settings() -> Dict[str, Any]:
    base_url = config.portal_oidc_base_url
    well_known_url = config.portal_oidc_well_known_url
    client_id = config.portal_oidc_client_id
    client_secret = config.portal_oidc_client_secret
    enabled = bool(
        config.portal_oidc_enabled
        and (base_url or well_known_url)
        and client_id
        and client_secret
        and config.cluster_role != "subnode"
    )
    return {
        "enabled": enabled,
        "base_url": base_url,
        "well_known_url": well_known_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": config.portal_oidc_scope,
        "authorization_url": f"{base_url}/oauth/authorize" if base_url else "",
        "token_url": f"{base_url}/oauth/token" if base_url else "",
        "userinfo_url": f"{base_url}/oauth/userinfo" if base_url else "",
    }


def _build_portal_redirect_uri(request: Request) -> str:
    public_base_url = config.portal_public_base_url
    if public_base_url:
        return f"{public_base_url}/api/portal/auth/oidc/callback"
    return f"{str(request.base_url).rstrip('/')}/api/portal/auth/oidc/callback"


def _mask_secret(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}{'*' * max(len(text) - 8, 4)}{text[-4:]}"


async def _oidc_http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
) -> tuple[int, Any]:
    req = urllib.request.Request(url=url, data=body, headers=headers or {}, method=method.upper())

    def _send() -> tuple[int, str, str]:
        with urllib.request.urlopen(req, timeout=20) as response:
            return (
                int(getattr(response, "status", 200)),
                str(response.headers.get("Content-Type") or ""),
                response.read().decode("utf-8", errors="replace"),
            )

    try:
        status, content_type, text = await asyncio.to_thread(_send)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OIDC 上游请求失败: {exc}")

    lowered_content_type = content_type.lower()
    if "application/json" in lowered_content_type:
        try:
            return status, json.loads(text or "{}")
        except Exception:
            raise HTTPException(status_code=502, detail="OIDC 上游返回了无效 JSON")
    if "application/x-www-form-urlencoded" in lowered_content_type:
        parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
        return status, {key: values[-1] if values else "" for key, values in parsed.items()}
    return status, text


async def _request_oidc_token(
    token_url: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> Dict[str, Any]:
    common_body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    masked_code = _mask_secret(code)
    masked_secret = _mask_secret(client_secret)
    auth_value = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
    attempts = [
        {
            "name": "client_secret_basic",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Authorization": f"Basic {auth_value}",
            },
            "body": urllib.parse.urlencode(common_body).encode("utf-8"),
        },
        {
            "name": "client_secret_post",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            "body": urllib.parse.urlencode(
                {
                    **common_body,
                    "client_id": client_id,
                    "client_secret": client_secret,
                }
            ).encode("utf-8"),
        },
    ]

    last_error_detail = "OIDC token 响应无效"
    for attempt in attempts:
        debug_logger.log_info(
            "[portal_oidc] token exchange attempt "
            f"mode={attempt['name']} token_url={token_url} client_id={client_id} "
            f"client_secret={masked_secret} redirect_uri={redirect_uri} code={masked_code}"
        )
        try:
            token_status, token_payload = await _oidc_http_request(
                token_url,
                method="POST",
                headers=attempt["headers"],
                body=attempt["body"],
            )
        except HTTPException as exc:
            last_error_detail = str(exc.detail)
            debug_logger.log_warning(
                f"[portal_oidc] token exchange failed via {attempt['name']}: {exc.detail}"
            )
            continue

        if 200 <= token_status < 300 and isinstance(token_payload, dict):
            access_token = str(token_payload.get("access_token") or "").strip()
            if access_token:
                return token_payload
            last_error_detail = "OIDC token 响应缺少 access_token"
        else:
            last_error_detail = (
                f"OIDC token 响应异常 status={token_status}"
                if not isinstance(token_payload, dict)
                else str(token_payload.get("error_description") or token_payload.get("error") or f"OIDC token 响应异常 status={token_status}")
            )
        debug_logger.log_warning(
            f"[portal_oidc] token exchange attempt rejected via {attempt['name']}: {last_error_detail}"
        )

    raise HTTPException(status_code=502, detail=last_error_detail)


async def _resolve_oidc_endpoints(settings: Dict[str, Any]) -> Dict[str, Any]:
    resolved = dict(settings)
    well_known_url = str(settings.get("well_known_url") or "").strip()
    if not well_known_url:
        return resolved

    _, payload = await _oidc_http_request(
        well_known_url,
        method="GET",
        headers={"Accept": "application/json"},
    )
    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="OIDC well-known 响应无效")

    authorization_url = str(payload.get("authorization_endpoint") or "").strip()
    token_url = str(payload.get("token_endpoint") or "").strip()
    userinfo_url = str(payload.get("userinfo_endpoint") or "").strip()
    issuer = str(payload.get("issuer") or "").strip().rstrip("/")

    missing_fields = []
    if not authorization_url:
        missing_fields.append("authorization_endpoint")
    if not token_url:
        missing_fields.append("token_endpoint")
    if not userinfo_url:
        missing_fields.append("userinfo_endpoint")
    if missing_fields:
        raise HTTPException(
            status_code=502,
            detail=f"OIDC well-known 缺少字段: {', '.join(missing_fields)}",
        )

    if issuer:
        resolved["base_url"] = issuer
    resolved["authorization_url"] = authorization_url
    resolved["token_url"] = token_url
    resolved["userinfo_url"] = userinfo_url
    return resolved


def _build_oidc_portal_username(base_url: str, subject: str) -> str:
    return f"oidc_{sha256(base_url.encode('utf-8')).hexdigest()[:8]}_{sha256(subject.encode('utf-8')).hexdigest()[:16]}"


async def _login_portal_user(response: Response, user_id: int) -> str:
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")
    await _db.mark_portal_user_login(user_id)
    token = issue_portal_user_token(user_id)
    response.set_cookie("portal_session", token, path="/", samesite="lax", httponly=True)
    return token


async def _resolve_or_create_oidc_user(claims: Dict[str, Any], provider_base_url: str) -> Dict[str, Any]:
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    subject = str(claims.get("sub") or "").strip()
    if not subject:
        raise HTTPException(status_code=502, detail="OIDC userinfo 缺少 sub")

    username = _build_oidc_portal_username(provider_base_url, subject)
    existing = await _db.get_portal_user_by_username(username)
    if existing:
        return await _db.get_portal_user(int(existing["id"])) or existing

    display_name = (
        str(claims.get("preferred_username") or "").strip()
        or str(claims.get("name") or "").strip()
        or str(claims.get("email") or "").strip()
        or username
    )
    ok, message, user = await _db.create_portal_user(
        username=username,
        password=secrets.token_urlsafe(32),
        register_location="oidc",
        display_name=display_name,
        initial_quota=config.portal_register_bonus_quota,
    )
    if not ok or not user:
        raise HTTPException(status_code=409, detail=message or "OIDC 用户创建失败")
    return user


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
    if config.cluster_role == "subnode":
        return {
            "base_url": base_url,
            "entry_mode": "subnode-status",
            "auth_scheme": "Service API Key / Master Dispatch",
            "console_actions": ["solve", "finish", "error", "custom-score"],
            "endpoints": [
                {"name": "子节点状态页", "method": "GET", "path": "/", "description": "子节点首页仅展示节点状态、健康检查和后台入口，不提供用户注册/登录。"},
                {"name": "健康检查", "method": "GET", "path": "/api/v1/health", "description": "用于容器健康探测、节点联通性确认和部署排查。"},
                {"name": "服务打码", "method": "POST", "path": "/api/v1/solve", "description": "可用于内部联调，生产集群通常由 master 调度转发到 subnode。"},
                {"name": "管理后台", "method": "GET", "path": "/admin", "description": "管理员查看运行配置、日志和本节点执行状态。"},
            ],
        }

    return {
        "base_url": base_url,
        "entry_mode": "user-portal",
        "auth_scheme": "Portal User Token / Service API Key",
        "console_actions": ["solve", "finish", "error", "custom-score"],
        "endpoints": [
            {"name": "用户注册", "method": "POST", "path": "/api/portal/auth/register", "description": "用户自注册，校验注册位置与重复用户名。"},
            {"name": "用户登录", "method": "POST", "path": "/api/portal/auth/login", "description": "登录后拿到 portal token，用户端打码不必暴露管理员数据。"},
            {"name": "兑换 CDK", "method": "POST", "path": "/api/portal/cdks/redeem", "description": "成功兑换后增加可用打码次数。"},
            {"name": "用户打码", "method": "POST", "path": "/api/portal/user/solve", "description": "先校验可用次数；最终生成成功才扣，失败会返还次数。"},
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


def _build_pagination(limit: int, offset: int, total: int) -> Dict[str, Any]:
    safe_limit = max(1, int(limit or 1))
    safe_offset = max(0, int(offset or 0))
    safe_total = max(0, int(total or 0))
    return {
        "limit": safe_limit,
        "offset": safe_offset,
        "total": safe_total,
        "page": (safe_offset // safe_limit) + 1,
        "total_pages": max(1, (safe_total + safe_limit - 1) // safe_limit) if safe_total > 0 else 1,
        "has_prev": safe_offset > 0,
        "has_next": safe_offset + safe_limit < safe_total,
    }


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
    checkin = await _db.get_portal_user_checkin_status(user_id)
    leaderboard = await _db.get_portal_usage_leaderboard(limit=10)
    return {
        "success": True,
        "user": summary["user"],
        "usage": summary["usage"],
        "recent_sessions": recent_sessions,
        "recent_redeems": recent_redeems,
        "recent_transactions": recent_transactions,
        "api_keys": api_keys,
        "checkin": checkin,
        "leaderboard": leaderboard,
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


async def _safe_create_portal_user_job_log(**kwargs):
    if _db is None:
        return
    try:
        await _db.create_portal_user_job_log(**kwargs)
    except Exception as e:
        debug_logger.log_warning(
            "[portal_api] create_portal_user_job_log failed "
            f"status={kwargs.get('status')} session_id={kwargs.get('session_id')}: {e}"
        )


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
            "portal_path": "/portal" if config.cluster_role != "subnode" else None,
            "public_path": "/",
            "public_page_variant": "subnode-status" if config.cluster_role == "subnode" else "user-portal",
            "admin_path": "/admin",
        },
        "service": {
            "name": "flow_captcha_service",
            "node_name": config.node_name,
            "role": config.cluster_role,
            "local_solve_enabled": config.cluster_role != "master",
            "public_page_variant": "subnode-status" if config.cluster_role == "subnode" else "user-portal",
        },
        "health": {
            "status": "ok",
            "local_solve_enabled": config.cluster_role != "master",
        },
        "capabilities": {
            "user_portal": config.cluster_role != "subnode",
            "self_register": config.cluster_role != "subnode" and not config.portal_oauth_only,
            "user_login": config.cluster_role != "subnode" and not config.portal_oauth_only,
            "user_login_oidc": _get_oidc_settings()["enabled"],
            "cdk_redeem": config.cluster_role != "subnode",
            "subnode_status_page": config.cluster_role == "subnode",
            "api_console": True,
            "session_center": True,
            "daily_checkin": config.portal_checkin_max_quota > 0,
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
        "auth": {
            "oidc": {
                "enabled": _get_oidc_settings()["enabled"],
                "scope": _get_oidc_settings()["scope"],
            },
            "oauth_only": config.portal_oauth_only,
            "register_bonus_quota": config.portal_register_bonus_quota,
            "checkin_min_quota": config.portal_checkin_min_quota,
            "checkin_max_quota": config.portal_checkin_max_quota,
        },
    }


@router.get("/summary")
async def get_portal_summary(request: Request):
    return await get_portal_overview(request)


@router.post("/auth/register")
async def portal_user_register(request: PortalRegisterRequest, raw_request: Request, response: Response):
    _assert_portal_public_role("用户自注册")
    _assert_local_portal_auth_enabled("用户自注册")
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
        initial_quota=config.portal_register_bonus_quota,
    )
    if not ok or not user:
        raise HTTPException(status_code=409, detail=message)

    token = await _login_portal_user(response, int(user["id"]))
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
    _assert_local_portal_auth_enabled("用户名密码登录")
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")

    user = await _db.verify_portal_user_credentials(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")

    token = await _login_portal_user(response, int(user["id"]))
    payload = await _build_portal_user_workspace_payload(int(user["id"]))
    return {
        "success": True,
        "message": "登录成功",
        "authenticated": True,
        "token": token,
    }


@router.get("/auth/oidc")
@router.get("/auth/oidc/start")
async def portal_oidc_start(request: Request):
    _assert_portal_public_role("OIDC 登录")
    settings = await _resolve_oidc_endpoints(_get_oidc_settings())
    if not settings["enabled"]:
        raise HTTPException(status_code=400, detail="当前未启用 OIDC 登录")

    state_value = secrets.token_urlsafe(24)
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": settings["client_id"],
            "redirect_uri": _build_portal_redirect_uri(request),
            "scope": settings["scope"],
            "state": state_value,
        }
    )
    response = RedirectResponse(url=f"{settings['authorization_url']}?{query}", status_code=302)
    response.set_cookie(PORTAL_OIDC_STATE_COOKIE, state_value, path="/", max_age=600, samesite="lax", httponly=True)
    return response


@router.get("/auth/oidc/callback")
async def portal_oidc_callback(
    request: Request,
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
    portal_oidc_state: Optional[str] = Cookie(default=None),
):
    _assert_portal_public_role("OIDC 登录")
    settings = await _resolve_oidc_endpoints(_get_oidc_settings())
    portal_path = "/portal"
    if not settings["enabled"]:
        return RedirectResponse(url=f"{portal_path}?oidc_error={urllib.parse.quote('当前未启用 OIDC 登录')}", status_code=302)
    if error:
        return RedirectResponse(url=f"{portal_path}?oidc_error={urllib.parse.quote(error)}", status_code=302)
    if not code:
        return RedirectResponse(url=f"{portal_path}?oidc_error={urllib.parse.quote('OIDC 回调缺少 code')}", status_code=302)
    if not state or not portal_oidc_state or state != portal_oidc_state:
        return RedirectResponse(url=f"{portal_path}?oidc_error={urllib.parse.quote('OIDC state 校验失败')}", status_code=302)

    token_payload = await _request_oidc_token(
        token_url=settings["token_url"],
        client_id=settings["client_id"],
        client_secret=settings["client_secret"],
        code=code,
        redirect_uri=_build_portal_redirect_uri(request),
    )
    access_token = str(token_payload.get("access_token") or "").strip()
    if not access_token:
        raise HTTPException(status_code=502, detail="OIDC token 响应缺少 access_token")

    userinfo_status, userinfo_payload = await _oidc_http_request(
        settings["userinfo_url"],
        method="GET",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
    )
    if userinfo_status < 200 or userinfo_status >= 300 or not isinstance(userinfo_payload, dict):
        raise HTTPException(status_code=502, detail="OIDC userinfo 响应无效")

    user = await _resolve_or_create_oidc_user(userinfo_payload, settings["base_url"])
    response = RedirectResponse(url=f"{portal_path}?oidc=success", status_code=302)
    await _login_portal_user(response, int(user["id"]))
    response.delete_cookie(PORTAL_OIDC_STATE_COOKIE, path="/")
    return response


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
async def list_portal_user_transactions(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: dict = Depends(verify_portal_user_token),
):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")
    user_id = int(user["id"])
    items = await _db.list_portal_user_transactions(user_id, limit=limit, offset=offset)
    total = await _db.count_portal_user_transactions(user_id)
    return {
        "success": True,
        "items": items,
        **_build_pagination(limit=limit, offset=offset, total=total),
    }


@router.get("/user/checkin")
async def get_portal_user_checkin(user: dict = Depends(verify_portal_user_token)):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")
    return {
        "success": True,
        **(await _db.get_portal_user_checkin_status(int(user["id"]))),
        "min_quota": config.portal_checkin_min_quota,
        "max_quota": config.portal_checkin_max_quota,
    }


@router.post("/user/checkin")
async def claim_portal_user_checkin(user: dict = Depends(verify_portal_user_token)):
    if _db is None:
        raise HTTPException(status_code=500, detail="服务未初始化")
    ok, message, payload = await _db.claim_portal_user_checkin(
        int(user["id"]),
        min_quota=config.portal_checkin_min_quota,
        max_quota=config.portal_checkin_max_quota,
    )
    if not ok:
        raise HTTPException(status_code=400, detail=message)
    workspace = await _build_portal_user_workspace_payload(int(user["id"]))
    return {
        "success": True,
        "message": message,
        "checkin": payload,
        **workspace,
    }


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
    total = await _db.count_portal_user_jobs(
        portal_user_id=int(user["id"]),
        status=status,
        project_id=project_id,
    )
    return {
        "success": True,
        "items": items,
        "filters": {"status": status, "project_id": project_id},
        **_build_pagination(limit=limit, offset=offset, total=total),
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

        consumed, consume_message = await _db.consume_portal_user_quota(
            user_id,
            source_type="solve_success",
            source_ref=str(result.get("session_id") or "") if result else None,
            note="portal_user_solve",
        )
        if not consumed:
            await _cleanup_portal_success_result(result)
            raise HTTPException(status_code=403, detail=consume_message)

        elapsed = int((time.perf_counter() - started) * 1000)
        await _safe_create_portal_user_job_log(
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
        await _safe_create_portal_user_job_log(
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
            debug_logger.log_warning(
                "[portal_api] finish dispatch failed "
                f"session_id={session_id} status={request.status} {diag_label(e)}: {e}"
            )
            raise HTTPException(status_code=500, detail=f"finish 转发失败: {e}")
    else:
        try:
            ok, message, entry = await _runtime.finish(session_id)
        except Exception as e:
            debug_logger.log_warning(
                "[portal_api] local finish failed "
                f"session_id={session_id} {diag_label(e)}: {e}"
            )
            raise HTTPException(status_code=500, detail=f"finish 本地处理失败: {e}")
        if not ok:
            raise HTTPException(status_code=404, detail=message)

    normalized_status = str(request.status or "").strip().lower()
    refund_reason = f"finish:{normalized_status}" if normalized_status and normalized_status != "success" else None
    try:
        await _db.finalize_portal_user_session(
            portal_user_id=int(user["id"]),
            session_id=session_id,
            project_id=entry.project_id if entry else None,
            action=entry.action if entry else None,
            status=f"finish:{request.status}",
            error_reason=None,
            refund_reason=refund_reason,
        )
    except Exception as e:
        debug_logger.log_warning(
            "[portal_api] finalize finish failed "
            f"status={request.status} session_id={session_id} {diag_label(e)}: {e}"
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
            debug_logger.log_warning(
                "[portal_api] error dispatch failed "
                f"session_id={session_id} error_reason={request.error_reason} {diag_label(e)}: {e}"
            )
            raise HTTPException(status_code=500, detail=f"error 转发失败: {e}")
    else:
        try:
            ok, message, entry = await _runtime.mark_error(session_id, request.error_reason)
        except Exception as e:
            debug_logger.log_warning(
                "[portal_api] local error failed "
                f"session_id={session_id} error_reason={request.error_reason} {diag_label(e)}: {e}"
            )
            raise HTTPException(status_code=500, detail=f"error 本地处理失败: {e}")
        if not ok:
            raise HTTPException(status_code=404, detail=message)

    try:
        await _db.finalize_portal_user_session(
            portal_user_id=int(user["id"]),
            session_id=session_id,
            project_id=entry.project_id if entry else None,
            action=entry.action if entry else None,
            status="error_reported",
            error_reason=request.error_reason,
            refund_reason=request.error_reason or "error_reported",
        )
    except Exception as e:
        debug_logger.log_warning(
            "[portal_api] finalize error failed "
            f"session_id={session_id} error_reason={request.error_reason} {diag_label(e)}: {e}"
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
        await _safe_create_portal_user_job_log(
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
        await _safe_create_portal_user_job_log(
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
