from __future__ import annotations

import asyncio
import gc
import sys
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from ..core.config import config
from ..core.database import Database
from ..core.diagnostics import diag_label
from ..core.logger import debug_logger
from .session_registry import SessionRegistry, SessionEntry


class CaptchaRuntime:
    def __init__(self, db: Database):
        self.db = db
        self.registry = SessionRegistry()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._browser_service = None
        self._service_mode: Optional[str] = None
        self._browser_service_lock = asyncio.Lock()

    async def start(self):
        if self._cleanup_task and not self._cleanup_task.done():
            return
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        if config.cluster_role != "master":
            try:
                service = await self._get_browser_service()
                await self._warmup_local_service(service)
            except Exception as e:
                debug_logger.log_warning(f"[CaptchaRuntime] browser warmup failed: {e}")

    def _resolve_local_captcha_method(self) -> str:
        return "personal" if str(config.captcha_method or "").strip().lower() == "personal" else "browser"

    async def _close_current_service_locked(self):
        if self._browser_service is None:
            self._service_mode = None
            return
        try:
            await self._browser_service.close()
        except Exception as e:
            debug_logger.log_warning(f"[CaptchaRuntime] close browser service failed: {e}")
        finally:
            self._browser_service = None
            self._service_mode = None

    async def _close_current_service(self):
        async with self._browser_service_lock:
            await self._close_current_service_locked()

    async def _warmup_local_service(self, service):
        method = self._service_mode or self._resolve_local_captcha_method()
        if method == "personal":
            project_id = str(getattr(config, "browser_auto_warm_project_id", "") or "").strip()
            warmup_limit = max(1, int(getattr(config, "personal_max_resident_tabs", 1) or 1))
            if hasattr(service, "warmup_resident_tabs"):
                project_ids = [project_id] if project_id else []
                await service.warmup_resident_tabs(project_ids, limit=warmup_limit)
            return

        await service.warmup_browser_slots()

    async def _get_browser_service(self):
        if config.cluster_role == "master":
            raise RuntimeError("master 角色不执行本地打码")

        async with self._browser_service_lock:
            current_mode = self._resolve_local_captcha_method()
            if self._browser_service is not None and self._service_mode != current_mode:
                await self._close_current_service_locked()

            if self._browser_service is None:
                if current_mode == "personal":
                    from .browser_captcha_personal import BrowserCaptchaService as PersonalCaptchaService

                    self._browser_service = await PersonalCaptchaService.get_instance(self.db)
                else:
                    from .browser_captcha import BrowserCaptchaService

                    self._browser_service = await BrowserCaptchaService.get_instance(self.db)
                self._service_mode = current_mode
            return self._browser_service

    @staticmethod
    def _extract_token_response(raw_result: Any, fallback_browser_id: Optional[str] = None) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]]]:
        if raw_result is None:
            return None, fallback_browser_id, None

        if isinstance(raw_result, str):
            token = str(raw_result or "").strip() or None
            return token, fallback_browser_id, None

        token = str(getattr(raw_result, "token", "") or "").strip() or None
        browser_ref = getattr(raw_result, "browser_ref", None)
        browser_id = browser_ref if browser_ref is not None else getattr(raw_result, "browser_id", None)
        if browser_id is None:
            browser_id = fallback_browser_id
        fingerprint = getattr(raw_result, "fingerprint", None)
        return token, browser_id, fingerprint

    async def solve(
        self,
        project_id: str,
        action: str,
        token_id: Optional[int],
        api_key_id: int,
    ) -> Dict[str, Any]:
        service = await self._get_browser_service()
        if self._service_mode == "personal":
            token_result = await service.get_token(project_id, action)
            token, browser_id, fingerprint = self._extract_token_response(
                token_result,
                fallback_browser_id=project_id,
            )
        else:
            token_result = await service.get_token(project_id, action, token_id=token_id)
            token, browser_id, fingerprint = self._extract_token_response(token_result)

        if not token or browser_id is None:
            raise RuntimeError("有头打码失败，未获取到 token")

        if fingerprint is None:
            if hasattr(service, "get_fingerprint"):
                maybe_fingerprint = service.get_fingerprint(browser_id)
                fingerprint = await maybe_fingerprint if asyncio.iscoroutine(maybe_fingerprint) else maybe_fingerprint
            elif hasattr(service, "get_last_fingerprint"):
                fingerprint = service.get_last_fingerprint()
        session_id = str(uuid.uuid4())
        await self.registry.create(
            session_id=session_id,
            browser_id=browser_id,
            api_key_id=api_key_id,
            project_id=project_id,
            action=action,
        )

        return {
            "session_id": session_id,
            "token": token,
            "fingerprint": fingerprint,
            "node_name": config.node_name,
            "expires_in_seconds": config.session_ttl_seconds,
        }

    async def custom_score(
        self,
        website_url: str,
        website_key: str,
        verify_url: str,
        action: str,
        enterprise: bool,
    ) -> Dict[str, Any]:
        service = await self._get_browser_service()
        if self._service_mode == "personal":
            score_result = await service.get_custom_score(
                website_url=website_url,
                website_key=website_key,
                verify_url=verify_url,
                action=action,
                enterprise=enterprise,
            )
            if isinstance(score_result, tuple) and len(score_result) == 2:
                payload, browser_id = score_result
            else:
                payload, browser_id = score_result, website_url
        else:
            payload, browser_id = await service.get_custom_score(
                website_url=website_url,
                website_key=website_key,
                verify_url=verify_url,
                action=action,
                enterprise=enterprise,
            )
        payload = payload if isinstance(payload, dict) else {}
        payload["browser_id"] = browser_id
        payload["node_name"] = config.node_name
        return payload

    async def prime_solve_pool(
        self,
        project_id: str,
        action: str = "IMAGE_GENERATION",
        token_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        service = await self._get_browser_service()
        if self._service_mode == "personal":
            if hasattr(service, "prime_token_pool"):
                payload = await service.prime_token_pool(
                    project_id=project_id,
                    action=action,
                    token_id=token_id,
                )
            else:
                warmed_slots = []
                if hasattr(service, "warmup_resident_tabs"):
                    warmed_slots = await service.warmup_resident_tabs([project_id], limit=1)
                payload = {
                    "success": True,
                    "method": "personal",
                    "project_id": project_id,
                    "action": action,
                    "warmed_slots": warmed_slots,
                }
        else:
            payload = await service.prime_token_pool(
                project_id=project_id,
                action=action,
                token_id=token_id,
            )
        payload["node_name"] = config.node_name
        return payload

    async def custom_token(
        self,
        website_url: str,
        website_key: str,
        action: str,
        enterprise: bool,
        captcha_type: str = "recaptcha_v3",
        is_invisible: bool = True,
    ) -> Dict[str, Any]:
        service = await self._get_browser_service()
        if self._service_mode == "personal":
            token_result = await service.get_custom_token(
                website_url=website_url,
                website_key=website_key,
                action=action,
                enterprise=enterprise,
            )
            token, browser_id, fingerprint = self._extract_token_response(token_result)
        else:
            token_result = await service.get_custom_token(
                website_url=website_url,
                website_key=website_key,
                action=action,
                enterprise=enterprise,
                captcha_type=captcha_type,
                is_invisible=is_invisible,
            )
            token, browser_id, fingerprint = self._extract_token_response(token_result)
        if not token:
            raise RuntimeError("通用打码失败，未获取到 token")

        if fingerprint is None and browser_id is not None:
            if hasattr(service, "get_fingerprint"):
                maybe_fingerprint = service.get_fingerprint(browser_id)
                fingerprint = await maybe_fingerprint if asyncio.iscoroutine(maybe_fingerprint) else maybe_fingerprint
        if fingerprint is None and hasattr(service, "get_last_fingerprint"):
            fingerprint = service.get_last_fingerprint()
        return {
            "token": token,
            "browser_id": browser_id,
            "fingerprint": fingerprint,
            "node_name": config.node_name,
        }

    async def finish(self, session_id: str) -> Tuple[bool, str, Optional[SessionEntry]]:
        entry = await self.registry.get(session_id)
        if not entry:
            debug_logger.log_warning(f"[CaptchaRuntime] finish missing session_id={session_id}")
            return False, "session_not_found", None

        if entry.status != "pending":
            return True, f"session_already_{entry.status}", entry

        service = await self._get_browser_service()
        if hasattr(service, "report_request_finished"):
            await service.report_request_finished(entry.browser_id)
        finished_entry = await self.registry.finish(session_id)
        return True, "ok", finished_entry

    async def mark_error(self, session_id: str, error_reason: str) -> Tuple[bool, str, Optional[SessionEntry]]:
        entry = await self.registry.get(session_id)
        if not entry:
            debug_logger.log_warning(f"[CaptchaRuntime] error missing session_id={session_id} error_reason={error_reason}")
            return False, "session_not_found", None

        if entry.status != "pending":
            return True, f"session_already_{entry.status}", entry

        service = await self._get_browser_service()
        if self._service_mode == "personal" and hasattr(service, "report_flow_error"):
            await service.report_flow_error(entry.project_id, error_reason=error_reason, error_message=session_id)
        elif hasattr(service, "report_error"):
            await service.report_error(entry.browser_id, error_reason=error_reason)
        error_entry = await self.registry.mark_error(session_id, error_reason)
        return True, "ok", error_entry

    async def reload_browser_count(self):
        if config.cluster_role == "master":
            return
        if self._browser_service is None:
            return
        try:
            if self._service_mode == "personal" and hasattr(self._browser_service, "reload_config"):
                await self._browser_service.reload_config()
            else:
                await self._browser_service.reload_browser_count()
        except Exception as e:
            debug_logger.log_warning(f"[CaptchaRuntime] reload_browser_count failed: {e}")

    async def refresh_browser_warmup_settings(self):
        if config.cluster_role == "master":
            return
        try:
            service = await self._get_browser_service()
            if self._service_mode == "personal":
                if hasattr(service, "reload_config"):
                    await service.reload_config()
                await self._warmup_local_service(service)
            else:
                await service.refresh_warmup_settings()
        except Exception as e:
            debug_logger.log_warning(f"[CaptchaRuntime] refresh_browser_warmup_settings failed: {e}")

    async def get_stats(self) -> Dict[str, Any]:
        pending_sessions = await self.registry.active_count()
        total_sessions = await self.registry.total_count()

        browser_stats: Dict[str, Any] = {
            "total_solve_count": 0,
            "total_error_count": 0,
            "risk_403_count": 0,
            "browser_count": 0,
            "configured_browser_count": config.browser_count,
            "busy_browser_count": 0,
            "idle_browser_count": config.browser_count,
            "standby_token_count": 0,
        }

        if self._browser_service is not None:
            try:
                if hasattr(self._browser_service, "get_stats"):
                    browser_stats = self._browser_service.get_stats()
                elif self._service_mode == "personal":
                    resident_count = 0
                    if hasattr(self._browser_service, "get_resident_count"):
                        resident_count = max(0, int(self._browser_service.get_resident_count() or 0))
                    configured_tabs = max(1, int(config.personal_max_resident_tabs or 1))
                    browser_stats = {
                        "mode": "personal",
                        "total_solve_count": 0,
                        "total_error_count": 0,
                        "risk_403_count": 0,
                        "browser_count": resident_count,
                        "configured_browser_count": configured_tabs,
                        "busy_browser_count": 0,
                        "idle_browser_count": max(configured_tabs - 0, 0),
                        "standby_token_count": 0,
                        "shared_browser_count": resident_count,
                    }
            except Exception as e:
                debug_logger.log_warning(f"[CaptchaRuntime] get browser stats failed: {e}")
        elif config.cluster_role != "master":
            try:
                if self._resolve_local_captcha_method() == "personal":
                    browser_stats["configured_browser_count"] = max(1, int(config.personal_max_resident_tabs or 1))
                else:
                    captcha_cfg = await self.db.get_captcha_config()
                    browser_stats["configured_browser_count"] = max(1, int(captcha_cfg.browser_count or 1))
                browser_stats["idle_browser_count"] = browser_stats["configured_browser_count"]
            except Exception as e:
                debug_logger.log_warning(f"[CaptchaRuntime] read browser_count from db failed: {e}")

        default_configured = config.personal_max_resident_tabs if self._resolve_local_captcha_method() == "personal" else config.browser_count
        configured_count = max(1, int(browser_stats.get("configured_browser_count") or default_configured or 1))
        busy_count = max(0, int(browser_stats.get("busy_browser_count") or 0))
        browser_stats["thread_total"] = configured_count
        browser_stats["thread_idle"] = max(configured_count - busy_count, 0)
        browser_stats["thread_active"] = busy_count

        return {
            "node_name": config.node_name,
            "role": config.cluster_role,
            "active_sessions": busy_count,
            "pending_sessions": pending_sessions,
            "cached_sessions": total_sessions,
            "local_solve_enabled": config.cluster_role != "master",
            "browser": browser_stats,
        }

    def _resolve_session_timeout_seconds(self, action: str) -> int:
        configured_ttl = max(120, int(getattr(config, "session_ttl_seconds", 1200) or 1200))
        flow_timeout = max(10, int(getattr(config, "flow_timeout", 300) or 300))
        upsample_timeout = max(10, int(getattr(config, "upsample_timeout", 300) or 300))

        action_name = str(action or "").strip().upper()
        if action_name == "IMAGE_GENERATION":
            expected = max(flow_timeout, upsample_timeout) + 120
        elif action_name == "VIDEO_GENERATION":
            expected = max(flow_timeout + 240, upsample_timeout + 180, 600)
        else:
            expected = max(flow_timeout + 180, upsample_timeout + 120, 480)

        return max(120, min(configured_ttl, int(expected)))

    def _resolve_entry_ttl(self, entry: SessionEntry) -> int:
        return self._resolve_session_timeout_seconds(entry.action)

    async def _cleanup_loop(self):
        while True:
            try:
                await asyncio.sleep(30)
                expired_entries = await self.registry.list_expired(
                    config.session_ttl_seconds,
                    ttl_resolver=self._resolve_entry_ttl,
                )
                if expired_entries and self._browser_service is not None:
                    started = time.perf_counter()
                    for entry in expired_entries:
                        try:
                            age_seconds = max(0, int(time.time() - entry.created_at.timestamp()))
                            debug_logger.log_warning(
                                "[CaptchaRuntime] session expired before finish "
                                f"session_id={entry.session_id} action={entry.action} "
                                f"project_id={entry.project_id} age={age_seconds}s"
                            )
                            await self._browser_service.report_error(
                                entry.browser_id,
                                error_reason=entry.error_reason or "session_timeout",
                            )
                        except Exception as e:
                            debug_logger.log_warning(
                                f"[CaptchaRuntime] expired session cleanup failed {diag_label(e)}: {e}"
                            )
                    elapsed = int((time.perf_counter() - started) * 1000)
                    debug_logger.log_info(
                        f"[CaptchaRuntime] cleaned {len(expired_entries)} expired session(s) in {elapsed}ms"
                    )

                stale_refunds = await self.db.refund_stale_session_quotas(
                    stale_seconds=config.session_ttl_seconds,
                    limit=200,
                )
                refund_total = int(stale_refunds.get("portal_refunded", 0)) + int(stale_refunds.get("service_refunded", 0))
                if refund_total > 0:
                    debug_logger.log_info(
                        "[CaptchaRuntime] refunded stale sessions "
                        f"portal={int(stale_refunds.get('portal_refunded', 0))} "
                        f"service={int(stale_refunds.get('service_refunded', 0))} "
                        f"timeout_logs={int(stale_refunds.get('timeout_logs_created', 0))}"
                    )
            except asyncio.CancelledError:
                return
            except Exception as e:
                debug_logger.log_warning(f"[CaptchaRuntime] cleanup loop error {diag_label(e)}: {e}")

    async def close(self):
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        await self._close_current_service()
        if sys.platform.startswith("win"):
            gc.collect()
            await asyncio.sleep(0)
            await asyncio.sleep(0.1)
