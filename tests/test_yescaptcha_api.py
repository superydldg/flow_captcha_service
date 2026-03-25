import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from fastapi import HTTPException

from src.api import service, yescaptcha
from src.core.auth import set_database
from src.core.database import Database
from src.services.yescaptcha_manager import YesCaptchaTaskManager


class FakeRuntime:
    def __init__(self):
        self.custom_token_delay = 0.0
        self.custom_token_error = None
        self.custom_token_calls = []
        self.solve_calls = []

    async def solve(self, project_id: str, action: str, token_id: int | None, api_key_id: int):
        self.solve_calls.append(
            {
                "project_id": project_id,
                "action": action,
                "token_id": token_id,
                "api_key_id": api_key_id,
            }
        )
        return {
            "session_id": "legacy-session",
            "token": "legacy-token",
            "fingerprint": {"userAgent": "legacy-agent"},
            "node_name": "test-node",
            "expires_in_seconds": 1200,
        }

    async def custom_token(
        self,
        website_url: str,
        website_key: str,
        action: str,
        enterprise: bool,
        captcha_type: str = "recaptcha_v3",
        is_invisible: bool = True,
    ):
        self.custom_token_calls.append(
            {
                "website_url": website_url,
                "website_key": website_key,
                "action": action,
                "enterprise": enterprise,
                "captcha_type": captcha_type,
                "is_invisible": is_invisible,
            }
        )
        if self.custom_token_delay > 0:
            await asyncio.sleep(self.custom_token_delay)
        if self.custom_token_error is not None:
            raise RuntimeError(str(self.custom_token_error))
        return {
            "token": "yes-token",
            "browser_id": 7,
            "fingerprint": {"userAgent": "fake-agent/1.0"},
            "node_name": "test-node",
        }


class FakeClusterManager:
    async def dispatch_solve(self, request_payload):
        raise AssertionError("standalone test should not dispatch_solve")

    async def dispatch_custom_token(self, request_payload):
        raise AssertionError("standalone test should not dispatch_custom_token")

    async def dispatch_custom_score(self, request_payload):
        raise AssertionError("standalone test should not dispatch_custom_score")


class YesCaptchaApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.env_patcher = patch.dict(os.environ, {"FCS_CLUSTER_ROLE": "standalone"}, clear=False)
        self.env_patcher.start()

        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp_dir.name) / "test.sqlite3")
        await self.db.init_db()
        set_database(self.db)

        self.runtime = FakeRuntime()
        self.cluster = FakeClusterManager()
        self.task_manager = YesCaptchaTaskManager(task_ttl_seconds=600, cleanup_interval_seconds=60)
        await self.task_manager.start()

        service.set_dependencies(self.db, self.runtime, self.cluster)
        yescaptcha.set_dependencies(self.db, self.runtime, self.cluster, self.task_manager)

        self.app = FastAPI()
        self.app.include_router(service.router)
        self.app.include_router(yescaptcha.router)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://testserver",
        )

        self.raw_key, self.api_key = await self.db.create_api_key("yes-test", 5)

    async def asyncTearDown(self):
        try:
            await self.client.aclose()
            await self.task_manager.close()
            await self.db.close()
            for attempt in range(5):
                try:
                    self.temp_dir.cleanup()
                    break
                except (PermissionError, NotADirectoryError):
                    if attempt >= 4:
                        raise
                    await asyncio.sleep(0.05)
        finally:
            self.env_patcher.stop()

    async def _poll_task_result(self, task_id: str, *, max_attempts: int = 20):
        payload = {}
        for _ in range(max_attempts):
            response = await self.client.post(
                "/getTaskResult",
                json={"clientKey": self.raw_key, "taskId": task_id},
            )
            payload = response.json()
            if payload.get("status") == "ready" or int(payload.get("errorId") or 0) > 0:
                return payload
            await asyncio.sleep(0.05)
        return payload

    async def test_create_task_processing_then_ready(self):
        self.runtime.custom_token_delay = 0.2

        create_response = await self.client.post(
            "/createTask",
            json={
                "clientKey": self.raw_key,
                "task": {
                    "type": "RecaptchaV3TaskProxyless",
                    "websiteURL": "https://example.com",
                    "websiteKey": "site-key",
                    "pageAction": "submit",
                },
            },
        )
        create_payload = create_response.json()
        self.assertEqual(create_payload["errorId"], 0)
        task_id = create_payload["taskId"]
        self.assertTrue(task_id)

        processing_response = await self.client.post(
            "/getTaskResult",
            json={"clientKey": self.raw_key, "taskId": task_id},
        )
        processing_payload = processing_response.json()
        self.assertEqual(processing_payload["errorId"], 0)
        self.assertEqual(processing_payload["status"], "processing")

        ready_payload = await self._poll_task_result(task_id)
        self.assertEqual(ready_payload["errorId"], 0)
        self.assertEqual(ready_payload["status"], "ready")
        self.assertEqual(ready_payload["solution"]["token"], "yes-token")
        self.assertEqual(ready_payload["solution"]["gRecaptchaResponse"], "yes-token")
        self.assertEqual(ready_payload["solution"]["userAgent"], "fake-agent/1.0")
        self.assertEqual(len(self.runtime.custom_token_calls), 1)
        self.assertEqual(self.runtime.custom_token_calls[0]["captcha_type"], "recaptcha_v3")
        self.assertEqual(self.runtime.custom_token_calls[0]["action"], "submit")

    async def test_unsupported_task_type_returns_protocol_error(self):
        response = await self.client.post(
            "/createTask",
            json={
                "clientKey": self.raw_key,
                "task": {
                    "type": "HCaptchaTaskProxyless",
                    "websiteURL": "https://example.com",
                    "websiteKey": "site-key",
                },
            },
        )
        payload = response.json()
        self.assertGreater(int(payload["errorId"]), 0)
        self.assertEqual(payload["errorCode"], "ERROR_TASK_NOT_SUPPORTED")

    async def test_background_failure_returns_protocol_error(self):
        self.runtime.custom_token_error = "solver exploded"

        create_response = await self.client.post(
            "/createTask",
            json={
                "clientKey": self.raw_key,
                "task": {
                    "type": "RecaptchaV3TaskProxyless",
                    "websiteURL": "https://example.com",
                    "websiteKey": "site-key",
                },
            },
        )
        task_id = create_response.json()["taskId"]
        result_payload = await self._poll_task_result(task_id)
        self.assertGreater(int(result_payload["errorId"]), 0)
        self.assertEqual(result_payload["errorCode"], "ERROR_CAPTCHA_UNSOLVABLE")

    async def test_legacy_solve_route_keeps_original_response_shape(self):
        response = await self.client.post(
            "/api/v1/solve",
            headers={"Authorization": f"Bearer {self.raw_key}"},
            json={"project_id": "demo-project", "action": "IMAGE_GENERATION"},
        )
        payload = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["session_id"], "legacy-session")
        self.assertEqual(payload["token"], "legacy-token")
        self.assertEqual(payload["node_name"], "test-node")
        self.assertEqual(len(self.runtime.solve_calls), 1)

    async def test_get_balance_reuses_client_key_cache_between_polls(self):
        call_counter = {"total": 0}

        async def fake_resolve(raw_key: str, *, allow_internal: bool = True):
            call_counter["total"] += 1
            if raw_key != self.raw_key:
                raise HTTPException(status_code=401, detail="bad key")
            return dict(self.api_key)

        yescaptcha._client_key_cache.clear()
        with patch("src.api.yescaptcha.resolve_service_api_key_token", side_effect=fake_resolve):
            response_one = await self.client.post("/getBalance", json={"clientKey": self.raw_key})
            response_two = await self.client.post("/getBalance", json={"clientKey": self.raw_key})

        self.assertEqual(response_one.status_code, 200)
        self.assertEqual(response_two.status_code, 200)
        self.assertEqual(response_one.json()["errorId"], 0)
        self.assertEqual(response_two.json()["errorId"], 0)
        self.assertEqual(call_counter["total"], 1)


if __name__ == "__main__":
    unittest.main()
