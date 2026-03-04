from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Dict, Optional

import tomli


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _toml_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return str(value)
    if value is None:
        return '""'
    return _toml_quote(str(value))


class Config:
    ORDERED_TOP_SECTIONS = ("server", "storage", "admin", "captcha", "log", "cluster")
    ENV_OVERRIDE_KEYS = (
        "FCS_CONFIG_FILE",
        "FCS_SERVER_HOST",
        "FCS_SERVER_PORT",
        "FCS_DB_PATH",
        "FCS_ADMIN_USERNAME",
        "FCS_ADMIN_PASSWORD",
        "FCS_BROWSER_LAUNCH_BACKGROUND",
        "FCS_BROWSER_SCORE_DOM_WAIT_SECONDS",
        "FCS_BROWSER_RECAPTCHA_SETTLE_SECONDS",
        "FCS_BROWSER_SCORE_TEST_WARMUP_SECONDS",
        "FCS_FLOW_TIMEOUT",
        "FCS_UPSAMPLE_TIMEOUT",
        "FCS_SESSION_TTL_SECONDS",
        "FCS_NODE_NAME",
        "FCS_BROWSER_COUNT",
        "FCS_BROWSER_PROXY_ENABLED",
        "FCS_BROWSER_PROXY_URL",
        "FCS_LOG_LEVEL",
        "FCS_CLUSTER_ROLE",
        "FCS_CLUSTER_MASTER_BASE_URL",
        "FCS_CLUSTER_MASTER_CLUSTER_KEY",
        "FCS_CLUSTER_NODE_PUBLIC_BASE_URL",
        "FCS_CLUSTER_NODE_API_KEY",
        "FCS_CLUSTER_HEARTBEAT_INTERVAL_SECONDS",
        "FCS_CLUSTER_NODE_WEIGHT",
        "FCS_CLUSTER_NODE_MAX_CONCURRENCY",
        "FCS_CLUSTER_MASTER_NODE_STALE_SECONDS",
        "FCS_CLUSTER_MASTER_DISPATCH_TIMEOUT_SECONDS",
    )

    def __init__(self):
        self._root_dir = Path(__file__).resolve().parents[2]
        default_path = self._root_dir / "config" / "setting.toml"
        env_path = os.getenv("FCS_CONFIG_FILE", "").strip()
        self._config_path = Path(env_path) if env_path else default_path
        self._config = self._load_config()

    def _defaults(self) -> Dict[str, Any]:
        return {
            "server": {
                "host": "0.0.0.0",
                "port": 8060,
            },
            "storage": {
                "db_path": "data/captcha_service.db",
            },
            "admin": {
                "username": "admin",
                "password": "admin",
            },
            "captcha": {
                "browser_count": 1,
                "browser_proxy_enabled": False,
                "browser_proxy_url": "",
                "browser_launch_background": True,
                "browser_score_dom_wait_seconds": 25,
                "browser_recaptcha_settle_seconds": 3,
                "browser_score_test_warmup_seconds": 12,
                "flow_timeout": 300,
                "upsample_timeout": 300,
                "session_ttl_seconds": 7200,
                "node_name": "standalone-node",
            },
            "log": {
                "level": "INFO",
            },
            "cluster": {
                "role": "standalone",
                "master_base_url": "",
                "master_cluster_key": "",
                "node_public_base_url": "",
                "node_api_key": "",
                "heartbeat_interval_seconds": 15,
                "node_weight": 100,
                "node_max_concurrency": 1,
                "master_node_stale_seconds": 120,
                "master_dispatch_timeout_seconds": 45,
            },
        }

    def _read_user_config(self) -> Dict[str, Any]:
        if not self._config_path.exists():
            return {}
        raw_text = self._config_path.read_text(encoding="utf-8-sig")
        parsed = tomli.loads(raw_text)
        if not isinstance(parsed, dict):
            return {}
        return parsed

    def _load_config(self) -> Dict[str, Any]:
        return _deep_merge(self._defaults(), self._read_user_config())

    def _get(self, section: str, key: str, default: Any = None) -> Any:
        return self._config.get(section, {}).get(key, default)

    def _dump_toml(self, data: Dict[str, Any]) -> str:
        lines: list[str] = []
        top_keys = list(self.ORDERED_TOP_SECTIONS)
        top_keys.extend(sorted(k for k in data.keys() if k not in self.ORDERED_TOP_SECTIONS))

        for top_key in top_keys:
            section_data = data.get(top_key)
            if not isinstance(section_data, dict):
                continue
            self._append_toml_section(lines, top_key, section_data)

        return "\n".join(lines).rstrip() + "\n"

    def _append_toml_section(self, lines: list[str], path: str, section_data: Dict[str, Any]):
        lines.append(f"[{path}]")
        for key, value in section_data.items():
            if isinstance(value, dict):
                continue
            lines.append(f"{key} = {_toml_literal(value)}")
        lines.append("")

        for key, value in section_data.items():
            if isinstance(value, dict):
                self._append_toml_section(lines, f"{path}.{key}", value)

    def _normalize_top_level_config(self, payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        normalized: Dict[str, Dict[str, Any]] = {}
        for section, value in payload.items():
            if not isinstance(section, str) or not isinstance(value, dict):
                continue
            clean_section = section.strip()
            if not clean_section:
                continue
            normalized[clean_section] = dict(value)
        return normalized

    @property
    def root_dir(self) -> Path:
        return self._root_dir

    @property
    def config_path(self) -> Path:
        return self._config_path

    def reload_config(self):
        self._config = self._load_config()

    def get_merged_config(self) -> Dict[str, Any]:
        return copy.deepcopy(self._config)

    def get_active_env_overrides(self) -> Dict[str, str]:
        active: Dict[str, str] = {}
        for env_key in self.ENV_OVERRIDE_KEYS:
            value = os.getenv(env_key)
            if value is None:
                continue
            text = str(value).strip()
            if text == "":
                continue
            active[env_key] = text
        return active

    def update_config_sections(self, sections: Dict[str, Any]) -> Dict[str, Any]:
        normalized = self._normalize_top_level_config(sections)
        user_cfg = self._read_user_config()

        for section, payload in normalized.items():
            current = user_cfg.get(section)
            if not isinstance(current, dict):
                current = {}
            for key, value in payload.items():
                current[key] = value
            user_cfg[section] = current

        merged_to_write = _deep_merge(self._defaults(), user_cfg)
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        self._config_path.write_text(self._dump_toml(merged_to_write), encoding="utf-8")
        self._config = merged_to_write
        return self.get_merged_config()

    @property
    def server_host(self) -> str:
        return str(os.getenv("FCS_SERVER_HOST", self._get("server", "host", "0.0.0.0")))

    @property
    def server_port(self) -> int:
        value = os.getenv("FCS_SERVER_PORT")
        if value:
            return int(value)
        return int(self._get("server", "port", 8060))

    @property
    def db_path(self) -> Path:
        env_path = os.getenv("FCS_DB_PATH", "").strip()
        raw = env_path or str(self._get("storage", "db_path", "data/captcha_service.db"))
        path = Path(raw)
        if not path.is_absolute():
            path = self._root_dir / path
        return path

    @property
    def admin_username(self) -> str:
        return str(os.getenv("FCS_ADMIN_USERNAME", self._get("admin", "username", "admin")))

    @property
    def admin_password(self) -> str:
        return str(os.getenv("FCS_ADMIN_PASSWORD", self._get("admin", "password", "admin")))

    @property
    def browser_launch_background(self) -> bool:
        value = os.getenv("FCS_BROWSER_LAUNCH_BACKGROUND")
        if value:
            return _as_bool(value, True)
        return _as_bool(self._get("captcha", "browser_launch_background", True), True)

    @property
    def browser_score_dom_wait_seconds(self) -> float:
        value = os.getenv("FCS_BROWSER_SCORE_DOM_WAIT_SECONDS")
        if value:
            return float(value)
        return float(self._get("captcha", "browser_score_dom_wait_seconds", 25))

    @property
    def browser_recaptcha_settle_seconds(self) -> float:
        value = os.getenv("FCS_BROWSER_RECAPTCHA_SETTLE_SECONDS")
        if value:
            return float(value)
        return float(self._get("captcha", "browser_recaptcha_settle_seconds", 3))

    @property
    def browser_score_test_warmup_seconds(self) -> float:
        value = os.getenv("FCS_BROWSER_SCORE_TEST_WARMUP_SECONDS")
        if value:
            return float(value)
        return float(self._get("captcha", "browser_score_test_warmup_seconds", 12))

    @property
    def flow_timeout(self) -> int:
        value = os.getenv("FCS_FLOW_TIMEOUT")
        if value:
            return int(value)
        return int(self._get("captcha", "flow_timeout", 300))

    @property
    def upsample_timeout(self) -> int:
        value = os.getenv("FCS_UPSAMPLE_TIMEOUT")
        if value:
            return int(value)
        return int(self._get("captcha", "upsample_timeout", 300))

    @property
    def session_ttl_seconds(self) -> int:
        value = os.getenv("FCS_SESSION_TTL_SECONDS")
        if value:
            return int(value)
        return int(self._get("captcha", "session_ttl_seconds", 7200))

    @property
    def node_name(self) -> str:
        return str(os.getenv("FCS_NODE_NAME", self._get("captcha", "node_name", "standalone-node")))

    @property
    def browser_count(self) -> int:
        value = os.getenv("FCS_BROWSER_COUNT")
        if value:
            return max(1, int(value))
        return max(1, int(self._get("captcha", "browser_count", 1)))

    @property
    def browser_proxy_enabled(self) -> bool:
        value = os.getenv("FCS_BROWSER_PROXY_ENABLED")
        if value:
            return _as_bool(value, False)
        return _as_bool(self._get("captcha", "browser_proxy_enabled", False), False)

    @property
    def browser_proxy_url(self) -> str:
        return str(os.getenv("FCS_BROWSER_PROXY_URL", self._get("captcha", "browser_proxy_url", "")))

    @property
    def log_level(self) -> str:
        return str(os.getenv("FCS_LOG_LEVEL", self._get("log", "level", "INFO"))).upper()

    @property
    def cluster_role(self) -> str:
        return str(os.getenv("FCS_CLUSTER_ROLE", self._get("cluster", "role", "standalone"))).strip().lower()

    @property
    def cluster_master_base_url(self) -> str:
        return str(
            os.getenv(
                "FCS_CLUSTER_MASTER_BASE_URL",
                self._get("cluster", "master_base_url", ""),
            )
        ).strip().rstrip("/")

    @property
    def cluster_master_cluster_key(self) -> str:
        return str(
            os.getenv(
                "FCS_CLUSTER_MASTER_CLUSTER_KEY",
                self._get("cluster", "master_cluster_key", ""),
            )
        ).strip()

    @property
    def cluster_node_public_base_url(self) -> str:
        return str(
            os.getenv(
                "FCS_CLUSTER_NODE_PUBLIC_BASE_URL",
                self._get("cluster", "node_public_base_url", ""),
            )
        ).strip().rstrip("/")

    @property
    def node_api_key(self) -> str:
        return str(
            os.getenv(
                "FCS_CLUSTER_NODE_API_KEY",
                self._get("cluster", "node_api_key", ""),
            )
        ).strip()

    @property
    def cluster_heartbeat_interval_seconds(self) -> int:
        value = os.getenv("FCS_CLUSTER_HEARTBEAT_INTERVAL_SECONDS")
        if value:
            return max(5, int(value))
        return max(5, int(self._get("cluster", "heartbeat_interval_seconds", 15)))

    @property
    def cluster_node_weight(self) -> int:
        value = os.getenv("FCS_CLUSTER_NODE_WEIGHT")
        if value:
            return max(1, int(value))
        return max(1, int(self._get("cluster", "node_weight", 100)))

    @property
    def cluster_node_max_concurrency(self) -> int:
        value = os.getenv("FCS_CLUSTER_NODE_MAX_CONCURRENCY")
        if value:
            return max(1, int(value))
        return max(1, int(self._get("cluster", "node_max_concurrency", self.browser_count)))

    @property
    def cluster_master_node_stale_seconds(self) -> int:
        value = os.getenv("FCS_CLUSTER_MASTER_NODE_STALE_SECONDS")
        if value:
            return max(10, int(value))
        return max(10, int(self._get("cluster", "master_node_stale_seconds", 120)))

    @property
    def cluster_master_dispatch_timeout_seconds(self) -> int:
        value = os.getenv("FCS_CLUSTER_MASTER_DISPATCH_TIMEOUT_SECONDS")
        if value:
            return max(5, int(value))
        return max(5, int(self._get("cluster", "master_dispatch_timeout_seconds", 45)))


config = Config()
