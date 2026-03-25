import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core.config import Config


class BrowserConfigSettingsTests(unittest.TestCase):
    def _build_config(self, env_overrides: dict[str, str]) -> Config:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "setting.toml"
            config_path.write_text("[captcha]\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {
                    "FCS_CONFIG_FILE": str(config_path),
                    **env_overrides,
                },
                clear=False,
            ):
                return Config()

    def test_execute_timeout_env_zero_keeps_auto_mode(self):
        config = self._build_config({"FCS_BROWSER_EXECUTE_TIMEOUT_SECONDS": "0"})
        self.assertEqual(config.browser_execute_timeout_seconds, 0.0)

    def test_standby_bucket_idle_ttl_env_zero_keeps_auto_mode(self):
        config = self._build_config({"FCS_BROWSER_STANDBY_BUCKET_IDLE_TTL_SECONDS": "0"})
        self.assertEqual(config.browser_standby_bucket_idle_ttl_seconds, 0.0)


if __name__ == "__main__":
    unittest.main()
