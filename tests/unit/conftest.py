"""Общие фикстуры unit-тестов StealthNode."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "stealthnode" / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

os.environ.setdefault("SN_ALLOW_NONROOT", "1")
os.environ.setdefault("NO_COLOR", "1")


@pytest.fixture
def sn_root(tmp_path, monkeypatch):
    """Изолированный /opt/stealthnode во временном каталоге."""
    root = tmp_path / "opt-stealthnode"
    root.mkdir()
    monkeypatch.setenv("SN_ROOT", str(root))
    monkeypatch.setenv("SN_CREDENTIALS_FILE", str(tmp_path / "credentials.txt"))
    return root


@pytest.fixture
def settings(sn_root):
    from stealthnode import config

    values = config.fill_defaults({"SN_DOMAIN": "vpn.example.test", "SN_PUBLIC_IP": "203.0.113.10"}, "2.0.0")
    values["SN_XUI_API_TOKEN"] = "test-token"
    s = config.Settings(values)
    assert s.validate() == []
    config.save_settings(s)
    return s
