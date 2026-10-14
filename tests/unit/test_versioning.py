"""Журнал версий не расходится с кодом: VERSION, __version__, CHANGELOG, versions.env."""

from __future__ import annotations

import re
from pathlib import Path

import stealthnode

ROOT = Path(__file__).resolve().parents[2]


def test_version_file_matches_package():
    assert (ROOT / "VERSION").read_text().strip() == stealthnode.__version__


def test_changelog_has_entry_for_current_version():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"^## \[{re.escape(stealthnode.__version__)}\] — \d{{4}}-\d{{2}}-\d{{2}}$", text, re.M)
    assert "## [Unreleased]" in text


def test_pinned_versions_are_well_formed():
    env = (ROOT / "stealthnode" / "versions.env").read_text()
    assert re.search(r'^XUI_VERSION="v\d+\.\d+\.\d+"$', env, re.M)
    assert re.search(r'^XUI_INSTALL_SHA256="[0-9a-f]{64}"$', env, re.M)
    assert "${XUI_VERSION}/install.sh" in env
