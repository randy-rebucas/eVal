"""Render deployment files stay consistent with the main image and the app's required configuration."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def instructions(path: Path) -> list[str]:
    """Dockerfile instructions with continuation lines joined and whitespace normalised."""
    text = re.sub(r"\\\n", " ", path.read_text(encoding="utf-8"))
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    return [re.sub(r"\s+", " ", ln) for ln in lines]


def test_render_image_has_the_same_toolchain_as_the_main_image():
    render = set(instructions(ROOT / "Dockerfile.render"))
    # Expected differences: Render runs as root until the start script drops privileges, uses its own CMD/port,
    # and keeps the Trivy cache on its disk instead of a separate volume.
    skip = ("USER ", "CMD ", "EXPOSE ", "RUN useradd ")
    missing = [i for i in instructions(ROOT / "Dockerfile") if not i.startswith(skip) and i not in render]
    assert missing == []


def test_blueprint_supplies_required_settings():
    blueprint = (ROOT / "render.yaml").read_text(encoding="utf-8")
    assert "dockerfilePath: ./Dockerfile.render" in blueprint
    for key in ("EVAL_SECRET_KEY", "DATABASE_URL", "EVAL_ENCRYPTION_KEYS", "REDIS_URL"):  # config.validate + Celery
        assert f"key: {key}" in blueprint
    assert "maxmemoryPolicy: noeviction" in blueprint
    assert "preDeployCommand: flask db upgrade" in blueprint
    assert "COPY scripts/render-start.sh" in (ROOT / "Dockerfile.render").read_text(encoding="utf-8")


def test_start_script_is_valid_bash_with_lf_endings():
    script = ROOT / "scripts" / "render-start.sh"
    assert b"\r\n" not in script.read_bytes()
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available")
    # Syntax check via stdin: on Windows `bash` may be WSL's, which cannot open Windows paths.
    result = subprocess.run([bash, "-n"], input=script.read_bytes(), capture_output=True)  # noqa: S603  # nosec B603
    if result.returncode == 127 or b"not installed" in result.stderr.lower():
        pytest.skip("bash is not usable here")
    assert result.returncode == 0, result.stderr.decode(errors="replace")
