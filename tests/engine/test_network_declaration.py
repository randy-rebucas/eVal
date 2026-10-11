"""Keep the declared network use (Analyzer.network_use, docs/NETWORK.md) in sync with the code."""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from eval_engine.analyzers import registry

ROOT = Path(__file__).resolve().parents[2]
# Code that can open a connection from Python. Tool-based analyzers are covered by the explicit list below,
# because their network use happens inside the external program.
NETWORK_CODE = re.compile(r"^\s*(?:import|from)\s+(?:requests|urllib\.request|http\.client|httpx|socket|aiohttp)\b",
                          re.M)
INTERNET_ANALYZERS = {"osv", "registry", "semgrep", "trivy"}


def test_declared_internet_analyzers():
    declared = {a.name for a in registry.all_analyzers() if a.network_use}
    assert declared == INTERNET_ANALYZERS, "update docs/NETWORK.md when this set changes"


def test_analyzers_that_open_connections_declare_it():
    for analyzer in registry.all_analyzers():
        cls = type(analyzer)
        module_imports = [ln for ln in inspect.getsource(inspect.getmodule(cls)).splitlines()
                          if NETWORK_CODE.match(ln) and not ln[:1].isspace()]
        # A module-level import counts against every analyzer in the module; a local import only against its class.
        if module_imports or NETWORK_CODE.search(inspect.getsource(cls)):
            assert analyzer.network_use, f"{analyzer.name} can open connections but declares no network_use"


def test_internet_analyzers_are_skipped_offline_unless_configured(monkeypatch, tmp_path):
    from eval_engine.analyzers.base import AnalyzerContext
    from eval_engine.languages import LanguageReport

    monkeypatch.delenv("EVAL_SEMGREP_CONFIG", raising=False)
    monkeypatch.delenv("EVAL_TRIVY_CACHE_DIR", raising=False)
    # Trivy's default per-user cache: empty here, whatever this machine has already downloaded.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    ctx = AnalyzerContext(root=ROOT, files=[], languages=LanguageReport(), offline=True)
    for analyzer in registry.all_analyzers():
        needs = analyzer.network_required(ctx)
        assert bool(needs) == bool(analyzer.network_use), analyzer.name


def test_trivy_uses_a_persistent_default_cache(monkeypatch, tmp_path):
    """The sandbox gives each tool run a throwaway HOME, so without a default cache Trivy would re-download its
    database (over 1 GB) on every audit."""
    from eval_engine.analyzers import trivy
    from eval_engine.analyzers.base import AnalyzerContext
    from eval_engine.languages import LanguageReport

    monkeypatch.delenv("EVAL_TRIVY_CACHE_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    cache = tmp_path / "eval" / "trivy"
    assert trivy.cache_dir() == str(cache) and cache.is_dir()
    ctx = AnalyzerContext(root=ROOT, files=[], languages=LanguageReport(), offline=True)
    analyzer = registry.get(["trivy"])[0]
    assert analyzer.network_required(ctx)  # empty cache: needs the network
    (cache / "db").mkdir()
    (cache / "db" / "trivy.db").write_bytes(b"")
    assert analyzer.network_required(ctx) is None  # pre-seeded: works offline
    monkeypatch.setenv("EVAL_TRIVY_CACHE_DIR", str(tmp_path / "configured"))
    assert trivy.cache_dir() == str(tmp_path / "configured")  # the operator's setting wins


def test_network_doc_lists_every_internet_analyzer():
    doc = (ROOT / "docs" / "NETWORK.md").read_text(encoding="utf-8")
    for name in INTERNET_ANALYZERS:
        assert f"`{name}`" in doc
    for host in ("api.osv.dev", "semgrep.dev", "mirror.gcr.io", "api.github.com", "cdn.jsdelivr.net"):
        assert host in doc
