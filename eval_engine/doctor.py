"""``eval-audit doctor``: check this machine for local, private audits.

Reports which analyzers are installed, whether a local model server is reachable and has the model, and which
checks would be skipped under ``--offline``. Read-only: it never installs tools or pulls models.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import ENGINE_VERSION, sandbox
from .ai.local import is_loopback_url
from .analyzers import registry
from .analyzers.base import AnalyzerContext
from .languages import LanguageReport


@dataclass
class ModelServerStatus:
    reachable: bool
    models: list[str] = field(default_factory=list)
    error: str = ""

    def has(self, model: str) -> bool:
        # Ollama lists "name:tag"; a bare name means ":latest".
        wanted = model if ":" in model else f"{model}:latest"
        return any(m in (model, wanted) for m in self.models)


def probe_model_server(base_url: str, timeout: float = 3.0) -> ModelServerStatus:
    """GET ``{base_url}/models`` (OpenAI-compatible). Loopback only, proxies ignored."""
    if not is_loopback_url(base_url):
        return ModelServerStatus(False, error="not a loopback address")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # loopback only, checked above
    try:
        with opener.open(base_url.rstrip("/") + "/models", timeout=timeout) as resp:  # nosec B310
            data = json.loads(resp.read(1_000_000))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return ModelServerStatus(False, error=str(reason)[:200])
    items = data.get("data") if isinstance(data, dict) else None
    models = sorted(str(m.get("id")) for m in items or [] if isinstance(m, dict) and m.get("id"))
    return ModelServerStatus(True, models=models)


def run_doctor(*, ai_url: str, ai_model: str, out) -> int:
    """Print a readiness report. Exit 0 when ``--ai local`` will work with ``ai_model``, else 1."""
    ctx = AnalyzerContext(root=Path.cwd(), files=[], languages=LanguageReport())
    analyzers = registry.all_analyzers()

    def line(status: str, name: str, note: str = "") -> None:
        out.write(f"  {status:<8} {name:<16} {note}".rstrip() + "\n")

    out.write(f"eVal engine {ENGINE_VERSION}\n\nAnalyzers\n")
    for a in analyzers:
        if a.tool and sandbox.which(a.tool) is None:
            line("missing", a.name, f"{a.tool} not installed; its checks are reported as not assessed")
        else:
            line("ok", a.name, a.tool or "built-in")

    out.write(f"\nLocal AI ({ai_url})\n")
    server = probe_model_server(ai_url)
    ready = False
    if not server.reachable:
        line("missing", "model server", f"unreachable ({server.error}); install Ollama and run `ollama serve`, "
                                        "or start LM Studio's local server")
    else:
        line("ok", "model server", f"{len(server.models)} model(s): {', '.join(server.models[:8]) or 'none'}")
        ready = server.has(ai_model)
        line("ok" if ready else "missing", "model", ai_model if ready else
             f"{ai_model} not available; run `ollama pull {ai_model}` or pass --ai-model")

    out.write("\nNetwork use (see docs/NETWORK.md)\n")
    local = [a.name for a in analyzers if not a.network_use]
    line("local", "analyzers", ", ".join(local))
    line("local", "AI (--ai local)", f"{ai_url} on this machine; proxies ignored")
    for a in analyzers:
        if a.network_use:
            installed = not (a.tool and sandbox.which(a.tool) is None)
            offline = ("skipped" if a.network_required(ctx) else "runs offline") if installed else "not installed"
            line("internet", a.name, f"{a.network_use} [--offline: {offline}]")

    out.write("\n" + ("Ready: eval-audit PATH --ai local" + (f" --ai-model {ai_model}" if ai_model else "")
                      if ready else "Not ready for --ai local (see above). Audits without AI still work.") + "\n")
    return 0 if ready else 1
