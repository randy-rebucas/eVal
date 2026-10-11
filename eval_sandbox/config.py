"""Sandbox service settings, from the environment. The service holds no database or repository credentials."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .tokens import MIN_SECRET_LENGTH


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class SandboxConfig:
    secret: str
    docker_host: str = "unix:///var/run/docker.sock"
    image: str = "eval-sandbox-workspace:latest"
    runtime: str = "runsc"  # gVisor: the workspace runs untrusted code, so a user-space kernel sits in between
    allow_runc: bool = False  # local development only: plain runc shares the host kernel
    network: str = "none"  # "none", or the name of a Docker network with an egress policy you control
    memory_mb: int = 2048
    cpus: float = 1.0
    pids: int = 256
    max_file_mb: int = 512
    max_sessions: int = 8
    max_per_org: int = 2
    max_minutes: int = 30
    idle_minutes: int = 10
    allowed_origins: list[str] = field(default_factory=list)  # eVal web origins allowed to open terminals
    host: str = "0.0.0.0"  # noqa: S104 - a container port; publish it behind TLS
    port: int = 8100

    def __post_init__(self) -> None:
        if len(self.secret) < MIN_SECRET_LENGTH:
            raise ValueError(f"EVAL_SANDBOX_SECRET must be at least {MIN_SECRET_LENGTH} characters")
        if self.runtime == "runc" and not self.allow_runc:
            raise ValueError("EVAL_SANDBOX_RUNTIME=runc shares the host kernel with untrusted code; use runsc "
                             "(gVisor), or set EVAL_SANDBOX_ALLOW_RUNC=true for local development only")
        if self.network in ("host", "bridge", "default") or self.network.startswith("container:"):
            raise ValueError("EVAL_SANDBOX_NETWORK must be 'none' or a dedicated network with an egress policy")
        if not self.allowed_origins:
            raise ValueError("EVAL_SANDBOX_ALLOWED_ORIGINS must list the eVal web origin (e.g. https://eval.example.com)")

    @property
    def insecure(self) -> bool:
        return self.runtime != "runsc"

    @classmethod
    def from_env(cls) -> SandboxConfig:
        return cls(
            secret=os.environ.get("EVAL_SANDBOX_SECRET", ""),
            docker_host=os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"),
            image=os.environ.get("EVAL_SANDBOX_IMAGE", "eval-sandbox-workspace:latest"),
            runtime=os.environ.get("EVAL_SANDBOX_RUNTIME", "runsc"),
            allow_runc=_bool("EVAL_SANDBOX_ALLOW_RUNC"),
            network=os.environ.get("EVAL_SANDBOX_NETWORK", "none"),
            memory_mb=_int("EVAL_SANDBOX_MEMORY_MB", 2048),
            cpus=float(os.environ.get("EVAL_SANDBOX_CPUS", "1.0")),
            pids=_int("EVAL_SANDBOX_PIDS", 256),
            max_file_mb=_int("EVAL_SANDBOX_MAX_FILE_MB", 512),
            max_sessions=_int("EVAL_SANDBOX_MAX_SESSIONS", 8),
            max_per_org=_int("EVAL_SANDBOX_MAX_PER_ORG", 2),
            max_minutes=_int("EVAL_SANDBOX_MAX_MINUTES", 30),
            idle_minutes=_int("EVAL_SANDBOX_IDLE_MINUTES", 10),
            allowed_origins=[o.strip().rstrip("/") for o in os.environ.get("EVAL_SANDBOX_ALLOWED_ORIGINS", "")
                             .split(",") if o.strip()],
            port=_int("EVAL_SANDBOX_PORT", 8100),
        )


def container_config(cfg: SandboxConfig, session: str, org: str, expires: int) -> dict:
    """Docker ``POST /containers/create`` body for one terminal session: no privileges, no network (by default),
    no mounts, no secrets in the environment, bounded memory/CPU/processes/file size, removed when it stops."""
    file_bytes = cfg.max_file_mb * 1024 * 1024
    memory = cfg.memory_mb * 1024 * 1024
    return {
        "Image": cfg.image,
        "User": "1000:1000",
        "WorkingDir": "/workspace",
        "Hostname": "sandbox",
        "Tty": True, "OpenStdin": True, "StdinOnce": False,
        "AttachStdin": True, "AttachStdout": True, "AttachStderr": True,
        "Env": ["TERM=xterm-256color", "HOME=/home/sandbox", "LANG=C.UTF-8"],
        "Labels": {"eval.sandbox": "1", "eval.session": session, "eval.org": org, "eval.expires": str(expires)},
        "NetworkDisabled": cfg.network == "none",
        "HostConfig": {
            "Runtime": cfg.runtime,
            "NetworkMode": cfg.network,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Memory": memory, "MemorySwap": memory,
            "NanoCpus": int(cfg.cpus * 1_000_000_000),
            "PidsLimit": cfg.pids,
            "Ulimits": [{"Name": "nofile", "Soft": 4096, "Hard": 4096},
                        {"Name": "fsize", "Soft": file_bytes, "Hard": file_bytes}],
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=256m"},  # noqa: S108 - the container's own private tmpfs
            "IpcMode": "private",
            "Init": True,
            "AutoRemove": True,
            "Binds": [], "Mounts": [], "Devices": [],
        },
    }
