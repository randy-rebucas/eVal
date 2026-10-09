"""Offline guard for the CLI: block and record outbound network access from this process.

Loopback stays allowed (on-device model servers). This covers eVal's own Python code — OSV lookups and AI
clients; external analyzers run as subprocesses and are kept offline by their flags or skipped
(see ``Analyzer.network_required``). Not for the web worker: it patches ``socket`` process-wide and the worker
needs its database and Redis connections.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from contextlib import contextmanager

_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


class OfflineViolation(OSError):
    pass


def _is_local(host) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "ignore")
    host = str(host).strip("[]").split("%", 1)[0].lower()
    if host in _LOCAL_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@contextmanager
def block_outbound() -> Iterator[list[str]]:
    """Within the block, non-loopback DNS lookups and connections raise ``OfflineViolation``. Yields the list of
    blocked destinations (``host`` or ``host:port``), in order, so callers can report them."""
    blocked: list[str] = []
    orig_getaddrinfo = socket.getaddrinfo
    orig_connect, orig_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def _deny(target: str):
        blocked.append(target)
        return OfflineViolation(f"eVal offline mode blocked network access to {target}")

    def getaddrinfo(host, *args, **kwargs):
        if not _is_local(host):
            raise _deny(str(host))
        return orig_getaddrinfo(host, *args, **kwargs)

    def _check(sock, address) -> None:
        if sock.family in (socket.AF_INET, socket.AF_INET6) and isinstance(address, tuple) and \
                not _is_local(address[0]):
            raise _deny(f"{address[0]}:{address[1]}")

    def connect(self, address):
        _check(self, address)
        return orig_connect(self, address)

    def connect_ex(self, address):
        _check(self, address)
        return orig_connect_ex(self, address)

    socket.getaddrinfo, socket.socket.connect, socket.socket.connect_ex = getaddrinfo, connect, connect_ex
    try:
        yield blocked
    finally:
        socket.getaddrinfo, socket.socket.connect, socket.socket.connect_ex = (orig_getaddrinfo, orig_connect,
                                                                              orig_connect_ex)
