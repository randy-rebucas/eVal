"""The few Docker Engine API calls the sandbox needs, over the Unix socket (or tcp:// in development)."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import re
import tarfile
from urllib.parse import urlsplit

import aiohttp

API = "v1.43"


class DockerError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"Docker API {status}: {message}")
        self.status = status


class Docker:
    def __init__(self, host: str):
        self._host = host
        parts = urlsplit(host)
        if parts.scheme == "unix":
            self._connector: aiohttp.BaseConnector = aiohttp.UnixConnector(path=parts.path)
            self._base = f"http://docker/{API}"
        elif parts.scheme in ("tcp", "http"):
            self._connector = aiohttp.TCPConnector()
            self._base = f"http://{parts.netloc}/{API}"
        else:
            raise ValueError(f"Unsupported DOCKER_HOST {host!r}")
        self._session = aiohttp.ClientSession(connector=self._connector, timeout=aiohttp.ClientTimeout(total=120))

    async def close(self) -> None:
        await self._session.close()

    async def _call(self, method: str, path: str, *, params=None, json_body=None, data=None, headers=None,
                    expect=(200, 201, 204, 304)):
        async with self._session.request(method, self._base + path, params=params, json=json_body, data=data,
                                         headers=headers) as resp:
            body = await resp.read()
            if resp.status not in expect:
                try:
                    message = json.loads(body).get("message", "")
                except ValueError:
                    message = body[:200].decode(errors="replace")
                raise DockerError(resp.status, message)
            return resp.status, body

    async def runtimes(self) -> set[str]:
        _, body = await self._call("GET", "/info")
        return set((json.loads(body).get("Runtimes") or {}).keys())

    async def create(self, name: str, config: dict) -> str:
        _, body = await self._call("POST", "/containers/create", params={"name": name}, json_body=config)
        return json.loads(body)["Id"]

    async def put_archive(self, cid: str, path: str, tar: bytes) -> None:
        await self._call("PUT", f"/containers/{cid}/archive", params={"path": path, "copyUIDGID": "1"}, data=tar,
                         headers={"Content-Type": "application/x-tar"})

    async def start(self, cid: str) -> None:
        await self._call("POST", f"/containers/{cid}/start")

    async def kill(self, cid: str) -> None:
        """Stop and remove (containers are created with AutoRemove); a container already gone is fine."""
        await self._call("DELETE", f"/containers/{cid}", params={"force": "1"}, expect=(204, 404, 409))

    async def resize(self, cid: str, rows: int, cols: int) -> None:
        await self._call("POST", f"/containers/{cid}/resize", params={"h": str(rows), "w": str(cols)},
                         expect=(200, 201, 204, 404, 409, 500))

    async def list_sessions(self) -> list[dict]:
        """Running sandbox containers: [{"id", "session", "org", "expires"}]."""
        filters = json.dumps({"label": ["eval.sandbox=1"]})
        _, body = await self._call("GET", "/containers/json", params={"all": "1", "filters": filters})
        out = []
        for c in json.loads(body):
            labels = c.get("Labels") or {}
            out.append({"id": c["Id"], "session": labels.get("eval.session", ""), "org": labels.get("eval.org", ""),
                        "expires": int(labels.get("eval.expires", "0") or 0), "state": c.get("State", "")})
        return out

    async def read_file(self, cid: str, path: str, max_bytes: int) -> bytes | None:
        """One regular file from a container, or None if it is missing, not a regular file, or too large."""
        status, body = await self._call("GET", f"/containers/{cid}/archive", params={"path": path},
                                        expect=(200, 404))
        if status == 404:
            return None
        with tarfile.open(fileobj=io.BytesIO(body)) as tar:
            member = next(iter(tar.getmembers()), None)
            if member is None or not member.isfile() or member.size > max_bytes:
                return None
            f = tar.extractfile(member)
            return f.read() if f else None

    def attach(self, cid: str) -> Attach:
        """The container's terminal (stdin, stdout and stderr of its shell) as a raw byte stream."""
        return Attach(self._host, cid)


class Attach:
    """``POST /containers/{id}/attach`` upgraded to a raw stream, the way the docker CLI attaches. (The
    ``attach/ws`` websocket variant is unreliable across Docker versions.) With ``Tty`` on, the stream is not
    multiplexed: bytes in are keystrokes, bytes out are terminal output."""

    def __init__(self, host: str, cid: str):
        if not re.fullmatch(r"[0-9a-zA-Z_.-]{1,128}", cid):
            raise ValueError("bad container id")
        self._host, self._cid = host, cid
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def __aenter__(self) -> Attach:
        parts = urlsplit(self._host)
        if parts.scheme == "unix":
            self._reader, self._writer = await asyncio.open_unix_connection(parts.path)
        else:
            self._reader, self._writer = await asyncio.open_connection(parts.hostname, parts.port or 2375)
        self._writer.write(
            f"POST /{API}/containers/{self._cid}/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1\r\n"
            "Host: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n".encode())
        await self._writer.drain()
        head = await asyncio.wait_for(self._reader.readuntil(b"\r\n\r\n"), 10)
        status = head.split(b"\r\n", 1)[0].split(b" ")
        if len(status) < 2 or status[1] not in (b"101", b"200"):
            await self.__aexit__(None, None, None)
            raise DockerError(int(status[1]) if len(status) > 1 and status[1].isdigit() else 0, "attach refused")
        return self

    async def __aexit__(self, *exc) -> bool:
        if self._writer is not None:
            self._writer.close()
            with contextlib.suppress(OSError, ConnectionError):
                await self._writer.wait_closed()
        return False

    def __aiter__(self) -> Attach:
        return self

    async def __anext__(self) -> bytes:
        data = await self._reader.read(65536)
        if not data:
            raise StopAsyncIteration
        return data

    async def send_bytes(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()
