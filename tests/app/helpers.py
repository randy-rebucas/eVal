from __future__ import annotations

import io
import zipfile
from pathlib import Path


def zip_bytes(src: Path, mutate=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*")):
            if p.is_file():
                z.write(p, f"myrepo-main/{p.relative_to(src).as_posix()}")
        if mutate:
            mutate(z)
    return buf.getvalue()


def make_project(client, org, name="Shop"):
    resp = client.post(f"/o/{org}/projects", data={"name": name})
    assert resp.status_code == 302, resp.data[:200]
    return resp.headers["Location"].rsplit("/", 1)[-1]


def upload_new(client, org, pid, data: bytes, name="vulnapp"):
    return client.post(
        f"/o/{org}/projects/{pid}/repos/new",
        data={"kind": "upload", "up-name": name, "up-archive": (io.BytesIO(data), "src.zip")},
        content_type="multipart/form-data",
    )
