from __future__ import annotations

import io
import os
import stat
import zipfile

import pytest

from eval_engine import workspace as ws
from eval_engine.workspace import Limits, WorkspaceError, extract_zip


def make_zip(path, entries):
    """entries: list of (name, data_bytes) or (ZipInfo, data)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return path


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/etc/passwd", "C:/Windows/x.txt",
                                  "..\\evil.py", "a\\..\\..\\b"])
def test_traversal_and_absolute_paths_rejected(tmp_path, name):
    z = make_zip(tmp_path / "x.zip", [("ok.txt", b"ok"), (name, b"bad")])
    with pytest.raises(WorkspaceError):
        extract_zip(z, tmp_path / "out")
    assert not (tmp_path / "evil.py").exists()


def test_extracts_and_strips_single_top_level_dir(tmp_path):
    z = make_zip(tmp_path / "x.zip", [("repo-abc123/app.py", b"print(1)"), ("repo-abc123/pkg/mod.py", b"x=1")])
    stats = extract_zip(z, tmp_path / "out")
    assert (tmp_path / "out" / "app.py").read_text() == "print(1)"
    assert (tmp_path / "out" / "pkg" / "mod.py").exists()
    assert stats.files == 2


def test_symlink_members_are_skipped(tmp_path):
    info = zipfile.ZipInfo("link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(tmp_path / "x.zip", "w") as z:
        z.writestr("a.txt", "a")
        z.writestr(info, "/etc/passwd")
    stats = extract_zip(tmp_path / "x.zip", tmp_path / "out")
    assert not (tmp_path / "out" / "link").exists()
    assert any("symlink" in s for s in stats.skipped)


def test_zip_bomb_ratio_rejected(tmp_path):
    z = make_zip(tmp_path / "x.zip", [("big.txt", b"0" * 5_000_000)])
    with pytest.raises(WorkspaceError, match="compression ratio"):
        extract_zip(z, tmp_path / "out", Limits(max_compression_ratio=100))


def test_total_size_and_file_count_limits(tmp_path):
    z = make_zip(tmp_path / "x.zip", [(f"f{i}.txt", os.urandom(1000)) for i in range(5)])
    with pytest.raises(WorkspaceError, match="file limit"):
        extract_zip(z, tmp_path / "o1", Limits(max_files=3))
    with pytest.raises(WorkspaceError, match="total"):
        extract_zip(z, tmp_path / "o2", Limits(max_total_bytes=2500))


def test_oversized_member_skipped_not_extracted(tmp_path):
    z = make_zip(tmp_path / "x.zip", [("small.txt", b"x"), ("large.bin", os.urandom(5000))])
    stats = extract_zip(z, tmp_path / "out", Limits(max_file_bytes=1000))
    assert not (tmp_path / "out" / "large.bin").exists()
    assert any("size limit" in s for s in stats.skipped)


def test_lying_header_size_detected(tmp_path):
    """A member whose real data exceeds its declared size must not be written past the limit."""
    path = tmp_path / "x.zip"
    make_zip(path, [("a.txt", b"A" * 4000)])
    raw = bytearray(path.read_bytes())
    # Patch the uncompressed size in the central directory and local header to claim 10 bytes.
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        idx = raw.find(sig)
        off = 22 if sig == b"PK\x03\x04" else 24
        raw[idx + off: idx + off + 4] = (10).to_bytes(4, "little")
    path.write_bytes(bytes(raw))
    with pytest.raises((WorkspaceError, zipfile.BadZipFile)):
        extract_zip(path, tmp_path / "out", Limits(max_compression_ratio=10_000))


def test_not_a_zip(tmp_path):
    p = tmp_path / "x.zip"
    p.write_bytes(b"not a zip")
    with pytest.raises(WorkspaceError, match="valid ZIP"):
        extract_zip(p, tmp_path / "out")


def test_encrypted_member_rejected(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", "x")
    data = bytearray(buf.getvalue())
    # Set the "encrypted" general-purpose flag bit in the local and central headers.
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = data.find(sig)
        data[i + off] |= 0x1
    (tmp_path / "x.zip").write_bytes(bytes(data))
    with pytest.raises(WorkspaceError, match="Encrypted"):
        extract_zip(tmp_path / "x.zip", tmp_path / "out")


def test_safe_join_blocks_escape(tmp_path):
    assert ws.safe_join(tmp_path, "a/b.txt") == (tmp_path / "a" / "b.txt").resolve()
    with pytest.raises(WorkspaceError):
        ws.safe_join(tmp_path, "../outside.txt")


@pytest.mark.parametrize("url", [
    "http://github.com/a/b", "git@github.com:a/b.git", "https://evil.com/a/b", "https://user:pw@github.com/a/b",
    "https://github.com/a/b?x=1", "https://github.com/a", "https://github.com:8443/a/b", "file:///etc/passwd",
    "ext::sh -c touch% /tmp/pwned", "https://github.com/a/b/../../c",
])
def test_git_url_validation_rejects(url):
    with pytest.raises(WorkspaceError):
        ws.validate_git_url(url, ["github.com"])


def test_git_url_validation_accepts():
    assert ws.validate_git_url("https://github.com/octo-org/my.repo.git", ["github.com"]) == (
        "github.com", "octo-org", "my.repo")


@pytest.mark.parametrize("ref", ["--upload-pack=x", "a..b", "main@{1}", "feat/", "x.lock", "", "a b", "-x"])
def test_ref_validation_rejects(ref):
    with pytest.raises(WorkspaceError):
        ws.validate_ref(ref)


@pytest.mark.parametrize("ref", ["main", "release/1.2", "v1.0.0", "a" * 40, "feature/JIRA-12_fix"])
def test_ref_validation_accepts(ref):
    assert ws.validate_ref(ref) == ref


def test_git_env_keeps_token_out_of_argv_and_disables_dangerous_features(tmp_path):
    env = ws._git_env("ghp_" + "x" * 36, tmp_path)
    pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert pairs["protocol.allow"] == "never" and pairs["protocol.https.allow"] == "always"
    assert pairs["core.symlinks"] == "false" and pairs["submodule.recurse"] == "false"
    assert pairs["http.extraHeader"].startswith("Authorization: Basic ")
    assert "ghp_" not in pairs["http.extraHeader"]  # base64-encoded, never raw
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert "EVAL_SECRET_KEY" not in env


def test_git_error_sanitized():
    class E(Exception):
        stderr = "fatal: Authorization: Basic eC1hY2Nlc3M6c2VjcmV0 failed for tok_SECRET123"

    msg = ws._sanitize_git_error(E(), "tok_SECRET123")
    assert "SECRET" not in msg and "eC1h" not in msg


def test_iter_files_skips_vendor_dirs_symlinks_and_large_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("x")
    (tmp_path / "big.txt").write_bytes(b"x" * 2000)
    files = list(ws.iter_files(tmp_path, max_file_bytes=1000))
    assert files == ["src/a.py"]


def test_read_text_rejects_binary(tmp_path):
    (tmp_path / "b.bin").write_bytes(b"\x00\x01\x02")
    (tmp_path / "t.txt").write_text("hello")
    assert ws.read_text(tmp_path, "b.bin") is None
    assert ws.read_text(tmp_path, "t.txt") == "hello"
    assert ws.read_text(tmp_path, "../etc/passwd") is None
