import io
import subprocess
import tarfile
from http.client import IncompleteRead

import pytest

from backend.repository import git_client


def test_https_clone_forces_http11_without_global_git_configuration(monkeypatch, tmp_path):
    commands = []

    def fake_run(command):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(git_client, "_run_git", fake_run)

    git_client._git_clone("https://github.com/example/repo", tmp_path / "repo", None)

    assert commands == [[
        "git", "-c", "http.version=HTTP/1.1", "clone", "-v", "--depth=1",
        "--", "https://github.com/example/repo", str(tmp_path / "repo"),
    ]]


def test_failed_branch_clone_falls_back_to_github_archive_at_requested_branch(monkeypatch, tmp_path):
    commands = []
    archive_calls = []

    def fail_git(command):
        commands.append(command)
        return subprocess.CompletedProcess(command, 128, b"", b"early EOF")

    def fake_archive(url, dest, ref):
        archive_calls.append((url, dest, ref))
        dest.mkdir()

    monkeypatch.setattr(git_client, "_run_git", fail_git)
    monkeypatch.setattr(git_client, "_clone_github_archive", fake_archive, raising=False)

    dest = tmp_path / "repo"
    git_client._git_clone("https://github.com/example/repo.git", dest, "release-1.2")

    assert archive_calls == [
        ("https://github.com/example/repo.git", dest, "release-1.2"),
    ]
    assert len(commands) == 1
    assert commands[0][commands[0].index("--branch") + 1] == "release-1.2"


def test_failed_pinned_commit_clone_falls_back_to_same_github_archive_ref(monkeypatch, tmp_path):
    commit = "a" * 40
    archive_calls = []

    def fail_fetch(command):
        return subprocess.CompletedProcess(command, 128, b"", b"early EOF")

    def fake_archive(url, dest, ref):
        archive_calls.append((url, dest, ref))
        dest.mkdir()

    monkeypatch.setattr(git_client, "_run_git", fail_fetch)
    monkeypatch.setattr(git_client, "_clone_github_archive", fake_archive, raising=False)

    dest = tmp_path / "repo"
    git_client._git_clone("https://github.com/example/repo", dest, commit)

    assert archive_calls == [
        ("https://github.com/example/repo", dest, commit),
    ]


def test_github_archive_url_encodes_requested_ref_and_rejects_other_hosts():
    assert git_client._github_archive_url(
        "https://github.com/example/repo.git", "feature/static-scan",
    ) == "https://api.github.com/repos/example/repo/tarball/feature%2Fstatic-scan"
    assert git_client._github_archive_url("https://gitlab.com/example/repo", "main") is None


def test_github_archive_extraction_rejects_path_traversal(tmp_path):
    archive_path = tmp_path / "source.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("../outside.py")
        content = b"print('unsafe')\n"
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))

    with pytest.raises(RuntimeError, match="unsafe archive member"):
        git_client._extract_github_archive(archive_path, tmp_path / "extracted")


def test_github_archive_download_retries_after_incomplete_response(monkeypatch, tmp_path):
    attempts = []

    class FakeResponse:
        def __init__(self, chunks):
            self.chunks = iter(chunks)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            item = next(self.chunks)
            if isinstance(item, Exception):
                raise item
            return item

    def fake_urlopen(request, timeout):
        attempts.append((request.full_url, timeout))
        if len(attempts) == 1:
            return FakeResponse([IncompleteRead(b"partial", 10)])
        return FakeResponse([b"complete archive", b""])

    monkeypatch.setattr(git_client, "urlopen", fake_urlopen)
    destination = tmp_path / "source.tar.gz"

    git_client._download_github_archive("https://api.github.com/example/archive", destination)

    assert len(attempts) == 2
    assert destination.read_bytes() == b"complete archive"


def test_github_archive_download_removes_partial_file_after_size_limit(monkeypatch, tmp_path):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            return b"too large" if not hasattr(self, "read_once") else b""

    response = FakeResponse()
    monkeypatch.setattr(git_client, "urlopen", lambda *args, **kwargs: response)
    monkeypatch.setattr(git_client, "_MAX_GITHUB_ARCHIVE_BYTES", 1)
    destination = tmp_path / "source.tar.gz"

    with pytest.raises(RuntimeError, match="download limit"):
        git_client._download_github_archive("https://api.github.com/example/archive", destination)

    assert not destination.with_name("source.tar.gz.part").exists()


def test_github_archive_download_uses_bounded_read_timeout(monkeypatch, tmp_path):
    timeouts = []

    class FakeResponse:
        def __init__(self):
            self.reads = [b"archive", b""]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            return self.reads.pop(0)

    def fake_urlopen(request, timeout):
        timeouts.append(timeout)
        return FakeResponse()

    monkeypatch.setattr(git_client, "urlopen", fake_urlopen)
    monkeypatch.setattr(git_client.settings, "git_clone_timeout", 600)

    git_client._download_github_archive(
        "https://api.github.com/example/archive", tmp_path / "source.tar.gz",
    )

    assert timeouts == [git_client._GITHUB_ARCHIVE_READ_TIMEOUT]
