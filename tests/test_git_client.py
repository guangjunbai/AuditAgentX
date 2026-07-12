import subprocess

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
