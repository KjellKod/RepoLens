from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def block_live_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_connect(*args: object, **kwargs: object) -> None:
        raise RuntimeError("live network is disabled for security tests")

    monkeypatch.setattr(socket, "create_connection", fail_connect)
    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", fail_connect)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def synthetic_fixture_root(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures" / "synthetic"


@pytest.fixture(scope="session")
def fixture_manifest_path(synthetic_fixture_root: Path) -> Path:
    return synthetic_fixture_root / "fixture_manifest.json"


def git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )


def create_local_repo(root: Path, *, gitmodules: str | None = None) -> Path:
    repo = root / "acme-source"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "acme@example.invalid")
    git(repo, "config", "user.name", "Acme Tester")
    (repo / "README.md").write_text("acme fixture\n", encoding="utf-8")
    if gitmodules is not None:
        (repo / ".gitmodules").write_text(gitmodules, encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "initial")
    return repo


@pytest.fixture
def local_repo_factory(tmp_path: Path):
    def factory(*, gitmodules: str | None = None) -> Path:
        return create_local_repo(tmp_path, gitmodules=gitmodules)

    return factory
