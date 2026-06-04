from __future__ import annotations

import base64
import subprocess
from pathlib import Path

import pytest

from repolens.security.clone import (
    CloneCredential,
    CloneOptions,
    _build_clone_command,
    _scrubbed_git_env,
    _validate_gitmodules,
    classify_git_failure,
    hardened_clone,
)
from repolens.security.errors import (
    CloneAccessDenied,
    CloneAuthRequired,
    CloneRateLimited,
    CloneSecurityError,
    CloneTransient,
)
from repolens.security.limits import SecurityLimits


def test_clone_uses_all_hardening_flags(tmp_path: Path) -> None:
    command = _build_clone_command(
        CloneOptions("https://example.invalid/acme.git", tmp_path / "dst"),
        tmp_path / "clone",
    )
    joined = " ".join(command)
    assert "-c protocol.file.allow=never" in joined
    assert "-c core.hooksPath=/dev/null" in joined
    assert "-c core.symlinks=false" in joined
    assert "--depth=1" in command
    assert "--no-tags" in command
    assert "--single-branch" in command
    assert "--no-recurse-submodules" in command
    assert command[-3:] == ["--", "https://example.invalid/acme.git", str(tmp_path / "clone")]


def test_clone_scrubs_git_environment() -> None:
    token = "ghp_" + "acme" * 5
    env = _scrubbed_git_env(
        {
            "PATH": "/bin",
            "GIT_ASKPASS": "leak",
            "GITHUB_TOKEN": token,
            "GIT_CONFIG_GLOBAL": "/tmp/unsafe",
        }
    )
    assert env["PATH"] == "/bin"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_COUNT"] == "0"
    assert "GIT_ASKPASS" not in env
    assert "GITHUB_TOKEN" not in env


def test_clone_rejects_file_remote(tmp_path: Path) -> None:
    with pytest.raises(CloneSecurityError):
        hardened_clone(CloneOptions("file:///tmp/acme.git", tmp_path / "dst"))


def test_clone_rejects_file_submodule_url(tmp_path: Path) -> None:
    gitmodules = tmp_path / ".gitmodules"
    gitmodules.write_text(
        '[submodule "acme-lib"]\n\tpath = vendor/acme-lib\n\turl = file:///tmp/acme-lib\n',
        encoding="utf-8",
    )
    with pytest.raises(CloneSecurityError):
        _validate_gitmodules(gitmodules)


def test_clone_rejects_git_config_dotted_submodule_url(tmp_path: Path) -> None:
    gitmodules = tmp_path / ".gitmodules"
    gitmodules.write_text(
        "[submodule.acme-lib]\n\tpath = vendor/acme-lib\n\turl = file:///tmp/acme-lib\n",
        encoding="utf-8",
    )
    with pytest.raises(CloneSecurityError):
        _validate_gitmodules(gitmodules)


def test_clone_cleans_tempdir_on_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="fatal: acme failure\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(CloneSecurityError):
        hardened_clone(CloneOptions("https://example.invalid/acme.git", tmp_path / "dst"))
    assert not list(tmp_path.glob(".dst.clone-*"))
    assert len(calls) == 2


def test_clone_failure_redacts_supported_tokens(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token = "ghp_" + "1234567890abcdef1234567890abcdef1234"

    def fake_run(command, **kwargs):
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr=f"fatal: Authentication failed for https://x:{token}@allowed.example/acme.git\n",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(CloneSecurityError) as exc_info:
        hardened_clone(CloneOptions("https://allowed.example/acme.git", tmp_path / "dst"))

    assert token not in str(exc_info.value)
    assert "[REDACTED_TOKEN]" in str(exc_info.value)


def test_clone_timeout_cleans_tempdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command, **kwargs):
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        raise subprocess.TimeoutExpired(command, timeout=kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    limits = SecurityLimits(clone_timeout_seconds=0.01)
    with pytest.raises(CloneSecurityError, match="timed out"):
        hardened_clone(
            CloneOptions("https://example.invalid/acme.git", tmp_path / "dst", limits=limits)
        )
    assert not list(tmp_path.glob(".dst.clone-*"))


def test_clone_rejects_old_git_version(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="git version 2.44.0\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(CloneSecurityError, match="below required"):
        hardened_clone(CloneOptions("https://example.invalid/acme.git", tmp_path / "dst"))


# --- credential injection -------------------------------------------------


def test_scrubbed_env_injects_extraheader_when_credential_present() -> None:
    token = "ghp_" + "A" * 36
    env = _scrubbed_git_env({"PATH": "/bin"}, credential=CloneCredential(token))

    assert env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
    expected = base64.b64encode(f"x-access-token:{token}".encode()).decode("ascii")
    assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {expected}"
    # The raw token never appears verbatim in the env (only its base64 form).
    assert token not in env["GIT_CONFIG_VALUE_0"]


def test_scrubbed_env_no_credential_keeps_count_zero() -> None:
    env = _scrubbed_git_env({"PATH": "/bin"})
    assert env["GIT_CONFIG_COUNT"] == "0"
    assert "GIT_CONFIG_KEY_0" not in env
    assert not any("Authorization" in value for value in env.values())


def test_clone_credential_repr_is_redacted() -> None:
    token = "ghp_" + "B" * 36
    cred = CloneCredential(token)
    assert token not in repr(cred)
    assert token not in str(cred)
    assert "<redacted>" in repr(cred)


def test_clone_options_repr_hides_credential() -> None:
    token = "ghp_" + "C" * 36
    options = CloneOptions(
        "https://example.invalid/acme.git",
        Path("/tmp/dst"),
        credential=CloneCredential(token),
    )
    encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode("ascii")
    assert token not in repr(options)
    assert encoded not in repr(options)


def test_classify_git_failure_maps_auth_403_429_transient() -> None:
    assert classify_git_failure(128, "fatal: could not read Username for 'https://github.com'") is (
        CloneAuthRequired
    )
    assert classify_git_failure(128, "terminal prompts disabled") is CloneAuthRequired
    assert classify_git_failure(128, "remote: HTTP 403 Forbidden") is CloneAccessDenied
    assert classify_git_failure(128, "The requested URL returned error: 403") is (CloneAccessDenied)
    assert classify_git_failure(128, "remote: Repository not found.") is CloneAccessDenied
    assert classify_git_failure(128, "The requested URL returned error: 404") is (CloneAccessDenied)
    assert classify_git_failure(128, "Permission denied") is CloneAccessDenied
    assert classify_git_failure(128, "HTTP 429 too many requests") is CloneRateLimited
    assert classify_git_failure(128, "The requested URL returned error: 429") is (CloneRateLimited)
    assert classify_git_failure(128, "You have exceeded a secondary rate limit") is CloneRateLimited
    assert classify_git_failure(128, "fatal: The requested URL returned error: 503") is (
        CloneTransient
    )
    assert classify_git_failure(128, "fatal: unable to access: Connection reset by peer") is (
        CloneTransient
    )
    assert classify_git_failure(128, "fatal: unable to access: Could not resolve host") is (
        CloneTransient
    )
    # Timeout-class stderr (a gh/git-reported network timeout) is transient too.
    assert classify_git_failure(128, "error: Operation timed out after 30000 ms") is CloneTransient
    # Unrecognised stays the generic base class.
    assert classify_git_failure(1, "fatal: something else entirely") is CloneSecurityError


def test_classify_git_failure_ignores_incidental_numeric_substrings() -> None:
    assert classify_git_failure(128, "processed 403 objects before failing") is (CloneSecurityError)
    assert classify_git_failure(128, "processed 404 objects before failing") is CloneSecurityError
    assert classify_git_failure(128, "wrote 429 bytes before failing") is CloneSecurityError
    assert classify_git_failure(128, "processed 503 objects before failing") is (CloneSecurityError)


def test_classify_git_failure_ambiguous_403_rate_limit_is_access_denied() -> None:
    # A 403 that also mentions "rate limit" must classify as access-denied (never
    # retried), because auth/access precedence wins over rate-limit/transient.
    assert classify_git_failure(128, "remote: HTTP 403: rate limit-ish wording") is (
        CloneAccessDenied
    )


def test_clone_injects_credential_env_into_subprocess(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token = "ghp_" + "D" * 36
    captured: dict[str, dict[str, str]] = {}

    def fake_run(command, **kwargs):
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        captured["env"] = kwargs["env"]
        # Materialise the clone target so the move + gitmodules steps succeed.
        clone_path = Path(command[-1])
        clone_path.mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    hardened_clone(
        CloneOptions(
            "https://github.com/acme-owner/acme.git",
            tmp_path / "dst",
            credential=CloneCredential(token),
        )
    )

    clone_env = captured["env"]
    assert clone_env["GIT_CONFIG_COUNT"] == "1"
    assert "Authorization: Basic " in clone_env["GIT_CONFIG_VALUE_0"]


def test_clone_timeout_raises_transient(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command, **kwargs):
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        raise subprocess.TimeoutExpired(command, timeout=kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    limits = SecurityLimits(clone_timeout_seconds=0.01)
    with pytest.raises(CloneTransient, match="timed out"):
        hardened_clone(
            CloneOptions("https://example.invalid/acme.git", tmp_path / "dst", limits=limits)
        )
