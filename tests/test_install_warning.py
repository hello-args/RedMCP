"""Tests for application venv install warning."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from mcts._install_warning import maybe_warn_venv_install, should_warn_app_venv


def test_should_warn_in_app_venv_with_pyproject(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "my-app"\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / ".venv"))
    assert should_warn_app_venv() is True


def test_should_not_warn_without_virtual_env(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "my-app"\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    assert should_warn_app_venv() is False


def test_should_not_warn_in_mcts_dev_checkout(monkeypatch) -> None:
    root = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(root)
    monkeypatch.setenv("VIRTUAL_ENV", str(root / ".venv"))
    assert should_warn_app_venv() is False


def test_mcts_no_venv_warn_skips(monkeypatch, capsys) -> None:
    with patch("mcts._install_warning.should_warn_app_venv", return_value=True):
        monkeypatch.setenv("MCTS_NO_VENV_WARN", "1")
        import mcts._install_warning as mod

        mod._WARNED = False
        from rich.console import Console

        maybe_warn_venv_install(Console())
        captured = capsys.readouterr()
        assert "project virtual environment" not in captured.err


def test_maybe_warn_prints_once(monkeypatch, capsys) -> None:
    from rich.console import Console

    with patch("mcts._install_warning.should_warn_app_venv", return_value=True):
        monkeypatch.delenv("MCTS_NO_VENV_WARN", raising=False)
        import mcts._install_warning as mod

        mod._WARNED = False
        maybe_warn_venv_install(Console())
        maybe_warn_venv_install(Console())
        captured = capsys.readouterr()
        assert captured.err.count("project virtual environment") == 1
        assert "openai" in captured.err
