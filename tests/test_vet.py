"""Tests for pre-install package vetting."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mcts.reporting.models import Severity
from mcts.vet.parse import parse_package_spec
from mcts.vet.runner import run_vet


def test_parse_package_spec_pypi() -> None:
    spec = parse_package_spec("pypi:requests@2.31.0")
    assert spec.ecosystem == "pypi"
    assert spec.name == "requests"
    assert spec.version == "2.31.0"


def test_parse_package_spec_pypi_colon_version() -> None:
    spec = parse_package_spec("pypi:kubernetes:25.0.0")
    assert spec.ecosystem == "pypi"
    assert spec.name == "kubernetes"
    assert spec.version == "25.0.0"


def test_parse_package_spec_pypi_equals_version() -> None:
    spec = parse_package_spec("pypi:fastapi==0.136.3")
    assert spec.ecosystem == "pypi"
    assert spec.name == "fastapi"
    assert spec.version == "0.136.3"


def test_parse_package_spec_npm_scoped() -> None:
    spec = parse_package_spec("npm:@types/node@20.0.0")
    assert spec.ecosystem == "npm"
    assert spec.name == "@types/node"
    assert spec.version == "20.0.0"


def test_parse_package_spec_oci() -> None:
    spec = parse_package_spec("oci:ghcr.io/org/image:1.2.3")
    assert spec.ecosystem == "oci"
    assert spec.name == "ghcr.io/org/image:1.2.3"
    assert spec.version == "1.2.3"


def test_vet_pypi_flags_yanked_release() -> None:
    payload = {
        "info": {
            "name": "demo-package",
            "version": "1.0.0",
            "summary": "Demo package",
            "description": "Safe description",
            "yanked": True,
            "project_urls": {},
        }
    }
    mock_response = MagicMock(status_code=200, json=lambda: payload)
    mock_response.raise_for_status = MagicMock()

    with patch("mcts.vet.pypi.httpx.get", return_value=mock_response):
        report = run_vet("pypi:demo-package")

    assert report.verdict == "fail"
    assert any(f.id == "vet-yanked" for f in report.findings)


def test_vet_pypi_not_found() -> None:
    mock_response = MagicMock(status_code=404)
    with patch("mcts.vet.pypi.httpx.get", return_value=mock_response):
        report = run_vet("pypi:missing-package-xyz")
    assert report.verdict == "not_found"
    assert report.findings[0].severity == Severity.HIGH


def test_vet_pypi_version_not_found_suggests_latest() -> None:
    version_response = MagicMock(status_code=404)
    project_payload = {
        "info": {"version": "32.0.1"},
        "releases": {
            "30.1.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}],
            "31.0.0": [{"upload_time_iso_8601": "2025-05-01T00:00:00Z"}],
            "32.0.1": [{"upload_time_iso_8601": "2025-10-01T00:00:00Z"}],
        },
    }
    project_response = MagicMock(status_code=200, json=lambda: project_payload)
    project_response.raise_for_status = MagicMock()

    with patch("mcts.vet.pypi.httpx.get", side_effect=[version_response, project_response]) as get:
        report = run_vet("pypi:kubernetes:25.0.0")

    assert report.verdict == "version_not_found"
    assert report.package == "kubernetes"
    assert report.version == "25.0.0"
    assert report.findings[0].id == "vet-version-not-found"
    assert "Latest: 32.0.1" in report.findings[0].description
    assert report.findings[0].evidence["suggestions"] == ["32.0.1", "31.0.0", "30.1.0"]
    assert get.call_args_list[0].args[0] == "https://pypi.org/pypi/kubernetes/25.0.0/json"
    assert get.call_args_list[1].args[0] == "https://pypi.org/pypi/kubernetes/json"


def test_vet_npm_flags_lifecycle_script() -> None:
    payload = {
        "description": "Install helper",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "description": "Install helper",
                "scripts": {"postinstall": "node setup.js"},
            }
        },
    }
    mock_response = MagicMock(status_code=200, json=lambda: payload)
    mock_response.raise_for_status = MagicMock()

    with patch("mcts.vet.npm.httpx.get", return_value=mock_response):
        report = run_vet("npm:demo-helper")

    assert any(f.id == "vet-npm-script-postinstall" for f in report.findings)


def test_vet_oci_unknown_registry() -> None:
    report = run_vet("oci:evil-registry.example/suspicious/image:latest")
    assert any(f.id == "vet-oci-unknown-registry" for f in report.findings)


def test_vet_invalid_spec_raises() -> None:
    with pytest.raises(ValueError, match="pypi:, npm:, or oci:"):
        parse_package_spec("requests")
