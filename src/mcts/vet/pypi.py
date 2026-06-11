"""PyPI package vetting."""

from __future__ import annotations

import httpx

from mcts.reporting.models import Severity
from mcts.vet.heuristics import metadata_text_findings, typosquat_findings, url_findings
from mcts.vet.models import VetFinding, VetReport
from mcts.vet.parse import PackageSpec


def _pypi_get(url: str) -> httpx.Response:
    try:
        return httpx.get(url, timeout=20.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"PyPI request failed: {exc}") from exc


def _release_suggestions(releases: object, latest: str | None, *, limit: int = 3) -> list[str]:
    suggestions: list[str] = []

    def add(version: object) -> None:
        text = str(version or "").strip()
        if text and text not in suggestions:
            suggestions.append(text)

    add(latest)
    if isinstance(releases, dict):
        dated_versions: list[tuple[str, str]] = []
        undated_versions: list[str] = []
        for version, files in releases.items():
            newest_upload = ""
            if isinstance(files, list):
                newest_upload = max(
                    (
                        str(file.get("upload_time_iso_8601") or file.get("upload_time") or "")
                        for file in files
                        if isinstance(file, dict)
                    ),
                    default="",
                )
            if newest_upload:
                dated_versions.append((newest_upload, str(version)))
            else:
                undated_versions.append(str(version))

        for _, version in sorted(dated_versions, reverse=True):
            add(version)
            if len(suggestions) >= limit:
                return suggestions
        for version in reversed(undated_versions):
            add(version)
            if len(suggestions) >= limit:
                return suggestions

    return suggestions[:limit]


def _package_not_found_report(spec: PackageSpec) -> VetReport:
    return VetReport(
        ecosystem="pypi",
        package=spec.name,
        version=spec.version,
        verdict="not_found",
        findings=[
            VetFinding(
                id="vet-not-found",
                title="Package not found on PyPI",
                description=f"No PyPI project matches {spec.name!r}.",
                severity=Severity.HIGH,
                recommendation="Verify the package name and index URL.",
            )
        ],
    )


def _version_not_found_report(spec: PackageSpec, payload: dict) -> VetReport:
    info = payload.get("info") or {}
    latest = str(info.get("version") or "")
    suggestions = _release_suggestions(payload.get("releases"), latest)
    latest_hint = f" Latest: {latest}." if latest else ""
    latest_title_hint = f" (latest: {latest})" if latest else ""
    recommendation = (
        f"Try pypi:{spec.name}:{suggestions[0]} or check the available PyPI releases."
        if suggestions
        else "Check the available PyPI releases and choose an existing version."
    )
    return VetReport(
        ecosystem="pypi",
        package=spec.name,
        version=spec.version,
        verdict="version_not_found",
        findings=[
            VetFinding(
                id="vet-version-not-found",
                title=f"Version {spec.version!r} not found for {spec.name!r}{latest_title_hint}",
                description=f"PyPI has project {spec.name!r}, but not version {spec.version!r}.{latest_hint}",
                severity=Severity.HIGH,
                recommendation=recommendation,
                evidence={
                    "requested_version": spec.version,
                    "latest": latest,
                    "suggestions": suggestions,
                },
            )
        ],
    )


def vet_pypi(spec: PackageSpec) -> VetReport:
    url = f"https://pypi.org/pypi/{spec.name}/json"
    if spec.version:
        url = f"https://pypi.org/pypi/{spec.name}/{spec.version}/json"

    response = _pypi_get(url)

    if response.status_code == 404:
        if spec.version:
            project_response = _pypi_get(f"https://pypi.org/pypi/{spec.name}/json")
            if project_response.status_code == 200:
                return _version_not_found_report(spec, project_response.json())
            if project_response.status_code != 404:
                project_response.raise_for_status()
        return _package_not_found_report(spec)

    response.raise_for_status()
    payload = response.json()
    info = payload.get("info") or {}
    version = spec.version or info.get("version")

    findings: list[VetFinding] = []
    findings.extend(typosquat_findings(ecosystem="pypi", name=spec.name))

    summary = str(info.get("summary") or "")
    description = str(info.get("description") or "")
    findings.extend(metadata_text_findings(text=f"{summary}\n{description}", source="description"))

    project_urls = info.get("project_urls") or {}
    if isinstance(project_urls, dict):
        findings.extend(url_findings({str(k): str(v) for k, v in project_urls.items()}))

    if info.get("yanked"):
        findings.append(
            VetFinding(
                id="vet-yanked",
                title="Yanked PyPI release",
                description=f"Version {version} is marked yanked on PyPI.",
                severity=Severity.HIGH,
                recommendation="Do not install yanked releases; pick a maintained version.",
                evidence={"version": version, "yanked_reason": info.get("yanked_reason")},
            )
        )

    verdict = "fail" if any(f.severity in {Severity.CRITICAL, Severity.HIGH} for f in findings) else "pass"
    return VetReport(
        ecosystem="pypi",
        package=spec.name,
        version=version,
        verdict=verdict,
        findings=findings,
    )
