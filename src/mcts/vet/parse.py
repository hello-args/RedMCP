"""Parse package vetting specs (pypi:, npm:, oci:)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PackageSpec:
    ecosystem: str
    name: str
    version: str | None = None


def parse_package_spec(spec: str) -> PackageSpec:
    text = spec.strip()
    if ":" not in text:
        raise ValueError("Package spec must use pypi:, npm:, or oci: prefix")

    ecosystem, rest = text.split(":", 1)
    eco = ecosystem.lower().strip()
    if eco not in {"pypi", "npm", "oci"}:
        raise ValueError(f"Unsupported ecosystem {ecosystem!r}; use pypi, npm, or oci")

    rest = rest.strip()
    if not rest:
        raise ValueError("Package name is required after ecosystem prefix")

    if eco == "oci":
        return PackageSpec(ecosystem=eco, name=rest, version=_oci_tag(rest))

    name, version = _split_name_version(rest)
    return PackageSpec(ecosystem=eco, name=name, version=version)


def _split_name_version(rest: str) -> tuple[str, str | None]:
    if "==" in rest:
        name, version = rest.split("==", 1)
        return name, version or None

    if rest.startswith("@"):
        if rest.count("@") >= 2:
            name, version = rest.rsplit("@", 1)
            return name, version or None
        if ":" in rest:
            name, version = rest.rsplit(":", 1)
            return name, version or None
        return rest, None

    if "@" in rest:
        name, version = rest.rsplit("@", 1)
        return name, version or None
    if ":" in rest:
        name, version = rest.rsplit(":", 1)
        return name, version or None
    return rest, None


def _oci_tag(ref: str) -> str | None:
    if "@" in ref:
        _, digest = ref.rsplit("@", 1)
        return digest or None
    if ":" in ref and not ref.endswith(":"):
        return ref.rsplit(":", 1)[-1]
    return None
