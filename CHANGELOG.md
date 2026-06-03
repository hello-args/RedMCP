# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Renamed project from RedMCP to MCPAudit (`mcpaudit` package and CLI)

### Added
- Initial project scaffold with `uv`, `src/` layout, and `pyproject.toml`
- CLI: `mcpaudit scan`, `mcpaudit report`, `mcpaudit fuzz`, `mcpaudit pentest` (stubs)
- Analyzers: permissions, prompt injection, tool abuse, data leakage, jailbreak, attack chains
- Risk scoring engine and HTML report generation
- Example vulnerable MCP server and pytest suite
- GitHub Actions CI, pre-commit, and OSS community files

## [0.1.0] - 2026-06-03

### Added
- Alpha release: static analysis scanner for Python MCP servers
