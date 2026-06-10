"""Go parameter-to-sink flow analysis."""

from __future__ import annotations

import re

from mcts.sast.go.sinks import detect_go_sinks
from mcts.sast.python.taint import TaintResult

_PARAM_PATTERN = re.compile(r"func\s+\w+\s*\(([^)]*)\)")
_SHORT_VAR_PATTERN = re.compile(r"(\w+)\s*:=\s*(\w+)")


def analyze_go_taint(source: str) -> TaintResult:
    """Detect sinks reached by handler parameters (tree-sitter optional)."""
    try:
        return _tree_sitter_taint(source)
    except ImportError:
        return _regex_taint(source)


def _regex_taint(source: str) -> TaintResult:
    params = _extract_params(source)
    tainted = set(params)
    for match in _SHORT_VAR_PATTERN.finditer(source):
        if match.group(2) in tainted:
            tainted.add(match.group(1))
    sinks: list[str] = []
    for sink in detect_go_sinks(source):
        if _sink_uses_tainted(source, sink, tainted):
            sinks.append(sink)
    return TaintResult(sinks=list(dict.fromkeys(sinks)), tainted_params=params)


def _sink_uses_tainted(source: str, sink: str, tainted: set[str]) -> bool:
    if not tainted:
        return False
    return any(re.search(rf"\b{re.escape(param)}\b", source) for param in tainted)


def _extract_params(source: str) -> set[str]:
    params: set[str] = set()
    match = _PARAM_PATTERN.search(source)
    if not match:
        return params
    for part in match.group(1).split(","):
        chunk = part.strip()
        if chunk:
            params.add(chunk.split()[0])
    return params


def _tree_sitter_taint(source: str) -> TaintResult:
    import tree_sitter_go as tsgo
    from tree_sitter import Language, Parser

    parser = Parser(Language(tsgo.language()))
    tree = parser.parse(source.encode("utf-8"))
    root = tree.root_node
    params = _go_collect_params(root, source)
    tainted = set(params)
    tainted |= _go_propagate_assignments(root, source, tainted)
    sinks = [sink for sink in detect_go_sinks(source) if _sink_uses_tainted(source, sink, tainted)]
    if sinks and tainted:
        return TaintResult(sinks=list(dict.fromkeys(sinks)), tainted_params=params)
    return _regex_taint(source)


def _go_collect_params(node: object, source: str) -> set[str]:
    names: set[str] = set()
    node_type = getattr(node, "type", "")
    if node_type == "parameter_declaration":
        for child in getattr(node, "children", []):
            if getattr(child, "type", "") == "identifier":
                names.add(source[child.start_byte : child.end_byte])  # type: ignore[attr-defined]
    for child in getattr(node, "children", []):
        names |= _go_collect_params(child, source)
    return names


def _go_propagate_assignments(node: object, source: str, tainted: set[str]) -> set[str]:
    expanded = set(tainted)
    node_type = getattr(node, "type", "")
    if node_type == "short_var_declaration":
        children = getattr(node, "children", [])
        identifiers = [
            source[child.start_byte : child.end_byte]  # type: ignore[attr-defined]
            for child in children
            if getattr(child, "type", "") == "identifier"
        ]
        if len(identifiers) >= 2 and identifiers[1] in expanded:
            expanded.add(identifiers[0])
    if node_type == "assignment_statement":
        children = getattr(node, "children", [])
        identifiers = [
            source[child.start_byte : child.end_byte]  # type: ignore[attr-defined]
            for child in children
            if getattr(child, "type", "") == "identifier"
        ]
        if len(identifiers) >= 2 and identifiers[1] in expanded:
            expanded.add(identifiers[0])
    for child in getattr(node, "children", []):
        expanded |= _go_propagate_assignments(child, source, expanded)
    return expanded
