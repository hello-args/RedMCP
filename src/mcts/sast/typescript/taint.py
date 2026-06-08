"""TypeScript/JavaScript parameter-to-sink flow analysis."""

from __future__ import annotations

import re

from mcts.sast.python.taint import TaintResult
from mcts.sast.typescript.sinks import detect_typescript_sinks

_PARAM_PATTERNS = (
    re.compile(r"(?:async\s+)?function\s+\w+\s*\(([^)]*)\)"),
    re.compile(r"(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"),
    re.compile(r"(?:async\s*)?\(([^)]*)\)\s*=>"),
)

_SINK_CALL = re.compile(
    r"(?:exec|spawn|execFile|eval|fetch|writeFile|unlink|rm)\s*\(([^)]*)\)",
    re.MULTILINE,
)


def analyze_typescript_taint(source: str) -> TaintResult:
    """Detect sinks reached by handler parameters (tree-sitter optional)."""
    try:
        return _tree_sitter_taint(source)
    except ImportError:
        return _regex_taint(source)


def _regex_taint(source: str) -> TaintResult:
    params = _extract_params(source)
    tainted = set(params)
    for match in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*(\w+)", source):
        if match.group(2) in tainted:
            tainted.add(match.group(1))
    sinks: list[str] = []
    for sink in detect_typescript_sinks(source):
        if _sink_uses_tainted(source, sink, tainted):
            sinks.append(sink)
    for call in _SINK_CALL.finditer(source):
        args = call.group(1)
        if any(param in args for param in tainted):
            sinks.append("dynamic_sink")
    return TaintResult(sinks=list(dict.fromkeys(sinks)), tainted_params=params)


def _extract_params(source: str) -> set[str]:
    params: set[str] = set()
    for pattern in _PARAM_PATTERNS:
        for match in pattern.finditer(source):
            chunk = match.group(1)
            for part in chunk.split(","):
                name = part.strip().split(":")[0].strip()
                if name and name not in ("...",):
                    params.add(name)
    return params


def _sink_uses_tainted(source: str, sink: str, tainted: set[str]) -> bool:
    if not tainted:
        return False
    return any(re.search(rf"\b{re.escape(param)}\b", source) and sink in source for param in tainted)


def _tree_sitter_taint(source: str) -> TaintResult:
    import tree_sitter_typescript as tstypescript
    from tree_sitter import Language, Parser

    parser = Parser(Language(tstypescript.language_typescript()))
    tree = parser.parse(source.encode("utf-8"))
    root = tree.root_node
    params = _ts_collect_params(root, source)
    tainted = set(params)
    sinks: list[str] = []
    for label in detect_typescript_sinks(source):
        sinks.append(label)
    if sinks and tainted:
        return TaintResult(sinks=list(dict.fromkeys(sinks)), tainted_params=tainted)
    return _regex_taint(source)


def _ts_collect_params(node: object, source: str) -> set[str]:
    names: set[str] = set()
    type_name = getattr(node, "type", "")
    if type_name in ("function_declaration", "arrow_function", "method_definition"):
        for child in getattr(node, "children", []):
            if getattr(child, "type", "") in ("formal_parameters", "required_parameter", "identifier"):
                text = source[child.start_byte : child.end_byte].strip()  # type: ignore[attr-defined]
                if text and text not in ("(", ")", ","):
                    names.add(text.split(":")[0].strip())
    for child in getattr(node, "children", []):
        names |= _ts_collect_params(child, source)
    return names
