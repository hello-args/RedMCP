"""Module-level Python taint analysis from a tool entry function."""

from __future__ import annotations

import ast

from mcts.sast.python.taint import (
    TaintResult,
    _call_sink_name,
    _expr_uses_tainted,
)


def analyze_python_module_taint(source: str, entry_name: str) -> TaintResult:
    """Trace tool parameters through same-file calls to security sinks."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return TaintResult()

    functions = _index_functions(tree)
    entry = functions.get(entry_name)
    if entry is None:
        return TaintResult()

    tainted = {arg.arg for arg in entry.args.args if arg.arg not in {"self", "cls"}}
    sinks: list[str] = []
    sinks.extend(_sinks_in_callees(entry, functions))

    for _ in range(8):
        changed = False
        for func in functions.values():
            for node in ast.walk(func):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Name)
                            and _expr_uses_tainted(node.value, tainted)
                            and target.id not in tainted
                        ):
                            tainted.add(target.id)
                            changed = True
                        if (
                            isinstance(target, ast.Name)
                            and isinstance(node.value, ast.Call)
                            and any(_expr_uses_tainted(arg, tainted) for arg in node.value.args)
                            and target.id not in tainted
                        ):
                            tainted.add(target.id)
                            changed = True
                elif isinstance(node, ast.AugAssign):
                    if (
                        isinstance(node.target, ast.Name)
                        and _expr_uses_tainted(node.value, tainted)
                        and node.target.id not in tainted
                    ):
                        tainted.add(node.target.id)
                        changed = True
                elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    _propagate_append(node.value, tainted)
                elif isinstance(node, ast.Call):
                    sink = _call_sink_name(node.func)
                    args = list(node.args) + [kw.value for kw in node.keywords]
                    if sink and any(_expr_uses_tainted(arg, tainted) for arg in args):
                        sinks.append(sink)
                    _propagate_call(node, functions, tainted)
        if not changed and sinks:
            break

    return TaintResult(sinks=list(dict.fromkeys(sinks)), tainted_params=set(tainted))


def _index_functions(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    indexed: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            indexed[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    indexed[child.name] = child
                    indexed[f"{node.name}.{child.name}"] = child
    return indexed


def _sinks_in_callees(
    entry: ast.FunctionDef | ast.AsyncFunctionDef,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[str]:
    """Flag sinks in functions called directly from the tool handler."""
    sinks: list[str] = []
    for node in ast.walk(entry):
        if not isinstance(node, ast.Call):
            continue
        callee = _resolve_callee(node, functions)
        if callee is None:
            continue
        for call in ast.walk(callee):
            if isinstance(call, ast.Call):
                sink = _call_sink_name(call.func)
                if sink:
                    sinks.append(sink)
    return sinks


def _propagate_call(
    node: ast.Call,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    tainted: set[str],
) -> None:
    callee = _resolve_callee(node, functions)
    if callee is None:
        return
    params = [arg.arg for arg in callee.args.args if arg.arg not in {"self", "cls"}]
    for index, arg in enumerate(node.args):
        if index >= len(params):
            break
        if _expr_uses_tainted(arg, tainted):
            tainted.add(params[index])
    for keyword in node.keywords:
        if keyword.arg and keyword.arg in params and _expr_uses_tainted(keyword.value, tainted):
            tainted.add(keyword.arg)


def _propagate_append(node: ast.Call, tainted: set[str]) -> None:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "append":
        return
    if not node.args or not _expr_uses_tainted(node.args[0], tainted):
        return
    if isinstance(node.func.value, ast.Name):
        tainted.add(node.func.value.id)


def _resolve_callee(
    node: ast.Call,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    func = node.func
    if isinstance(func, ast.Name):
        return functions.get(func.id)
    if isinstance(func, ast.Attribute):
        return functions.get(func.attr)
    return None
