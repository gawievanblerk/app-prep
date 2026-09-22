"""Same-file caller resolution: which expression a function's parameter is bound to.

Used when a value passed to a call (an SDK call, say) is a bare parameter with no local
assignment: the caller that supplied it might call the function directly, or hand the function
itself to a thread or executor runner (`to_thread.run_sync(self._dispatch, message)`,
`asyncio.to_thread(self._dispatch, message)`, `loop.run_in_executor(None, self._dispatch,
message)`, `executor.submit(self._dispatch, message)`).
"""

from __future__ import annotations

import ast

from dpr.parsing import pyast


def _function_ref(node: ast.expr, name: str) -> bool:
    """A bare reference to a function named `name`: its own name, or a self./cls. attribute
    access naming it, the shape a thread or executor runner is handed."""
    if isinstance(node, ast.Name):
        return node.id == name
    return (
        isinstance(node, ast.Attribute)
        and node.attr == name
        and isinstance(node.value, ast.Name)
        and node.value.id in ("self", "cls")
    )


def caller_value(tree: ast.Module, fn: ast.AST, param_name: str) -> ast.expr | None:
    """The argument a same-file caller binds to `param_name` of `fn`.

    Two call shapes are followed: a direct call to `fn` (by name, or a self./cls. attribute
    call), where the call's own arguments map onto `fn`'s parameters; and a call that passes
    `fn` itself as a positional argument to something else (a thread or executor runner), where
    the arguments that follow that reference map onto `fn`'s parameters instead. Either way,
    a keyword in the call maps to the parameter of the same name. First matching call only, one
    level: the caller is not itself traced further.
    """
    is_method = bool(fn.args.args) and fn.args.args[0].arg in ("self", "cls")
    params = [a.arg for a in (fn.args.args[1:] if is_method else fn.args.args)]
    if getattr(fn, "name", None) is None or param_name not in params:
        return None
    index = params.index(param_name)
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        callee = pyast.dotted(call.func) or ""
        name = callee.rsplit(".", 1)[-1]
        owner = callee.rsplit(".", 1)[0] if "." in callee else ""
        if name == fn.name and owner in ("", "self", "cls"):
            args_after = call.args
        else:
            ref_index = next(
                (i for i, arg in enumerate(call.args) if _function_ref(arg, fn.name)), None
            )
            if ref_index is None:
                continue
            args_after = call.args[ref_index + 1 :]
        for keyword in call.keywords:
            if keyword.arg == param_name:
                return keyword.value
        if index < len(args_after):
            return args_after[index]
    return None
