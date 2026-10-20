import ast
from typing import Dict, Any, List, Optional


def extract_ast_metadata(code_snippet: str) -> Dict[str, Any]:
    """
    Extracts structural metadata, symbols, and branch complexity metrics from Python source code
    using Python's Abstract Syntax Tree (AST).
    
    Catches SyntaxError safely and returns diagnostic information.
    """
    lines = code_snippet.splitlines()
    loc = len(lines)
    
    if not code_snippet.strip():
        return {
            "is_valid_syntax": True,
            "error": None,
            "error_line": None,
            "error_column": None,
            "functions": [],
            "classes": [],
            "imports": [],
            "complexity_score": 1,
            "lines_of_code": 0,
        }

    try:
        tree = ast.parse(code_snippet)
    except SyntaxError as e:
        return {
            "is_valid_syntax": False,
            "error": str(e.msg) if hasattr(e, "msg") else str(e),
            "error_line": e.lineno,
            "error_column": e.offset,
            "functions": [],
            "classes": [],
            "imports": [],
            "complexity_score": 1,
            "lines_of_code": loc,
        }
    except Exception as e:
        return {
            "is_valid_syntax": False,
            "error": f"Failed to parse AST: {str(e)}",
            "error_line": None,
            "error_column": None,
            "functions": [],
            "classes": [],
            "imports": [],
            "complexity_score": 1,
            "lines_of_code": loc,
        }

    functions: List[Dict[str, Any]] = []
    classes: List[Dict[str, Any]] = []
    imports: List[str] = []
    branch_count = 0

    # Branch nodes for cyclomatic complexity estimation
    branch_node_types = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.ExceptHandler,
        ast.With,
        ast.AsyncWith,
    )
    # Include pattern matching if present (Python 3.10+)
    if hasattr(ast, "Match"):
        branch_node_types = branch_node_types + (ast.Match,)

    for node in ast.walk(tree):
        # Cyclomatic complexity branch counting
        if isinstance(node, branch_node_types):
            branch_count += 1
        elif isinstance(node, ast.BoolOp):
            # Each 'and' / 'or' adds an extra conditional branch
            branch_count += max(0, len(node.values) - 1)

        # Functions (sync & async)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args_list = []
            for arg in node.args.args:
                args_list.append(arg.arg)
            if node.args.vararg:
                args_list.append(f"*{node.args.vararg.arg}")
            for kw in node.args.kwonlyargs:
                args_list.append(kw.arg)
            if node.args.kwarg:
                args_list.append(f"**{node.args.kwarg.arg}")

            returns_str: Optional[str] = None
            if node.returns is not None:
                try:
                    returns_str = ast.unparse(node.returns)
                except Exception:
                    returns_str = getattr(node.returns, "id", str(node.returns))

            docstring = ast.get_docstring(node)

            functions.append({
                "name": node.name,
                "lineno": node.lineno,
                "args": args_list,
                "returns": returns_str,
                "docstring": docstring,
            })

        # Classes
        elif isinstance(node, ast.ClassDef):
            methods = [
                n.name for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            bases = []
            for base in node.bases:
                try:
                    bases.append(ast.unparse(base))
                except Exception:
                    bases.append(getattr(base, "id", str(base)))

            classes.append({
                "name": node.name,
                "lineno": node.lineno,
                "methods": methods,
                "bases": bases,
            })

        # Imports
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imports.append(f"{alias.name} as {alias.asname}")
                else:
                    imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            names = ", ".join(
                f"{a.name} as {a.asname}" if a.asname else a.name for a in node.names
            )
            imports.append(f"from {mod} import {names}")

    # Cyclomatic complexity is base 1 + number of branches
    complexity_score = 1 + branch_count

    return {
        "is_valid_syntax": True,
        "error": None,
        "error_line": None,
        "error_column": None,
        "functions": functions,
        "classes": classes,
        "imports": imports,
        "complexity_score": complexity_score,
        "lines_of_code": loc,
    }
