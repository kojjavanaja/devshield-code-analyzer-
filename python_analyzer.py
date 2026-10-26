import ast
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 1}


def analyze_python(source: str, filename: str = "snippet.py") -> tuple[list[dict], dict]:
    findings = []
    lines = source.splitlines() or [""]

    def add(rule, title, severity, line, category, description, why, fix, confidence="medium", tool="DevShield AST rules"):
        line = max(1, min(int(line or 1), len(lines)))
        normalized = re.sub(r"\s+", " ", lines[line - 1].strip())
        fingerprint = hashlib.sha256(f"{rule}:{normalized}".encode()).hexdigest()[:32]
        findings.append(dict(rule_id=rule, title=title, severity=severity, confidence=confidence, line=line,
                             category=category, description=description, why_it_matters=why,
                             suggested_fix=fix, tool=tool, fingerprint=fingerprint, filename=filename))

    try:
        tree = ast.parse(source or "\n", filename=filename)
    except SyntaxError as e:
        add("PY-SYNTAX", "Python syntax error", "high", e.lineno or 1, "correctness", e.msg,
            "Invalid syntax prevents reliable parsing.", "Correct the syntax error, then scan again.", "high")
        return findings, {"lines_of_code": len(lines), "logical_lines": 0, "function_count": 0,
                          "class_count": 0, "cyclomatic_complexity": 0, "average_function_length": 0,
                          "max_nesting_depth": 0, "maintainability_index": 0}

    function_lengths, complexities = [], []
    max_depth = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
            add("PY-SEC-EVAL", "Dynamic eval usage", "high", node.lineno, "security",
                "eval() interprets a string as Python code.",
                "If the input is influenced by a user, arbitrary code execution may be possible.",
                "Avoid eval; parse expected data with safe formats or explicit dispatch.", "high")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"system", "popen"}:
            add("PY-SEC-SHELL", "Shell process invocation", "medium", node.lineno, "security",
                "A shell-related process API is used.",
                "Shell interpretation can introduce command injection when arguments contain untrusted data.",
                "Prefer subprocess.run with an argument list and shell=False.")
        if isinstance(node, ast.Assign):
            targets = [n.id.lower() for t in node.targets for n in ast.walk(t) if isinstance(n, ast.Name)]
            if (any(re.search(r"(password|passwd|secret|api_key|token)$", n) for n in targets)
                    and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                    and len(node.value.value) > 3):
                add("PY-SEC-SECRET", "Possible hardcoded secret", "high", node.lineno, "security",
                    "A credential-like variable is assigned a string literal.",
                    "Committed credentials may leak through source history or packages.",
                    "Load secrets from environment/configuration and rotate exposed credentials.")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            add("PY-QUALITY-BARE-EXCEPT", "Bare except handler", "medium", node.lineno, "maintainability",
                "A bare except catches nearly every exception.",
                "Unexpected failures may be hidden, making debugging difficult.",
                "Catch specific exception types and handle them deliberately.")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            length = end - node.lineno + 1
            function_lengths.append(length)
            if length > 50:
                add("PY-QUALITY-LONG-FUNCTION", "Long function", "medium", node.lineno, "maintainability",
                    f"Function spans {length} lines.", "Large functions are harder to test and change safely.",
                    "Split the function into small, cohesive helpers.")
            if not ast.get_docstring(node):
                add("PY-DOC-FUNCTION", "Missing function docstring", "low", node.lineno, "documentation",
                    "Function has no docstring.", "Callers may not understand the function contract.",
                    "Document purpose, parameters, return values and raised exceptions.")
            complexity = 1 + sum(
                isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.ExceptHandler,
                               ast.With, ast.AsyncWith, ast.IfExp, ast.comprehension))
                or (isinstance(n, ast.BoolOp) and len(n.values) > 1) for n in ast.walk(node))
            complexities.append(complexity)
            if complexity > 10:
                add("PY-COMPLEXITY-HIGH", "High cyclomatic complexity", "medium", node.lineno, "complexity",
                    f"Estimated cyclomatic complexity is {complexity}.",
                    "Many branches increase testing burden and edge-case risk.",
                    "Reduce branching, extract helpers, and add tests for each path.")

    def depth(node, d=0):
        nonlocal max_depth
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try,
                             ast.FunctionDef, ast.AsyncFunctionDef)):
            d += 1
            max_depth = max(max_depth, d)
        for child in ast.iter_child_nodes(node):
            depth(child, d)

    depth(tree)
    if max_depth >= 5:
        add("PY-QUALITY-NESTING", "Deeply nested logic", "medium", 1, "maintainability",
            f"Maximum estimated nesting depth is {max_depth}.",
            "Deep nesting obscures control flow and complicates reviews.",
            "Use guard clauses and extract nested blocks into helpers.")
    if not ast.get_docstring(tree):
        add("PY-DOC-MODULE", "Missing module docstring", "low", 1, "documentation",
            "Module has no top-level docstring.", "Module intent is less discoverable to maintainers.",
            "Add a concise module docstring.")

    # Optional external scanners receive a temporary text file; submitted code is never executed.
    with tempfile.TemporaryDirectory(prefix="devshield-") as td:
        p = Path(td) / Path(filename).name
        p.write_text(source, encoding="utf-8")
        if shutil.which("ruff"):
            try:
                result = subprocess.run(["ruff", "check", "--output-format=json", str(p)], capture_output=True,
                                        text=True, timeout=8, check=False)
                for item in json.loads(result.stdout or "[]"):
                    add("RUFF-" + item.get("code", "UNKNOWN"), item.get("message", "Ruff finding"), "low",
                        item.get("location", {}).get("row", 1), "style", item.get("message", "Lint finding"),
                        "Lint violations can conceal defects or reduce consistency.",
                        "Apply the suggested Ruff fix or update the code.", "high", "Ruff")
            except (subprocess.TimeoutExpired, ValueError):
                pass
        if shutil.which("bandit"):
            try:
                result = subprocess.run(["bandit", "-f", "json", "-q", str(p)], capture_output=True,
                                        text=True, timeout=8, check=False)
                data = json.loads(result.stdout or "{}")
                for item in data.get("results", []):
                    add(item.get("test_id", "BANDIT"), item.get("issue_text", "Bandit finding"),
                        item.get("issue_severity", "LOW").lower(), item.get("line_number", 1), "security",
                        item.get("issue_text", "Potential security issue"),
                        "Static rules identify a potentially unsafe pattern; exploitability depends on context.",
                        "Review the Bandit remediation guidance.", item.get("issue_confidence", "MEDIUM").lower(), "Bandit")
            except (subprocess.TimeoutExpired, ValueError):
                pass

    loc = sum(1 for line in lines if line.strip() and not line.strip().startswith("#"))
    function_count = sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree))
    class_count = sum(isinstance(n, ast.ClassDef) for n in ast.walk(tree))
    complexity = sum(complexities)
    metrics = {"lines_of_code": len(lines), "logical_lines": loc, "function_count": function_count,
               "class_count": class_count, "cyclomatic_complexity": complexity,
               "average_function_length": round(sum(function_lengths) / len(function_lengths), 1) if function_lengths else 0,
               "max_nesting_depth": max_depth,
               "maintainability_index": max(0, round(100 - min(100, complexity * 2 + max_depth * 4 + loc * .15), 1))}
    return findings, metrics


def score_risk(findings: list[dict], metrics: dict) -> tuple[int, str, list[str]]:
    weighted = sum(SEVERITY_WEIGHT.get(f["severity"], 1) for f in findings)
    raw = (weighted + max(0, metrics.get("cyclomatic_complexity", 0) - 5) * 1.5
           + max(0, metrics.get("max_nesting_depth", 0) - 3) * 4
           + max(0, metrics.get("average_function_length", 0) - 30) * .25)
    score = max(0, min(100, round(raw)))
    category = "Low" if score < 20 else "Moderate" if score < 45 else "High" if score < 70 else "Critical"
    factors = []
    if weighted: factors.append(f"Static findings contribute {weighted} weighted risk points")
    if metrics.get("cyclomatic_complexity", 0) > 10: factors.append("Elevated aggregate cyclomatic complexity")
    if metrics.get("max_nesting_depth", 0) >= 5: factors.append("Deeply nested control flow")
    if metrics.get("average_function_length", 0) > 50: factors.append("Long average function length")
    if not factors: factors.append("No major risk signals were detected by enabled rules")
    return score, category, factors
