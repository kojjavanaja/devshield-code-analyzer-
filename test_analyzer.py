from app.analyzers.python_analyzer import analyze_python, score_risk
def test_detects_eval_and_secret():
    findings, metrics = analyze_python("API_KEY = 'abc-secret-value'\ndef run(x):\n    return eval(x)\n")
    rules = {f["rule_id"] for f in findings}
    assert "PY-SEC-EVAL" in rules
    assert "PY-SEC-SECRET" in rules
    assert metrics["function_count"] == 1
def test_syntax_error_is_reported():
    findings, _ = analyze_python("def broken(:\n pass")
    assert findings[0]["rule_id"] == "PY-SYNTAX"
def test_risk_score_is_bounded():
    findings, metrics = analyze_python("x = eval(input())")
    score, category, factors = score_risk(findings, metrics)
    assert 0 <= score <= 100
    assert category in {"Low", "Moderate", "High", "Critical"}
    assert factors
