"""
Tests for the AI context engine's formatting helpers.

Regression coverage for the fuzzer-findings slicing bug: `_format_fuzzer_context`
previously iterated `findings[-5]` (a single element) instead of `findings[-5:]`
(the last five), which crashed context building whenever a job had findings.
"""

from types import SimpleNamespace

from medaudit.web.ai.context import context_engine


def _fake_job(findings):
    """A stand-in for a FuzzingJob DB row with no live status."""
    return SimpleNamespace(
        id="job-not-active",  # not in _active_jobs -> get_job_status returns None
        name="Test Job",
        target_host="localhost",
        target_port=2575,
        status="completed",
        progress=100,
        total_requests=10,
        error_requests=0,
        interesting_findings=len(findings),
        findings=findings,
    )


def _finding(i):
    return {
        "finding_type": "anomaly",
        "rule": f"rule-{i}",
        "mutation": f"payload-{i}",
    }


def test_fuzzer_context_renders_findings_without_crashing():
    """Findings must be dicts, not iterated char-by-char (the old bug)."""
    findings = [_finding(i) for i in range(8)]
    out = context_engine._format_fuzzer_context([_fake_job(findings)])

    assert "**Findings (8):**" in out
    # Only the last 5 are shown, most-recent inclusive.
    assert "rule-7" in out
    assert "rule-3" in out
    # Earlier findings are trimmed.
    assert "rule-2" not in out


def test_fuzzer_context_handles_fewer_than_five_findings():
    """`findings[-5:]` on a short list must not IndexError."""
    findings = [_finding(0), _finding(1)]
    out = context_engine._format_fuzzer_context([_fake_job(findings)])

    assert "**Findings (2):**" in out
    assert "rule-0" in out
    assert "rule-1" in out


def test_fuzzer_context_no_findings():
    out = context_engine._format_fuzzer_context([_fake_job([])])
    assert "Test Job" in out
    assert "Findings" not in out
