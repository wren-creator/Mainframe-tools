import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import customer_report as cr
import jes_spool_triage as jst
from dataclasses import asdict

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "sample_spool_dump.txt"


def _sample_payload():
    jobs, findings = jst.load(SAMPLE)
    summary = jst.summarize(jobs, findings)
    return {"summary": summary, "findings": [asdict(f) for f in findings]}


def test_redact_keeps_key_blanks_value():
    assert cr.redact("PASS=NotARealSecret123").startswith("PASS=")
    assert "NotARealSecret123" not in cr.redact("PASS=NotARealSecret123")


def test_redact_handles_no_equals():
    assert "redacted" in cr.redact("some random line")


def test_render_includes_customer_and_scope():
    report = cr.render(_sample_payload(), "Acme Corp", do_redact=True)
    assert "Acme Corp" in report
    assert "## Scope" in report
    assert "Jobs visible in the pool: 6" in report


def test_render_redacts_credential_values_by_default():
    report = cr.render(_sample_payload(), "Acme Corp", do_redact=True)
    assert "NotARealSecret123" not in report
    assert "racfadm2" not in report
    assert "redacted" in report


def test_render_can_include_raw_credentials():
    report = cr.render(_sample_payload(), "Acme Corp", do_redact=False)
    assert "NotARealSecret123" in report


def test_render_groups_by_category_with_remediation():
    report = cr.render(_sample_payload(), "Acme Corp", do_redact=True)
    assert "Credential exposed in job data" in report
    assert "rotate any credential found this way" in report
