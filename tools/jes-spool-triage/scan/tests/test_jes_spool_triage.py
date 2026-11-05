import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jes_spool_triage as jst

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "sample_spool_dump.txt"


def test_parse_dump_splits_jobs_and_dds():
    jobs = jst.parse_dump(SAMPLE)
    names = [j.jobname for j in jobs]
    assert names == [
        "FC1NSLRU",
        "SECADM3",
        "PARMUPD1",
        "FTPNITE1",
        "NORMAL01",
        "DENIED01",
    ]
    fc1 = jobs[0]
    assert set(fc1.dds) == {"JESMSGLG", "JESJCL", "SYSPRINT"}
    assert fc1.dds["JESJCL"][1].strip().startswith("//UNLOAD")


def test_racf_success_signal_fires_without_ich408i():
    findings = jst.scan_dump(SAMPLE)
    hits = [f for f in findings if f.category == "RACF_SUCCESS_SIGNAL"]
    assert len(hits) == 1
    assert hits[0].jobname == "FC1NSLRU"
    assert hits[0].severity == "high"


def test_racf_success_signal_does_not_fire_on_denied_job():
    findings = jst.scan_dump(SAMPLE)
    denied = [f for f in findings if f.jobname == "DENIED01"]
    assert all(f.category != "RACF_SUCCESS_SIGNAL" for f in denied)


def test_racf_batch_command_detected():
    findings = jst.scan_dump(SAMPLE)
    hits = [f for f in findings if f.category == "RACF_BATCH_COMMAND"]
    assert {f.jobname for f in hits} == {"SECADM3"}
    texts = {f.text for f in hits}
    assert "ALTUSER FC1NSLRU SPECIAL" in texts
    assert "SETROPTS REFRESH" in texts


def test_admin_utility_system_dataset_detected():
    findings = jst.scan_dump(SAMPLE)
    hits = [f for f in findings if f.category == "ADMIN_UTILITY_SYSTEM_DATASET"]
    assert len(hits) == 1
    assert hits[0].jobname == "PARMUPD1"


def test_credential_string_detected_but_not_leaked_elsewhere():
    findings = jst.scan_dump(SAMPLE)
    hits = [f for f in findings if f.category == "CREDENTIAL_STRING"]
    jobnames = {f.jobname for f in hits}
    assert "FTPNITE1" in jobnames
    assert "NORMAL01" not in jobnames


def test_privileged_naming_hint_is_info_severity_lead_only():
    findings = jst.scan_dump(SAMPLE)
    hits = [f for f in findings if f.category == "PRIVILEGED_NAMING_HINT"]
    jobnames = {f.jobname for f in hits}
    assert "SECADM3" in jobnames
    assert "PARMUPD1" in jobnames  # owner SYSPROG1
    assert all(f.severity == "info" for f in hits)


def test_normal_job_produces_no_findings():
    findings = jst.scan_dump(SAMPLE)
    assert not [f for f in findings if f.jobname == "NORMAL01"]


def test_render_text_report_sorts_critical_first():
    findings = jst.scan_dump(SAMPLE)
    report = jst.render_text_report(findings)
    first_line = next(line for line in report.splitlines() if line.startswith("["))
    assert first_line.startswith("[CRITICAL")


def test_render_text_report_handles_empty():
    assert jst.render_text_report([]) == "No signals found in this dump.\n"
