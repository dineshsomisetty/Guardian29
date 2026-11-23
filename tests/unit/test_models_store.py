import pytest
from pydantic import ValidationError

from guardian.core.models import Evidence, Finding, FindingCategory, new_ulid
from guardian.core.store import JsonStore, StoreError


def test_finding_without_evidence_raises():
    with pytest.raises(ValidationError):
        Finding(run_id="r", category=FindingCategory.CVE, title="x", detector="grype", evidence_ids=[])


def test_ulid_is_26_chars_and_unique():
    ids = {new_ulid() for _ in range(1000)}
    assert len(ids) == 1000 and all(len(i) == 26 for i in ids)


def test_store_append_only_and_reload(tmp_path):
    s = JsonStore(tmp_path)
    ev = s.add_evidence(Evidence(run_id="r", kind="sbom", source_tool="syft", facts={"n": 1}))
    with pytest.raises(StoreError):
        s.add_evidence(ev)
    fd = s.add_finding(Finding(run_id="r", category=FindingCategory.LOCKFILE, title="no lockfile",
                               detector="detector:lockfile", evidence_ids=[ev.evidence_id]))
    s2 = JsonStore(tmp_path)
    assert s2.get_evidence(ev.evidence_id).facts == {"n": 1}
    assert s2.get_finding(fd.finding_id).title == "no lockfile"


def test_store_rejects_finding_with_unknown_evidence(tmp_path):
    s = JsonStore(tmp_path)
    with pytest.raises(StoreError):
        s.add_finding(Finding(run_id="r", category=FindingCategory.CVE, title="x", detector="grype",
                              evidence_ids=["ev_missing"]))
