# Load httpx for threat intel tests.
import httpx

# Import IntelClient, parse_purl from guardian.tools.threat_intel.
from guardian.tools.threat_intel import IntelClient, parse_purl

# Store a mapping keyed by the fields below in OSV.
OSV = {"vulns": [
    # Supply the next part of the expression started above.
    {"id": "GHSA-aaaa", "aliases": ["CVE-2022-0001"], "affected": [{"package": {"name": "jsonwebtoken", "ecosystem": "npm"},
        # Provide the mapping fields ranges, events on this line.
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "8.5.1"}]}]}]},
    # Supply the next part of the expression started above.
    {"id": "GHSA-bbbb", "aliases": ["CVE-2022-0002"], "affected": [{"package": {"name": "jsonwebtoken", "ecosystem": "npm"},
        # Provide the mapping fields ranges, events on this line.
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.0.0"}]}]}]},
# Close the current expression or collection.
]}
# Store an ordered collection in calls.
calls = []


# Define handler for threat intel tests.
# Inputs include req.
def handler(req: httpx.Request):
    # Call calls.append at this point.
    calls.append(str(req.url))
    # Store the result of str in u.
    u = str(req.url)
    # Check whether 'api.first.org' in u.
    if "api.first.org" in u:
        # Return the result of httpx.Response to the caller.
        return httpx.Response(200, json={"data": [{"cve": "CVE-2022-0001", "epss": "0.5", "percentile": "0.93", "date": "d"}]})
    # Check whether 'cisa.gov' in u.
    if "cisa.gov" in u:
        # Return the result of httpx.Response to the caller.
        return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]})
    # Check whether 'api.osv.dev' in u.
    if "api.osv.dev" in u:
        # Return the result of httpx.Response to the caller.
        return httpx.Response(200, json=OSV)
    # Check whether 'registry.npmjs.org' in u.
    if "registry.npmjs.org" in u:
        # Return the result of httpx.Response to the caller.
        return httpx.Response(200, json={"name": "x", "dist-tags": {"latest": "1.0.0"}, "time": {"1.0.0": "2020-01-01T00:00:00Z"},
                                         # Provide the mapping fields versions, scripts on this line.
                                         "versions": {"1.0.0": {"deprecated": "use y", "scripts": {"postinstall": "x"}}}})
    # Return the result of httpx.Response to the caller.
    return httpx.Response(404)


# Define client for threat intel tests.
# Inputs include tmp_path.
def client(tmp_path, **kw):
    # Call kw.setdefault at this point.
    kw.setdefault("offline", False)
    # Return the result of IntelClient to the caller.
    return IntelClient(cache_dir=tmp_path, transport=httpx.MockTransport(handler), min_interval=0, **kw)


# Exercise the expected behavior for epss and cache.
def test_epss_and_cache(tmp_path):
    # Store the result of client in c.
    c = client(tmp_path)
    # Check that the expression on this line.
    assert c.epss_lookup(["cve-2022-0001", "bogus"])["CVE-2022-0001"]["percentile"] == 0.93
    # Store the result of len in n.
    n = len(calls)
    # Call c.epss_lookup at this point.
    c.epss_lookup(["CVE-2022-0001"])
    # Check that len(calls) == n.
    assert len(calls) == n  # served from cache


# Exercise the expected behavior for kev.
def test_kev(tmp_path):
    # Store the result of client(tmp_path).kev_lookup in k.
    k = client(tmp_path).kev_lookup(["CVE-2021-44228", "CVE-2000-1"])
    # Check that the expression on this line.
    assert k["CVE-2021-44228"]["dateAdded"] == "2021-12-10" and k["CVE-2000-1"] is None


# Exercise the expected behavior for offline uses cache and misses return none.
def test_offline_uses_cache_and_misses_return_none(tmp_path):
    # Call client(tmp_path).epss_lookup at this point.
    client(tmp_path).epss_lookup(["CVE-2022-0001"])
    # Store the result of client in off.
    off = client(tmp_path, offline=True)
    # Store the result of len in n.
    n = len(calls)
    # Check that 'CVE-2022-0001' in off.epss_lookup(['CVE-2022-0001']).
    assert "CVE-2022-0001" in off.epss_lookup(["CVE-2022-0001"])
    # Check that off.epss_lookup(['CVE-2099-0009']) == {}.
    assert off.epss_lookup(["CVE-2099-0009"]) == {}  # miss: no network, no error
    # Check that off.kev_lookup(['CVE-2021-44228']) == {}.
    assert off.kev_lookup(["CVE-2021-44228"]) == {}
    # Check that off.registry_metadata('pkg:npm/foo@1') is None.
    assert off.registry_metadata("pkg:npm/foo@1") is None
    # Check that len(calls) == n.
    assert len(calls) == n


# Exercise the expected behavior for env offline.
def test_env_offline(tmp_path, monkeypatch):
    # Call monkeypatch.setenv at this point.
    monkeypatch.setenv("GUARDIAN_OFFLINE", "1")
    # Store the result of len in n.
    n = len(calls)
    # Check that the expression on this line.
    assert client(tmp_path, offline=None).osv_query("pkg:npm/zzz@1.0.0") == []
    # Check that len(calls) == n.
    assert len(calls) == n


# Exercise the expected behavior for safe version all vulns.
def test_safe_version_all_vulns(tmp_path):
    # Store the result of client(tmp_path).safe_version_lookup in r.
    r = client(tmp_path).safe_version_lookup("pkg:npm/jsonwebtoken@0.4.0", ["CVE-2022-0001", "GHSA-bbbb"])
    # Check that the expression on this line.
    assert r["fixed_version"] == "9.0.0" and r["affected_range"] == "<8.5.1; <9.0.0"
    # Store the result of client(tmp_path).safe_version_lookup in only.
    only = client(tmp_path).safe_version_lookup("pkg:npm/jsonwebtoken@0.4.0", ["CVE-2022-0001"])
    # Check that only['fixed_version'] == '8.5.1'.
    assert only["fixed_version"] == "8.5.1"


# Exercise the expected behavior for registry trim.
def test_registry_trim(tmp_path):
    # Store the result of client(tmp_path).registry_metadata in m.
    m = client(tmp_path).registry_metadata("pkg:npm/%40s/x@1.0.0")
    # Check that the expression on this line.
    assert m["deprecated"] == "use y" and m["latest_has_install_script"] is True


# Exercise the expected behavior for parse purl.
def test_parse_purl():
    # Check that the expression on this line.
    assert parse_purl("pkg:npm/%40angular/core@17.0.0") == ("@angular/core", "17.0.0", "npm")
