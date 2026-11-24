import httpx

from guardian.tools.threat_intel import IntelClient, parse_purl

OSV = {"vulns": [
    {"id": "GHSA-aaaa", "aliases": ["CVE-2022-0001"], "affected": [{"package": {"name": "jsonwebtoken", "ecosystem": "npm"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "8.5.1"}]}]}]},
    {"id": "GHSA-bbbb", "aliases": ["CVE-2022-0002"], "affected": [{"package": {"name": "jsonwebtoken", "ecosystem": "npm"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.0.0"}]}]}]},
]}
calls = []


def handler(req: httpx.Request):
    calls.append(str(req.url))
    u = str(req.url)
    if "api.first.org" in u:
        return httpx.Response(200, json={"data": [{"cve": "CVE-2022-0001", "epss": "0.5", "percentile": "0.93", "date": "d"}]})
    if "cisa.gov" in u:
        return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]})
    if "api.osv.dev" in u:
        return httpx.Response(200, json=OSV)
    if "registry.npmjs.org" in u:
        return httpx.Response(200, json={"name": "x", "dist-tags": {"latest": "1.0.0"}, "time": {"1.0.0": "2020-01-01T00:00:00Z"},
                                         "versions": {"1.0.0": {"deprecated": "use y", "scripts": {"postinstall": "x"}}}})
    return httpx.Response(404)


def client(tmp_path, **kw):
    kw.setdefault("offline", False)
    return IntelClient(cache_dir=tmp_path, transport=httpx.MockTransport(handler), min_interval=0, **kw)


def test_epss_and_cache(tmp_path):
    c = client(tmp_path)
    assert c.epss_lookup(["cve-2022-0001", "bogus"])["CVE-2022-0001"]["percentile"] == 0.93
    n = len(calls)
    c.epss_lookup(["CVE-2022-0001"])
    assert len(calls) == n  # served from cache


def test_kev(tmp_path):
    k = client(tmp_path).kev_lookup(["CVE-2021-44228", "CVE-2000-1"])
    assert k["CVE-2021-44228"]["dateAdded"] == "2021-12-10" and k["CVE-2000-1"] is None


def test_offline_uses_cache_and_misses_return_none(tmp_path):
    client(tmp_path).epss_lookup(["CVE-2022-0001"])
    off = client(tmp_path, offline=True)
    n = len(calls)
    assert "CVE-2022-0001" in off.epss_lookup(["CVE-2022-0001"])
    assert off.epss_lookup(["CVE-2099-0009"]) == {}  # miss: no network, no error
    assert off.kev_lookup(["CVE-2021-44228"]) == {}
    assert off.registry_metadata("pkg:npm/foo@1") is None
    assert len(calls) == n


def test_env_offline(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_OFFLINE", "1")
    n = len(calls)
    assert client(tmp_path, offline=None).osv_query("pkg:npm/zzz@1.0.0") == []
    assert len(calls) == n


def test_safe_version_all_vulns(tmp_path):
    r = client(tmp_path).safe_version_lookup("pkg:npm/jsonwebtoken@0.4.0", ["CVE-2022-0001", "GHSA-bbbb"])
    assert r["fixed_version"] == "9.0.0" and r["affected_range"] == "<8.5.1; <9.0.0"
    only = client(tmp_path).safe_version_lookup("pkg:npm/jsonwebtoken@0.4.0", ["CVE-2022-0001"])
    assert only["fixed_version"] == "8.5.1"


def test_registry_trim(tmp_path):
    m = client(tmp_path).registry_metadata("pkg:npm/%40s/x@1.0.0")
    assert m["deprecated"] == "use y" and m["latest_has_install_script"] is True


def test_parse_purl():
    assert parse_purl("pkg:npm/%40angular/core@17.0.0") == ("@angular/core", "17.0.0", "npm")
