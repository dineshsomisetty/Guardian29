from guardian.tools.policy import build_policy_input, load_config, policy_check

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


def make(tmp_path, action, from1, from2, lock):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(f"jobs:\n  a:\n    steps:\n      - uses: {action}\n      - uses: ./local\n")
    (tmp_path / "Dockerfile").write_text(f"FROM {from1} AS installer\nRUN true\nFROM {from2}\nCOPY --from=installer /a /a\n")
    if lock:
        (tmp_path / "package-lock.json").write_text("{}")


def test_juice_shop_like_fails_and_patched_passes(tmp_path):
    cfg = load_config()
    before = tmp_path / "before"
    make(before, "coverallsapp/github-action@v2", "node:24", "gcr.io/distroless/nodejs24-debian13", lock=False)
    doc = build_policy_input(before, ["ngy-cookie", "express"])
    rules = {v["rule"] for v in policy_check(doc, cfg)}
    assert {"unpinned_action", "tag_only_image", "missing_lockfile", "denylisted_package"} <= rules
    assert len(policy_check(doc, cfg)) >= 5  # 1 action + 2 images + lockfile + denylist

    after = tmp_path / "after"
    make(after, f"coverallsapp/github-action@{SHA}", f"node:24@{DIGEST}", f"gcr.io/distroless/nodejs24-debian13@{DIGEST}", lock=True)
    assert policy_check(build_policy_input(after, ["express"]), cfg) == []


def test_violations_carry_file_and_line(tmp_path):
    make(tmp_path, "x/y@v1", "node:24", "node:24", lock=True)
    v = [x for x in policy_check(build_policy_input(tmp_path), load_config()) if x["rule"] == "unpinned_action"][0]
    assert v["file"] == ".github/workflows/ci.yml" and v["line"] == 4


def test_package_age_and_typosquat():
    doc = {"has_lockfile": True, "packages": [{"name": "fresh", "age_days": 2}, {"name": "old", "age_days": 400},
                                              {"name": "ngy-cookies", "typosquat_of": "ngx-cookie"}]}
    rules = [v["rule"] for v in policy_check(doc, {"thresholds": {"min_package_age_days": 7}})]
    assert rules == ["package_too_new", "typosquat_package"]
