import json
import threading
import urllib.error
import urllib.request
from functools import partial
from http.server import ThreadingHTTPServer

import httpx
import pytest

from guardian.core.config import load_settings
from guardian.llm.provider import LLMError, LLMProvider, OpenAICompatBackend
from guardian.serve import RunsHandler


class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._p = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._p


def test_deepseek_defaults(monkeypatch):
    # set to "" rather than deleted: load_settings() re-reads .env, which would bring a local value back
    monkeypatch.setenv("GUARDIAN_MODEL", "")
    monkeypatch.setenv("LLM_BASE_URL", "")
    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "deepseek")
    s = load_settings()
    assert s.llm_model == "deepseek-chat" and s.llm_base_url == "https://api.deepseek.com"


def test_deepseek_json_mode_request(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-not-real")
    seen = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        seen.update(url=url, body=json, headers=headers)
        return _Resp(200, {"model": "deepseek-chat", "choices": [{"finish_reason": "stop",
                     "message": {"content": '{"assessments": []}'}}], "usage": {"prompt_tokens": 5}})

    monkeypatch.setattr(httpx, "post", fake_post)
    b = OpenAICompatBackend("deepseek-chat", "https://api.deepseek.com", key_env="DEEPSEEK_API_KEY",
                            json_mode="json_object")
    r = b.complete_json("sys", "user", {"type": "object"})
    assert seen["url"] == "https://api.deepseek.com/chat/completions"
    assert seen["body"]["response_format"] == {"type": "json_object"}
    assert "json" in seen["body"]["messages"][0]["content"].lower()
    assert r.text == '{"assessments": []}'


def test_deepseek_missing_key_and_truncation(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    b = OpenAICompatBackend("deepseek-chat", "https://api.deepseek.com", key_env="DEEPSEEK_API_KEY")
    with pytest.raises(LLMError, match="DEEPSEEK_API_KEY"):
        b.complete_json("s", "u", {})
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    b = OpenAICompatBackend("deepseek-chat", "https://api.deepseek.com", key_env="DEEPSEEK_API_KEY")
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(200, {"choices": [{"finish_reason": "length",
                                                                                "message": {"content": "{"}}]}))
    with pytest.raises(LLMError, match="truncated"):
        b.complete_json("s", "u", {})


def test_provider_factory_picks_deepseek(monkeypatch, tmp_path):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    s = load_settings(llm_provider="deepseek", llm_base_url="https://api.deepseek.com", llm_model="deepseek-chat")
    p = LLMProvider.from_settings(s)
    assert isinstance(p._backend_or_create(), OpenAICompatBackend)


def test_serve_runs_refuses_work_copy(tmp_path):
    run = tmp_path / "run_x"
    (run / "work").mkdir(parents=True)
    (run / "work" / "ctf.key").write_text("secret")
    (run / "run_summary.json").write_text("{}")
    (run / ".env").write_text("K=1")
    (tmp_path / "LATEST").write_text("run_x")
    RunsHandler.runs_dir = tmp_path
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), partial(RunsHandler, directory=str(tmp_path)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        assert urllib.request.urlopen(f"http://127.0.0.1:{port}/latest/run_summary.json").status == 200
        bypasses = ("/latest/work/ctf.key", "/run_x/work/ctf.key", "/run_x/./work/ctf.key",
                    "/run_x/%77ork/ctf.key", "/run_x/WORK/ctf.key", "/run_x//work/ctf.key",
                    "/run_x/x/../work/ctf.key", "/run_x/.env")
        for path in bypasses:
            for method in ("GET", "HEAD"):
                req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
                with pytest.raises(urllib.error.HTTPError) as e:
                    urllib.request.urlopen(req)
                assert e.value.code == 403, (method, path)
    finally:
        httpd.shutdown()
