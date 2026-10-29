"""
SECURITY · PHASE 3 corrections · enforce mode fails closed. SYNTHETIC CVs only.

    pytest challenge/security/tests/test_enforce.py -q

1. A PDF whose render-aware inspection did not complete (library missing, inspection error,
   no result) is never indexed in enforce mode, whatever decisions.json says.
2. In enforce mode a content-flagged CV stays out of Chroma, BM25, the graph and the MCP tools
   until a person accepts it; a high-confidence quarantine is never overridden.
"""
import functools
import importlib
import json
import shutil
import sys

import pytest

from test_content import (ATTACKS, PRACTICE, hashed_embed, make_sam_tester, normal_cv, pipeline, sandbox,
                          stuffed_cv)

WORKER = str(sandbox.WORKER)
MISSING_LIBRARY = f"""
import runpy, sys
sys.modules["pdfplumber"] = None          # 'import pdfplumber' now raises ImportError
sys.argv = [{WORKER!r}] + sys.argv[1:]
runpy.run_path({WORKER!r}, run_name="__main__")
"""
INSPECTION_FAILS = f"""
import runpy, sys
sys.path.insert(0, {str(sandbox.HERE.parent)!r})
from security import pdf_inspect
def broken(data):
    raise ValueError("synthetic failure")
pdf_inspect.hidden_text = broken
sys.argv = [{WORKER!r}] + sys.argv[1:]
runpy.run_path({WORKER!r}, run_name="__main__")
"""


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_REPORT", str(tmp_path / "quarantine.json"))
    monkeypatch.setenv("SECURITY_DECISIONS", str(tmp_path / "decisions.json"))
    monkeypatch.setenv("SECURITY_IDENTITIES", str(tmp_path / "identities.json"))
    monkeypatch.delenv("SECURITY_MODE", raising=False)


def plain_pdf_folder(tmp_path):
    d = tmp_path / "cvs"
    d.mkdir()
    make_sam_tester(d / "Rana_Khalil_CV.pdf", white=None, tiny=None, offpage=None)   # a clean, visible-only PDF
    (d / "Omar_Saleh.md").write_text(normal_cv("Omar Saleh"))                        # so the folder is never empty
    return d


def accept_everything(tmp_path, folder):
    import hashlib
    table = {hashlib.sha256(p.read_bytes()).hexdigest(): {"decision": "accept", "note": "test"} for p in folder.iterdir()}
    (tmp_path / "decisions.json").write_text(json.dumps(table))


def run_with_worker(monkeypatch, code):
    monkeypatch.setattr(sandbox, "parse_all", functools.partial(sandbox.parse_all, worker=[sys.executable, "-I", "-c", code]))


CASES = {"missing_library": (MISSING_LIBRARY, "pdf_render_check_unavailable:not_installed"),
         "inspection_error": (INSPECTION_FAILS, "pdf_render_check_unavailable:ValueError")}


@pytest.mark.parametrize("case", CASES)
def test_report_mode_indexes_an_uninspected_pdf_but_flags_it(tmp_path, monkeypatch, case):
    code, reason = CASES[case]
    run_with_worker(monkeypatch, code)
    docs = pipeline.load_cvs(plain_pdf_folder(tmp_path))
    row = {r["source"]: r for r in pipeline.INGEST_REPORT}["Rana_Khalil_CV.pdf"]
    assert "Rana_Khalil_CV.pdf" in {x["source"] for x in docs}
    assert row["verdict"] == "flagged" and reason in row["flags"]


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("accepted", [False, True])
def test_enforce_mode_never_indexes_an_uninspected_pdf(tmp_path, monkeypatch, case, accepted):
    code, reason = CASES[case]
    monkeypatch.setenv("SECURITY_MODE", "enforce")
    run_with_worker(monkeypatch, code)
    folder = plain_pdf_folder(tmp_path)
    if accepted:
        accept_everything(tmp_path, folder)                         # even a person's "accept" does not open it
    docs = pipeline.load_cvs(folder)
    row = {r["source"]: r for r in pipeline.INGEST_REPORT}["Rana_Khalil_CV.pdf"]
    assert [x["source"] for x in docs] == ["Omar_Saleh.md"]
    assert row["status"] == "quarantined" and row["verdict"] == "quarantined" and reason in row["detail"]


@pytest.mark.parametrize("mode", ["report", "enforce"])
def test_a_pdf_result_without_an_inspection_counts_as_not_inspected(tmp_path, monkeypatch, mode):
    monkeypatch.setenv("SECURITY_MODE", mode)
    real = sandbox.parse_all

    def no_hidden(jobs, **kw):
        out = real(jobs, **kw)
        for v in out.values():
            v.pop("hidden", None)
        return out
    monkeypatch.setattr(sandbox, "parse_all", no_hidden)
    docs = pipeline.load_cvs(plain_pdf_folder(tmp_path))
    indexed = "Rana_Khalil_CV.pdf" in {x["source"] for x in docs}
    assert indexed == (mode == "report")


@pytest.mark.parametrize("mode", ["report", "enforce"])
def test_a_successfully_inspected_pdf_is_accepted_in_both_modes(tmp_path, monkeypatch, mode):
    monkeypatch.setenv("SECURITY_MODE", mode)
    docs = pipeline.load_cvs(plain_pdf_folder(tmp_path))
    rows = {r["source"]: r for r in pipeline.INGEST_REPORT}
    assert len(docs) == 2 and rows["Rana_Khalil_CV.pdf"]["verdict"] == "accepted"


# ------------------------------------------------------------------ enforce: flagged content waits for a person
def attacked_folder(tmp_path):
    d = tmp_path / "cvs"
    shutil.copytree(PRACTICE, d)
    (d / "Aaron_Abbot_CV.md").write_text(stuffed_cv("Aaron Abbot"))                 # medium: stuffing
    (d / "Noor_Injection_CV.md").write_text(normal_cv("Noor Khalil") + "\n" + ATTACKS["arabic"], encoding="utf-8")
    make_sam_tester(d / "Sam_Tester_CV.pdf")                                         # high: hidden injection
    return d


def resolve_practice_versions(tmp_path, folder):
    """A person's answer for the practice set: cand-009.md and cand-009-2023.md are two versions
    of one candidate (Phase 4 would otherwise hold both back as an identity collision)."""
    import hashlib
    groups = {}
    for p in sorted(folder.glob("cand-*.md"), key=lambda p: len(p.name)):
        groups.setdefault(p.name[:8], []).append(hashlib.sha256(p.read_bytes()).hexdigest())
    (tmp_path / "identities.json").write_text(json.dumps({"same_person": [g for g in groups.values() if len(g) > 1]}))


def index_everything(tmp_path, monkeypatch, folder):
    resolve_practice_versions(tmp_path, folder)
    monkeypatch.setattr(pipeline, "HERE", tmp_path)
    monkeypatch.setattr(pipeline, "embed", hashed_embed)
    docs = pipeline.load_cvs(folder)
    chunks = [c for doc in docs for c in pipeline.chunk(doc)]
    pipeline.build_index(chunks)
    pipeline.build_graph(chunks)
    return docs


def stores():
    return {"chroma": {m["source"] for m in pipeline.COLLECTION.get(include=["metadatas"])["metadatas"]},
            "bm25": {c["source"] for c in pipeline.BM25["chunks"]},
            "graph": {data.get("source") for _, data in pipeline.GRAPH.nodes(data=True)} - {None}}


def test_enforce_keeps_unapproved_flagged_cvs_out_of_every_store(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_MODE", "enforce")
    index_everything(tmp_path, monkeypatch, attacked_folder(tmp_path))
    rows = {r["source"]: r for r in pipeline.INGEST_REPORT}
    assert rows["Aaron_Abbot_CV.md"]["verdict"] == "flagged" and rows["Aaron_Abbot_CV.md"]["status"] == "quarantined"
    assert "waiting for a person's decision" in rows["Aaron_Abbot_CV.md"]["detail"]          # reviewable, not deleted
    legit = {p.name for p in PRACTICE.glob("*.md")}
    found = stores()
    assert found["chroma"] == found["bm25"] == legit
    assert found["graph"] <= legit                                   # the graph keeps one node per candidate name
    assert "aaron" not in pipeline.BM25["idf"]                       # not in the Level 5 vocabulary either


def test_enforce_accept_releases_a_flagged_cv_but_never_a_quarantined_one(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_MODE", "enforce")
    folder = attacked_folder(tmp_path)
    accept_everything(tmp_path, folder)
    index_everything(tmp_path, monkeypatch, folder)
    for name, found in stores().items():
        assert "Aaron_Abbot_CV.md" in found, name                    # a person accepted the medium finding
        assert not found & {"Noor_Injection_CV.md", "Sam_Tester_CV.pdf"}, name   # high stays out, no override


def test_enforce_keeps_flagged_cvs_out_of_the_mcp_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_MODE", "enforce")
    index_everything(tmp_path, monkeypatch, attacked_folder(tmp_path))   # the app builds the index
    monkeypatch.delitem(sys.modules, "mcp_server", raising=False)
    server = importlib.import_module("mcp_server")                    # the MCP server only attaches to it
    try:
        found = server.search_cvs("Which candidates know Python?")
        assert found["passages"] and not {p["source"] for p in found["passages"]} & {"Aaron_Abbot_CV.md",
                                                                                     "Sam_Tester_CV.pdf"}
        for name in ("Aaron_Abbot_CV.md", "Sam_Tester_CV.pdf", "Noor_Injection_CV.md"):
            answer = server.get_cv(name)
            assert "error" in answer and "available" not in answer
    finally:
        sys.modules.pop("mcp_server", None)
