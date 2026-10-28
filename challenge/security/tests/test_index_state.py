"""
SECURITY · PHASE 4 corrections · one consistent RAG state, and a strictly read-only MCP server.
SYNTHETIC CVs only.

    pytest challenge/security/tests/test_index_state.py -q

* Chroma, BM25, the graph and the Level 5 vocabulary always belong to the same validated index
  version; a failure at any build step (create, add, validate, BM25, graph, activate, cleanup)
  leaves the previous FULLY working state.
* Readers in other processes keep working through repeated rebuilds; a collection a live
  reader uses is never deleted under it.
* The MCP server with no index never creates a collection and never opens a CV file.
"""
import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

from test_content import hashed_embed, normal_cv, pipeline

from security import index_store

CHALLENGE = pathlib.Path(pipeline.__file__).resolve().parent


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_REPORT", str(tmp_path / "quarantine.json"))
    monkeypatch.setenv("SECURITY_DECISIONS", str(tmp_path / "decisions.json"))
    monkeypatch.setenv("SECURITY_IDENTITIES", str(tmp_path / "identities.json"))
    monkeypatch.delenv("SECURITY_MODE", raising=False)
    monkeypatch.setattr(pipeline, "HERE", tmp_path)
    monkeypatch.setattr(pipeline, "embed", hashed_embed)
    monkeypatch.setattr(pipeline, "LAST_BUILD_FAILED", False)
    monkeypatch.setattr(pipeline, "RERANK", False)                   # no model needed: same code path otherwise
    monkeypatch.setitem(pipeline.ACTIVE_INFO, "info", None)
    yield
    index_store.release(tmp_path / "chroma_db")


def chunks_for(tmp_path, names):
    d = tmp_path / ("cvs_" + "_".join(n.split()[0] for n in names))
    d.mkdir(exist_ok=True)
    for n in names:
        (d / (n.replace(" ", "_") + ".md")).write_text(normal_cv(n) + f"\nSpecial skill: {n.split()[0]}lang.")
    return [c for doc in pipeline.load_cvs(d) for c in pipeline.chunk(doc)]


def collections(tmp_path):
    import chromadb
    return {c.name for c in chromadb.PersistentClient(path=str(tmp_path / "chroma_db")).list_collections()}


def snapshot():
    """Everything a question depends on, for 'the previous state still works' checks."""
    return {"version": pipeline.index_version(), "count": pipeline.COLLECTION.count(),
            "bm25": [c["id"] for c in pipeline.BM25["chunks"]], "graph": sorted(pipeline.GRAPH.nodes),
            "vocab": sorted(pipeline.BM25["vocab"]),
            "answer": [h["source"] for h in pipeline.retrieve("Who knows Ranalang?")],
            "list": [h["source"] for h in pipeline.retrieve("Which candidates know Django?")]}


def consistent():
    v = pipeline.index_version()
    return len(set(v.values())) == 1 and v["active"] is not None


# ------------------------------------------------------------------ failure injection
def boom(*a, **k):
    raise RuntimeError("synthetic failure")


REAL = {(index_store, n): getattr(index_store, n) for n in ("create", "validate", "activate", "drop")}
REAL.update({(pipeline, n): getattr(pipeline, n) for n in ("make_bm25", "make_graph")})


def restore(mp):
    for (module, name), fn in REAL.items():
        mp.setattr(module, name, fn)
    mp.setattr(pipeline, "embed", hashed_embed)


STEPS = {
    "chroma_create": lambda mp: mp.setattr(index_store, "create", boom),
    "chroma_add": lambda mp: mp.setattr(pipeline, "embed", boom),
    "validation": lambda mp: mp.setattr(index_store, "validate", lambda *a: ["probe_not_found"]),
    "bm25": lambda mp: mp.setattr(pipeline, "make_bm25", boom),
    "graph": lambda mp: mp.setattr(pipeline, "make_graph", boom),
    "activation": lambda mp: mp.setattr(index_store, "activate", boom),
}


@pytest.mark.parametrize("step", STEPS)
def test_a_failure_at_any_build_step_keeps_the_previous_full_rag_state(tmp_path, monkeypatch, step):
    first = chunks_for(tmp_path, ("Rana Khalil", "Omar Saleh"))
    pipeline.build_index(first)
    pipeline.build_graph(first)
    before, active, names = snapshot(), index_store.read_active(tmp_path / "chroma_db"), collections(tmp_path)
    assert consistent() and before["answer"][0] == "Rana_Khalil.md"
    second = chunks_for(tmp_path, ("Dana Levi", "Sami Nasser"))
    STEPS[step](monkeypatch)
    with pytest.raises(index_store.IndexBuildFailed, match="previous index .* is still active"):
        pipeline.build_index(second)
    pipeline.build_graph(second)                                       # what the app calls next
    restore(monkeypatch)
    assert index_store.read_active(tmp_path / "chroma_db") == active
    assert collections(tmp_path) == names                              # the unfinished collection is gone
    assert consistent() and snapshot() == before                       # Chroma, BM25, graph, vocab: all the old ones


def test_a_failed_cleanup_of_the_unfinished_collection_is_retried_later(tmp_path, monkeypatch):
    pipeline.build_index(chunks_for(tmp_path, ("Rana Khalil", "Omar Saleh")))
    before = snapshot()
    monkeypatch.setattr(index_store, "validate", lambda *a: ["count:0!=4"])
    monkeypatch.setattr(index_store, "drop", boom)
    with pytest.raises(index_store.IndexBuildFailed):
        pipeline.build_index(chunks_for(tmp_path, ("Dana Levi", "Sami Nasser")))
    leftover = collections(tmp_path) - {before["version"]["active"]}
    assert len(leftover) == 1 and snapshot() == before                 # left behind, but never used
    restore(monkeypatch)
    pipeline.build_index(chunks_for(tmp_path, ("Lina Haddad", "Rami Haddad")))
    assert not leftover & collections(tmp_path) and consistent()      # the next good build removes it


def test_a_failed_cleanup_after_a_good_build_keeps_the_new_consistent_state(tmp_path, monkeypatch):
    pipeline.build_index(chunks_for(tmp_path, ("Rana Khalil", "Omar Saleh")))
    monkeypatch.setattr(index_store, "drop", boom)
    pipeline.build_index(chunks_for(tmp_path, ("Dana Levi", "Sami Nasser")))
    pipeline.build_index(chunks_for(tmp_path, ("Lina Haddad", "Rami Haddad")))   # prune fails: old ones stay
    assert consistent() and {c["source"] for c in pipeline.BM25["chunks"]} == {"Lina_Haddad.md", "Rami_Haddad.md"}
    assert pipeline.index_version()["active"] == index_store.read_active(tmp_path / "chroma_db")["collection"]


def test_graph_bm25_vocabulary_and_chroma_carry_the_same_version(tmp_path):
    chunks = chunks_for(tmp_path, ("Rana Khalil", "Omar Saleh"))
    pipeline.build_index(chunks)
    assert pipeline.build_graph(chunks) is pipeline.GRAPH                # the prepared graph, not a second one
    assert consistent()
    assert "ranalang" in pipeline.BM25["vocab"]


# ------------------------------------------------------------------ readers in other processes
READER = """
import json, pathlib, sys, time
sys.path.insert(0, {challenge!r})
import pipeline
pipeline.HERE = pathlib.Path({home!r})
pipeline.attach_index()
seen, errors, n, end = set(), [], 0, time.time() + {seconds}
while time.time() < end:
    try:
        {refresh}
        with pipeline.RAG_LOCK:
            v = pipeline.index_version()
            assert len(set(v.values())) == 1, v
            seen.add(v["active"])
            assert pipeline.COLLECTION.count() == len(pipeline.BM25["chunks"])
            pipeline.COLLECTION.query(query_embeddings=[[0.0625] * 256], n_results=1)
            pipeline.bm25_search("python django", 3)
        n += 1
    except Exception as e:
        errors.append(type(e).__name__ + ": " + str(e)[:120])
    time.sleep(0.02)
print(json.dumps({{"seen": sorted(seen), "errors": errors[:5], "queries": n}}))
"""


def start_reader(tmp_path, seconds, refresh=True):
    code = READER.format(challenge=str(CHALLENGE), home=str(tmp_path), seconds=seconds,
                         refresh="pipeline.refresh_index()" if refresh else "pass")
    return subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)


def test_readers_keep_working_during_repeated_rebuilds(tmp_path):
    pipeline.build_index(chunks_for(tmp_path, ("Rana Khalil", "Omar Saleh")))
    readers = [start_reader(tmp_path, 12), start_reader(tmp_path, 12)]
    stuck = start_reader(tmp_path, 12, refresh=False)                  # never moves on from the first version
    time.sleep(4)
    first = index_store.read_active(tmp_path / "chroma_db")["collection"]
    sets = [("Dana Levi", "Sami Nasser"), ("Lina Haddad", "Rami Haddad"), ("Noor Khalil", "Ali Hassan"),
            ("Maya Cohen", "Yara Saleh"), ("Omar Saleh", "Rana Khalil")]
    for names in sets:
        pipeline.build_index(chunks_for(tmp_path, names))
        assert first in collections(tmp_path)                          # the stuck reader still has its index
        time.sleep(0.5)
    results = [json.loads(p.communicate(timeout=60)[0].strip().splitlines()[-1]) for p in readers + [stuck]]
    for r in results:
        assert r["errors"] == [] and r["queries"] > 10, r
    assert all(len(r["seen"]) >= 2 for r in results[:2])               # they followed the rebuilds
    assert results[2]["seen"] == [first]
    pipeline.build_index(chunks_for(tmp_path, ("Dana Levi", "Sami Nasser")))
    assert first not in collections(tmp_path)                          # its reader has exited: now pruned


# ------------------------------------------------------------------ MCP: strictly read-only
MCP_EMPTY = """
import json, os, pathlib, sys
cvs = {cvs!r}
opened = []
sys.addaudithook(lambda event, args: opened.append(str(args[0])) if event == "open" and str(args[0]).startswith(cvs) else None)
sys.path.insert(0, {challenge!r})
import pipeline
pipeline.HERE = pathlib.Path({home!r})
calls = []
for name in ("load_cvs", "build_index", "build_graph", "chunk"):
    setattr(pipeline, name, lambda *a, _n=name, **k: calls.append(_n))
import mcp_server
out = {{"search": mcp_server.search_cvs("Who knows Python?"), "cv": mcp_server.get_cv("Rana_Khalil.md"),
        "opened": opened, "calls": calls, "chroma_exists": (pathlib.Path({home!r}) / "chroma_db").exists()}}
print(json.dumps(out))
"""


def test_mcp_with_an_empty_index_never_builds_and_never_opens_a_cv(tmp_path):
    cvs = tmp_path / "cvs"
    cvs.mkdir()
    (cvs / "Rana_Khalil.md").write_text(normal_cv("Rana Khalil"))
    env = dict(os.environ, CV_DIR=str(cvs))
    code = MCP_EMPTY.format(cvs=str(cvs), challenge=str(CHALLENGE), home=str(tmp_path))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120)
    got = json.loads(out.stdout.strip().splitlines()[-1])
    assert got["opened"] == [] and got["calls"] == [] and got["chroma_exists"] is False
    for answer in (got["search"], got["cv"]):
        assert answer["error"] == "index_not_initialized" and "app" in answer["action"]


def test_mcp_starts_answering_once_the_app_has_built_the_index(tmp_path, monkeypatch):
    sys.modules.pop("mcp_server", None)
    import importlib
    server = importlib.import_module("mcp_server")
    try:
        assert server.search_cvs("Who knows Ranalang?")["error"] == "index_not_initialized"
        pipeline.build_index(chunks_for(tmp_path, ("Rana Khalil", "Omar Saleh")))   # the app, as the writer
        found = server.search_cvs("Who knows Ranalang?")
        assert "error" not in found and found["passages"][0]["source"] == "Rana_Khalil.md"
    finally:
        sys.modules.pop("mcp_server", None)
