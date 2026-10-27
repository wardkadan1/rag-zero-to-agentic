"""
SECURITY · PHASE 4 · who a CV belongs to, decided from trusted facts only.

    document id   doc_id = the first 16 hex characters of the file's SHA-256 (from the gate).
                  It names one exact version of one file. Not the file name, not the CV's text.
    candidate id  "cand-" + a document id. By default every document is its own candidate:
                  two CVs are NEVER merged because their names match (a name is a claim the CV
                  makes, like its city, skills and years).
    collision     two documents of different candidates that claim the same name. Both are
                  flagged "identity_collision" until a person resolves it in identities.json.

identities.json (git-ignored, written by a person, keyed by SHA-256):
    {"same_person":      [["<sha256 current version>", "<sha256 older version>", ...], ...],
     "different_people": [["<sha256>", "<sha256>"], ...]}
same_person: the documents share one candidate id (the first one listed is the current
version, which the graph uses); different_people: the collision is known and accepted.
"""
import json
import os
import pathlib
import re

from . import content

HERE = pathlib.Path(__file__).resolve().parent


def load_identities(path=None):
    path = pathlib.Path(path or os.getenv("SECURITY_IDENTITIES", HERE / "identities.json"))
    try:
        table = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"same_person": [], "different_people": []}
    groups = [[s for s in g if isinstance(s, str)] for g in table.get("same_person", []) if isinstance(g, list)]
    pairs = [g for g in table.get("different_people", []) if isinstance(g, list) and len(g) == 2]
    return {"same_person": groups, "different_people": pairs}


def name_key(name):
    """How two claimed names are compared: case, accents, marks, spacing and punctuation ignored."""
    return re.sub(r"[^\w]+", " ", content.detection_view(name or "")).strip()


def assign(docs, identities=None):
    """docs: [{"source", "sha256", "doc_id", "name"}]. Returns ({source: candidate_id},
    {source: current_version_source}, [(source_a, source_b), ...] unresolved collisions)."""
    identities = identities or load_identities()
    by_sha = {d["sha256"]: d for d in docs}
    candidate, current = {}, {}
    for group in identities["same_person"]:
        present = [by_sha[s] for s in group if s in by_sha]
        if not present:
            continue
        cid = "cand-" + present[0]["doc_id"][:12]
        for d in present:
            candidate.setdefault(d["source"], cid)
            current.setdefault(d["source"], present[0]["source"])
    for d in docs:
        candidate.setdefault(d["source"], "cand-" + d["doc_id"][:12])
        current.setdefault(d["source"], d["source"])
    known = {frozenset(p) for p in identities["different_people"]}
    by_name = {}
    for d in docs:
        if name_key(d["name"]):
            by_name.setdefault(name_key(d["name"]), []).append(d)
    collisions = []
    for same in by_name.values():
        for i, a in enumerate(same):
            for b in same[i + 1:]:
                if candidate[a["source"]] != candidate[b["source"]] and frozenset((a["sha256"], b["sha256"])) not in known:
                    collisions.append((a["source"], b["source"]))
    return candidate, current, collisions
