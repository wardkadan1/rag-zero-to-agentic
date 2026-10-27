"""
SECURITY · PHASE 4 · atomic index builds: build aside, validate, then switch.

    with writer_lock(folder):                one index writer at a time (others get IndexBusy)
    name = new_collection_name()             cvs_<time>_<random>: never the active collection
    problems = validate(collection, chunks)  [] when the new collection is complete and correct
    activate(folder, info)                   ACTIVE.json replaced atomically (write, fsync, rename)
    read_active(folder)                      what readers attach to; they never create or delete
    keep_names(info)                         the active and the previous collection (prune the rest)

A failed build never touches ACTIVE.json, so the previous working index stays the one in use.
The previous collection is kept one more build, so a reader attached to it keeps working
until it re-attaches.
"""
import contextlib
import json
import os
import pathlib
import secrets
import time

ACTIVE = "ACTIVE.json"
LOCK = ".writer.lock"
PREFIX = "cvs_"


class IndexBusy(RuntimeError):
    """Another process is building the index right now."""


class IndexBuildFailed(RuntimeError):
    """The new index was not activated; the previous one is still in use."""


class IndexNotReady(RuntimeError):
    """There is no active index to attach to yet."""


@contextlib.contextmanager
def writer_lock(folder):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    fd = os.open(folder / LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:                            # Windows
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    except OSError:                                    # someone else holds it
        os.close(fd)
        raise IndexBusy("another process is building the CV index: try again when it has finished") from None
    try:
        yield
    finally:
        os.close(fd)                                   # closing the file releases the lock


def new_collection_name():
    return f"{PREFIX}{time.strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(3)}"


def read_active(folder):
    try:
        info = json.loads((pathlib.Path(folder) / ACTIVE).read_text(encoding="utf-8"))
        return info if isinstance(info, dict) and isinstance(info.get("collection"), str) else None
    except (OSError, ValueError):
        return None


def activate(folder, info):
    folder = pathlib.Path(folder)
    tmp = folder / f".{ACTIVE}.{secrets.token_hex(4)}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, folder / ACTIVE)                   # readers see the old file or the new one, never half


def keep_names(info):
    return {n for n in (info.get("collection"), info.get("previous")) if n}


def validate(collection, chunks, embed):
    """Problems with a freshly built collection ([] = fine). Checks the count, that every chunk
    id is there with its source and document id, and that a stored chunk finds itself."""
    problems = []
    want = {c["id"]: c for c in chunks}
    if len(want) != len(chunks):
        problems.append("duplicate_chunk_ids")
    if collection.count() != len(want):
        problems.append(f"count:{collection.count()}!={len(want)}")
    got = collection.get(ids=list(want), include=["metadatas"])
    if set(got["ids"]) != set(want):
        problems.append("missing_chunks")
    for cid, meta in zip(got["ids"], got["metadatas"]):
        if meta.get("source") != want[cid]["source"] or meta.get("doc_id") != want[cid].get("doc_id"):
            problems.append("wrong_metadata")
            break
    if chunks and not problems:
        probe = chunks[len(chunks) // 2]
        res = collection.query(query_embeddings=embed([probe["text"]]).tolist(), n_results=min(5, len(chunks)))
        if probe["id"] not in res["ids"][0]:
            problems.append("probe_not_found")
    return problems
