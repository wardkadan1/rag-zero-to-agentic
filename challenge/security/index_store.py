"""
SECURITY · PHASE 4 · atomic index builds: build aside, validate, then switch.

    with writer_lock(folder):                one index writer at a time (others get IndexBusy)
    name = new_collection_name()             cvs_<time>_<random>: never the active collection
    problems = validate(collection, chunks)  [] when the new collection is complete and correct
    activate(folder, info)                   ACTIVE.json replaced atomically (write, fsync, rename)
    read_active(folder)                      what readers attach to; they never create or delete
    keep_names(info)                         the active and the previous collection (prune the rest)
    lease(folder, name) / release(folder)    a reader says which collection it is using
    prune(client, folder, info)              delete the rest, never one a live reader still uses

A failed build never touches ACTIVE.json, so the previous working index stays the one in use.
The previous collection is kept one more build, and any collection a live reader process has
leased is kept until that reader moves on, so a reader never loses its index mid-question.
"""
import contextlib
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import threading
import time

from . import POLICY_VERSION

ACTIVE = "ACTIVE.json"
LOCK = ".writer.lock"
PREFIX = "cvs_"
READERS = "readers"
LEASE_S = 3600             # a lease older than this (reader hung or killed) no longer protects
HEARTBEAT_S = 300          # a live reader renews its lease this often, so an active reader never expires
KEY = ".index_key"         # HMAC key for ACTIVE.json (0600): detects edited or foreign manifests
TRUSTED = ("accepted", "reviewed")


def now():
    return time.time()                                 # one clock, so tests can move it


class IndexBusy(RuntimeError):
    """Another process is building the index right now."""


class IndexBuildFailed(RuntimeError):
    """The new index was not activated; the previous one is still in use."""


class IndexNotReady(RuntimeError):
    """There is no active index to attach to yet."""


class IndexRejected(IndexNotReady):
    """There is an active index, but this process must not serve it (wrong mode, policy, provenance)."""


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


def create(client, name):
    return client.create_collection(name, metadata={"hnsw:space": "cosine"})


def drop(client, name):
    client.delete_collection(name)


def lease(folder, name):
    """Record that THIS process reads collection `name` (renewed on every attach)."""
    readers = pathlib.Path(folder) / READERS
    readers.mkdir(parents=True, exist_ok=True)
    path = readers / f"{os.getpid()}.json"
    tmp = readers / f".{os.getpid()}.{secrets.token_hex(3)}.tmp"
    tmp.write_text(json.dumps({"collection": name, "pid": os.getpid(), "t": now()}))
    os.replace(tmp, path)
    HELD.update(folder=str(folder), name=name)
    _start_heartbeat()


HELD = {"folder": None, "name": None}                  # this process's lease
_BEAT = {"thread": None, "stop": threading.Event()}


def renew():
    """Refresh this process's lease (the heartbeat, and every refresh_index, call this)."""
    if HELD["folder"] and HELD["name"]:
        try:
            lease(HELD["folder"], HELD["name"])
        except OSError:
            pass


def _start_heartbeat():
    if _BEAT["thread"] and _BEAT["thread"].is_alive():
        return
    _BEAT["stop"].clear()

    def beat():
        while not _BEAT["stop"].wait(HEARTBEAT_S):
            renew()
    _BEAT["thread"] = threading.Thread(target=beat, name="index-lease-heartbeat", daemon=True)
    _BEAT["thread"].start()


def release(folder):
    try:
        (pathlib.Path(folder) / READERS / f"{os.getpid()}.json").unlink()
    except OSError:
        pass
    if HELD["folder"] == str(folder):
        HELD.update(folder=None, name=None)
        _BEAT["stop"].set()


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:                            # exists, owned by someone else
        return True


def leased(folder):
    """Collections that live reader processes still use. Dead or expired leases are removed."""
    out = set()
    for path in (pathlib.Path(folder) / READERS).glob("*.json"):
        try:
            entry = json.loads(path.read_text())
            if _alive(int(entry["pid"])) and now() - float(entry["t"]) < LEASE_S:
                out.add(entry["collection"])
                continue
        except (OSError, ValueError, KeyError, TypeError):
            pass
        try:
            path.unlink()
        except OSError:
            pass
    return out


def prune(client, folder, info):
    """Delete every collection that is not active, previous, or leased by a live reader."""
    keep = keep_names(info) | leased(folder)
    for c in client.list_collections():
        if c.name not in keep:
            drop(client, c.name)


# ----------------------------------------------------------------- index provenance (final review)
def fingerprint(chunks):
    """One hash over what a question can see: chunk ids, texts, document ids and trust, in order."""
    h = hashlib.sha256()
    for c in chunks:
        h.update(json.dumps([c["id"], hashlib.sha256(c["text"].encode()).hexdigest(), c.get("doc_id"), c.get("trust")]).encode())
    return h.hexdigest()


def _key(folder, create=False):
    path = pathlib.Path(folder) / KEY
    try:
        return path.read_bytes()
    except OSError:
        if not create:
            return None
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def _mac(key, info):
    body = json.dumps({k: v for k, v in info.items() if k != "signature"}, sort_keys=True).encode()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def sign(folder, info):
    return dict(info, signature=_mac(_key(folder, create=True), info))


def check(folder, info, chunks, mode):
    """Why THIS process must not serve this index ([] = it may). In enforce mode every problem
    is a refusal; in report mode (development) the caller only warns."""
    problems = []
    key = _key(folder)
    if not info.get("signature") or not key or not hmac.compare_digest(info["signature"], _mac(key, info)):
        problems.append("unverified:signature")
    if info.get("policy_version") != POLICY_VERSION:
        problems.append(f"policy_version:{info.get('policy_version')}!={POLICY_VERSION}")
    if info.get("fingerprint") != fingerprint(chunks):
        problems.append("content_mismatch")
    if mode == "enforce":
        if info.get("security_mode") != "enforce":
            problems.append(f"built_in_{info.get('security_mode') or 'unknown'}_mode")
        untrusted = sum(1 for c in chunks if c.get("trust") not in TRUSTED)
        if untrusted:
            problems.append(f"untrusted_chunks:{untrusted}")
    return problems
