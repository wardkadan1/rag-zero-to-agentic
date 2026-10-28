"""
SECURITY · PHASE 5 · retention: what is kept, for how long, and what is deleted (see RETENTION.md).

    sweep(folder)        files of deleted index versions: Chroma segment folders no collection
                         uses any more, and contact files of versions that no longer exist
    inventory(folder)    what is stored now (counts and names only, never CV content)

    python challenge/security/retention.py            show the inventory
    python challenge/security/retention.py --sweep    delete what the policy says is expired
    python challenge/security/retention.py --exports  also delete the app's Verify export

The index writer runs sweep() after every successful build, under the writer lock.
"""
import json
import pathlib
import re
import shutil
import sqlite3
import sys

HERE = pathlib.Path(__file__).resolve().parent
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def live(folder):
    """(segment ids, collection names) that Chroma still uses."""
    db = pathlib.Path(folder) / "chroma.sqlite3"
    if not db.exists():
        return set(), set()
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        segments = {r[0] for r in con.execute("SELECT id FROM segments")}
        names = {r[0] for r in con.execute("SELECT name FROM collections")}
    finally:
        con.close()
    return segments, names


def sweep(folder):
    folder = pathlib.Path(folder)
    segments, names = live(folder)
    removed = {"segment_folders": 0, "contact_files": 0}
    if (folder / "chroma.sqlite3").exists():
        for d in folder.iterdir():
            if d.is_dir() and UUID.fullmatch(d.name) and d.name not in segments:
                shutil.rmtree(d, ignore_errors=True)    # vectors and text of a deleted version
                removed["segment_folders"] += 1
    for f in (folder / "contacts").glob("*.json"):
        if f.stem not in names:
            f.unlink(missing_ok=True)
            removed["contact_files"] += 1
    return removed


def inventory(folder):
    folder = pathlib.Path(folder)
    segments, names = live(folder)
    active = {}
    try:
        active = json.loads((folder / "ACTIVE.json").read_text())
    except (OSError, ValueError):
        pass
    return {"active": active.get("collection"), "previous": active.get("previous"), "collections": sorted(names),
            "segment_folders": sum(1 for d in folder.iterdir() if d.is_dir() and UUID.fullmatch(d.name)) if folder.exists() else 0,
            "orphan_segment_folders": sum(1 for d in folder.iterdir() if d.is_dir() and UUID.fullmatch(d.name)
                                          and d.name not in segments) if folder.exists() else 0,
            "contact_files": sorted(f.name for f in (folder / "contacts").glob("*.json")),
            "reader_leases": sorted(f.name for f in (folder / "readers").glob("*.json"))}


if __name__ == "__main__":
    store = HERE.parent / "chroma_db"
    if "--sweep" in sys.argv or "--exports" in sys.argv:
        sys.path.insert(0, str(HERE.parent))
        from security import index_store
        with index_store.writer_lock(store):
            print("removed:", sweep(store))
        if "--exports" in sys.argv:
            export = HERE.parent / "verify_results.json"
            export.unlink(missing_ok=True)
            print("removed:", export.name)
    print(json.dumps(inventory(store), indent=1))
