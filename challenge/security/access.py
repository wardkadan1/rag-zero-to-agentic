"""
SECURITY · PHASE 5 · contact details live apart from the searchable CV text.

At ingestion the contact details are cut out of the text (pii.split_contacts). They are kept
with the index version they belong to, in chroma_db/contacts/<collection>.json (file mode 0600),
and deleted together with that version. Nothing that searches, ranks or answers sees them.

Reading them needs EXPLICIT authorization:
    CV_CONTACT_ACCESS=granted   set by the operator for this process (default: denied)
    a stated purpose            at least a few words, written to the access log
Every attempt, allowed or not, is appended to chroma_db/contact_access.log: time, document id,
decision and purpose. The log never contains the contact details themselves.
"""
import json
import os
import pathlib
import time

CONTACTS = "contacts"
LOG = "contact_access.log"
MIN_PURPOSE = 10


class NotAuthorized(PermissionError):
    pass


def path_for(folder, collection):
    return pathlib.Path(folder) / CONTACTS / f"{collection}.json"


def save(folder, collection, table):
    """{doc_id: [{"kind", "value"}, ...]} for one index version, readable by its owner only."""
    path = path_for(folder, collection)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(table, f)
    os.chmod(path, 0o600)


def remove(folder, collection):
    try:
        path_for(folder, collection).unlink()
    except OSError:
        pass


def audit(folder, doc_id, decision, purpose):
    line = json.dumps({"t": round(time.time()), "doc_id": doc_id, "decision": decision, "purpose": purpose[:200]})
    fd = os.open(pathlib.Path(folder) / LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def read(folder, collection, doc_id, purpose):
    purpose = (purpose or "").strip()
    if os.getenv("CV_CONTACT_ACCESS", "").strip().lower() != "granted":
        audit(folder, doc_id, "denied:not_authorized", purpose)
        raise NotAuthorized("contact details need explicit authorization (the operator sets CV_CONTACT_ACCESS=granted)")
    if len(purpose) < MIN_PURPOSE:
        audit(folder, doc_id, "denied:no_purpose", purpose)
        raise NotAuthorized("say why the contact details are needed (purpose)")
    try:
        table = json.loads(path_for(folder, collection).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        table = {}
    audit(folder, doc_id, "granted", purpose)
    return table.get(doc_id, [])
