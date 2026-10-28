"""
SECURITY · PHASE 5 · contact details live apart from the searchable CV text.

At ingestion the contact details are cut out of the text (pii.split_contacts). They are kept
with the index version they belong to, in chroma_db/contacts/<collection>.json (file mode 0600),
and deleted together with that version. Nothing that searches, ranks or answers sees them.

Reading them needs EXPLICIT authorization:
    CV_CONTACT_ACCESS=granted   set by the operator for this process (default: denied)
    a stated purpose            at least a few words, written to the access log
Every attempt, allowed or not, is appended to chroma_db/contact_access.log: time, document id,
decision and purpose. The log never contains the contact details themselves: the purpose is
stored after the PII policy (and any long number) has masked it.

DEVELOPMENT ONLY. CV_CONTACT_ACCESS authorizes the whole PROCESS, not a person: anyone or any
agent that can call this process gets the same access. It is refused outright when
RAG_ENV=production. A per-user design (CONTACT_ACCESS.md) is required before production.
"""
import json
import os
import pathlib
import re
import time

from . import pii

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


DIGITS = re.compile(r"\d(?:[\s\-./()]*\d){4,}")       # 5+ digits, also spaced or split ("0 5 2 5 5…")


def safe_purpose(purpose, known=()):
    """What may be written to the log: the PII policy, every contact value stored for this CV
    (however it is cased or spaced), then any 5+ digits masked. A purpose can never carry the
    details it asks for into the log."""
    text = purpose or ""
    for value in sorted({v for v in known if v and len(v) >= 4}, key=len, reverse=True):
        text = re.sub(r"\s*".join(map(re.escape, re.sub(r"\s+", "", value))), "⟨contact⟩", text, flags=re.I)
    return DIGITS.sub("⟨number⟩", pii.redact(text))[:200]


def audit(folder, doc_id, decision, purpose, known=()):
    line = json.dumps({"t": round(time.time()), "doc_id": doc_id, "decision": decision,
                       "purpose": safe_purpose(purpose, known)}, ensure_ascii=False)
    fd = os.open(pathlib.Path(folder) / LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def read(folder, collection, doc_id, purpose):
    purpose = (purpose or "").strip()
    try:
        table = json.loads(path_for(folder, collection).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        table = {}
    known = [c.get("value", "") for c in table.get(doc_id, [])]     # only to keep them out of the log
    if os.getenv("RAG_ENV", "").strip().lower() in ("prod", "production"):
        audit(folder, doc_id, "denied:development_only", purpose, known)
        raise NotAuthorized("process-wide contact access is development-only; production needs per-user authorization")
    if os.getenv("CV_CONTACT_ACCESS", "").strip().lower() != "granted":
        audit(folder, doc_id, "denied:not_authorized", purpose, known)
        raise NotAuthorized("contact details need explicit authorization (the operator sets CV_CONTACT_ACCESS=granted)")
    if len(purpose) < MIN_PURPOSE:
        audit(folder, doc_id, "denied:no_purpose", purpose, known)
        raise NotAuthorized("say why the contact details are needed (purpose)")
    audit(folder, doc_id, "granted", purpose, known)
    return table.get(doc_id, [])
