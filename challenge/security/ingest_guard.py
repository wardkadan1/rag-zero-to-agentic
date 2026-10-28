"""
SECURITY · PHASE 1 · the one gate every CV file passes BEFORE a parser opens it.

    decide(path, root)  ->  Decision(status, reasons, flags, sha256, doc_id, kind, size)

Two kinds of result, on purpose:
  BLOCK  known-dangerous, checked from the file system and the raw bytes only, never overridden:
         a symlink that leaves the CV folder, a FIFO or device, a file over the size limit, a ZIP
         that would expand too much, a ZIP entry that points outside the archive, a file whose
         bytes are not the type its extension claims.
  FLAG   heuristic: the file is still ingested (report-only), and the flag is written to the
         quarantine report so a person can look. A person's decision in decisions.json (keyed by
         the file's SHA-256, so an edited file needs a new decision) can accept or reject it.
         SECURITY_MODE=enforce leaves flagged files out until a person accepts them.

Nothing here reads or prints CV text: only file names, sizes, hashes and reason codes.
"""
import dataclasses
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import sys
import unicodedata
import zipfile

MAX_FILE_BYTES = 10 * 2**20        # largest real CV today: 4 MB (a PDF with images)
MAX_ZIP_TOTAL = 25 * 2**20         # DOCX: all entries uncompressed (real DOCX: 2.4 MB)
MAX_ZIP_RATIO = 100                # DOCX: one entry's uncompressed ÷ compressed size (real max: 12)
ZIP_RATIO_MIN_BYTES = 2**20        # ... checked only on entries over 1 MB uncompressed
MAX_ZIP_ENTRIES = 1000
MAX_NAME_CHARS = 120

DOCX_REQUIRED = {"[Content_Types].xml", "word/document.xml"}
# top-level parts found in valid OOXML word files; anything else is flagged, never blocked
DOCX_KNOWN_ROOTS = {"[Content_Types].xml", "_rels", "docProps", "word", "customXml", "customUI",
                    "_xmlsignatures", "[trash]"}
MAGIC = {"pdf": b"%PDF-", "zip": b"PK\x03\x04"}
BINARY_MAGIC = (b"%PDF-", b"PK\x03\x04", b"\x7fELF", b"MZ", b"\xd0\xcf\x11\xe0")   # PDF, ZIP, ELF, EXE, old Office

HERE = pathlib.Path(__file__).resolve().parent


@dataclasses.dataclass
class Decision:
    source: str
    status: str = "accept"         # accept | flag | block | quarantine (Phase 2: the parser failed)
    reasons: list = dataclasses.field(default_factory=list)   # why it is blocked
    flags: list = dataclasses.field(default_factory=list)     # heuristic findings (report-only)
    sha256: str = ""
    kind: str = ""                 # what the bytes are: pdf | docx | text
    size: int = 0
    review: str = ""               # a person's decision from decisions.json: accept | reject | ""
    snapshot: bytes = dataclasses.field(default=b"", repr=False)   # the exact bytes that were hashed (Phase 2 parses these)

    @property
    def doc_id(self):
        return self.sha256[:16]

    @property
    def verdict(self):
        """Phase 3: the one word a person reads. accepted · flagged (a person should review it:
        indexed in report mode, held back until accepted in enforce mode) · quarantined (never
        indexed: blocked, unsafe to parse, malicious, or rejected by a person)."""
        if self.status in ("block", "quarantine") or self.review == "reject":
            return "quarantined"
        return "flagged" if self.flags else "accepted"

    @property
    def ingest(self):
        """Should the pipeline read this file?"""
        if self.status in ("block", "quarantine") or self.review == "reject":
            return False
        if self.status == "flag" and mode() == "enforce":
            return self.review == "accept"
        return True


class SecurityConfigError(RuntimeError):
    """The security settings are wrong or unsafe for this environment: nothing is ingested."""


def mode():
    """report (development) or enforce. Phase 5: an unknown value is an error (never a silent
    fallback to report), and RAG_ENV=production refuses to run without SECURITY_MODE=enforce."""
    raw = os.getenv("SECURITY_MODE", "").strip().lower()
    if raw not in ("", "report", "enforce"):
        raise SecurityConfigError(f"SECURITY_MODE={raw!r} is not 'report' or 'enforce'")
    if os.getenv("RAG_ENV", "").strip().lower() in ("prod", "production") and raw != "enforce":
        raise SecurityConfigError("RAG_ENV=production requires SECURITY_MODE=enforce")
    return raw or "report"


def _block(d, reason):
    d.status = "block"
    d.reasons.append(reason)
    d.snapshot = b""
    return d


def quarantine(d, reason):
    """Phase 2: the file passed the gate but could not be parsed safely. Phase 3: or its text is
    high-confidence malicious. No text is kept, and a person's "accept" does not override it."""
    d.status = "quarantine"
    d.reasons.append(reason)
    d.snapshot = b""
    return d


def _flag(d, reason):
    d.flags.append(reason)
    if d.status == "accept":
        d.status = "flag"


flag = _flag                                           # Phase 3: content findings after parsing


def check_name(d, name):
    if len(name) > MAX_NAME_CHARS:
        _flag(d, f"name_too_long:{len(name)}")
    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in name):
        _flag(d, "name_control_or_invisible_chars")       # bidi overrides, zero-width characters
    if name.startswith("."):
        _flag(d, "hidden_file")


def check_zip(d, data):
    """A DOCX is a ZIP: look at its directory (sizes, names) without decompressing anything.
    It reads the same in-memory bytes that were hashed and that the parser worker will get."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
    except zipfile.BadZipFile:
        return _block(d, "type_mismatch:not_a_zip")
    if len(infos) > MAX_ZIP_ENTRIES:
        return _block(d, f"zip_too_many_entries:{len(infos)}")
    names = {i.filename for i in infos}
    for i in infos:
        n = i.filename
        if n.startswith(("/", "\\")) or ".." in n.replace("\\", "/").split("/") or re.match(r"[A-Za-z]:", n):
            return _block(d, "zip_entry_path_escape")
        if i.flag_bits & 0x1:
            return _block(d, "zip_entry_encrypted")
        if i.file_size > ZIP_RATIO_MIN_BYTES and i.file_size > MAX_ZIP_RATIO * max(i.compress_size, 1):
            return _block(d, f"zip_ratio:{i.file_size // max(i.compress_size, 1)}")
    total = sum(i.file_size for i in infos)
    if total > MAX_ZIP_TOTAL:
        return _block(d, f"zip_uncompressed_too_large:{total // 2**20}MB")
    missing = DOCX_REQUIRED - names
    if missing:
        return _block(d, "type_mismatch:not_a_docx")
    unknown = sorted({n.split("/")[0] for n in names} - DOCX_KNOWN_ROOTS)
    if unknown:
        _flag(d, "docx_unexpected_parts:" + ",".join(unknown)[:80])
    return d


def opened_path(fd):
    """The real path of an open file (Linux: /proc, macOS: F_GETPATH). None when the OS cannot say."""
    try:
        if sys.platform.startswith("linux"):
            return os.readlink(f"/proc/self/fd/{fd}")
        import fcntl
        if hasattr(fcntl, "F_GETPATH"):
            return fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(1024)).split(b"\0", 1)[0].decode()
    except OSError:
        pass
    return None


def decide(path, root):
    """Look at one file BEFORE it is parsed. `root` is the CV folder."""
    path, root = pathlib.Path(path), pathlib.Path(root).resolve()
    d = Decision(source=path.name)
    check_name(d, path.name)
    try:
        st = os.lstat(path)
    except OSError as e:
        return _block(d, f"unreadable:{type(e).__name__}")
    target = path
    if stat.S_ISLNK(st.st_mode):
        target = pathlib.Path(os.path.realpath(path))
        if root not in target.parents:
            return _block(d, "symlink_outside_cv_folder")
        _flag(d, "symlink")
    elif not stat.S_ISREG(st.st_mode):
        return _block(d, "not_a_regular_file")             # a FIFO would hang the reader, a device never ends
    # Open ONCE, then judge the open file itself (fstat, its real path), never the name again:
    # O_NONBLOCK so a FIFO swapped in after lstat cannot hang us, O_NOFOLLOW so the last step is no link.
    try:
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        return _block(d, f"unreadable:{type(e).__name__}")   # e.g. ELOOP: a link swapped in after the check
    with os.fdopen(fd, "rb") as f:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            return _block(d, "not_a_regular_file")
        opened = opened_path(fd)
        if opened is not None and root not in pathlib.Path(opened).parents:
            return _block(d, "opened_file_outside_cv_folder")   # a folder on the way was swapped for a link
        d.size = fst.st_size
        if fst.st_size > MAX_FILE_BYTES:
            return _block(d, f"file_too_large:{fst.st_size // 2**20}MB")
        data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:                          # grew while we read
        return _block(d, "file_too_large")
    d.sha256 = hashlib.sha256(data).hexdigest()
    d.snapshot = data
    suffix = path.suffix.lower()                           # the type the CV folder entry claims, link or not
    if suffix == ".pdf":
        d.kind = "pdf"
        if MAGIC["pdf"] not in data[:1024]:
            return _block(d, "type_mismatch:not_a_pdf")
    elif suffix == ".docx":
        d.kind = "docx"
        if not data.startswith(MAGIC["zip"]):
            return _block(d, "type_mismatch:not_a_zip")
        check_zip(d, data)
    else:
        d.kind = "text"
        if b"\x00" in data[:8192] or data.startswith(BINARY_MAGIC):
            return _block(d, "type_mismatch:binary_in_text_file")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            _flag(d, "text_not_utf8")
    return d


# ----------------------------------------------------------------- a person's decisions + the report
def load_decisions(path=None):
    """decisions.json: {"<sha256>": {"decision": "accept" | "reject", "note": "..."}}"""
    path = pathlib.Path(path or os.getenv("SECURITY_DECISIONS", HERE / "decisions.json"))
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def apply_decisions(decisions, table):
    for d in decisions:
        review = table.get(d.sha256, {}).get("decision", "") if d.sha256 else ""
        if review in ("accept", "reject") and d.status not in ("block", "quarantine"):   # never overridden
            d.review = review
    return decisions


def write_report(decisions, path=None):
    """quarantine.json: every file that is blocked or flagged, with reason codes only (git-ignored)."""
    path = pathlib.Path(path or os.getenv("SECURITY_REPORT", HERE / "quarantine.json"))
    rows = [{"source": d.source, "verdict": d.verdict, "status": d.status, "reasons": d.reasons, "flags": d.flags, "sha256": d.sha256,
             "size": d.size, "review": d.review, "ingested": d.ingest} for d in decisions if d.status != "accept"]
    try:
        path.write_text(json.dumps({"mode": mode(), "files": rows}, indent=1, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        print(f"security: could not write {path}: {e}")
    return rows


def gate(folder, suffixes):
    """Every CV-looking entry of `folder` (sorted, not recursive), decided and reviewed."""
    folder = pathlib.Path(folder)
    entries = [p for p in sorted(folder.iterdir()) if p.suffix.lower() in suffixes
               and (p.is_symlink() or not p.is_dir())]     # directories are skipped as before; links are judged
    decisions = apply_decisions([decide(p, folder) for p in entries], load_decisions())
    write_report(decisions)
    return list(zip(entries, decisions))
