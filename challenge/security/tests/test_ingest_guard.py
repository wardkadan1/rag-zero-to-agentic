"""Phase 1 regression tests for the ingestion gate. Every fixture is synthetic and built in tmp_path.

    .venv/bin/python -m pytest -q challenge/security/tests
"""
import io
import json
import os
import pathlib
import sys
import tracemalloc
import zipfile

import pytest

CHALLENGE = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CHALLENGE))
import pipeline  # noqa: E402
from security import ingest_guard as G  # noqa: E402

PRACTICE = CHALLENGE.parent / "data" / "cvs" / "candidates"
CV_TEXT = "Lina Haddad\nBackend engineer in Haifa. Python, Kafka and Docker since 2019.\n" + "Built services. " * 20


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_REPORT", str(tmp_path / "quarantine.json"))
    monkeypatch.setenv("SECURITY_DECISIONS", str(tmp_path / "decisions.json"))
    monkeypatch.delenv("SECURITY_MODE", raising=False)


def cvdir(tmp_path):
    d = tmp_path / "cvs"
    d.mkdir(exist_ok=True)
    return d


def make_docx(path, text=CV_TEXT, extra=None):
    import docx
    doc = docx.Document()
    for line in text.splitlines():
        doc.add_paragraph(line)
    doc.save(path)
    if extra:                                          # add parts a valid OOXML file may carry
        with zipfile.ZipFile(path, "a") as z:
            for name, data in extra.items():
                z.writestr(name, data)


def make_pdf(path, text="Lina Haddad Backend engineer Python Kafka"):
    """A minimal one-page PDF with one line of text (built by hand, no extra library)."""
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offsets = io.BytesIO(), []
    out.write(b"%PDF-1.4\n")
    for i, o in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + o + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offsets))
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref))
    path.write_bytes(out.getvalue())


def make_docx_bomb(path, mb=150):
    body = "<w:p><w:r><w:t>" + "A" * 1000 + "</w:t></w:r></w:p>"
    xml = ('<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
           'wordprocessingml/2006/main"><w:body>' + body * (mb * 1000) + "</w:body></w:document>")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", xml)


def report(tmp_path):
    return {r["source"]: r for r in json.loads((tmp_path / "quarantine.json").read_text())["files"]}


def rows():
    return {r["source"]: r for r in pipeline.INGEST_REPORT}


# ------------------------------------------------------------------ legitimate files keep working
def test_valid_files_of_every_type_are_accepted(tmp_path):
    d = cvdir(tmp_path)
    make_pdf(d / "Lina_Haddad.pdf")
    make_docx(d / "Omar_Saleh.docx")
    (d / "Rana_Khalil.txt").write_text(CV_TEXT)
    (d / "Sami_Nasser.md").write_text("# " + CV_TEXT)
    decisions = {p.name: G.decide(p, d) for p in d.iterdir()}
    assert {n: x.status for n, x in decisions.items()} == dict.fromkeys(decisions, "accept")
    docs = pipeline.load_cvs(d)
    assert len(docs) == 4 and all(r["status"] in ("ok", "short") and not r["flags"] for r in pipeline.INGEST_REPORT)


def test_docx_with_customxml_and_other_ooxml_parts_is_not_blocked(tmp_path):
    d = cvdir(tmp_path)
    make_docx(d / "a.docx", extra={"customXml/item9.xml": "<x/>", "docProps/custom.xml": "<x/>"})
    make_docx(d / "b.docx", extra={"weird/part.bin": "x"})
    assert G.decide(d / "a.docx", d).status == "accept"
    b = G.decide(d / "b.docx", d)
    assert b.status == "flag" and b.flags[0].startswith("docx_unexpected_parts") and b.ingest


def test_practice_cvs_ingest_exactly_as_before(tmp_path):
    docs = pipeline.load_cvs(PRACTICE)
    assert len(docs) == len(list(PRACTICE.glob("*.md")))
    assert all(r["status"] == "ok" and not r["flags"] for r in pipeline.INGEST_REPORT)


def test_exact_duplicates_are_still_skipped(tmp_path):
    d = cvdir(tmp_path)
    (d / "CV.txt").write_text(CV_TEXT)
    (d / "CV 2.txt").write_text(CV_TEXT)
    assert len(pipeline.load_cvs(d)) == 1 and rows()["CV 2.txt"]["status"] == "duplicate"


# ------------------------------------------------------------------ hard blocks: never opened by a parser
def test_symlink_outside_cv_folder_is_blocked_and_never_read(tmp_path):
    d = cvdir(tmp_path)
    (d / "Real_CV.txt").write_text(CV_TEXT)
    secret = tmp_path / "secret.txt"
    secret.write_text("API_KEY=sk-test-123 " * 30)
    os.symlink(secret, d / "Zed_Link_CV.txt")
    docs = pipeline.load_cvs(d)
    assert rows()["Zed_Link_CV.txt"]["status"] == "blocked"
    assert not any("API_KEY" in doc["text"] for doc in docs)
    assert "API_KEY" not in (tmp_path / "quarantine.json").read_text()


def test_symlink_inside_cv_folder_is_flagged_not_blocked(tmp_path):
    d = cvdir(tmp_path)
    (d / "sub").mkdir()
    (d / "sub" / "a.txt").write_text(CV_TEXT)
    os.symlink(d / "sub" / "a.txt", d / "Link.txt")
    x = G.decide(d / "Link.txt", d)
    assert x.status == "flag" and "symlink" in x.flags and x.ingest


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_fifo_is_blocked_without_hanging(tmp_path):
    d = cvdir(tmp_path)
    os.mkfifo(d / "pipe.txt")
    (d / "Real_CV.txt").write_text(CV_TEXT)
    assert len(pipeline.load_cvs(d)) == 1
    assert rows()["pipe.txt"]["status"] == "blocked"


def test_oversized_file_is_blocked_before_reading(tmp_path):
    d = cvdir(tmp_path)
    with open(d / "Huge_CV.txt", "wb") as f:                # sparse: 11 MB on paper, nothing on disk
        f.truncate(G.MAX_FILE_BYTES + 2**20)
    x = G.decide(d / "Huge_CV.txt", d)
    assert x.status == "block" and x.reasons[0].startswith("file_too_large") and not x.sha256


def test_docx_bomb_is_blocked_before_parsing(tmp_path, monkeypatch):
    d = cvdir(tmp_path)
    make_docx_bomb(d / "Bomb_CV.docx")
    (d / "Real_CV.txt").write_text(CV_TEXT)
    from security import sandbox
    real = sandbox.parse_all

    def guarded(jobs, **kw):
        assert all(j[0] != "Bomb_CV.docx" for j in jobs), "a blocked file reached the parser"
        return real(jobs, **kw)
    monkeypatch.setattr(sandbox, "parse_all", guarded)
    tracemalloc.start()
    docs = pipeline.load_cvs(d)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert len(docs) == 1 and rows()["Bomb_CV.docx"]["status"] == "blocked"
    assert "zip_ratio" in rows()["Bomb_CV.docx"]["detail"]
    assert peak < 50 * 2**20


def test_docx_too_large_uncompressed_is_blocked(tmp_path, monkeypatch):
    d = cvdir(tmp_path)
    make_docx(d / "a.docx")
    monkeypatch.setattr(G, "MAX_ZIP_TOTAL", 1000)
    assert G.decide(d / "a.docx", d).reasons[0].startswith("zip_uncompressed_too_large")


@pytest.mark.parametrize("entry", ["../evil.xml", "/etc/evil.xml", "C:/evil.xml", "word/../../evil.xml"])
def test_zip_entry_escaping_the_archive_is_blocked(tmp_path, entry):
    d = cvdir(tmp_path)
    make_docx(d / "a.docx", extra={entry: "<x/>"})
    assert G.decide(d / "a.docx", d).reasons == ["zip_entry_path_escape"]


@pytest.mark.parametrize("name,data,reason", [
    ("text_as.pdf", b"not a pdf at all", "type_mismatch:not_a_pdf"),
    ("text_as.docx", b"not a zip", "type_mismatch:not_a_zip"),
    ("pdf_as.docx", b"%PDF-1.4 hello", "type_mismatch:not_a_zip"),
    ("random.txt", bytes(range(256)) * 16, "type_mismatch:binary_in_text_file"),
    ("zip_as.md", b"PK\x03\x04rest", "type_mismatch:binary_in_text_file"),
])
def test_spoofed_extension_is_blocked(tmp_path, name, data, reason):
    d = cvdir(tmp_path)
    (d / name).write_bytes(data)
    assert G.decide(d / name, d).reasons == [reason]


def test_zip_that_is_not_a_docx_is_blocked(tmp_path):
    d = cvdir(tmp_path)
    with zipfile.ZipFile(d / "a.docx", "w") as z:
        z.writestr("hello.txt", "hi")
    assert G.decide(d / "a.docx", d).reasons == ["type_mismatch:not_a_docx"]


# ------------------------------------------------------------------ heuristics: report-only, a person decides
def test_non_utf8_text_is_flagged_but_still_ingested(tmp_path):
    d = cvdir(tmp_path)
    (d / "Latin1_CV.txt").write_bytes(CV_TEXT.encode() + "café".encode("latin-1"))
    assert len(pipeline.load_cvs(d)) == 1
    assert rows()["Latin1_CV.txt"]["flags"] == ["text_not_utf8"]
    assert report(tmp_path)["Latin1_CV.txt"]["ingested"] is True


@pytest.mark.parametrize("name,flag", [("Lina\u202egnp.exe.txt", "name_control_or_invisible_chars"),
                                       ("Li\u200bna.txt", "name_control_or_invisible_chars"),
                                       ("x" * 130 + ".txt", "name_too_long:134"), (".hidden.txt", "hidden_file")])
def test_suspicious_file_names_are_flagged(tmp_path, name, flag):
    d = cvdir(tmp_path)
    (d / name).write_text(CV_TEXT)
    x = G.decide(d / name, d)
    assert x.status == "flag" and flag in x.flags and x.ingest


def test_enforce_mode_and_decisions(tmp_path, monkeypatch):
    d = cvdir(tmp_path)
    (d / "Latin1_CV.txt").write_bytes(CV_TEXT.encode() + "é".encode("latin-1"))
    (d / "Other_CV.txt").write_bytes(CV_TEXT.encode() + "ü".encode("latin-1"))
    monkeypatch.setenv("SECURITY_MODE", "enforce")
    with pytest.raises(ValueError):                          # both flagged, nobody decided: nothing ingested
        pipeline.load_cvs(d)
    assert rows()["Latin1_CV.txt"]["status"] == "quarantined"
    sha = {r["source"]: r["sha256"] for r in report(tmp_path).values()}
    (tmp_path / "decisions.json").write_text(json.dumps({sha["Latin1_CV.txt"]: {"decision": "accept"},
                                                         sha["Other_CV.txt"]: {"decision": "reject"}}))
    docs = pipeline.load_cvs(d)
    assert [doc["source"] for doc in docs] == ["Latin1_CV.txt"]
    assert rows()["Other_CV.txt"]["detail"] == "rejected by a person's decision"
    (d / "Latin1_CV.txt").write_bytes(CV_TEXT.encode() + "è".encode("latin-1"))   # edited: the old accept no longer applies
    with pytest.raises(ValueError):
        pipeline.load_cvs(d)


def test_a_decision_never_overrides_a_hard_block(tmp_path):
    d = cvdir(tmp_path)
    (d / "fake.pdf").write_bytes(b"not a pdf")
    (d / "Real_CV.txt").write_text(CV_TEXT)
    pipeline.load_cvs(d)
    sha = report(tmp_path)["fake.pdf"]["sha256"]
    (tmp_path / "decisions.json").write_text(json.dumps({sha: {"decision": "accept"}}))
    pipeline.load_cvs(d)
    assert rows()["fake.pdf"]["status"] == "blocked"


def test_report_holds_reason_codes_never_cv_text(tmp_path):
    d = cvdir(tmp_path)
    (d / "Latin1_CV.txt").write_bytes(b"SECRET-PHRASE lina@example.com 052-555-1234 " + "é".encode("latin-1"))
    (d / "fake.pdf").write_bytes(b"SECRET-PHRASE")
    pipeline.load_cvs(d)
    text = (tmp_path / "quarantine.json").read_text()
    assert "SECRET-PHRASE" not in text and "@" not in text and "555" not in text
