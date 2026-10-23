"""
YOUR PIPELINE · the only file you edit today
=============================================
The app (challenge/app.py) calls these functions. You build them level by level, with Claude Code
or Kiro, and press "Reload pipeline" in the app after every change. The status box at the top of
the app shows which levels work.

  LEVEL 1 · Ingest   load_cvs, chunk          → the 📄 Data tab shows your CVs and chunks
  LEVEL 2 · Index    build_index (Chroma)     → the status shows how many chunks are stored
  LEVEL 3 · Answer   retrieve, build_prompt   → the 💬 Chat works: this is NAIVE RAG.
                                                Run ✅ Verify: that is your first score.
  LEVEL 4 · Features make_query, retrieve, should_refuse, build_graph … (see challenge/README.md)

Given to you (helpers.py):  embed(texts) -> normalized vectors · llm(system, user) -> answer text
Stuck or behind?  cp challenge/checkpoints/level3.py challenge/pipeline.py   (naive RAG, done)
"""
import pathlib
import re

import networkx as nx

from helpers import embed

HERE = pathlib.Path(__file__).resolve().parent
K = 3                     # chunks per prompt
REFUSAL = "I don't know based on the CVs."
SYSTEM_PROMPT = ("You are a recruiting assistant. Answer ONLY from the numbered CV passages. "
                 "Cite every fact like [1]. If the passages do not contain the answer, reply exactly: "
                 f"\"{REFUSAL}\" Be brief.")


# ================================================================= LEVEL 1 · INGEST
# Prompt idea: "In challenge/pipeline.py implement load_cvs and chunk as their docstrings say.
#  Use pypdf for PDF and python-docx for DOCX. Start with fixed-size chunks of 800 characters
#  with 100 overlap. Don't change other files."
CV_TYPES = {".pdf", ".docx", ".txt", ".md"}
CHUNK_SIZE = 800          # characters per chunk
CHUNK_OVERLAP = 100       # characters shared by two neighbouring chunks
MIN_CHARS = 200           # less text than this: the reader probably missed the CV
INGEST_REPORT = []        # one row per file from the last load_cvs: source, status, chars, detail


def read_pdf(path):
    import logging
    from pypdf import PdfReader
    logging.getLogger("pypdf").setLevel(logging.ERROR)    # hide "wrong pointing object" noise
    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


def docx_paragraph(element):
    """The text of one Word paragraph, text boxes inside it included. A text box is stored twice
    (a modern copy and an mc:Fallback copy for old Word): read only the first."""
    from docx.oxml.ns import qn
    parts = []
    for n in element.iterchildren():
        if not isinstance(n.tag, str) or n.tag.endswith("}Fallback"):
            continue
        if n.tag == qn("w:t"):
            parts.append(n.text or "")
        elif n.tag == qn("w:tab"):
            parts.append("\t")
        elif n.tag in (qn("w:br"), qn("w:cr")) or (n.tag == qn("w:p") and parts):
            parts.append("\n")
        if n.tag != qn("w:t"):
            parts.append(docx_paragraph(n))
    return "".join(parts)


def docx_blocks(element):
    """The text of a Word body, cell, header or footer, top to bottom: paragraphs and tables
    in the order they appear, nested tables included, each cell read once."""
    from docx.oxml.ns import qn
    lines = []
    for child in element.iterchildren():
        if child.tag == qn("w:p"):
            lines.append(docx_paragraph(child))
        elif child.tag == qn("w:tbl"):
            for row in child.iterchildren(qn("w:tr")):
                cells = ["\n".join(docx_blocks(cell)).strip() for cell in row.iterchildren(qn("w:tc"))]
                cells = [c for c in cells if c]
                if all("\n" not in c for c in cells):
                    lines.append(" | ".join(cells))    # a data row: keep its cells on one line
                else:
                    lines.extend(cells)                # a layout row (columns): one cell after the other
        elif child.tag == qn("w:sdt"):                 # content control: read what is inside
            for content in child.iterchildren(qn("w:sdtContent")):
                lines.extend(docx_blocks(content))
    return lines


def read_docx(path):
    import docx
    d = docx.Document(path)
    lines, seen = [], set()
    for section in d.sections:                         # headers often hold the name: read each one once
        for part in (section.header, section.footer):
            if not part.is_linked_to_previous:
                for line in docx_blocks(part._element):
                    if line.strip() and line not in seen:
                        seen.add(line)
                        lines.append(line)
    return "\n".join(lines + docx_blocks(d.element.body))


def read_file(path):
    """The plain text of one CV file."""
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return read_pdf(path)
    if suffix == ".docx":
        return read_docx(path)
    return path.read_text(encoding="utf-8", errors="ignore")


SPACED = re.compile(r"(?<![^\W\d_])(?:[^\W\d_] ){2,}[^\W\d_](?![^\W\d_])")   # "P R O F I L E"
SEPARATOR = re.compile(r"[-–—_=*~•·.─━═▪■□●○◆◇|]{4,}")                      # "————", "=====", "....."


def normalize(text):
    """Clean extracted text without changing its words: join letter-spaced headings, drop
    decorative separator runs, tidy spaces and blank lines."""
    text = text.replace(" ", " ").replace("​", "").replace("\r", "\n")
    text = SPACED.sub(lambda m: m.group().replace(" ", ""), text)
    text = SEPARATOR.sub(" ", text)
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def load_cvs(folder):
    """Read every CV in `folder` (PDF, DOCX, TXT, MD).
    Return a list of documents: [{"source": "<file name>", "text": "<all the text>"}, ...]
    `source` must be the FILE NAME: Verify checks retrieval against it.
    Exact duplicate files and files without text are left out, and every file gets a row in
    INGEST_REPORT (printed to the console), so nothing is skipped silently."""
    import hashlib
    INGEST_REPORT.clear()
    paths = [p for p in sorted(pathlib.Path(folder).iterdir()) if p.is_file() and p.suffix.lower() in CV_TYPES]
    digest = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    keep = {}                                          # one file per content: the shortest name ("CV.pdf", not "CV 2.pdf")
    for path in sorted(paths, key=lambda p: (len(p.name), p.name)):
        keep.setdefault(digest[path], path.name)
    docs = []
    for path in paths:
        row = {"source": path.name, "status": "ok", "chars": 0, "detail": ""}
        INGEST_REPORT.append(row)
        if keep[digest[path]] != path.name:
            row.update(status="duplicate", detail=f"same bytes as {keep[digest[path]]}: not indexed twice")
            continue
        try:
            text = normalize(read_file(path))
        except Exception as e:
            row.update(status="failed", detail=f"{type(e).__name__}: {e}")
            continue
        row["chars"] = len(text)
        if not text:
            row.update(status="empty", detail="no text extracted (scanned image? unsupported layout?)")
            continue
        if len(text) < MIN_CHARS:
            row.update(status="short", detail=f"only {len(text)} characters: check this CV")
        docs.append({"source": path.name, "text": text})
    print_ingest_report()
    if INGEST_REPORT and not docs:
        raise ValueError(f"none of the {len(INGEST_REPORT)} CV files gave text: see the console")
    return docs


def print_ingest_report():
    counts = {}
    for row in INGEST_REPORT:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    print("Ingestion: " + ", ".join(f"{n} {status}" for status, n in counts.items()))
    for row in INGEST_REPORT:
        if row["status"] != "ok":
            print(f"  {row['status'].upper():9} {row['source']}: {row['detail']}")


def chunk(doc):
    """Split ONE document into chunks.
    Return [{"id": "<unique id>", "source": doc["source"], "text": "<chunk text>"}, ...]
    You may add more keys (they become metadata), e.g. "name", "section", "city"."""
    text, step = doc["text"], CHUNK_SIZE - CHUNK_OVERLAP
    chunks = []
    for start in range(0, max(len(text) - CHUNK_OVERLAP, 1), step):
        piece = text[start:start + CHUNK_SIZE]
        if piece.strip():
            chunks.append({"id": f"{doc['source']}#{len(chunks)}", "source": doc["source"], "text": piece})
    return chunks


# ================================================================= LEVEL 2 · INDEX (the vector DB)
# Prompt idea: "Implement build_index with chromadb: a PersistentClient in HERE / 'chroma_db',
#  delete and recreate a collection 'cvs' with cosine distance, add every chunk with its id,
#  text, metadata and embed(texts) as embeddings. Return the collection count."
COLLECTION = None


def build_index(chunks):
    """Store every chunk with its vector in a Chroma collection. Return how many are stored."""
    raise NotImplementedError("LEVEL 2: implement build_index() in challenge/pipeline.py")


# ================================================================= LEVEL 3 · RETRIEVE AND PROMPT
# Prompt idea: "Implement retrieve: embed the query, query the Chroma collection for k results,
#  and return them as dicts with rank, source, text, score (1 - distance) and via='vector'.
#  Implement build_prompt: number the passages [1], [2]… with their source, then the question."
def retrieve(query, k=K):
    """Return the k best chunks: [{"rank": 1, "source": ..., "text": ..., "score": ..., "via": "vector"}, ...]"""
    raise NotImplementedError("LEVEL 3: implement retrieve() in challenge/pipeline.py")


def build_prompt(question, hits):
    """The text the LLM receives: the numbered passages, then the question."""
    raise NotImplementedError("LEVEL 3: implement build_prompt() in challenge/pipeline.py")


# ================================================================= LEVEL 4 · FEATURES
# These already work in their simplest form. Each step of the menu replaces one of them
# (or retrieve / chunk above). One step at a time, then Verify.
def make_query(question, history):
    """STEP 1 · Follow-ups: rewrite "and where did he study?" using `history` (earlier questions)."""
    return question


def should_refuse(query, hits):
    """STEP 6 · Return True when nothing relevant came back: the app answers REFUSAL without the LLM."""
    return False


def build_graph(chunks):
    """STEP 7 · Graph RAG: return a networkx graph with (type, name) nodes, e.g.
    ("candidate", "Lina Haddad") —has_skill— ("skill", "kubernetes"). Give candidate nodes
    source=<file name>. The 🕸 Graph tab draws it; use it in retrieve for "which candidates…" questions."""
    return nx.Graph()
