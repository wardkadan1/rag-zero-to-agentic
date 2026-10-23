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


def read_file(path):
    """The plain text of one CV file."""
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        from pypdf import PdfReader
        return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)
    if suffix == ".docx":
        import docx
        return "\n".join(p.text for p in docx.Document(path).paragraphs)
    return path.read_text(encoding="utf-8", errors="ignore")


def load_cvs(folder):
    """Read every CV in `folder` (PDF, DOCX, TXT, MD).
    Return a list of documents: [{"source": "<file name>", "text": "<all the text>"}, ...]
    `source` must be the FILE NAME: Verify checks retrieval against it."""
    docs = []
    for path in sorted(pathlib.Path(folder).iterdir()):
        if path.is_file() and path.suffix.lower() in CV_TYPES:
            docs.append({"source": path.name, "text": read_file(path).strip()})
    return docs


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
