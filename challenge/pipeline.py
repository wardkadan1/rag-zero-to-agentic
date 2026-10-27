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
    pages = []
    for page in PdfReader(path).pages:
        text = page.extract_text() or ""
        lines = [l for l in text.splitlines() if l.strip()]
        if lines and sum(len(l.split()) == 1 for l in lines) / len(lines) > 0.5:
            # one word per line: this PDF stores every word apart. Layout mode rebuilds the lines
            # from the word positions (only here: on multi-column pages it mixes the columns).
            text = page.extract_text(extraction_mode="layout") or text
        pages.append(text)
    return "\n".join(pages)


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


NOT_NAME = {"cv", "resume", "curriculum", "vitae", "general", "final", "new", "updated", "docx", "pdf", "doc", "my",
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}
NOT_NAME_WORDS = NOT_NAME | {"name", "title", "profile", "summary", "software", "engineer", "developer", "contact",
                             "experience", "education", "skills", "student", "graduate", "manager", "email", "phone"}


def candidate_name(source, text):
    """The candidate's name, as the CV writes it. First the words of the file name
    ("Ward_Keadan_cv.pdf" → Ward, Keadan) found close together in the text; else a short
    line of capitalized words near the top. "" when neither works."""
    stem = pathlib.Path(source).stem
    tokens = [t for t in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", stem) if len(t) > 1 and t.lower() not in NOT_NAME]
    found = sorted(m.span() for t in tokens for m in [re.search(rf"\b{re.escape(t)}\b", text, re.I)] if m)
    name = ""
    if found:
        start, end = found[0]
        for s, e in found[1:]:
            if s - end > 40:
                break
            end = max(end, e)
        if end == found[0][1]:                         # one word only ("FadiCV.pdf"): it needs a surname after it
            nxt = re.match(r" ([A-Z][\w'-]+)", text[end:end + 40])
            end = end + nxt.end() if nxt and nxt.group(1).lower() not in NOT_NAME_WORDS else start
        name = re.sub(r"\s+", " ", text[start:end]).strip(" |·-")
    if not name:
        for part in re.split(r"[\n:|·•,]", re.sub(r"\([^)]*\)", "", text[:400])):
            words = part.split()
            if 2 <= len(words) <= 4 and all(re.fullmatch(r"[A-Z][\w.'-]*", w) for w in words) \
                    and not any(w.lower() in NOT_NAME_WORDS for w in words):
                name = " ".join(words)
                break
    return name.title() if name.isupper() else name


# ----------------------------------------------------------------- STEP 5 · facts for metadata filters
CITIES = ["Tel Aviv", "Jerusalem", "Haifa", "Nazareth", "Be'er Sheva", "Beer Sheva", "Beersheba", "Netanya", "Herzliya",
          "Ra'anana", "Raanana", "Petah Tikva", "Rishon LeZion", "Holon", "Ashdod", "Ashkelon", "Rehovot", "Kfar Saba",
          "Hadera", "Acre", "Akko", "Karmiel", "Afula", "Nahariya", "Jaffa", "Ramat Gan", "Bnei Brak", "Bat Yam",
          "Modiin", "Yokneam", "Tiberias", "Safed", "Eilat", "Lod", "Ramla", "Rahat", "Umm al-Fahm", "Sakhnin", "Tamra",
          "Shefa-Amr", "Tayibe", "Tira", "Kafr Qasim", "Kafr Qara", "Baqa al-Gharbiyye", "Qalansawe", "Arraba", "Kafr Kanna",
          "Daliyat al-Karmel", "Isfiya", "Jatt", "Ramallah", "Bethlehem", "Nablus", "Amman"]
CITY_ALIASES = {"Beer Sheva": "Be'er Sheva", "Beersheba": "Be'er Sheva", "Raanana": "Ra'anana", "Akko": "Acre"}
MONTHS = {m: i for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}
MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*"
DATE = rf"(?:\b({MONTH})\.?[ \t]*|\b(\d{{1,2}})/)?((?:19|20)\d\d)"
RANGE = re.compile(DATE + r"[ \t]*[-–—]+[ \t]*(?:" + DATE + r"|(present|current|now|today))", re.I)
STUDY = re.compile(r"universit|college|b\.?sc|m\.?sc|bachelor|master|degree|gpa|student|school|graduat|course|"
                   r"program|academ|education|diploma|thesis|ph\.?d|institute|certific|high school|bagrut", re.I)


HEADING = re.compile(r"^\W*(?:[A-Za-z&]+[ \t]+){0,2}(?:education|experience|employment|work|volunteer\w*|certific\w*|"
                     r"courses?|projects?|training|awards?|honors?)\w*(?:[ \t]+[A-Za-z&]+){0,2}\W*$", re.I | re.M)   # section titles
NOT_WORK = re.compile(r"education|volunteer|certific|course|project|training|award|honor", re.I)


def find_city(text):
    """The city the CV lists for the candidate: looked for only in the header (first 300
    characters) or right after "Address"/"Location", so "Tel Aviv University" does not count."""
    places = [text[:300]] + [m.group(1) for m in re.finditer(r"(?:address|location|lives in|📍)\W{0,3}([\s\S]{0,80})", text, re.I)]
    for place in places:
        for city in CITIES:
            m = re.search(rf"\b{re.escape(city)}\b(?!\s+(?:University|College|Institute))", place, re.I)
            if m:
                return CITY_ALIASES.get(city, city)
    return ""


def years_of_experience(text):
    """Years of work experience: the CV's own "N+ years of experience" if it says so, else the
    job date ranges added up (overlaps counted once, study periods left out)."""
    import datetime
    said = [int(n) for n in re.findall(r"(\d{1,2})\+?\s*years?\s+(?:of\s+)?(?:\w+\s+){0,2}(?:experience|leading|working)", text, re.I)]
    if said:
        return float(max(said))
    today = datetime.date.today()
    def month(name, num, year, default):
        m = MONTHS.get((name or "")[:3].lower()) or (int(num) if num and 1 <= int(num) <= 12 else default)
        return int(year) * 12 + m - 1
    spans = []
    for r in RANGE.finditer(text):
        line_start = text.rfind("\n", 0, r.start()) + 1
        line_end = text.find("\n", r.end())
        line_end = len(text) if line_end < 0 else line_end
        if not re.search(r"\w", text[r.end():line_end]):  # the date ends its line: what it is, is on the next line
            nxt = text.find("\n", line_end + 1)
            line_end = len(text) if nxt < 0 else nxt
        heading = [h for h in HEADING.finditer(text, 0, r.start())]
        if STUDY.search(text[line_start:line_end]) or (heading and NOT_WORK.search(heading[-1].group())):
            continue
        start = month(r.group(1), r.group(2), r.group(3), 1)
        end = today.year * 12 + today.month - 1 if r.group(7) else month(r.group(4), r.group(5), r.group(6), 12)
        if start < end <= today.year * 12 + today.month:
            spans.append((start, end))
    total, last = 0, None
    for a, b in sorted(spans):                         # merge overlapping jobs
        if last is None or a > last[1]:
            total += (last[1] - last[0]) if last else 0
            last = [a, b]
        else:
            last[1] = max(last[1], b)
    total += (last[1] - last[0]) if last else 0
    return round(total / 12, 1)


def chunk(doc):
    """Split ONE document into chunks.
    Return [{"id": "<unique id>", "source": doc["source"], "text": "<chunk text>"}, ...]
    You may add more keys (they become metadata), e.g. "name", "section", "city".
    Every chunk starts with whose CV it is, so a chunk from the middle of a CV still
    matches a question that names the candidate."""
    text, step = doc["text"], CHUNK_SIZE - CHUNK_OVERLAP
    name = candidate_name(doc["source"], text)
    facts = {"name": name, "city": find_city(text), "years": years_of_experience(text)}   # STEP 5 metadata
    head = f"CV of {name}:\n" if name else ""
    chunks = []
    for start in range(0, max(len(text) - CHUNK_OVERLAP, 1), step):
        piece = text[start:start + CHUNK_SIZE]
        if piece.strip():
            chunks.append({"id": f"{doc['source']}#{len(chunks)}", "source": doc["source"], **facts,
                           "text": head + piece})
    return chunks


# ================================================================= LEVEL 2 · INDEX (the vector DB)
# Prompt idea: "Implement build_index with chromadb: a PersistentClient in HERE / 'chroma_db',
#  delete and recreate a collection 'cvs' with cosine distance, add every chunk with its id,
#  text, metadata and embed(texts) as embeddings. Return the collection count."
COLLECTION = None


def build_index(chunks):
    """Store every chunk with its vector in a Chroma collection. Return how many are stored."""
    import chromadb
    global COLLECTION
    client = chromadb.PersistentClient(path=str(HERE / "chroma_db"))
    if "cvs" in [c.name for c in client.list_collections()]:
        client.delete_collection("cvs")               # rebuild from scratch: no stale CVs left behind
    COLLECTION = client.create_collection("cvs", metadata={"hnsw:space": "cosine"})
    for start in range(0, len(chunks), 256):          # Chroma limits how much one add() takes
        batch = chunks[start:start + 256]
        COLLECTION.add(ids=[c["id"] for c in batch],
                       documents=[c["text"] for c in batch],
                       metadatas=[{k: v for k, v in c.items() if k not in ("id", "text")} for c in batch],
                       embeddings=embed([c["text"] for c in batch]).tolist())
    build_bm25(chunks)
    return COLLECTION.count()


# ----------------------------------------------------------------- STEP 3 · BM25 keyword search
# Vector search finds similar MEANING; BM25 finds the exact WORDS (names, tools, certificates).
STOP = set("a an and are as at be by did do does for from has have he her his in is it its of on or she that the "
           "their they this to was were what which who whom with candidate candidates cv".split())
BM25 = {"chunks": [], "tf": [], "len": [], "idf": {}, "avg": 1.0}


def tokenize(text):
    """Lowercase words; keeps tech words like c++, c#, node.js and ci/cd pieces whole."""
    return [t for t in re.findall(r"[a-z0-9]+(?:[+#]+|(?:[.][a-z0-9]+)+)?", text.lower()) if t not in STOP]


def build_bm25(chunks, k1=1.5, b=0.75):
    import collections, math
    docs = [tokenize(c["text"]) for c in chunks]
    df = collections.Counter(t for d in docs for t in set(d))
    n = len(docs)
    BM25.update(chunks=chunks, tf=[collections.Counter(d) for d in docs], len=[len(d) for d in docs],
                avg=sum(map(len, docs)) / max(n, 1), k1=k1, b=b,
                idf={t: math.log((n - f + 0.5) / (f + 0.5) + 1) for t, f in df.items()})


def bm25_search(query, n, want=None):
    """The n chunks with the best BM25 score (a word scores more when it is rare across the CVs)."""
    q, scores = tokenize(query), []
    for i, tf in enumerate(BM25["tf"]):
        if want and not meets(BM25["chunks"][i], want):
            continue
        norm = BM25["k1"] * (1 - BM25["b"] + BM25["b"] * BM25["len"][i] / BM25["avg"])
        s = sum(BM25["idf"][t] * tf[t] * (BM25["k1"] + 1) / (tf[t] + norm) for t in q if tf.get(t))
        if s > 0:
            scores.append((s, i))
    return [{"id": BM25["chunks"][i]["id"], "source": BM25["chunks"][i]["source"], "text": BM25["chunks"][i]["text"],
             "score": s} for s, i in sorted(scores, reverse=True)[:n]]


# ================================================================= LEVEL 3 · RETRIEVE AND PROMPT
# Prompt idea: "Implement retrieve: embed the query, query the Chroma collection for k results,
#  and return them as dicts with rank, source, text, score (1 - distance) and via='vector'.
#  Implement build_prompt: number the passages [1], [2]… with their source, then the question."
HYBRID = True             # STEP 3: False = vector search only (to compare in Verify)
CANDIDATES = 20           # how many each search brings to the fusion
RRF_K = 60


def question_filters(question):
    """STEP 5 · The hard requirements a question states: a city it names, a minimum of years
    ("5+ years", "at least 5 years", "5 or more years"). {} when it states none."""
    want = {}
    for city in CITIES:
        if re.search(rf"\b{re.escape(city)}\b", question, re.I):
            want["city"] = CITY_ALIASES.get(city, city)
            break
    m = re.search(r"(?:at least|minimum(?: of)?|more than|over)\s+(\d{1,2})\s*years?|(\d{1,2})\s*(?:\+|or more|plus)\s*years?", question, re.I)
    if m:
        want["years"] = int(m.group(1) or m.group(2))
    return want


def chroma_where(want):
    parts = ([{"city": want["city"]}] if "city" in want else []) + ([{"years": {"$gte": want["years"]}}] if "years" in want else [])
    return None if not parts else parts[0] if len(parts) == 1 else {"$and": parts}


def meets(chunk, want):
    return chunk.get("city") == want.get("city", chunk.get("city")) and chunk.get("years", 0) >= want.get("years", 0)


def vector_search(query, n, where=None):
    res = COLLECTION.query(query_embeddings=embed([query]).tolist(), n_results=min(n, COLLECTION.count()), where=where)
    return [{"id": cid, "source": meta["source"], "text": text, "score": 1 - dist}
            for cid, text, meta, dist in zip(res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0])]


RERANK = True             # STEP 4: False = keep the fusion order (to compare in Verify)
FILTERS = True            # STEP 5: False = no city / years filters
GRAPH_ON = True           # STEP 7: False = list questions use the normal search
GRAPH_MAX = 10            # at most this many candidates from the graph (the prompt has to fit)
RERANKER = None


def rerank(query, pool, k):
    """STEP 4 · A cross-encoder reads the question and each chunk TOGETHER and scores the pair:
    slower than comparing two vectors, so only the pool of candidates gets it."""
    global RERANKER
    import time
    if RERANKER is None:
        from ragkit import Reranker
        RERANKER = Reranker()
    if RERANKER.model is None or not pool:
        return pool[:k]
    t = time.perf_counter()
    scores = RERANKER.model.predict([(query, h["text"]) for h in pool])
    for h, sc in zip(pool, scores):
        h["rerank"] = round(float(sc), 3)
    print(f"rerank: {len(pool)} chunks in {(time.perf_counter() - t) * 1000:.0f} ms")
    return sorted(pool, key=lambda h: -h["rerank"])[:k]


def retrieve(query, k=K):
    """Return the k best chunks: [{"rank": 1, "source": ..., "text": ..., "score": ..., "via": "vector"}, ...]"""
    route = graph_route(query)
    if route is not None:                              # STEP 7: the graph answers list questions
        want = question_filters(query) if FILTERS else {}
        pool = []
        for source, name, entity in route[:GRAPH_MAX]:
            where = {"source": source}
            if "years" in want:                        # a minimum of years still applies
                where = {"$and": [where, {"years": {"$gte": want["years"]}}]}
            best = vector_search(query, 1, where)
            if best:
                pool.append(dict(best[0], via=f"graph: {entity} → {name}"))
        best = rerank(query, pool, len(pool)) if RERANK else pool
        return [dict(h, rank=i + 1) for i, h in enumerate(best)]
    pool_size = CANDIDATES if (HYBRID or RERANK) else k
    want = question_filters(query) if FILTERS else {}
    if want:
        print("filters:", want)
    vec = vector_search(query, pool_size, chroma_where(want))
    if not HYBRID:
        pool = [dict(h, via=f"vector #{i}") for i, h in enumerate(vec, 1)]
        best = rerank(query, pool, k) if RERANK else pool[:k]
        return [dict(h, rank=i + 1) for i, h in enumerate(best)]
    # Reciprocal Rank Fusion: score = sum of 1/(60 + rank) over the lists a chunk appears in.
    # Ranks, not raw scores, so a cosine 0.4 and a BM25 12.0 can be merged fairly.
    fused = {}
    for name, hits in (("vector", vec), ("bm25", bm25_search(query, CANDIDATES, want))):
        for rank, h in enumerate(hits, 1):
            f = fused.setdefault(h["id"], {"source": h["source"], "text": h["text"], "rrf": 0.0, "cos": 0.0, "found": []})
            f["rrf"] += 1 / (RRF_K + rank)
            f["found"].append(f"{name} #{rank}")
            if name == "vector":
                f["cos"] = h["score"]                  # keep the cosine as the score (STEP 6 uses it)
    pool = [{"source": h["source"], "text": h["text"], "score": h["cos"], "rrf": round(h["rrf"], 4),
             "via": " + ".join(h["found"])} for h in sorted(fused.values(), key=lambda h: -h["rrf"])[:CANDIDATES]]
    best = rerank(query, pool, k) if RERANK else pool[:k]
    return [dict(h, rank=i + 1) for i, h in enumerate(best)]


def build_prompt(question, hits):
    """The text the LLM receives: the numbered passages, then the question."""
    passages = "\n\n".join(f"[{i}] (from {h['source']})\n{h['text']}" for i, h in enumerate(hits, 1))
    return f"CV passages:\n\n{passages}\n\nQuestion: {question}"


# ================================================================= LEVEL 4 · FEATURES
# These already work in their simplest form. Each step of the menu replaces one of them
# (or retrieve / chunk above). One step at a time, then Verify.
FOLLOW_UP = re.compile(r"^\s*(and|also|what about|how about)\b|\b(he|she|him|her|his|hers|they|them|their|"
                       r"this (person|candidate|one)|that (person|candidate|one)|the same (person|candidate))\b", re.I)
REWRITE_PROMPT = ("Rewrite the user's last question so it can be understood without the earlier questions: "
                  "replace pronouns like he, she or that candidate with who they refer to. "
                  "Reply with the rewritten question only.")


def make_query(question, history):
    """STEP 1 · Follow-ups: rewrite "and where did he study?" using `history` (earlier questions)."""
    if not history or not FOLLOW_UP.search(question):
        return question                               # a stand-alone question: search it as it is
    previous = history[-1]
    try:
        from helpers import llm
        from ragkit import get_llm                    # the same shared model llm() uses
        if getattr(get_llm(), "can_reason", True):    # the offline fallback cannot rewrite
            earlier = "\n".join(f"- {q}" for q in history[-3:])
            rewritten = llm(REWRITE_PROMPT, f"Earlier questions:\n{earlier}\n\nLast question: {question}", 60).strip()
            if 0 < len(rewritten) < 300:
                return rewritten
    except Exception as e:
        print("make_query: LLM rewrite failed, using the rule:", e)
    # Rule: the person is named or described in the previous question, so search both together.
    return f"{previous} {question}"


REFUSE_BELOW = -9.5       # STEP 6: cross-encoder score of the best chunk under which we refuse


def should_refuse(query, hits):
    """STEP 6 · Return True when nothing relevant came back: the app answers REFUSAL without the LLM.
    The reranker's score of the best chunk measures "does this passage answer this question".
    On our questions every unanswerable one scored -10.1 to -11.3 except two near misses (-7.7, -7.0),
    and the lowest answerable one -8.8: -9.5 refuses no valid question and accepts those two misses."""
    if not hits:
        return True                                    # e.g. a filter that no CV meets
    top = hits[0].get("rerank")
    return top is not None and top < REFUSE_BELOW


# STEP 7a · a general list of tech skills (not taken from any question), matched as whole words
SKILLS = ["python", "java", "javascript", "typescript", "c++", "c#", "kotlin", "scala", "swift", "php", "ruby", "matlab",
          "sql", "nosql", "html", "css", "bash", "assembly", "vhdl", "verilog", "systemverilog", "flutter", "dart",
          "react", "react native", "angular", "vue", "next.js", "node.js", "express", "django", "flask", "fastapi",
          "spring", "spring boot", "hibernate", "laravel", ".net", "graphql", "rest api", "microservices", "websockets",
          "mysql", "postgresql", "mongodb", "redis", "dynamodb", "firebase", "elasticsearch", "pinecone", "chroma",
          "aws", "azure", "google cloud", "gcp", "docker", "kubernetes", "helm", "terraform", "jenkins", "github actions",
          "ci/cd", "linux", "git", "kafka", "rabbitmq", "spark", "hadoop", "hive", "airflow", "kestra", "etl", "dbt",
          "power bi", "tableau", "looker", "excel", "dax", "pandas", "numpy", "scikit-learn", "pytorch", "tensorflow",
          "keras", "hugging face", "opencv", "computer vision", "nlp", "machine learning", "deep learning", "llm",
          "rag", "langchain", "openai", "prompt engineering", "mcp", "n8n", "selenium", "playwright", "junit", "jira",
          "figma", "arduino", "raspberry pi", "embedded", "iot", "android", "ios", "unity", "autocad", "solidworks"]
SKILL_RE = {sk: re.compile(rf"(?<![\w+#.]){re.escape(sk)}(?![\w+#])", re.I) for sk in SKILLS}
GRAPH = nx.Graph()


def extract(text):
    """STEP 7a · The skills and the city one CV mentions."""
    return {"skills": sorted(sk for sk, rx in SKILL_RE.items() if rx.search(text)), "city": find_city(text)}


def build_graph(chunks):
    """STEP 7 · Graph RAG: return a networkx graph with (type, name) nodes, e.g.
    ("candidate", "Lina Haddad") —has_skill— ("skill", "kubernetes"). Give candidate nodes
    source=<file name>. The 🕸 Graph tab draws it; use it in retrieve for "which candidates…" questions."""
    global GRAPH
    g, cvs = nx.Graph(), {}
    for c in chunks:                                   # 7b · one CV = all its chunks
        cvs.setdefault(c["source"], {"name": c.get("name") or c["source"], "text": []})["text"].append(c["text"])
    for source, cv in cvs.items():
        person = ("candidate", cv["name"])
        g.add_node(person, source=source)
        facts = extract("\n".join(cv["text"]))
        for sk in facts["skills"]:
            g.add_edge(person, ("skill", sk), relation="has_skill")
        if facts["city"]:
            g.add_edge(person, ("city", facts["city"]), relation="lives_in")
    GRAPH = g
    return g


LIST_QUESTION = re.compile(r"\b(which|who|list|all|any)\b[^?]*\bcandidates\b|\bcandidates\b[^?]*\b(who|with|that)\b", re.I)


def graph_route(query):
    """STEP 7c · For a "which candidates …" question that names skills or a city of the graph:
    every candidate connected to ALL of them (no top-K limit). None when it does not apply."""
    if not GRAPH_ON or GRAPH.number_of_nodes() == 0 or not LIST_QUESTION.search(query):
        return None
    named = [("skill", sk) for sk, rx in SKILL_RE.items() if rx.search(query) and GRAPH.has_node(("skill", sk))]
    named = [n for n in named if not any(n != m and n[1] in m[1] for m in named)]   # "spring" inside "spring boot"
    want = question_filters(query)
    if "city" in want and GRAPH.has_node(("city", want["city"])):
        named.append(("city", want["city"]))
    if not named:
        return None
    people = set.intersection(*(set(GRAPH.neighbors(n)) for n in named))
    return [(GRAPH.nodes[p]["source"], p[1], " + ".join(n[1] for n in named)) for p in sorted(people)]
