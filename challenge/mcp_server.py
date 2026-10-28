"""
STEP 8 · Your CV chatbot as an MCP server (for Claude Code, Claude Desktop or Kiro)

It imports challenge/pipeline.py, so it serves exactly the pipeline you built: ingestion,
Chroma + BM25, rerank, filters, refusal and the graph. The assistant's own model writes the
answer; this server only finds the CV evidence. It only READS the index the app built (the
active collection in chroma_db/ACTIVE.json) and follows the app's rebuilds. With no index it
answers every call with an initialization error; it never opens the CV files itself.

Run it by hand to check it starts:   python challenge/mcp_server.py   (it waits for a client; Ctrl+C to stop)
Connect it:                          .mcp.json has it as "cv-chatbot" (start the app once first: it builds the index)

Privacy: the CVs are real people's data. Phone numbers and e-mail addresses are masked in
everything this server returns, so they never reach the assistant's answers.
"""
import contextlib
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from mcp.server.fastmcp import FastMCP

with contextlib.redirect_stdout(sys.stderr):   # stdout is reserved for the MCP protocol
    import pipeline
    from security import index_store
    NOT_READY = None
    try:                                       # SECURITY · Phase 4: strictly a READER of the app's index:
        pipeline.attach_index()                # it never reads CV files, ingests, builds, activates or deletes
    except index_store.IndexNotReady as e:
        NOT_READY = str(e)


def not_ready():
    """The initialization error while there is no index; None once the app has built one."""
    global NOT_READY
    if NOT_READY:
        try:
            with contextlib.redirect_stdout(sys.stderr):
                pipeline.attach_index()
            NOT_READY = None
        except index_store.IndexNotReady as e:
            NOT_READY = str(e)
    return {"error": "index_not_initialized", "detail": NOT_READY,
            "action": "An operator must build the index with the app: python challenge/app.py, then Reload pipeline."} \
        if NOT_READY else None


def documents():
    """{source: (first chunk, whole text)} rebuilt from the index (chunk offsets), not from the files."""
    out = {}
    for c in pipeline.BM25["chunks"]:
        head = f"CV of {c['name']}:\n" if c.get("name") else ""
        piece, at = c["text"][len(head):], c.get("offset", 0)
        first, text = out.get(c["source"], (c, ""))
        out[c["source"]] = (first, text[:at] + piece if at < len(text) else text + piece)
    return out

mcp = FastMCP("cv-chatbot")


def private(text):
    """Mask contact details: e-mail addresses, phone numbers, LinkedIn/GitHub profile links."""
    text = re.sub(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", "[email]", text)
    text = re.sub(r"(?<!\w)\+?\d[\d\s().-]{7,}\d(?!\w)",       # 9+ digits: a phone, not "2021 - 2025"
                  lambda m: "[phone]" if sum(ch.isdigit() for ch in m.group()) >= 9 else m.group(), text)
    return re.sub(r"(?:https?://)?(?:www\.)?(?:linkedin\.com|github\.com)/\S*", "[profile link]", text)


@mcp.tool()
def search_cvs(question: str) -> dict:
    """Search the candidates' CVs. Returns the CV passages to answer from, each with its source
    file and candidate name. Ask one focused question per call; "which candidates know X?"
    returns every matching candidate. If 'refused' is true, no CV contains the answer: say so
    and do not guess. Judge candidates only on job-relevant facts."""
    if not_ready():
        return not_ready()
    with contextlib.redirect_stdout(sys.stderr):
        pipeline.refresh_index()               # the app may have activated a newer index
        query = pipeline.make_query(question, [])
        hits = pipeline.retrieve(query, pipeline.K)
        refused = bool(pipeline.should_refuse(query, hits))
    by_source = {c["source"]: c.get("name", "") for c in pipeline.BM25["chunks"]}
    return {
        "searched_for": query,
        "refused": refused,
        "passages": [] if refused else [{"source": h["source"], "candidate": by_source.get(h["source"], ""),
                                         "found_by": h.get("via", ""), "text": private(h["text"])} for h in hits],
    }


@mcp.tool()
def get_cv(file_name: str) -> dict:
    """Return one whole CV by its file name (the 'source' of a passage), with the facts the
    pipeline extracted: candidate name, city, years of experience and skills. These are the
    CV's own claims, not verified facts; document_id and candidate_id are assigned by ingestion."""
    if not_ready():
        return not_ready()
    with contextlib.redirect_stdout(sys.stderr):
        pipeline.refresh_index()
    docs = documents()
    if file_name in docs:
        first, text = docs[file_name]
        return {"source": file_name, "document_id": first.get("doc_id", ""), "candidate_id": first.get("candidate_id", ""),
                "claims_verified": False, "candidate": first.get("name", ""), "city": first.get("city", ""),
                "years_of_experience": first.get("years", 0), "skills": pipeline.extract(text)["skills"],
                "text": private(text)}
    return {"error": f"No CV named {file_name!r}. Use the 'source' of a search_cvs passage.",
            "available": sorted(docs)}


if __name__ == "__main__":
    mcp.run()
