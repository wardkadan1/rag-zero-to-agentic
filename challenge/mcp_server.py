"""
STEP 8 · Your CV chatbot as an MCP server (for Claude Code, Claude Desktop or Kiro)

It imports challenge/pipeline.py, so it serves exactly the pipeline you built: ingestion,
Chroma + BM25, rerank, filters, refusal and the graph. The assistant's own model writes the
answer; this server only finds the CV evidence.

Run it by hand to check it starts:   python challenge/mcp_server.py   (it waits for a client; Ctrl+C to stop)
Connect it:                          .mcp.json has it as "cv-chatbot" (set CV_DIR there if your CVs are elsewhere)

Privacy: the CVs are real people's data. Phone numbers and e-mail addresses are masked in
everything this server returns, so they never reach the assistant's answers.
"""
import contextlib
import os
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from mcp.server.fastmcp import FastMCP

with contextlib.redirect_stdout(sys.stderr):   # stdout is reserved for the MCP protocol
    import pipeline
    CV_DIR = pathlib.Path(os.getenv("CV_DIR", HERE / "cvs"))
    DOCS = pipeline.load_cvs(CV_DIR)
    CHUNKS = [c for d in DOCS for c in pipeline.chunk(d)]
    pipeline.build_index(CHUNKS)
    pipeline.build_graph(CHUNKS)

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
    with contextlib.redirect_stdout(sys.stderr):
        query = pipeline.make_query(question, [])
        hits = pipeline.retrieve(query, pipeline.K)
        refused = bool(pipeline.should_refuse(query, hits))
    by_source = {c["source"]: c.get("name", "") for c in CHUNKS}
    return {
        "searched_for": query,
        "refused": refused,
        "passages": [] if refused else [{"source": h["source"], "candidate": by_source.get(h["source"], ""),
                                         "found_by": h.get("via", ""), "text": private(h["text"])} for h in hits],
    }


@mcp.tool()
def get_cv(file_name: str) -> dict:
    """Return one whole CV by its file name (the 'source' of a passage), with the facts the
    pipeline extracted: candidate name, city, years of experience and skills."""
    for d in DOCS:
        if d["source"] == file_name:
            first = pipeline.chunk(d)[0]
            return {"source": file_name, "candidate": first.get("name", ""), "city": first.get("city", ""),
                    "years_of_experience": first.get("years", 0), "skills": pipeline.extract(d["text"])["skills"],
                    "text": private(d["text"])}
    return {"error": f"No CV named {file_name!r}. Use the 'source' of a search_cvs passage.",
            "available": sorted(d["source"] for d in DOCS)}


if __name__ == "__main__":
    mcp.run()
