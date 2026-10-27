"""
SECURITY · PHASE 3 · find PDF text a reader cannot see. Runs ONLY inside the parser worker.

    hidden_text(data) -> {"chars": n, "reasons": {"no_ink": n, "offpage": n, "tiny": n}, "text": "..."}

pdfplumber gives every character and its box; pypdfium2 renders the page as a reader would see
it. A character is hidden when:
    no_ink   its box on the rendered page is one flat colour (white on white, render mode 3,
             covered by a shape, clipped away): nothing was drawn there
    offpage  its box is outside the visible page
    tiny     its font is under 3 pt (unreadable on screen or paper)
Render-aware on purpose: a colour comparison alone gave false positives on real CVs with
coloured side panels. Text drawn UNDER a picture is not caught (the picture has ink).
"""
import io

import numpy as np
import pdfplumber
import pypdfium2

SCALE = 2.0              # render at 144 dpi: a 6 pt letter is ~17 pixels tall
FLAT = 0.12              # brightest minus darkest pixel in a box below this: no ink
TINY_PT = 3.0
MAX_TEXT = 4000          # the hidden text handed back for the content checks


def _reason(ch, page, img):
    h, w = img.shape
    x0, x1 = int((ch["x0"] - page.bbox[0]) * SCALE), int(np.ceil((ch["x1"] - page.bbox[0]) * SCALE))
    y0, y1 = int((ch["top"] - page.bbox[1]) * SCALE), int(np.ceil((ch["bottom"] - page.bbox[1]) * SCALE))
    if x1 <= 0 or y1 <= 0 or x0 >= w or y0 >= h:
        return "offpage"
    box = img[max(y0, 0):min(y1, h), max(x0, 0):min(x1, w)]
    if box.size == 0 or float(box.max() - box.min()) < FLAT:
        return "no_ink"
    if ch["size"] < TINY_PT:
        return "tiny"
    return None


def hidden_text(data):
    reasons, parts, last = {}, [], None
    doc = pypdfium2.PdfDocument(data)
    try:
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            for n, page in enumerate(pdf.pages):
                bitmap = doc[n].render(scale=SCALE)
                img = bitmap.to_numpy()[..., :3].astype(np.float32).mean(axis=2) / 255
                bitmap.close()
                for ch in page.chars:
                    if not ch["text"].strip():
                        continue
                    why = _reason(ch, page, img)
                    if why is None:
                        last = None
                        continue
                    reasons[why] = reasons.get(why, 0) + 1
                    gap = last is not None and (ch["x0"] - last["x1"] > 0.2 * ch["size"] or abs(ch["top"] - last["top"]) > 0.5 * ch["size"])
                    parts.append((" " if (last is None or gap) and parts else "") + ch["text"])
                    last = ch
                last = None
    finally:
        doc.close()
    text = "".join(parts)
    return {"chars": sum(reasons.values()), "reasons": reasons, "text": text[:MAX_TEXT]}
