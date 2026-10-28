"""
SECURITY · PHASE 5 · one PII policy for everything that leaves ingestion.

    split_contacts(text) -> (masked_text, [{"kind", "value"}, ...])   at ingestion: contacts out of the index
    redact(text)         -> text                                       at every output (LLM, MCP, exports)

What counts as a contact detail: e-mail addresses, phone numbers (9 to 15 digits in a phone
shape), and links (http/https/www and bare profile domains such as linkedin.com/in/...).
Masks keep the SAME LENGTH as what they replace ("⟨email⟩" + spaces), so chunk boundaries,
offsets and the number of chunks do not move. Dates, years and date ranges, percentages,
versions, grades and other numbers are not contact details and are never masked.
The masks use ⟨ ⟩, not [ ], so they cannot be confused with passage numbers like [1].
"""
import re

EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
LINK = re.compile(r"(?:\b(?:https?|ftp)://|\bwww\.)[^\s<>()\"']+"
                  r"|\b(?:linkedin\.com|github\.com|gitlab\.com|wa\.me|t\.me|facebook\.com|instagram\.com|twitter\.com|x\.com)"
                  r"/[^\s<>()\"']*", re.I)
PHONE = re.compile(r"(?<![\w/])\+?\(?\d[\d \t().-]{7,}\d(?![\w/])")
YEAR = re.compile(r"(?:19|20)\d\d")
ORDER = (("email", EMAIL), ("link", LINK), ("phone", PHONE))


def is_phone(s):
    digits = re.sub(r"\D", "", s)
    if not 9 <= len(digits) <= 15:
        return False
    groups = re.findall(r"\d+", s)
    if all(YEAR.fullmatch(g) or len(g) <= 2 for g in groups):   # "2019 - 2023 2023-2024", "01 2019 - 12 2023"
        return False
    if re.fullmatch(r"\s*\d{1,3}(?:[ ,.]\d{3})+(?:\.\d+)?\s*", s):  # "1 000 000", "250.000"
        return False
    return True


def mask(kind, value):
    tag = f"⟨{kind}⟩"
    return tag + " " * (len(value) - len(tag)) if len(value) >= len(tag) else tag[:len(value)]


def split_contacts(text):
    found = []

    def take(kind, rx, s):
        def sub(m):
            if kind == "phone" and not is_phone(m.group()):
                return m.group()
            found.append({"kind": kind, "value": m.group().strip()})
            return mask(kind, m.group())
        return rx.sub(sub, s)
    for kind, rx in ORDER:
        text = take(kind, rx, text)
    return text, found


MASK_RUN = re.compile(r"(⟨(?:email|phone|link)⟩) +")


def redact(text):
    """The output policy: contact details masked (a second, defensive pass: the index holds
    masked text already), and the masks' padding removed for readability."""
    return MASK_RUN.sub(r"\1 ", split_contacts(text)[0])
