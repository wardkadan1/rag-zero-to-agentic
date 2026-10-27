"""
SECURITY · PHASE 3 · content checks on the text a CV gives, after parsing and before indexing.

    detection_view(text)        a SEPARATE normalized copy for detectors only (the indexed text is untouched)
    scan_injection(text)        instructions aimed at an AI, in English, Arabic and Hebrew
    scan_stuffing(text, skills) keyword / skill-list manipulation
    near_duplicates(docs)       pairs of CVs that share most of their wording (never merged)
    hidden_verdict(hidden)      what the parser worker found invisible in a PDF

Each check returns findings as (level, code): "high" findings keep the file out of Chroma, BM25
and the graph (quarantined); "medium" findings are flagged for a person to review and the file is
still indexed. These are heuristics: defence in depth, not a guarantee. They report reason
codes only, never the CV's words.
"""
import itertools
import re
import unicodedata

# ----------------------------------------------------------------- the detection view
CONFUSABLES = str.maketrans({                     # look-alike letters used to dodge word filters
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ɡ": "g", "ո": "n", "ν": "v", "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "τ": "t", "ρ": "p",
    "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c", "Х": "x", "І": "i", "Ι": "i", "Ο": "o", "Α": "a", "Ε": "e",
})
ARABIC_MARKS = re.compile(r"[ؐ-ًؚ-ٰٟۖ-ۭـ]")   # harakat, Quranic marks, tatweel
HEBREW_MARKS = re.compile(r"[֑-ׇ]")                                     # niqqud and cantillation
ARABIC_LETTERS = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ى": "ي", "ة": "ه", "ؤ": "و", "ئ": "ي"})
SPACED = re.compile(r"(?<!\w)(?:\w[ .\-_*]){3,}\w(?!\w)")                         # "i g n o r e", "i.g.n.o.r.e"


def detection_view(text):
    """NFKC, invisible format characters removed, look-alikes mapped, Arabic/Hebrew marks removed,
    letter-spaced words joined, every run of spaces or line breaks made one space, lower case."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")       # zero-width, bidi controls
    text = text.translate(CONFUSABLES)
    text = ARABIC_MARKS.sub("", HEBREW_MARKS.sub("", text)).translate(ARABIC_LETTERS)
    text = re.sub(r"(\w)-\s*\n\s*(\w)", r"\1\2", text)                           # "ig-\nnore"
    text = SPACED.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group()), text)
    return re.sub(r"\s+", " ", text).casefold().strip()


# ----------------------------------------------------------------- prompt injection
W = r"(?:\S+ ){0,4}"                               # a few words in between: split or padded instructions
AI = (r"(?:ai|a\.i\.|llm|gpt|chatgpt|claude|gemini|copilot|language model|assistant|chatbot|bot|screener|"
      r"screening (?:tool|system|software)|recruit\w* (?:assistant|bot|ai|tool|system|software)|ats|hr (?:ai|bot|system))")
PATTERNS = {
    "override": [  # high on its own
        rf"\b(?:ignore|disregard|forget|override|bypass|skip)\b {W}(?:previous|prior|above|earlier|preceding|existing|original|system|other|all) {W}?(?:instructions?|prompts?|rules|guidelines|directions|messages|context)\b",
        r"\b(?:new|updated|real) (?:system )?instructions?\s?:",
        r"(?:تجاهل|اهمل|انس|تخط|تخطي)\S* " + r"(?:\S+ ){0,3}" + r"(?:التعليمات|الاوامر|التوجيهات|القواعد|الارشادات)",
        r"(?:התעלמ|התעלם|שכח|עקו|בטל)\S* (?:\S+ ){0,3}(?:\S*הוראות|\S*הנחיות|\S*כללים)",
    ],
    "address_ai": [
        rf"\b(?:note|message|instructions?|attention|reminder|memo|notice)\b (?:to|for) (?:any |the |all |every |an? )?{AI}\b",
        rf"\b(?:dear|hey|hi|hello|attention) {AI}\b",
        rf"\bif you are (?:an? )?{AI}\b",
        r"\byou are now\b|\bfrom now on,? you\b|\bact as (?:an?|the) (?:recruiter|hiring|evaluator)",
        r"(?:ملاحظه|رساله|تعليمات|تنبيه|تعليمه)\s+(?:الى\s+)?(?:لل|ال|ل)(?:مساعد|ذكاء الاصطناعي|نموذج|روبوت|نظام)",
        r"(?:عزيزي|ايها|يا)\s+(?:ال)?(?:مساعد|ذكاء الاصطناعي|نموذج|روبوت)",
        r"(?:הערה|הודעה|הנחיה|הוראה|תזכורת)\s+(?:אל\s+|ל)?(?:ה)?(?:עוזר|בינה|מודל|בוט|מערכת)",
        r"(?:עוזר|מודל|בוט) (?:יקר|יקרה)|(?:שלום|היי) (?:ל)?(?:עוזר|בינה|מודל|בוט)",
    ],
    "ranking": [
        r"\brank (?:me|him|her|them|this (?:candidate|applicant|person|cv|resume)|[a-z]+ [a-z]+) (?:as )?(?:first|1st|top|highest|number one|#1)\b",
        r"\b(?:must|should|shall) be (?:ranked|rated|placed|listed|selected|shortlisted|hired|recommended|considered) (?:as )?(?:first|top|highest|above|the (?:best|strongest|top))",
        r"\b(?:give|assign) (?:this (?:candidate|applicant|cv)|him|her|me) (?:the )?(?:highest|top|maximum|best|perfect) (?:score|rating|rank)",
        r"\b(?:already|has been|was|were) (?:been )?(?:verified|approved|vetted|pre-approved|confirmed|validated) by (?:the )?(?:hiring|recruiting|recruitment|hr) (?:team|manager|department|committee)",
        r"(?<!\S)(?:ضع|ضعي|ضعوا|رتب|رتبي|رتبوا|اجعل|اجعلي|قدم|قدمي|صنف|صنفي) (?:\S+ ){0,3}(?:اولا|في المرتبه الاولى|في المقدمه|على راس)",
        r"(?:افضل|اقوى) (?:مرشح|متقدم)\b",
        r"(?<!\S)(?:דרג|דרגי|דרגו|שים|שימי|שימו|הצב|הצבי|מקם|מקמי) (?:\S+ ){0,3}(?:ראשון|ראשונה|במקום הראשון|בראש)",
        r"(?:המועמד|המועמדת) (?:הטוב|הטובה|החזק|החזקה|המתאים|המתאימה) ביותר",
    ],
    "secrecy": [
        r"\b(?:do not|don't|never) (?:mention|reveal|disclose|tell|repeat|show|cite) (?:this|these|the) (?:note|instructions?|message|text|request)",
        r"\bhidden (?:instructions?|note|message)\b",
        r"لا (?:تذكر|تكشف|تخبر|تظهر)\S* (?:هذه|هذا|عن)",
        r"אל (?:תזכיר|תגלה|תספר|תציג)\S*",
    ],
}
COMPILED = {cat: [re.compile(p) for p in pats] for cat, pats in PATTERNS.items()}


def scan_injection(text):
    """[(level, code)] for text that talks to an AI. One category alone is medium, except an
    explicit override; an AI being addressed AND asked to rank or keep a secret is high."""
    view = detection_view(text)
    hits = {cat for cat, pats in COMPILED.items() if any(p.search(view) for p in pats)}
    if not hits:
        return []
    high = "override" in hits or ("address_ai" in hits and hits & {"ranking", "secrecy"})
    return [("high" if high else "medium", "injection:" + "+".join(sorted(hits)))]


# ----------------------------------------------------------------- keyword stuffing
# Calibrated on the 25 real CVs (2026-10-27): at most 42 distinct skills, skill density 0.18,
# one word at most 3.5% of all words. Every threshold below is well above that.
MAX_DISTINCT_SKILLS = 60
MAX_SKILL_DENSITY = 0.30
MAX_TERM_SHARE = 0.08
MIN_WORDS = 120                                     # shorter texts are too small to judge


def scan_stuffing(text, skill_patterns, stop=frozenset()):
    words = re.findall(r"\w+", text.lower())
    if len(words) < MIN_WORDS:
        return []
    found, mentions = 0, 0
    for rx in skill_patterns.values():
        n = len(rx.findall(text))
        found += n > 0
        mentions += n
    out = []
    if found > MAX_DISTINCT_SKILLS:
        out.append(("medium", f"stuffing:distinct_skills:{found}"))
    if mentions / len(words) > MAX_SKILL_DENSITY:
        out.append(("medium", f"stuffing:skill_density:{mentions / len(words):.2f}"))
    counts = {}
    for w in words:
        if len(w) > 2 and w not in stop:
            counts[w] = counts.get(w, 0) + 1
    if counts and max(counts.values()) / len(words) > MAX_TERM_SHARE:
        out.append(("medium", f"stuffing:repeated_term:{max(counts.values()) / len(words):.2f}"))
    return out


# ----------------------------------------------------------------- near-duplicates
NEAR_DUPLICATE = 0.5                                # real set: the most similar pair shares 0.09 of its 5-grams


def shingles(text, n=5):
    w = re.findall(r"\w+", detection_view(text))
    return {" ".join(w[i:i + n]) for i in range(max(len(w) - n + 1, 1))}


def near_duplicates(docs):
    """[(source_a, source_b, jaccard)] for pairs above NEAR_DUPLICATE. Two people with one
    template are NOT the same person: this only asks a person to look."""
    sh = {d["source"]: shingles(d["text"]) for d in docs}
    out = []
    for a, b in itertools.combinations(sorted(sh), 2):
        union = len(sh[a] | sh[b])
        j = len(sh[a] & sh[b]) / union if union else 0.0
        if j >= NEAR_DUPLICATE:
            out.append((a, b, round(j, 2)))
    return out


# ----------------------------------------------------------------- hidden PDF text (found by the worker)
MIN_HIDDEN_CHARS = 20                               # a stray invisible character or two is layout noise
HIDDEN_SKILLS = 3


def hidden_verdict(hidden, skill_patterns):
    """`hidden` = {"chars": n, "reasons": {...}, "text": "..."} from the worker. Invisible text that
    talks to an AI or lists skills is high; other invisible text is flagged for review."""
    if not hidden or hidden.get("chars", 0) < MIN_HIDDEN_CHARS:
        return []
    text, why = hidden.get("text", ""), "+".join(sorted(hidden.get("reasons", {})))
    if scan_injection(text):
        return [("high", f"hidden_text:instructions:{why}")]
    if sum(1 for rx in skill_patterns.values() if rx.search(text)) >= HIDDEN_SKILLS:
        return [("high", f"hidden_text:skill_list:{why}")]
    return [("medium", f"hidden_text:{hidden['chars']}_chars:{why}")]
