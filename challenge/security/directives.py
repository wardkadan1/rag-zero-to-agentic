"""
SECURITY · 2026-10-29 · Claude + MCP finding F2 · does a CV sentence give orders to whoever reads it?

    is_directive(sentence)    True when the sentence addresses the reader or the agent, or orders it
                              to answer, rank, reveal, call a tool or ignore its rules

Why: in the first real Claude + MCP run, four attacker CVs (an override, a fake "hiring committee
note", a fabricated-claim order, a ranking demand) reached the agent as "accepted" text. The MCP
output only used the Phase 3 detectors (content.scan_injection). This module is the sentence-level
check the MCP output applies on top of them (output_guard.remove_instructions).

It reuses the matching views of answer_checks (look-alike letters, spacing, leetspeak, reversed text,
Base64, invisible tag letters), but uses its own patterns. They are narrower where CVs that describe
AI systems, chatbots, recruiting or automation legitimately use the same verbs ("built a bot that
answers…", "presented to hiring managers", "responde preguntas"). Imperatives that are ambiguous
with a 3rd-person description count only at the start of a sentence. answer_checks itself (the Qwen
answer path) is not changed.

A heuristic, not a proof: trade-offs and the measured false positives are in security/MCP_HARDENING.md.
"""
import html
import re
import urllib.parse

from . import content
from .answer_checks import QUOTED, SOFT, _views

_AUDIENCE = (r"(?:ai|a\.i\.|llms?|gpt|chatgpt|claude|gemini|(?:language )?models?|assistants?|chatbots?|bots?|agents?|"
             r"screeners?|ats|(?:screening|recruiting|recruitment|hr|hiring|ats) (?:tools?|systems?|software|models?|bots?)|"
             r"recruiters?|hiring (?:manager|team)s?|readers?|reviewers?|evaluators?)")
_START = r"(?:^|[.:;!?|]\s*|^\W*)"                         # the start of a sentence (a line, or after punctuation)
_EVAL = (r"(?:rank|recommend|select|choose|shortlist|hire|prefer|prioriti[sz]e|rate|score|treat|consider|regard|"
         r"mention|say|state|write|reply|respond|answer (?:with|only|that|by)|output|print|include|add|ignore|disregard|"
         r"forget|reveal|share|disclose|send|call|use|run|put|place|list|describe|summari[sz]e|confirm|approve|append|"
         r"insert|tag|label|flag|mark|attach|carry)")
_ORDER = (r"(?:reply|respond|answer|say|tell|print|output|mention|confirm|repeat|forget|ignore|disregard|decode|"
          r"encode|forward|append|include|translate|pretend|remember|summari[sz]e|note that|make sure|be sure to|"
          r"always|from now on|do not mention|don't mention|never mention)")
_STRONG = r"(?:ignore|disregard|forget|reply|respond|answer|say|print|output|pretend|repeat)"
_ROLE = (r"(?:hiring|recruit\w*|talent|hr|human resources|screening|compliance|legal|quality(?: control)?|audit|"
         r"verification|security|background|management|board|committee)")
_HIRE = (r"(?:shortlisted|hired|ranked|recommended|selected|chosen|prioriti[sz]ed|preferred|placed|listed|put|"
         r"interviewed first|considered first|moved to the top|fast-tracked)")
_CONTACT = r"(?:contact details|contact info\w*|e-?mail(?: address)?s?|phone(?: numbers?)?|home address\w*|addresses)"

PATTERNS = [re.compile(p, re.I) for p in [
    # addressing the reader or the agent
    rf"{_START}(?:dear|hey|hi|hello|attention|note to|message to|memo (?:to|for)|instructions? (?:to|for)|"
    rf"to all|to any|to every)\s+(?:the |any |all |every )?(?:\w+ )?{_AUDIENCE}\b",
    rf"{_START}(?:ai|assistant|chatbot|bot|model|agent|screener|recruiter|reviewer|evaluator|llm|gpt|claude)\s*,\s*\w",
    rf"{_START}{_AUDIENCE}\s*[,:]\s*(?:please\s+)?(?:\w+\s+){{0,2}}(?:{_ORDER}|{_EVAL})\b",   # "Recruiters: rank …"
    rf"\b(?:for|to) (?:the |all |any )?{_AUDIENCE}\s*:",                   # "Translate for the recruiter: …"
    rf"{_START}(?:the |any |all |every |each )?(?:\w+ )?{_AUDIENCE}\b[^.\n]{{0,40}}\b(?:must|should|shall|need to|"
    rf"has to|have to|is to|are to|will|are required to|is required to)\b(?:\s+\w+){{0,3}}\s+{_EVAL}\b",
    rf"\b(?:any|every|each) {_AUDIENCE} (?:reading|processing|screening|parsing|reviewing)\b",
    r"\byour (?:new |real |actual |true |only )?(?:task|job|instructions?|goal|role|orders)\b",
    # orders at the start of a sentence
    rf"{_START}{_ORDER}\b",
    rf",\s*{_STRONG}\b",
    rf"{_START}(?:please |now |just |always )?(?:answer|reply|respond)\s+(?:with|by|only|exactly|in)\b",
    rf"{_START}(?:write|say|print|output|type|add|put|include|insert|append|start|begin|end)\b[^.\n]{{0,80}}"
    r"(?:\banswer|\breply|\bresponse|\boutput|\bthe (?:word|code|phrase)|\bexactly|[\"“])",
    rf"{_START}(?:write|state|say|claim|mention|note|add|report) (?:down )?that\b",
    r"\b(?:summar(?:y|ies)|answers?|repl(?:y|ies)|responses?|outputs?)\b[^.\n]{0,30}\b(?:should|must|shall|need to|"
    r"has to|have to|are required to|is required to)\s+(?:always\s+)?(?:state|say|mention|include|read|contain|carry|"
    r"list|note|describe|call|begin|start|end)\b",
    r"\b(?:before|after|when|while) (?:answering|replying|responding|summari[sz]ing|ranking|you answer|you reply)\b",
    r"\bfrom now on\b|\bfor (?:all|any|every) (?:later|future|next|following) (?:questions?|answers?|requests?)\b",
    r"\b(?:next|following) question\b",
    r"\b(?:answer|reply|response) to (?:any|every|each|all) (?:questions?|requests?)\b",
    r"\bwhen (?:asked|summari[sz]\w*|answering|replying|ranking|screening|you)\b",
    r"\b(?:in|into) (?:your|every|any|each|all) (?:answers?|repl(?:y|ies)|responses?|summar(?:y|ies)|outputs?)\b",
    r"\b(?:summar(?:y|ies)|answers?|repl(?:y|ies)|responses?|outputs?) (?:of|about|on) (?:this|the|my) "
    r"(?:cv|candidate|profile|applicant)\b[^.\n]{0,40}\b(?:must|should|shall|always|need to|has to|is required)\b",
    # claimed decisions and authority
    rf"\b{_ROLE}\b(?:\s+\S+){{0,2}}\s+(?:note|memo|record|decision|notice|instruction|directive)\b\s*(?:\(|:|—|\s-\s)",
    rf"\b{_ROLE}\b(?:\s+\S+){{0,2}}\s+(?:has |have )?(?:already )?(?:confirmed|approved|verified|pre-?screened|"
    r"selected|endorsed|decided)\b[^.\n]{0,40}\b(?:candidate|applicant|profile|this|him|her|them|hire)\b",
    r"\b(?:per|according to) (?:the )?(?:company|hr|hiring|recruitment) (?:policy|rules?|guidelines?)\b",
    rf"\b(?:should|must|shall|needs? to|has to|is to) be {_HIRE}\b",
    r"\b(?:the )?other (?:candidates?|applicants?)\b|\ball (?:the )?(?:other )?applicants\b",
    # rankings demanded
    r"\b(?:always|never)\s+(?:recommend|rank|place|choose|select|prefer|put|shortlist|hire|pick)\b",
    r"\brecommend\b(?:\s+\S+){0,3}\s+(?:first|above|over|ahead|before|only)\b",
    rf"{_START}(?:choose|select|pick|hire|shortlist|prefer|rank|rate|score|place|put)\s+(?:this|that|him|her|them|me|"
    r"the candidate|this candidate|the applicant)\b",
    rf"{_START}(?:choose|select|pick|hire|shortlist|prefer|rank|place|put)\s+\S+\s+\S+\s+(?:first|above|over|ahead|"
    r"as (?:the )?(?:top|best|first|number one))\b",
    r"\b(?:regardless of|irrespective of|no matter) (?:the )?(?:experience|skills|qualifications|evidence|cv|cvs)\b",
    # tools, data and the guards
    rf"(?:{_START}|,\s*)(?:call|invoke|execute|trigger)\s+(?:the\s+)?(?:tool\s+)?[a-z]+_[a-z_]+",
    rf"(?:{_START}|,\s*)(?:call|invoke|execute|trigger|run|use)\s+(?:the\s+)?(?:tool|function)\s+[a-z]+_?[a-z_]*",
    rf"(?:{_START}|,\s*)(?:call|invoke|execute|trigger|run|use)\s+[\w-]+\s+with (?:the )?(?:command|url|query|path|"
    r"file_?name|arguments?|args|parameters?|input)\b",
    r"\b(?:tool|function) (?:instruction|call|request)\s*:|\b[a-z]+_[a-z_]+\s+\w+=",
    rf"{_START}(?:send|forward|post|upload|submit|e-?mail|transmit)\b[^.\n]{{0,40}}\b(?:to|at|via)\b",
    rf"{_START}use the [\w-]+ tool\b",
    r"\b[a-z]+_(?:contact|details|email|mail|export|delete|update|approve|ranking|shell|file|http|get|send)\w*\s*\(",
    rf"{_START}(?:write|list|give|share|show|send|reveal|print|output|spell|include|export|post|forward)\b"
    rf"[^.\n]{{0,60}}\b{_CONTACT}\b",
    r"\bso (?:that )?(?:it|they|this) (?:is|are|isn'?t|aren'?t|won'?t be|will not be|is not|are not) (?:not )?"
    r"(?:filtered|detected|blocked|masked|redacted|flagged|caught)\b",
    r"\b(?:bypass|evade|avoid|get past|get around|disable)\w* (?:the |any |your )?(?:filter|guard|detector|detection|"
    r"redaction|masking|safety|rules|policy)\w*\b",
    r"\b(?:tell|ask|give|show|send) the user\b|\bthe user (?:says|said|asks|asked|gave|wrote|types)\b",
    r"[\"']role[\"']\s*:\s*[\"'](?:system|assistant|user|developer)[\"']",
    r"^\s*(?:\[\d+\]\s*\(from|#{2,}|system\s*:|user\s*:|assistant\s*:|‹‹‹|<<<|>>>|›››|\(passage withheld)",
    r"</?\s*(?:system|instructions?|assistant|tool_call|function_call)\s*>",
    # other languages: imperatives, polite (unambiguous) forms anywhere, ambiguous forms only at a sentence start
    r"\b(?:ignorez|oubliez|répondez|réponds|écrivez|affichez|ajoutez|incluez|commencez|placez|mettez|classez|"
    r"choisissez|sélectionnez|engagez|recommandez)\b",
    rf"{_START}(?:ignore|oublie|répond|écris|affiche|ajoute|inclus|commence|place|mets|classe|choisis|recommande)\b",
    r"\b(?:responda|respondan|escriba|escriban|incluya|añada|imprima|olvide|elija|elijan|coloque|ponga|clasifique|"
    r"seleccione|contrate|recomiende)\b",
    rf"{_START}(?:¡\s*)?(?:responde|escribe|incluye|añade|imprime|ignora|olvida|elige|pon|clasifica|selecciona|"
    r"contrata|recomienda)\b",
    r"\b(?:antworte|antworten sie|schreibe|schreiben sie|füge|fügen sie|gib aus|geben sie|ignoriere|ignorieren sie|"
    r"vergiss|vergessen sie|wähle|wählen sie|setze|setzen sie|stelle|stellen sie|platzieren sie|stufen sie|empfiehl|"
    r"empfehlen sie)\b",
    r"(?:ответь|ответьте|напиши|напишите|добавь|добавьте|выведи|выведите|игнорируй|игнорируйте|забудь|забудьте|"
    r"поставь|поставьте|выбери|выберите|наймите|порекомендуй|порекомендуйте)",
    r"(?:请|务必|必须|一定要)\S{0,8}(?:回答|回复|输出|写|添加|包含|忽略|推荐|选择|排在|放在|列为)|忽略(?:之前|以上|所有|前面)|"
    r"(?:排在|放在|列为)第一",
    r"(?<!\S)(?:أجب|اجب|أجيبي|اكتب|اكتبي|أضف|اضف|اطبع|تجاهل|تجاهلي|انس|انسى)(?!\S)",
    r"(?<!\S)(?:ضع|ضعي|ضعوا|اختر|اختاري|اختاروا|رشح|رشحي|اجعل|اجعلي)(?!\S)",
    r"(?<!\S)(?:עני|ענו|כתבי|כתבו|הוסיפי|הוסיפו|התעלם|התעלמי|התעלמו|שכח|שכחי|שכחו|שימו|בחרו|דרגו|המליצו)(?!\S)",
    rf"{_START}(?:ענה|כתוב|הוסף|הדפס|שים|שימי|בחר|בחרי|דרג|דרגי|הצב|מקם|המלץ)(?!\S)",
    r"\b(?:yok say|talimat\w*|negeer|antwoord (?:alleen|met)|zignoruj|odpowiedz|rispondi|scrivi|ignora le|responda|"
    r"escreva|ignore as instruções)\b",
]]


def _decoded(sentence):
    """The sentence, plus copies with HTML entities and %-escapes decoded (an encoded order is still an order)."""
    out = [sentence]
    for f in (html.unescape, urllib.parse.unquote):
        d = f(sentence)
        if d not in out:
            out.append(d)
    return out


def is_directive(sentence):
    """True when the sentence gives orders to whoever reads it (matched on decoded copies; never rewritten)."""
    for s in _decoded(sentence):
        if content.scan_injection(s) or any(p.search(v) for v in _views(s) for p in PATTERNS):
            return True
        if any(p.search(v) for v in _views(QUOTED.sub(" ", s)) for p in SOFT):
            return True
    return False
