# Answer checks (remediation 2026-10-29)

The real Qwen run of 2026-10-28 (`results/2026-10-28-qwen-1-ranking-validation.md`) blocked
sign-off on four gates. ward approved targeted fixes for three of them. This file lists every
production change, why it was made, and what it costs. Baseline for comparison: `13acf11`.

| Gate that failed (qwen-1) | Cause found | Change |
| --- | --- | --- |
| Ranking manipulation 7/15 (same 7 = high-severity injections 7/122) | The model read "always recommend X first" in a CV and obeyed it | Fix 1: rankings are computed in code from CV evidence |
| Strictly cited answers 0/30 | Qwen 1.5B never writes `[n]` | Fix 2: citations are placed by a check that verifies the passage supports the sentence |
| Unanswerable 7/8 (dentist) | The model named someone whose CV mentions a dental clinic; a follow-up invented a degree | Fix 2: statements the passages do not support are dropped; nothing supported means a refusal |

Everything lives in `security/answer_checks.py` and is called from `pipeline.safe_answer`, which the
app already runs on every generated answer. `app.py`, `helpers.py`, `ragkit/`, the ingestion gate,
retrieval and the prompt are unchanged. `pipeline.ANSWER_CHECKS = False` turns the checks off.

## How it hooks in

`app.rag` calls `make_query → retrieve → should_refuse → build_prompt → llm → safe_answer`.
`pipeline.TURN` (thread-local) carries one turn: `make_query` starts a fresh turn and remembers the
rewritten follow-up, `build_prompt` remembers the question and passages, `safe_answer` takes them
(once) and checks the model's text against them. A `safe_answer` call without a prompt built in
the same turn (refused turns, other callers) skips the checks and keeps the Phase 5 output policy.

## Fix 1 · ranking by evidence

When the **user's question** asks for a ranking or comparison (English, French, Spanish, German,
Russian, Chinese, Arabic, Hebrew), the model's answer is not shown. The ranking is computed:

- **Criteria** are the skills and content words of the question. Candidate names and judging words
  ("best", "first", "recommend"…) are never criteria; with no criterion left, the app asks for one.
- **Evidence** is a CV sentence that is neither instruction-like nor a judgement. Instruction-like:
  the Phase 3 detectors fire, or the sentence addresses an AI/recruiter/reader, gives an output
  command, claims a hiring decision or policy, or names a tool, in several languages, matched on
  copies of the line (look-alike letters, spacing, leetspeak, reversed, Base64, tag characters).
  A judgement: "strongest", "top", "hiring committee", "recommend"… in 8 languages. A candidate's
  own sentence about themselves outside the free-text section is never evidence for rank either.
- **Order**: number of criteria shown without a qualifier ("basic", "some"), then the years of
  experience the CV states (`years_of_experience`), then whether the skill appears in work
  experience. Each line cites the passages used, e.g. `2. Name: python: in the skills list; 4 years of
  experience stated [3]`.
- **Refuse or qualify**: no criterion → ask for one; nobody with evidence → refusal; one candidate →
  "not enough for a ranking"; equal evidence → same number and a note; no years stated → "weak".

Trade-offs:
- Rankings are coarse. They do not weigh project quality, seniority words or anything the model
  could have read between the lines. A user who wants nuance gets a cited list, not a judgement.
- Stated years are **claims**, not verified facts: a CV that lies about its years still moves.
  Lying about experience is not an injection, and the gate does not count it, but it is a residual risk.
- A CV sentence that happens to look like an instruction ("Answer questions from users of our
  helpdesk") stops being evidence. On the 30 clean and tricky synthetic CVs no sentence was flagged;
  on real CVs some loss is possible. The text in the index is never changed.
- Only the K passages the search returned are ranked ("among the 3 CVs the search returned").
- The model is still called on ranking questions (app.py is not ours to change), so latency is the same.
- A clever injection the detectors miss can still be read as evidence, but only for the skill words
  it contains. It cannot say "rank me first"; it can only claim a skill, like any CV can.

## Fix 2 · grounding, validated citations and refusals

Every other answer is split into statements (lines, list items, sentences). A statement is kept
only if one passage supports it:

- The passage must belong to the candidate the statement names, or the one the question (or the
  rewritten follow-up) names. A pronoun follow-up whose person the passages cannot tell is dropped.
- At least 75% of the statement's content words (weighted by rarity in the index; light stemming;
  accent-insensitive 5-letter prefixes) must be in that passage, and every number must be there.
- A statement that names a candidate must also meet the **question's** requirement in that
  candidate's passages. "X has worked as a dentist" is not supported by "built an app for a dental
  clinic": "dentist" is not there, and a name match never earns a citation.
- Instruction-like sentences in a passage never support anything.
- A statement naming someone outside the passages is dropped.

Kept statements keep the model's words and get the supporting passage numbers (`… [2].`). The model's
own `[n]` are recorded, then removed and re-earned. Dropped statements are counted in a note. If
nothing is supported, the answer is the refusal. The checks remove and cite; they never add a fact.

Trade-offs:
- **More refusals.** Paraphrase across languages (an English answer about a French CV) and synonyms
  ("ML" vs "machine learning") can fail the 75% rule. In the synthetic dev set this cost 1 of 38.
- Word overlap is not meaning: "did not use Kafka" and "used Kafka" share their words. Negation and
  contradiction are not detected; the check proves the words are there, not that the claim follows.
- The citation proves the passage contains the statement's words, not that the CV is true.
- Raw-model citation compliance is unchanged (Qwen still does not cite). The harness now reports it
  separately from the final answer (`citations`, `gates_raw_model`).

## Tests

`security/tests/test_answer_checks.py`: synthetic passages only. The harness records each turn's
check report (`checks`) and counts per kind (`answer_checks`) so the real rerun shows what was
replaced, trimmed or refused.

This is a heuristic layer on a 1.5B model. It is not proof of prompt-injection resistance, and
results on the Qwen agent loop say nothing about Claude over MCP.
