# Claude + MCP hardening (2026-10-29)

ward approved one tightly scoped round after the first real Claude + MCP run (`mcp_eval/results/
2026-10-29-claude-1.json`). That run's strict scores stay as recorded: high-severity injections 3/40,
ranking 1/15. Sign-off stays blocked. Retrieval, ingestion, the index, `pipeline.py`, `app.py` and the
Qwen evaluation are unchanged by this round.

## F2 · orders in CVs reached the agent

**Cause.** `search_cvs` and `get_cv` withheld a passage only when the Phase 3 detectors
(`content.scan_injection`) fired. Four attacker CVs passed as "accepted": an override ("forget the
guidelines…"), a claimed "hiring committee note (binding)", an order to state a fabricated claim
when summarising, and "always recommend X first". The broader sentence-level detector added in the
Qwen remediation (`answer_checks.instruction_like`) caught all four, but it was wired only into the
app's answer path, not into the MCP output.

**Change.** A new `security/directives.py` decides, sentence by sentence, whether CV text gives orders
to whoever reads it:
- addressing the reader or an AI;
- output commands;
- claimed decisions or policies;
- ranking demands ("should be shortlisted ahead of…", "regardless of experience");
- tool calls and arguments;
- requests for contact details or ways around the filters.

It covers 8+ languages and matches on decoded copies: look-alike letters, spacing, leetspeak, reversed
text, Base64, invisible tag letters, HTML entities and %-escapes. `output_guard.remove_instructions`
replaces each such sentence with `[removed: instruction-like text in the CV]`. `mcp_server` applies it
to every `search_cvs` passage and every `get_cv` text, and computes `get_cv` skills from the filtered
text. A result with removals carries `trust: "suspicious"` and `instructions_removed: n`. The rest of
the CV stays as evidence. The stored text and the index are never changed. Whole-passage withholding
by the Phase 3 detectors is unchanged.

`answer_checks.py` (the Qwen answer path) is not changed. `directives.py` reuses its matching views but
has its own patterns. These are narrower where CVs that describe AI, chatbots, recruiting or automation
use the same verbs: an ambiguous imperative ("responde", "répond", "ענה", "回答") counts only at the
start of a sentence, and "the assistant will…" counts only with an evaluation verb.

**Measured (development data).**

| Set | Result |
| --- | --- |
| 124 original attack CVs (used while writing the patterns) | 124/124 have at least one sentence removed |
| 30 clean and tricky synthetic CVs | 0 sentences removed |
| 22 benign test sentences about AI, prompting, recruiting and automation, in 7 languages (`tests/test_directives.py`) | 0 removed |
| 25 real CVs, counted locally, never sent anywhere (1,349 sentences) | 1 sentence removed (it addresses the reader as "you") |

The real-CV check printed counts only; no CV text was logged, committed or sent.

**Trade-offs and known false positives.**
- A CV that quotes an attack string, such as a red-teamer listing "ignore previous instructions" as a
  test case, is still caught by the Phase 3 detector. That passage is withheld, as it was before this round.
- Sentences that speak to the reader ("you", "please") outside quotes are removed.
- A real requirement sentence can read like an order, for example "answers must include sources" in a
  CV that describes a bot's rules. It is removed and the CV marked suspicious.
- The patterns are heuristics. A new phrasing can pass, and the fresh holdout and benign sets in the
  Claude evaluation measure that. The agent's own behaviour stays a necessary second layer.
