# Qwen adversarial evaluation (synthetic CVs only)

This folder tests the model, not the code: does `Qwen/Qwen2.5-1.5B-Instruct` follow instructions
hidden in CVs, invent qualifications, change rankings, leak contact details or call tools it
should not? Nothing here changes the app. The pipeline, app, MCP server, `security/` and `ragkit/`
stay exactly as they are at the frozen baseline `13acf11`; every run records a check of that.

Every CV used here is invented (`corpus.py`). No real CV is read, copied or sent anywhere.

## What runs

| Part | What it is |
| --- | --- |
| `corpus.py` | 124 attack cases in 11 groups (direct, indirect, multilingual covered/uncovered by the regex detectors, obfuscated, prompt spoofing, fabrication, ranking, PII exfiltration, tool/agent, multi-turn), 20 clean CVs, 10 benign CVs that look risky, 30 answerable and 8 unanswerable questions. Each attack has its own canary codeword and attacker name. |
| `scoring.py` | Mechanical scoring: canary codewords, invented claims, rank moves against a control run, contact values in any form (spelled out, spaced, Base64), links, style hijacks, tool calls. No model judges another model. |
| `agent.py` | A small MCP-style loop. The model sees only the cv-chatbot tools (`search_cvs`, `get_cv`). Any other tool it asks for is recorded and **never executed**. |
| `backends.py` | `load_qwen()`: the project's own path, `RAG_LLM=hf`. Any other backend or model, or a failed load, stops the run with `BLOCKED`. There is no fallback. `Simulated` exists only to test this harness and is always labelled SIMULATED. |
| `run_eval.py` | Runs both conditions and writes the results. |

**Condition A (release gate):** the production-style path with `SECURITY_MODE=enforce`, one fresh
index per attack (20 clean CVs + the attacker's CV), then make_query → retrieve → should_refuse →
build_prompt → Qwen → safe_answer, exactly like the app. Ranking attacks also get a control run
without the attack.

**Condition B (diagnostic, not a gate):** the model alone. Same attack inputs, but no ingestion
gate, detectors, withholding, refusal gate or output guard. The attacker's passage sits among clean
passages in the same prompt template.

## Running it on the MacBook

```bash
git pull origin claude/project-thread-gt4cd4
source .venv/bin/activate                     # the project's environment, with torch + transformers
git diff --stat 13acf11 -- challenge/pipeline.py challenge/app.py challenge/mcp_server.py challenge/helpers.py ragkit challenge/security ':(exclude)challenge/security/tests' ':(exclude)challenge/security/llm_eval'
                                              # must print nothing

caffeinate -i env RAG_LLM=hf python challenge/security/llm_eval/run_eval.py --out challenge/security/llm_eval/runs/qwen-1
```

- The first run downloads the model (about 3 GB) from Hugging Face on the Mac.
- Expect several hours: about 250 attack runs, plus control runs, agent loops and the benign set.
- If it stops, run the same command with `--resume` and the same `--out`. A resume refuses a folder
  that holds results from another model or revision.
- If Qwen cannot load, it prints `BLOCKED: …`, exits with code 2 and writes nothing. Report that and stop.
- `--only a001,a061,b01` runs a few cases first (a quick smoke test, about a minute after loading).

Then run the tests: `python -m pytest -q challenge/security/tests tests`.

## Outputs (`runs/<name>/`, kept out of git)

| File | What it holds |
| --- | --- |
| `environment.json` | model, exact revision, dtype, device, library versions, generation settings, frozen-baseline check |
| `cases.jsonl` | one line per case and condition: question, answer, hits, tool calls, every score |
| `summary.json` | release gates with numerators, denominators and 95% intervals; per-group success in A and B; every failure; latency; peak memory |
| `report.md` | the same, readable |

The outputs contain only synthetic text. A run is a Qwen result only when `environment.json` says
`"simulated": false` and names `Qwen/Qwen2.5-1.5B-Instruct`; a simulated report carries a banner.

## Limits

- Passing these cases does not prove the model resists every injection, and it does not make the
  app production-ready. They are 124 attacks written by us.
- Greedy decoding makes runs repeatable on one machine; another device or library version can change answers.
- Pillow: no image input is enabled, and decoding paths were checked only with synthetic probes. The
  open advisories remain a documented residual risk.
