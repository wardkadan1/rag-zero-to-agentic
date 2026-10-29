"""
SECURITY · LLM evaluation · a SANITIZED copy of a run, safe to commit.

    python challenge/security/llm_eval/export_results.py runs/qwen-2 results/2026-10-30-qwen-2-original.json

The raw traces (runs/<name>/cases.jsonl: prompts, passages, full answers) stay local and git-ignored.
This writes only: the environment, the gates (final answer and raw model), per-group counts, and one
line per failure (case id, group, severity, goal, ranks, tool names, and an answer excerpt of at most
160 characters through the PII policy). No prompts, no passages, no CV text, no full answers.
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parents[1]), str(HERE.parents[2])]

from security import pii  # noqa: E402

EXCERPT = 160
KEEP = ("id", "group", "severity", "goal", "attack_rank", "control_rank", "unauthorized", "manipulated")


def sanitize_failure(f):
    out = {k: f[k] for k in KEEP if f.get(k) not in (None, [], "")}
    if f.get("answer"):
        out["answer_excerpt"] = pii.redact(f["answer"])[:EXCERPT]
    if f.get("pii"):
        out["pii_leak_count"] = len(f["pii"])                    # the count only, never the values
    if f.get("links"):
        out["link_count"] = len(f["links"])
    return out


def export(run_dir):
    s = json.loads((pathlib.Path(run_dir) / "summary.json").read_text())
    env = s["environment"]
    return {"note": "Sanitized aggregate results. Raw traces stay local (runs/, git-ignored).",
            "simulated": env["simulated"], "label": env["label"], "case_set": env.get("case_set", "original"),
            "started": env["started"], "finished": s.get("finished"), "model": env["model"], "code": env["frozen"],
            "corpus": env["corpus"], "gates": s["gates"], "gates_raw_model": s.get("gates_raw_model"),
            "all_gates_pass": s["all_gates_pass"], "groups": s["groups"], "medium_A": s.get("medium_A"),
            "benign_failures": s.get("benign_failures"), "citations": s.get("citations"),
            "answer_checks": s.get("answer_checks"), "latency": s.get("latency"),
            "failures": {cond: [sanitize_failure(f) for f in fs] for cond, fs in s["failures"].items()}}


if __name__ == "__main__":
    src, dst = sys.argv[1], pathlib.Path(sys.argv[2])
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(export(src), indent=1, ensure_ascii=False))
    print(f"wrote {dst}")
