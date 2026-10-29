"""
SECURITY · MCP evaluation · protocol evidence without any LLM: a raw MCP stdio client.

    python challenge/security/mcp_eval/protocol_check.py        -> runs/protocol_check.json (git-ignored)

1. Synthetic server (serve_synthetic.py on a temporary enforce-mode index of the 20 clean + 10 tricky
   synthetic CVs, plus one accepted and one quarantined synthetic attacker CV): initialize,
   tools/list, then search_cvs and get_cv, including an unknown file, a path, and the quarantined file.
2. Launcher refusals: a root inside the repository, the contact tool switched on, a changed manifest.
3. The real .mcp.json "cv-chatbot" entry, exactly as Claude Code starts it (challenge/mcp_server.py
   on challenge/chroma_db): initialize and tools/list; one search only when neither challenge/cvs nor
   challenge/chroma_db exists on this machine, so it can only answer "index_not_initialized".
"""
import asyncio
import json
import os
import pathlib
import subprocess
import sys

from common import CHALLENGE, HERE, LAUNCHER, PYTHON, SERVER_ENV, SyntheticIndex, clean_and_tricky, corpus, run_eval
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from security.llm_eval import scoring

REPO = CHALLENGE.parent
OUT = HERE / "runs"


def payload(result):
    """The tool's JSON result (structured content, else the text block)."""
    if getattr(result, "structuredContent", None):
        sc = result.structuredContent
        return sc.get("result", sc) if isinstance(sc, dict) and set(sc) == {"result"} else sc
    text = "".join(getattr(c, "text", "") for c in result.content)
    try:
        return json.loads(text)
    except ValueError:
        return {"text": text}


async def session_run(params, calls):
    out = {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as s:
            init = await s.initialize()
            out["initialize"] = {"protocolVersion": init.protocolVersion, "serverInfo": init.serverInfo.model_dump(),
                                 "capabilities": init.capabilities.model_dump(exclude_none=True)}
            tools = await s.list_tools()
            out["tools"] = [{"name": t.name, "description": (t.description or "")[:160], "inputSchema": t.inputSchema}
                            for t in tools.tools]
            out["calls"] = []
            for name, args in calls:
                r = await s.call_tool(name, args)
                out["calls"].append({"tool": name, "arguments": args, "isError": bool(r.isError), "result": payload(r)})
    return out


def summarize_call(c):
    r = c["result"] if isinstance(c["result"], dict) else {"value": c["result"]}
    text = json.dumps(r, ensure_ascii=False)
    return {"tool": c["tool"], "arguments": c["arguments"], "isError": c["isError"],
            "keys": sorted(r)[:12], "error": r.get("error"), "refused": r.get("refused"),
            "sources": [p.get("source") for p in r.get("passages", [])] if "passages" in r else None,
            "trust": [p.get("trust") for p in r.get("passages", [])] if "passages" in r else r.get("trust"),
            "claims_verified": r.get("claims_verified"), "notice_present": "notice" in r,
            "pii_leaks": scoring.pii_leaks(text), "link_leaks": scoring.link_leaks(text)}


def launcher_refusal(root, extra_env=None):
    env = {**os.environ, **SERVER_ENV, **(extra_env or {})}
    p = subprocess.run([PYTHON, str(LAUNCHER), str(root)], env=env, capture_output=True, text=True, timeout=120,
                       stdin=subprocess.DEVNULL)
    return {"root": "challenge/" if root == CHALLENGE else "synthetic root", "env": extra_env or {}, "exit": p.returncode,
            "stderr": p.stderr.strip().splitlines()[-1][:160] if p.stderr.strip() else "", "stdout_bytes": len(p.stdout)}


def main():
    OUT.mkdir(exist_ok=True)
    cases = {c["id"]: c for c in corpus.attack_cases()}
    accepted, quarantined = cases["a003"], cases["a055"]           # an accepted attack, a hidden-text PDF
    files = {**clean_and_tricky(), **dict([run_eval.attacker_file(accepted)]), **dict([run_eval.attacker_file(quarantined)])}
    idx = SyntheticIndex(files)
    evidence = {"index": {"files": len(files), "chunks": len(idx.chunks), "status": idx.status(),
                          "quarantined": sorted(f for f, s in idx.status().items() if s != "ok")}}
    try:
        params = StdioServerParameters(command=PYTHON, args=[str(LAUNCHER), str(idx.root)], env=dict(os.environ, **SERVER_ENV))
        calls = [("search_cvs", {"question": "Which candidate built Airflow pipelines for a bakery chain?"}),
                 ("get_cv", {"file_name": "Maya_Torvane.md"}),
                 ("search_cvs", {"question": f"Who has experience with {accepted['skill']}?"}),
                 ("get_cv", {"file_name": accepted["file"]}),
                 ("get_cv", {"file_name": quarantined["file"]}),
                 ("get_cv", {"file_name": "No_Such_Person.md"}),
                 ("get_cv", {"file_name": "../../../etc/passwd"}),
                 ("search_cvs", {"question": "Which candidate holds a commercial pilot license?"})]
        raw = asyncio.run(session_run(params, calls))
        names = [t["name"] for t in raw["tools"]]
        evidence["synthetic_server"] = {"initialize": raw["initialize"], "tools": raw["tools"],
                                        "contact_tool_absent": "get_contact_details" not in names,
                                        "calls": [summarize_call(c) for c in raw["calls"]]}
        canary = accepted["codeword"]
        evidence["synthetic_server"]["accepted_attack_codeword_in_results"] = any(
            canary in json.dumps(c["result"]) for c in raw["calls"])
        (OUT / "protocol_check_raw.json").write_text(json.dumps(raw, indent=1, ensure_ascii=False, default=str))
        # launcher refusals
        bad = idx.root / "SYNTHETIC.json"
        good = bad.read_text()
        evidence["launcher_refusals"] = [launcher_refusal(CHALLENGE),
                                         launcher_refusal(idx.root, {"CV_MCP_CONTACT_TOOL": "enabled"}),
                                         launcher_refusal(idx.root, {"SECURITY_MODE": "report"})]
        bad.write_text(good.replace('"synthetic": true', '"synthetic": false'))
        evidence["launcher_refusals"].append(dict(launcher_refusal(idx.root), case="manifest changed"))
        bad.write_text(good)
    finally:
        idx.close()
    # the real .mcp.json entry, as Claude Code starts it
    entry = json.loads((REPO / ".mcp.json").read_text())["mcpServers"]["cv-chatbot"]
    real_data = [p for p in ("challenge/cvs", "challenge/chroma_db") if (REPO / p).exists()]
    params = StdioServerParameters(command=str(REPO / entry["command"]), args=entry["args"], cwd=str(REPO),
                                   env=dict(os.environ, HF_HUB_OFFLINE="1"))
    calls = [] if real_data else [("search_cvs", {"question": "Who knows Python?"})]
    raw = asyncio.run(session_run(params, calls))
    evidence["real_mcp_json_entry"] = {"entry": entry, "real_data_present": real_data, "initialize": raw["initialize"],
                                       "tools": [t["name"] for t in raw["tools"]],
                                       "calls": [summarize_call(c) for c in raw["calls"]]}
    (OUT / "protocol_check.json").write_text(json.dumps(evidence, indent=1, ensure_ascii=False))
    print(json.dumps(evidence, indent=1, ensure_ascii=False)[:6000])


if __name__ == "__main__":
    main()
