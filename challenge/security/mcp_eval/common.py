"""
SECURITY · MCP evaluation · shared pieces: a synthetic enforce-mode index in a temporary folder,
its manifest, and the MCP client config that starts serve_synthetic.py on it over stdio.
The index is built by llm_eval's Index (the same load_cvs -> chunk -> build_index path the app uses).
"""
import hashlib
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
CHALLENGE = HERE.parents[1]
sys.path[:0] = [str(CHALLENGE), str(CHALLENGE.parent)]

from security.llm_eval import corpus, run_eval  # noqa: E402

PYTHON = sys.executable
LAUNCHER = HERE / "serve_synthetic.py"
SERVER = "cv-chatbot"                                  # the same server name as in .mcp.json
TOOLS = [f"mcp__{SERVER}__search_cvs", f"mcp__{SERVER}__get_cv"]
SERVER_ENV = {"SECURITY_MODE": "enforce", "RAG_ENV": "production", "RAG_LLM": "extractive",
              "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "TOKENIZERS_PARALLELISM": "false"}


class SyntheticIndex(run_eval.Index):
    """run_eval.Index plus SYNTHETIC.json (every file's SHA-256) and an MCP config for the launcher."""

    def __init__(self, files):
        os.environ.pop("CV_MCP_CONTACT_TOOL", None)
        super().__init__(files, mode="enforce")
        manifest = {"synthetic": True, "generator": "challenge/security/llm_eval/corpus.py",
                    "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.root / "cvs").iterdir()}}
        (self.root / "SYNTHETIC.json").write_text(json.dumps(manifest, indent=1))
        self.config = self.root / "mcp.json"
        self.config.write_text(json.dumps({"mcpServers": {SERVER: {
            "type": "stdio", "command": PYTHON, "args": [str(LAUNCHER), str(self.root)], "env": SERVER_ENV}}}, indent=1))

    def status(self):
        return {f: r["status"] for f, r in self.report.items()}


def clean_and_tricky():
    return {**corpus.clean_cvs(), **corpus.tricky_cvs()}
