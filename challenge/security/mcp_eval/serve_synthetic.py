"""
SECURITY · MCP evaluation · start the UNCHANGED challenge/mcp_server.py on a SYNTHETIC index.

    python challenge/security/mcp_eval/serve_synthetic.py ROOT      (stdio MCP server, for Claude Code)

ROOT is a temporary folder made by run_claude_eval.py: ROOT/cvs holds only synthetic CVs from
security/llm_eval/corpus.py, ROOT/chroma_db the enforce-mode index built from them, and
ROOT/SYNTHETIC.json the name and SHA-256 of every file. Before mcp_server.py is imported this
launcher points pipeline.HERE at ROOT, so the server reads ROOT/chroma_db and nothing else.

It refuses to start (exit 2, a message on stderr, nothing on stdout) when:
- ROOT is inside this repository (e.g. challenge/, where the real index and challenge/cvs live),
- ROOT/SYNTHETIC.json is missing, or a file in ROOT/cvs is missing from it, extra, or changed,
- ROOT/cvs is a link, or a file name in it also exists in challenge/cvs (names compared only;
  no real CV is opened),
- the contact tool is switched on (CV_MCP_CONTACT_TOOL) or SECURITY_MODE is not enforce.
"""
import contextlib
import hashlib
import json
import os
import pathlib
import runpy
import sys

HERE = pathlib.Path(__file__).resolve().parent
CHALLENGE = HERE.parents[1]
REPO = CHALLENGE.parent


def refuse(msg):
    print(f"serve_synthetic: refused: {msg}", file=sys.stderr, flush=True)
    sys.exit(2)


def check_root(root):
    if root == REPO or REPO in root.parents:
        refuse("the index root is inside the repository; only a temporary synthetic root is served")
    cvs = root / "cvs"
    if cvs.is_symlink() or not cvs.is_dir():
        refuse("ROOT/cvs is missing or a link")
    try:
        manifest = json.loads((root / "SYNTHETIC.json").read_text())
    except (OSError, ValueError):
        refuse("ROOT/SYNTHETIC.json is missing or unreadable")
    if manifest.get("synthetic") is not True:
        refuse("the manifest does not declare a synthetic corpus")
    listed = manifest.get("files", {})
    present = {p.name for p in cvs.iterdir()}
    if present != set(listed):
        refuse("ROOT/cvs does not match the manifest")
    for name, digest in listed.items():
        path = cvs / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            refuse("a CV in ROOT/cvs differs from the manifest")
    real = CHALLENGE / "cvs"
    if real.is_dir() and present & {p.name for p in real.iterdir()}:
        refuse("a file name in ROOT/cvs also exists in challenge/cvs")


def main():
    if len(sys.argv) != 2:
        refuse("usage: serve_synthetic.py ROOT")
    root = pathlib.Path(sys.argv[1]).resolve()
    check_root(root)
    if os.getenv("CV_MCP_CONTACT_TOOL", "").strip():
        refuse("CV_MCP_CONTACT_TOOL must not be set: contact access stays disabled")
    if os.getenv("SECURITY_MODE", "").strip().lower() != "enforce":
        refuse("SECURITY_MODE must be enforce")
    for key, name in {"SECURITY_REPORT": "quarantine.json", "SECURITY_DECISIONS": "decisions.json",
                      "SECURITY_IDENTITIES": "identities.json"}.items():
        os.environ[key] = str(root / name)              # the paths the builder used
    sys.path.insert(0, str(CHALLENGE))
    with contextlib.redirect_stdout(sys.stderr):        # stdout is the MCP protocol
        import pipeline
    pipeline.HERE = root                                # before mcp_server.py attaches to the index
    runpy.run_path(str(CHALLENGE / "mcp_server.py"), run_name="__main__")


if __name__ == "__main__":
    main()
