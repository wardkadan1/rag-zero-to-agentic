"""
SECURITY · PHASE 2 · the parser worker: one CV file per process, never the original path.

    stdin   the staged snapshot of the validated bytes (a read-only file the parent opened)
    argv    kind (pdf | docx | text), the SHA-256 the gate computed, json limits
    stdout  {"ok": true, "text": ..., "pages": n, "hidden": {...}}  or  {"ok": false, "reason": "<code>"}

Phase 3: for a PDF the worker also renders the pages and reports text a reader cannot see
(pdf_inspect.py), so this inspection never runs in the app process.

It verifies the snapshot's SHA-256, loads the extraction code (challenge/pipeline.py, without
the embedding model), then locks itself down with an audit hook before touching the bytes:
no network, no subprocesses, no writes, and reads only inside the Python installation (for
lazy imports). This is defence in depth against Python-level misuse; the resource limits and
the separate process are what contain a crash or a native-code bug.
"""
import hashlib
import io
import json
import os
import pathlib
import site
import sys
import types

CHALLENGE = pathlib.Path(__file__).resolve().parents[1]
DENY = ("socket.", "subprocess.", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.system", "os.kill",
        "os.killpg", "pty.", "ctypes.", "os.remove", "os.unlink", "os.rename", "os.rmdir", "os.mkdir", "os.chmod",
        "os.chown", "os.link", "os.symlink", "os.truncate", "shutil.", "urllib.", "http.", "ftplib.", "smtplib.",
        "webbrowser.", "sqlite3.")
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC


def answer(obj):
    try:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False))
        sys.stdout.flush()
    except OSError:                                    # over RLIMIT_FSIZE (Python ignores SIGXFSZ): EFBIG
        os._exit(3)
    sys.exit(0)


def lock_down():
    roots = {os.path.realpath(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix, *site.getsitepackages())}
    roots = tuple(r.rstrip(os.sep) + os.sep for r in roots)

    def hook(event, args):
        if event == "open":
            path, mode, flags = (list(args) + [None, None, None])[:3]
            writing = (isinstance(flags, int) and flags & WRITE_FLAGS) or (isinstance(mode, str) and any(c in mode for c in "wax+"))
            if writing:
                raise PermissionError("parser worker: writing is not allowed")
            if isinstance(path, (str, bytes, os.PathLike)) and not os.path.realpath(os.fsdecode(path)).startswith(roots):
                raise PermissionError("parser worker: reading outside the Python installation is not allowed")
        elif event.startswith(DENY):
            raise PermissionError(f"parser worker: {event} is not allowed")

    sys.addaudithook(hook)


def main():
    kind, sha, limits = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
    data = sys.stdin.buffer.read(limits["max_bytes"] + 1)
    if len(data) > limits["max_bytes"] or hashlib.sha256(data).hexdigest() != sha:
        answer({"ok": False, "reason": "snapshot_hash_mismatch"})
    sys.path.insert(0, str(CHALLENGE))
    helpers = types.ModuleType("helpers")              # the worker parses: it never needs the embedding model
    helpers.embed = None
    sys.modules["helpers"] = helpers
    import pipeline
    import pypdf
    import docx  # noqa: F401  (loaded before the lock-down)
    pdf_inspect = None
    if kind == "pdf":
        try:
            from security import pdf_inspect           # pdfplumber + pypdfium2 (requirements-optional.txt)
        except ImportError:
            pass
    lock_down()
    try:
        pages = 0
        if kind == "pdf":
            pages = len(pypdf.PdfReader(io.BytesIO(data)).pages)
            if pages > limits["max_pages"]:
                answer({"ok": False, "reason": f"too_many_pages:{pages}"})
        text = pipeline.read_bytes(kind, data)
        if len(text) > limits["max_chars"]:
            answer({"ok": False, "reason": f"text_too_long:{len(text)}"})
        hidden = None
        if kind == "pdf":
            if pdf_inspect is None:
                hidden = {"unavailable": "not_installed"}
            else:
                try:
                    hidden = pdf_inspect.hidden_text(data)
                except (MemoryError, PermissionError):
                    raise
                except Exception as e:                 # noqa: BLE001 · the text is fine, the check could not run
                    hidden = {"unavailable": type(e).__name__}
    except MemoryError:
        answer({"ok": False, "reason": "memory_limit"})
    except RecursionError:
        answer({"ok": False, "reason": "parse_error:RecursionError"})
    except PermissionError as e:
        answer({"ok": False, "reason": "sandbox_violation:" + str(e).split(": ", 1)[-1][:60]})
    except Exception as e:                             # noqa: BLE001 · a malformed file: report its error type only
        answer({"ok": False, "reason": f"parse_error:{type(e).__name__}"})
    answer({"ok": True, "text": text, "pages": pages, "hidden": hidden})


if __name__ == "__main__":
    main()
