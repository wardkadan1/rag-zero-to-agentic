"""
SECURITY · PHASE 2 · parse every accepted CV in its own short-lived worker process.

    parse_all([(key, kind, sha256, data), ...])  ->  {key: {"ok": True, "text": ..., "pages": n}
                                                         | {"ok": False, "reason": "<code>"}}

* No TOCTOU: the gate read the file ONCE and hashed those bytes (`data`). They are written to a
  private staging folder (0700, file 0400) and handed to the worker as its stdin; the worker
  re-checks the SHA-256 before parsing. The original path is never opened again.
* Isolation: a fresh `python -I` per file (no user site, no PYTHON* variables, no script folder
  on sys.path), its own session (so the whole process group can be killed), an empty working
  folder, an environment with no tokens or credentials, the limits from limits.py, and the
  worker's own audit-hook lock-down (no network, no subprocesses, no writes).
* Not a kernel sandbox: on Linux a stronger box (bubblewrap, a container, seccomp) can wrap the
  same command later; nothing here depends on it.
* Failure of one file never touches the others: a timeout, crash, signal, limit or malformed
  output gives that file a reason code and NO text (partial output is never used).
"""
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
LAUNCHER, WORKER = HERE / "limits.py", HERE / "parse_worker.py"

# Calibrated on the 26 real CV files (2026-10-27): peak 109 MB virtual / 90 MB resident,
# 1.3 s CPU, 3 pages, 7,140 characters. Every limit leaves at least 4x headroom.
LIMITS = {"cpu_s": 10, "as_mb": 512, "fsize_mb": 2, "nofile": 64}
WORKER_LIMITS = {"max_pages": 30, "max_chars": 200_000}
RSS_MB = 384               # the parent's watchdog: the memory cap that also works on macOS
TIMEOUT_S = 20             # wall clock per file
PARALLEL = max(1, min(4, os.cpu_count() or 1))
SIGNALS = {getattr(signal, n): code for n, code in (("SIGXCPU", "cpu_limit"), ("SIGXFSZ", "output_too_large"),
                                                     ("SIGKILL", "worker_killed"), ("SIGSEGV", "worker_crashed:SIGSEGV"),
                                                     ("SIGABRT", "worker_crashed:SIGABRT"), ("SIGBUS", "worker_crashed:SIGBUS"))
           if hasattr(signal, n)}


def worker_command(kind, sha256, max_bytes, worker=None):
    """The launcher sets the limits, then execs the worker (tests swap in a fake worker)."""
    limits = dict(WORKER_LIMITS, max_bytes=max_bytes)
    return ([sys.executable, "-I", str(LAUNCHER), json.dumps(LIMITS), "--"]
            + (worker or [sys.executable, "-I", str(WORKER)]) + [kind, sha256, json.dumps(limits)])


def resident_mb(pid):
    """The worker's resident memory, for the watchdog. None when it cannot be read."""
    try:
        if sys.platform.startswith("linux"):
            for line in open(f"/proc/{pid}/status"):
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
            return None
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=2).stdout
        return int(out.strip()) // 1024 if out.strip() else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)            # the worker and anything it may have started
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o400)


def result_of(proc, out_path, reason):
    """Turn a finished worker into a result. Only a clean exit with a complete answer gives text."""
    if reason:
        return {"ok": False, "reason": reason}
    if proc.returncode < 0:
        return {"ok": False, "reason": SIGNALS.get(-proc.returncode, f"worker_crashed:signal_{-proc.returncode}")}
    if proc.returncode == 3:
        return {"ok": False, "reason": "output_too_large"}
    if proc.returncode != 0:
        return {"ok": False, "reason": f"worker_crashed:exit_{proc.returncode}"}
    try:
        answer = json.loads(out_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"ok": False, "reason": "worker_bad_output"}
    if answer.get("ok") is True and isinstance(answer.get("text"), str):
        return {"ok": True, "text": answer["text"], "pages": int(answer.get("pages", 0))}
    if answer.get("ok") is False and isinstance(answer.get("reason"), str):
        return {"ok": False, "reason": answer["reason"][:120]}
    return {"ok": False, "reason": "worker_bad_output"}


def parse_all(jobs, worker=None, timeout=TIMEOUT_S, parallel=PARALLEL):
    """Parse each job in its own worker, at most `parallel` at once. Single-threaded on purpose."""
    stage = pathlib.Path(tempfile.mkdtemp(prefix="cv-parse-"))     # 0700, removed at the end
    home = stage / "cwd"
    home.mkdir(mode=0o500)
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": str(home), "TMPDIR": str(home)}
    queue, running, results = list(enumerate(jobs)), {}, {}
    try:
        while queue or running:
            while queue and len(running) < parallel:
                i, (key, kind, sha, data) = queue.pop(0)
                src, out = stage / f"{i}.in", stage / f"{i}.out"
                write_private(src, data)
                with open(src, "rb") as fin, open(out, "xb") as fout:
                    proc = subprocess.Popen(worker_command(kind, sha, len(data), worker), stdin=fin, stdout=fout,
                                            stderr=subprocess.DEVNULL, cwd=home, env=env, close_fds=True,
                                            start_new_session=True)
                running[i] = (key, proc, out, time.monotonic())
            time.sleep(0.01)
            for i, (key, proc, out, t0) in list(running.items()):
                reason = None
                if proc.poll() is None:
                    rss = resident_mb(proc.pid)
                    if time.monotonic() - t0 > timeout:
                        reason = "parse_timeout"
                    elif rss is not None and rss > RSS_MB:
                        reason = "memory_limit"
                    else:
                        continue
                kill_group(proc)                        # also reaps anything left in its process group
                results[key] = result_of(proc, out, reason)
                del running[i]
    finally:
        for key, proc, out, t0 in running.values():    # an exception in the parent: leave no worker behind
            kill_group(proc)
        shutil.rmtree(stage, ignore_errors=True)        # the staged CV bytes and outputs
    return results
