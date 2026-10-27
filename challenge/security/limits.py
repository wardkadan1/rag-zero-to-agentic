"""
SECURITY · PHASE 2 · tiny launcher: set the resource limits, then become the parser worker.

    python -I limits.py '<json limits>' -- <worker command ...>

The limits are set here, in the child, and not with Popen(preexec_fn=...): preexec_fn is not
safe in a parent that runs threads (the Gradio app does). After os.execv the worker inherits them.

Linux enforces every limit. macOS ignores RLIMIT_AS (the address-space cap), so there the
parent's resident-memory watchdog (sandbox.py) is what stops a worker that eats memory.
"""
import json
import os
import resource
import sys

MB = 2**20


def cap(name, soft, hard=None):
    limit = getattr(resource, name, None)
    if limit is None:
        return
    try:
        resource.setrlimit(limit, (soft, soft if hard is None else hard))
    except (ValueError, OSError):
        pass                                    # not supported on this OS: the parent's watchdog still applies


def main():
    limits = json.loads(sys.argv[1])
    cmd = sys.argv[sys.argv.index("--") + 1:]
    cap("RLIMIT_CPU", limits["cpu_s"], limits["cpu_s"] + 1)   # soft: SIGXCPU, hard: SIGKILL
    if sys.platform.startswith("linux"):
        cap("RLIMIT_AS", limits["as_mb"] * MB)
    cap("RLIMIT_FSIZE", limits["fsize_mb"] * MB)            # the only file it writes is its stdout
    cap("RLIMIT_NOFILE", limits["nofile"])
    cap("RLIMIT_CORE", 0)                                   # a crash leaves no core file with CV bytes in it
    os.umask(0o077)
    os.execv(cmd[0], cmd)


if __name__ == "__main__":
    main()
