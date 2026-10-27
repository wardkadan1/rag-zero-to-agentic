"""Phase 2 regression tests: parsing in limited worker processes. Synthetic files and fake workers only.

    .venv/bin/python -m pytest -q challenge/security/tests
"""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import threading
import time

import pytest

CHALLENGE = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CHALLENGE))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pipeline  # noqa: E402
from security import ingest_guard as G, sandbox  # noqa: E402
from test_ingest_guard import CV_TEXT, make_docx, make_pdf  # noqa: E402

LINUX = sys.platform.startswith("linux")


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_REPORT", str(tmp_path / "quarantine.json"))
    monkeypatch.setenv("SECURITY_DECISIONS", str(tmp_path / "decisions.json"))
    monkeypatch.delenv("SECURITY_MODE", raising=False)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))     # staging folders land here, so the test can see them


def fake_worker(tmp_path, body, name="fake_worker.py"):
    """A stand-in worker run through the same launcher, limits and process handling as the real one."""
    path = tmp_path / name
    path.write_text("import json, os, sys, time\n" + textwrap.dedent(body))
    return [sys.executable, "-I", str(path)]


def job(data=b"hello", kind="text", key="a.txt"):
    return (key, kind, hashlib.sha256(data).hexdigest(), data)


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    if LINUX:                                           # a zombie is dead for our purposes
        return "Z" not in open(f"/proc/{pid}/stat").read().split(")")[-1].split()[0]
    return True


def no_orphans(marker):
    """No process whose command line mentions `marker` is still running."""
    out = subprocess.run(["ps", "-eo", "pid=,stat=,args="], capture_output=True, text=True).stdout
    return [line for line in out.splitlines() if marker in line and " Z" not in line[:20]] == []


# ------------------------------------------------------------------ the real worker: same text as before
def test_real_worker_gives_exactly_the_old_text(tmp_path):
    files = {"a.pdf": "pdf", "b.docx": "docx", "c.txt": "text", "d.md": "text"}
    make_pdf(tmp_path / "a.pdf")
    make_docx(tmp_path / "b.docx")
    (tmp_path / "c.txt").write_bytes(CV_TEXT.replace("\n", "\r\n").encode() + "Ünïcode ✓".encode())
    (tmp_path / "d.md").write_text("# " + CV_TEXT)
    out = sandbox.parse_all([(n, k, hashlib.sha256((tmp_path / n).read_bytes()).hexdigest(), (tmp_path / n).read_bytes())
                             for n, k in files.items()])
    for name in files:
        assert out[name]["ok"], out[name]
        assert out[name]["text"] == pipeline.read_file(tmp_path / name)


def test_practice_cvs_are_byte_identical_through_the_worker(tmp_path):
    practice = CHALLENGE.parent / "data" / "cvs" / "candidates"
    docs = pipeline.load_cvs(practice)
    assert [d["text"] for d in docs] == [pipeline.normalize(pipeline.read_file(p)) for p in sorted(practice.glob("*.md"))]


# ------------------------------------------------------------------ TOCTOU: the hashed snapshot is what gets parsed
def test_file_changed_after_validation_is_not_reread(tmp_path, monkeypatch):
    d = tmp_path / "cvs"
    d.mkdir()
    (d / "A_CV.txt").write_text(CV_TEXT)
    real_gate = G.gate

    def gate_then_swap(folder, suffixes):
        checked = real_gate(folder, suffixes)
        (d / "A_CV.txt").write_text("SWAPPED AFTER VALIDATION " * 20)    # the attacker wins the race on disk
        return checked
    monkeypatch.setattr(G, "gate", gate_then_swap)
    docs = pipeline.load_cvs(d)
    assert "SWAPPED" not in docs[0]["text"] and "Lina Haddad" in docs[0]["text"]


def test_snapshot_with_wrong_hash_is_refused():
    key, kind, sha, data = job()
    out = sandbox.parse_all([(key, kind, "0" * 64, data)])
    assert out[key] == {"ok": False, "reason": "snapshot_hash_mismatch"}


def test_staging_folder_is_private_and_removed(tmp_path):
    seen = []
    worker = fake_worker(tmp_path, """
        import stat
        st = os.fstat(0)
        print(json.dumps({"ok": True, "text": oct(stat.S_IMODE(st.st_mode)), "pages": 0}))
    """)
    before = set(os.listdir(tmp_path))
    out = sandbox.parse_all([job()], worker=worker)
    assert out["a.txt"]["text"] == "0o400"                      # the staged snapshot is read-only
    assert set(os.listdir(tmp_path)) == before                   # and gone afterwards


# ------------------------------------------------------------------ failures stay inside one file
def test_malformed_files_are_quarantined_and_others_continue(tmp_path):
    d = tmp_path / "cvs"
    d.mkdir()
    (d / "Broken.pdf").write_bytes(b"%PDF-1.4\n" + os.urandom(3000))
    (d / "Broken.docx").write_bytes(b"PK\x03\x04" + os.urandom(3000))      # passes the magic check, not a valid zip
    (d / "Good_CV.txt").write_text(CV_TEXT)
    docs = pipeline.load_cvs(d)
    rows = {r["source"]: r for r in pipeline.INGEST_REPORT}
    assert [x["source"] for x in docs] == ["Good_CV.txt"]
    assert rows["Broken.pdf"]["status"] == "quarantined" and "parse_failed:parse_error:" in rows["Broken.pdf"]["detail"]
    assert rows["Broken.docx"]["status"] in ("blocked", "quarantined")
    report = json.loads((tmp_path / "quarantine.json").read_text())["files"]
    assert {r["source"]: r["status"] for r in report}["Broken.pdf"] == "quarantine"


def test_timeout_kills_the_worker_and_its_children(tmp_path):
    pidfile = tmp_path / "pids"
    worker = fake_worker(tmp_path, f"""
        child = os.fork()
        if child == 0:
            time.sleep(600)
        open({str(pidfile)!r}, "w").write(f"{{os.getpid()}} {{child}}")
        time.sleep(600)
    """, name="sleepy_worker.py")
    t = time.monotonic()
    out = sandbox.parse_all([job()], worker=worker, timeout=1.5)
    assert out["a.txt"] == {"ok": False, "reason": "parse_timeout"}
    assert time.monotonic() - t < 10
    worker_pid, child_pid = map(int, pidfile.read_text().split())
    time.sleep(0.2)
    assert not alive(worker_pid) and not alive(child_pid)
    assert no_orphans("sleepy_worker.py")


@pytest.mark.parametrize("body,reason", [
    ("os.abort()", "worker_crashed:SIGABRT"),
    ("import ctypes; ctypes.string_at(0)", "worker_crashed:SIGSEGV"),
    ("sys.exit(7)", "worker_crashed:exit_7"),
    ("print('{\"ok\": true, \"te')", "worker_bad_output"),               # a partial answer is never used
    ("print(json.dumps({'ok': True, 'text': 'x' * 100})); sys.stdout.flush(); os.abort()", "worker_crashed:SIGABRT"),
])
def test_worker_crash_gives_a_reason_and_no_text(tmp_path, body, reason):
    out = sandbox.parse_all([job(), job(b"second", key="b.txt")], worker=fake_worker(tmp_path, body, "crashy_worker.py"))
    assert out["a.txt"] == {"ok": False, "reason": reason} and out["b.txt"]["reason"] == reason
    assert no_orphans("crashy_worker.py")


@pytest.mark.skipif(not LINUX, reason="RLIMIT_AS is enforced on Linux only (macOS relies on the RSS watchdog)")
def test_address_space_limit_stops_a_memory_bomb(tmp_path):
    worker = fake_worker(tmp_path, """
        try:
            blob = bytearray(2 * 2**30)
            print(json.dumps({"ok": True, "text": "allocated", "pages": 0}))
        except MemoryError:
            print(json.dumps({"ok": False, "reason": "memory_limit"}))
    """)
    assert sandbox.parse_all([job()], worker=worker)["a.txt"] == {"ok": False, "reason": "memory_limit"}


def test_rss_watchdog_stops_a_worker_that_grows(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "RSS_MB", 60)
    monkeypatch.setitem(sandbox.LIMITS, "as_mb", 4096)
    worker = fake_worker(tmp_path, """
        blob = bytearray(200 * 2**20)
        for i in range(0, len(blob), 4096):
            blob[i] = 1                                    # touch every page: resident, not just reserved
        time.sleep(600)
    """, name="hungry_worker.py")
    assert sandbox.parse_all([job()], worker=worker, timeout=30)["a.txt"] == {"ok": False, "reason": "memory_limit"}
    assert no_orphans("hungry_worker.py")


def test_cpu_limit_stops_a_busy_loop(tmp_path, monkeypatch):
    monkeypatch.setitem(sandbox.LIMITS, "cpu_s", 1)
    worker = fake_worker(tmp_path, "while True:\n    pass\n")
    assert sandbox.parse_all([job()], worker=worker, timeout=30)["a.txt"]["reason"] in ("cpu_limit", "worker_killed")


def test_output_limit_stops_a_flood(tmp_path, monkeypatch):
    monkeypatch.setitem(sandbox.LIMITS, "fsize_mb", 1)
    monkeypatch.setitem(sandbox.WORKER_LIMITS, "max_chars", 10**7)     # let the kernel's file-size cap be what stops it
    out = sandbox.parse_all([job(("word " * 400_000).encode())])       # 2 MB of text: its answer is over 1 MB
    assert out["a.txt"] == {"ok": False, "reason": "output_too_large"}


def test_page_and_text_limits_quarantine(tmp_path, monkeypatch):
    make_pdf(tmp_path / "a.pdf")
    data = (tmp_path / "a.pdf").read_bytes()
    monkeypatch.setitem(sandbox.WORKER_LIMITS, "max_chars", 10)
    assert sandbox.parse_all([job(data, "pdf", "a.pdf")])["a.pdf"]["reason"].startswith("text_too_long:")
    monkeypatch.setitem(sandbox.WORKER_LIMITS, "max_pages", 0)
    assert sandbox.parse_all([job(data, "pdf", "a.pdf")])["a.pdf"] == {"ok": False, "reason": "too_many_pages:1"}


# ------------------------------------------------------------------ least privilege inside the worker
def test_worker_environment_has_no_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-leak")
    monkeypatch.setenv("HF_TOKEN", "do-not-leak")
    worker = fake_worker(tmp_path, 'print(json.dumps({"ok": True, "text": json.dumps(dict(os.environ)), "pages": 0}))')
    env = json.loads(sandbox.parse_all([job()], worker=worker)["a.txt"]["text"])
    assert "do-not-leak" not in json.dumps(env) and set(env) <= {"PATH", "LANG", "LC_ALL", "HOME", "TMPDIR", "LC_CTYPE",
                                                                 "OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"}


def test_lock_down_blocks_network_processes_writes_and_outside_reads(tmp_path):
    probe = tmp_path / "probe.py"
    probe.write_text(textwrap.dedent(f"""
        import sys; sys.path.insert(0, {str(CHALLENGE / "security")!r})
        import parse_worker, socket, subprocess, os, json
        parse_worker.lock_down()
        tries = {{"socket": lambda: socket.create_connection(("127.0.0.1", 9)),
                 "subprocess": lambda: subprocess.run(["true"]),
                 "write": lambda: open({str(tmp_path / "x")!r}, "w"),
                 "read_outside": lambda: open({str(tmp_path / "probe.py")!r}).read(),
                 "remove": lambda: os.remove({str(probe)!r}),
                 "fork": lambda: os.fork()}}
        blocked = {{}}
        for name, f in tries.items():
            try:
                f(); blocked[name] = False
            except PermissionError:
                blocked[name] = True
        import json as j2                      # imports from the Python installation still work
        print(json.dumps(blocked))
    """))
    out = subprocess.run([sys.executable, "-I", str(probe)], capture_output=True, text=True, timeout=60)
    assert json.loads(out.stdout) == dict.fromkeys(["socket", "subprocess", "write", "read_outside", "remove", "fork"], True)


# ------------------------------------------------------------------ concurrency
def test_parallel_workers_return_every_result(tmp_path):
    jobs = [job(f"cv number {i} ".encode() * 50, key=f"{i}.txt") for i in range(10)]
    out = sandbox.parse_all(jobs, parallel=4)
    assert {k: v["text"].split()[2] for k, v in out.items()} == {f"{i}.txt": str(i) for i in range(10)}


def test_two_ingestions_at_once_do_not_mix(tmp_path):
    folders = []
    for n in range(2):
        d = tmp_path / f"cvs{n}"
        d.mkdir()
        for i in range(3):
            (d / f"cv{i}.txt").write_text(f"Folder {n} file {i}. " * 30)
        folders.append(d)
    results = {}
    threads = [threading.Thread(target=lambda d=d: results.__setitem__(d.name, pipeline.load_cvs(d))) for d in folders]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    for n, d in enumerate(folders):
        assert [x["text"].split()[1] for x in results[d.name]] == [str(n)] * 3
