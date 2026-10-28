"""Shared SYNTHETIC fixtures for the final-review tests (invented people and contacts only)."""
import importlib
import json
import pathlib
import sys

import pytest

from test_content import ATTACKS, hashed_embed, make_sam_tester, pipeline, stuffed_cv

from security import index_store

CHALLENGE = pathlib.Path(pipeline.__file__).resolve().parent
EMAIL, PHONE, LINK = "maya.tester@example.net", "+972-54-555-0142", "https://www.linkedin.com/in/maya-tester-0000"
# what a user might type: someone else's contact details, in the question and in the chat history
USER_EMAIL, USER_PHONE = "dana.private@example.com", "052-555-0177"
QUESTION = f"Is the candidate with e-mail {USER_EMAIL} or phone {USER_PHONE} a Python developer?"
HISTORY = [f"My number is {USER_PHONE}, write to {USER_EMAIL}", "Who knows Django?"]


PROFILES = {
    "Maya Tester": ("Data engineer in Haifa, 5 years.", "Built Spark and Airflow pipelines for a retail chain; "
                    "moved nightly batch jobs to streaming with Kafka.", "Python, SQL, Airflow, Spark, Kafka."),
    "Omar Saleh": ("Backend developer in Akko, 3 years.", "Wrote Django REST services for a clinic booking "
                   "system and kept PostgreSQL migrations safe during releases.", "Python, Django, PostgreSQL, Docker."),
    "Lina Haddad": ("Frontend engineer in Nazareth, 6 years.", "Designed React component libraries and "
                    "accessibility audits for a bank's customer portal.", "TypeScript, React, Jest, Figma."),
    "Rami Haddad": ("DevOps engineer in Tel Aviv, 4 years.", "Ran Kubernetes clusters on AWS with Terraform "
                    "and cut cloud costs by a quarter; on-call lead for payments.", "Kubernetes, Terraform, AWS, Go."),
    "Noor Khalil": ("Mobile developer in Jaffa, 2 years.", "Shipped Kotlin and Swift apps for a food "
                    "delivery start-up; added offline sync and crash reporting.", "Kotlin, Swift, Firebase."),
}


def cv(name):
    """A synthetic CV whose wording differs per person (no near-duplicate flags between them)."""
    head, work, skills = PROFILES[name]
    return f"{name}\n{head}\nExperience\n{work}\n{work.replace(';', ' and')}\nSkills: {skills}\n" \
           f"Education: {name.split()[0]} studied at a college in {head.split(' in ')[1].split(',')[0]}.\n"


CONTACT_CV = cv("Maya Tester").replace("\n", f"\nEmail: {EMAIL} · Phone: {PHONE} · {LINK}\n", 1)


def leaks(text):
    text = str(text)
    return [v for v in (EMAIL, PHONE, LINK, USER_EMAIL, USER_PHONE, "555-0142", "555-0177", "@example.")
            if v in text]


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    for k, v in {"SECURITY_REPORT": "quarantine.json", "SECURITY_DECISIONS": "decisions.json",
                 "SECURITY_IDENTITIES": "identities.json"}.items():
        monkeypatch.setenv(k, str(tmp_path / v))
    for k in ("SECURITY_MODE", "RAG_ENV", "CV_CONTACT_ACCESS", "CV_MCP_CONTACT_TOOL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(pipeline, "HERE", tmp_path)
    monkeypatch.setattr(pipeline, "embed", hashed_embed)
    monkeypatch.setattr(pipeline, "RERANK", False)
    monkeypatch.setattr(pipeline, "LAST_BUILD_FAILED", False)
    monkeypatch.setitem(pipeline.ACTIVE_INFO, "info", None)
    yield
    index_store.release(tmp_path / "chroma_db")
    sys.modules.pop("mcp_server", None)


def build(tmp_path, files, folder="cvs"):
    d = tmp_path / folder
    d.mkdir(exist_ok=True)
    for name, text in files.items():
        if name.endswith(".pdf"):
            make_sam_tester(d / name)
        else:
            (d / name).write_text(text, encoding="utf-8")
    docs = pipeline.load_cvs(d)
    chunks = [c for x in docs for c in pipeline.chunk(x)]
    pipeline.build_index(chunks)
    pipeline.build_graph(chunks)
    return docs, chunks


ATTACKED = {"Maya_Tester.md": CONTACT_CV, "Omar_Saleh.md": cv("Omar Saleh"),
            "Aaron_Abbot.md": stuffed_cv("Aaron Abbot"),                                  # medium: stuffing
            "Noor_Khalil.md": cv("Noor Khalil") + "\n" + ATTACKS["arabic"],           # high: injection
            "Sam_Tester_CV.pdf": None}                                                    # high: hidden PDF text


def active(tmp_path):
    return index_store.read_active(tmp_path / "chroma_db")


def rewrite_active(tmp_path, **changes):
    path = tmp_path / "chroma_db" / index_store.ACTIVE
    info = json.loads(path.read_text())
    info.update(changes)
    path.write_text(json.dumps(info))
    return info


def mcp(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    sys.modules.pop("mcp_server", None)
    return importlib.import_module("mcp_server")
