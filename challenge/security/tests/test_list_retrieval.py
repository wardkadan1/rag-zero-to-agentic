"""List questions, exhaustive candidate lists, residence and years semantics (2026-10-30).

SYNTHETIC CVs only (invented people). Pins the fixes for natural list wording ("Who has X?",
"Does anyone know X?", "Which people …", "List everyone …"), one entry per candidate, skill
intersections, residence vs. other city mentions, strict "more than N years", and the refusal gate
that still applies when a question adds a condition the structured match does not check.
"""
import importlib
import sys
import types

import pytest

from final_common import build, isolated, pipeline  # noqa: F401  (isolated: autouse fixture)

EXPERIENCE = ("Designed order-processing services for a logistics client, wrote integration tests, "
              "reviewed pull requests every week and mentored two junior colleagues. ")
CVS = {
    # lives in Jerusalem (labelled), 12 years, Spring Boot in two chunks
    "Ada_Brenner.md": "Ada Brenner\nLocation: Jerusalem\nBackend developer with 12 years of experience.\n\nExperience\n"
                      + "Built payment microservices with Spring Boot and Docker; added FastAPI tools for the data team. "
                      + EXPERIENCE * 6 + "\nLater project: migrated the billing platform to Spring Boot 3.\n"
                      + "Skills: Java, Spring Boot, Docker, FastAPI, PostgreSQL\nEducation: B.Sc. Computer Science\n",
    # lives in Haifa; studied in Jerusalem (not residence); exactly 10 years
    "Ben_Cohenik.md": "Ben Cohenik\nHaifa\nEmbedded and Java engineer with 10 years of experience.\n\nExperience\n"
                      + "Wrote Spring Boot services for a factory dashboard and prototyped sensors on Arduino boards. "
                      + EXPERIENCE * 2 + "\nSkills: Java, Spring Boot, Arduino, C++\n"
                      + "Education: B.Sc. Electrical Engineering, Hebrew University of Jerusalem\n",
    # lives in Tel Aviv; worked at a Jerusalem office (not residence)
    "Chen_Levitan.md": "Chen Levitan\nTel Aviv\nPython developer with 5 years of experience.\n\nExperience\n"
                       + "Built FastAPI services in Docker containers for an insurance portal. " + EXPERIENCE * 2
                       + "\n2019-2021: developer at Orbit Ltd, Jerusalem office.\nSkills: Python, FastAPI, Docker, Redis\n"
                       + "Education: B.Sc. Software Engineering\n",
    "Dana_Orbach.md": "Dana Orbach\nNazareth\nData analyst with 3 years of experience.\n\nExperience\n"
                      + "Built Tableau dashboards for a hospital network and automated reports with n8n workflows. "
                      + EXPERIENCE + "\nSkills: SQL, Tableau, n8n, Excel\nEducation: B.A. Economics\n",
    "Eli_Marom.md": "Eli Marom\nAkko\nIoT maker with 7 years of experience.\n\nExperience\n"
                    + "Built greenhouse controllers with Arduino and Raspberry Pi; wrote the firmware in C++. "
                    + EXPERIENCE + "\nSkills: Arduino, Raspberry Pi, C++, IoT\nEducation: Practical engineering diploma\n",
}


@pytest.fixture
def index(tmp_path):
    return build(tmp_path, CVS)


def sources(hits):
    return [h["source"] for h in hits]


@pytest.mark.parametrize("question", [
    "Who has Spring Boot experience?", "Does anyone here know FastAPI?", "Which people have Tableau experience?",
    "List everyone who has built things with Arduino.", "Which candidates live in Jerusalem?",
    "Who has used n8n for automation?", "Which candidates have more than 10 years of work experience?"])
def test_natural_list_wording_is_a_list_question(question):
    assert pipeline.list_intent(question)


@pytest.mark.parametrize("question", [
    "Who wrote the FastAPI service that tracks equipment loans for a school district?",   # one fact, many conditions
    "What did Ada Brenner build?", "Which university did he graduate from?", "Who is the best engineer?"])
def test_ordinary_questions_are_not_list_questions(question):
    assert not pipeline.list_intent(question)


def test_a_skill_list_returns_every_matching_candidate_once(index):
    _, chunks = index
    assert sum(c["source"] == "Ada_Brenner.md" and "Spring Boot" in c["text"] for c in chunks) >= 2   # several chunks
    hits = pipeline.retrieve("Who has Spring Boot experience?", pipeline.K)
    assert sorted(sources(hits)) == ["Ada_Brenner.md", "Ben_Cohenik.md"]                # unique, evidence-backed
    assert all(h.get("match") == "graph" for h in hits)
    assert not pipeline.should_refuse("Who has Spring Boot experience?", hits)


def test_more_matches_than_k_are_all_returned(index):
    hits = pipeline.retrieve("Who has Docker experience?", pipeline.K)
    assert sorted(sources(hits)) == ["Ada_Brenner.md", "Chen_Levitan.md"]
    hits = pipeline.retrieve("Does anyone know Arduino?", 1)
    assert sorted(sources(hits)) == ["Ben_Cohenik.md", "Eli_Marom.md"]                  # not cut to k


def test_two_skills_mean_the_intersection(index):
    hits = pipeline.retrieve("Who knows Docker and FastAPI?", pipeline.K)
    assert sorted(sources(hits)) == ["Ada_Brenner.md", "Chen_Levitan.md"]
    for q in ("Who knows Tableau and Arduino?",            # both known, nobody has both
              "Which candidates know Docker and live in Eilat?"):   # a city nobody lives in
        hits = pipeline.retrieve(q, pipeline.K)
        assert hits == [] and pipeline.should_refuse(q, hits), q


def test_ordinary_questions_keep_top_k(index):
    hits = pipeline.retrieve("What did Eli Marom build with Raspberry Pi?", pipeline.K)
    assert 0 < len(hits) <= pipeline.K and not any(h.get("match") for h in hits)


def test_residence_is_the_listed_city_not_a_university_or_an_office(index):
    hits = pipeline.retrieve("Which candidates live in Jerusalem?", pipeline.K)
    assert sources(hits) == ["Ada_Brenner.md"]                                            # not Ben (university), not Chen (office)
    assert not pipeline.should_refuse("Which candidates live in Jerusalem?", hits)
    assert sources(pipeline.retrieve("Which candidates live in Haifa?", pipeline.K)) == ["Ben_Cohenik.md"]


@pytest.mark.parametrize("phrase,op", [("more than 10 years", "gt"), ("over 10 years", "gt"), ("at least 10 years", "gte"),
                                       ("10+ years", "gte"), ("10 or more years", "gte"), ("a minimum of 10 years", "gte")])
def test_years_phrases(phrase, op):
    want = pipeline.question_filters(f"Which candidates have {phrase} of experience?")
    assert want["years"] == 10 and want["years_op"] == op


def test_more_than_is_strict_and_at_least_is_not(index):
    gt = pipeline.retrieve("Which candidates have more than 10 years of work experience?", pipeline.K)
    assert sources(gt) == ["Ada_Brenner.md"]                                              # 12 > 10; Ben's 10 is not more than 10
    assert all(h.get("match") == "filter" for h in gt)
    assert not pipeline.should_refuse("Which candidates have more than 10 years of work experience?", gt)
    gte = pipeline.retrieve("Which candidates have at least 10 years of experience?", pipeline.K)
    assert sorted(sources(gte)) == ["Ada_Brenner.md", "Ben_Cohenik.md"]
    assert pipeline.meets({"years": 10.0}, {"years": 10, "years_op": "gte"})
    assert not pipeline.meets({"years": 10.0}, {"years": 10, "years_op": "gt"})


def test_the_refusal_gate_still_applies_to_extra_conditions_and_to_ordinary_hits():
    weak = [{"source": "x.md", "text": "x", "rerank": -11.0, "match": "graph"}]
    assert not pipeline.should_refuse("Which candidates live in Jerusalem?", weak)       # the criteria are the question
    assert pipeline.should_refuse("Which candidates live in Jerusalem and hold a pilot license?", weak)
    assert pipeline.should_refuse("Who has a commercial pilot license?", [{"source": "x.md", "text": "x", "rerank": -11.0}])
    assert pipeline.should_refuse("Which candidates live in Jerusalem?", [])


def test_a_rewrite_that_still_says_he_falls_back_to_the_rule(monkeypatch):
    import helpers
    import ragkit
    monkeypatch.setattr(ragkit, "get_llm", lambda: types.SimpleNamespace(can_reason=True))
    monkeypatch.setattr(helpers, "llm", lambda *a, **k: "Which university did 'he' graduate from?")
    q = pipeline.make_query("Which university did he graduate from?", ["Who built greenhouse controllers?"])
    assert q == "Who built greenhouse controllers? Which university did he graduate from?"
    monkeypatch.setattr(helpers, "llm", lambda *a, **k: "Which university did Eli Marom graduate from?")
    assert pipeline.make_query("Which university did he graduate from?", ["Who built greenhouse controllers?"]) == \
        "Which university did Eli Marom graduate from?"


def test_mcp_search_cvs_returns_the_whole_list_read_only(index):
    sys.modules.pop("mcp_server", None)
    server = importlib.import_module("mcp_server")
    try:
        found = server.search_cvs("Who has Spring Boot experience?")
        assert found["refused"] is False
        assert sorted(p["source"] for p in found["passages"]) == ["Ada_Brenner.md", "Ben_Cohenik.md"]
        assert all(p["claims_verified"] is False for p in found["passages"])
    finally:
        sys.modules.pop("mcp_server", None)
