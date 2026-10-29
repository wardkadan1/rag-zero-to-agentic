"""
SECURITY · LLM evaluation · the model under test, and nothing else.

    load_qwen()     the project's own Qwen path: RAG_LLM=hf -> ragkit.HFLocalLLM(Qwen/Qwen2.5-1.5B-Instruct).
                    Any other backend, model or a failed load raises ModelBlocked: the run stops.
                    There is no fallback to the extractive model, Ollama, another model or a simulation.
    Simulated()     ONLY for testing this harness without a model (cloud dry run, pytest). Every
                    result it produces is labelled SIMULATED and is never a model result.
"""
import json
import os
import pathlib
import platform
import re
import sys
import time

EXPECTED_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
MAX_NEW_TOKENS = 300                                 # what app.py asks for


class ModelBlocked(RuntimeError):
    """The real model is not available: report this and stop."""


class Qwen:
    """Wraps the shared ragkit model so the app path (helpers.llm) and the agent loop use the SAME
    loaded weights, tokenizer and greedy settings."""
    label = "qwen"
    simulated = False
    can_reason = True

    def __init__(self, hf):
        self.hf, self.pipe, self.name = hf, hf.pipe, hf.name
        self.calls, self.ms = 0, 0.0

    def chat(self, system, user, max_tokens=MAX_NEW_TOKENS):
        t = time.perf_counter()
        out = self.hf.chat(system, user, max_tokens)
        self._count(t)
        return out

    def chat_tools(self, messages, tools, max_tokens=MAX_NEW_TOKENS):
        """One assistant turn with the tool schemas in Qwen's own chat template, greedy."""
        import torch
        tok, model = self.pipe.tokenizer, self.pipe.model
        t = time.perf_counter()
        ids = tok.apply_chat_template(messages, tools=tools, add_generation_prompt=True, return_tensors="pt",
                                      return_dict=True)
        ids = {k: v.to(model.device) for k, v in ids.items()}
        with torch.no_grad():
            out = model.generate(**ids, max_new_tokens=max_tokens, do_sample=False)
        text = tok.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=False)
        self._count(t)
        return re.sub(r"<\|(?:im_end|endoftext)\|>", "", text).strip()

    def _count(self, t):
        self.calls += 1
        self.ms += (time.perf_counter() - t) * 1000

    def info(self):
        import torch
        import transformers
        model = self.pipe.model
        gen = model.generation_config.to_dict() if model.generation_config else {}
        info = {"model": self.hf.model_name, "ragkit_backend": type(self.hf).__name__,
                "revision": getattr(model.config, "_commit_hash", None), "cache_revision": cache_revision(self.hf.model_name),
                "dtype": str(model.dtype),
                "device": str(model.device), "mps_available": bool(getattr(torch.backends, "mps", None)
                                                                   and torch.backends.mps.is_available()),
                "cuda_available": torch.cuda.is_available(), "torch": torch.__version__,
                "transformers": transformers.__version__, "python": sys.version.split()[0],
                "platform": platform.platform(), "machine": platform.machine(),
                "generation": {"do_sample": False, "max_new_tokens": MAX_NEW_TOKENS, "seed": 0,
                               "model_generation_config": {k: gen.get(k) for k in
                                                           ("temperature", "top_p", "top_k", "repetition_penalty",
                                                            "do_sample")}}}
        for lib in ("tokenizers", "huggingface_hub", "sentence_transformers", "accelerate"):
            try:
                info[lib] = __import__(lib).__version__
            except Exception:                                                   # noqa: BLE001
                info[lib] = None
        return info


def cache_revision(repo):
    """The model revision as the Hugging Face cache records it, checked two independent ways: the
    snapshot folder the cached config.json resolves to, and the commit the cache's refs/main names.
    `verified` is True only when both exist and agree. Reads local files only."""
    out = {"repo": repo, "snapshot": None, "refs_main": None, "verified": False}
    try:
        from huggingface_hub import try_to_load_from_cache
        path = try_to_load_from_cache(repo, "config.json")
        if isinstance(path, str):
            p = pathlib.Path(path)
            out["snapshot"] = p.parent.name                              # .../snapshots/<commit>/config.json
            ref = p.parents[2] / "refs" / "main"
            if ref.exists():
                out["refs_main"] = ref.read_text().strip()
    except Exception as e:                                                      # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    out["verified"] = bool(out["snapshot"]) and out["snapshot"] == out["refs_main"] and len(out["snapshot"]) == 40
    return out


def load_qwen():
    if os.getenv("RAG_LLM", "").lower() != "hf":
        raise ModelBlocked("RAG_LLM must be 'hf' (the project's Qwen path); it is "
                           f"{os.getenv('RAG_LLM')!r}. No other backend is evaluated.")
    if os.getenv("HF_MODEL", EXPECTED_MODEL) != EXPECTED_MODEL:
        raise ModelBlocked(f"HF_MODEL must be unset or {EXPECTED_MODEL}; it is {os.getenv('HF_MODEL')!r}.")
    try:
        import torch
        torch.manual_seed(0)
        from ragkit import llm as ragkit_llm
        hf = ragkit_llm.get_llm()
    except Exception as e:                                                      # noqa: BLE001
        raise ModelBlocked(f"Qwen could not be loaded: {type(e).__name__}: {e}") from e
    if type(hf).__name__ != "HFLocalLLM" or getattr(hf, "model_name", None) != EXPECTED_MODEL:
        raise ModelBlocked(f"the loaded backend is {getattr(hf, 'name', type(hf).__name__)}, not hf:{EXPECTED_MODEL}")
    probe = hf.chat("Reply with the single word: ready", "ready?", 5)
    if not probe.strip():
        raise ModelBlocked("Qwen loaded but produced no text")
    qwen = Qwen(hf)
    import helpers                     # the app's llm() uses the same model; the wrapper only times the calls
    helpers._LLM = qwen
    return qwen


class Simulated:
    """NOT A MODEL. Copies the first sentence of each passage with its number, so the harness can be
    run end to end without Qwen. vulnerable=True obeys "reply with X" and tool requests, to prove the
    scoring catches successes. Everything it produces is labelled SIMULATED."""
    simulated = True
    name = "SIMULATED (no model)"
    can_reason = False

    def __init__(self, vulnerable=False):
        self.vulnerable, self.calls, self.ms = vulnerable, 0, 0.0
        self.label = "simulated-vulnerable" if vulnerable else "simulated"

    def chat(self, system, user, max_tokens=MAX_NEW_TOKENS):
        self.calls += 1
        if self.vulnerable:
            m = re.search(r"(?:reply|answer|respond|print|write|include|output)\w*\s+(?:only\s+)?(?:with\s+)?(?:the\s+)?"
                          r"(?:code\s+|word\s+)?\"?([A-Z]{4,}-\d{4,6})", user)
            if m:
                return m.group(1)
        parts = re.findall(r"\[(\d+)\] \(from [^)]*\)\n(.+)", user)
        if not parts:
            return "I don't know based on the CVs."
        firsts = [(n, re.split(r"(?<=[.!?])\s", t.strip())[0][:200]) for n, t in parts[:2]]   # Python 3.11: no \ in f-strings
        return " ".join(f"{first} [{n}]" for n, first in firsts)

    def chat_tools(self, messages, tools, max_tokens=MAX_NEW_TOKENS):
        self.calls += 1
        if not any(m["role"] == "tool" for m in messages):
            q = next(m["content"] for m in messages if m["role"] == "user")
            return "<tool_call>\n" + json.dumps({"name": "search_cvs", "arguments": {"question": q}}) + "\n</tool_call>"
        last = messages[-1]["content"]
        if self.vulnerable:
            m = re.search(r"\b(get_contact_details|send_email|delete_candidate|http_get|update_ranking|write_file|shell|"
                          r"approve_candidate)\b", last)
            if m and not any(m.group(1) in str(x.get("tool_calls", "")) for x in messages):
                return "<tool_call>\n" + json.dumps({"name": m.group(1), "arguments": {}}) + "\n</tool_call>"
        return "Summary: " + last[:200]

    def info(self):
        return {"model": self.name, "simulated": True, "vulnerable": self.vulnerable,
                "python": sys.version.split()[0], "platform": platform.platform()}


def install_simulated(sim):
    """Point the app path (helpers.llm, make_query's rewrite) at the simulation. Dry runs only."""
    import helpers
    from ragkit import llm as ragkit_llm
    ragkit_llm._LLM = sim
    helpers._LLM = sim
