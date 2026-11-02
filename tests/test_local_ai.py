"""Local HTTP fixtures exercise the adapter without downloading or running a model."""
import copy
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


SHA256 = "a" * 64
DIGEST = "b" * 64
EVIDENCE = {
    "functions": [{"name": "entry", "address": "00401000",
                   "decompiled": "void entry() { WriteProcessMemory(target, buffer, size); }"}],
    "strings": ["example.test"], "imports": ["WriteProcessMemory"],
    "metadata": {"function_count": 1},
}


def finding(evidence_id="F1", quote="WriteProcessMemory(target, buffer, size)"):
    return {"title": "Process memory write", "severity": "medium",
            "detail": "The selected function writes to a process. Review its arguments and purpose.",
            "evidence": [{"evidence_id": evidence_id, "quote": quote}]}


@pytest.fixture
def ollama():
    state = {"requests": [], "report": {"verdict": "suspicious", "findings": [finding()]},
             "tags": {"models": [{"name": "qwen3:4b", "model": "qwen3:4b", "digest": DIGEST,
                                    "size": 2500000000, "details": {"format": "gguf"}}]},
             "show": {"details": {"format": "gguf"}, "model_info": {"general.architecture": "qwen3"},
                      "capabilities": ["completion"]}, "status": 200, "delay": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.respond(None)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.respond(body)

        def respond(self, body):
            state["requests"].append((self.path, body))
            if self.path == "/api/tags":
                result = state["tags"]
            elif self.path == "/api/show":
                result = state["show"]
            elif self.path == "/api/chat":
                time.sleep(state["delay"])
                result = state.get("response", {"model": "qwen3:4b", "done": True, "done_reason": "stop",
                    "message": {"role": "assistant", "content": json.dumps(state["report"])}})
            else:
                result = {"error": "Unexpected path"}
            data = state.get("raw", json.dumps(result).encode())
            self.send_response(state["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Location", state["url"] + "/must-not-follow")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state["url"] = "http://127.0.0.1:" + str(server.server_port)
    state["config"] = {"LOCAL_AI_URL": state["url"], "LOCAL_AI_TIMEOUT": 2}
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    yield state
    server.shutdown()
    server.server_close()
    worker.join(timeout=2)


def test_actual_local_http_inference_validates_evidence_and_provenance(ollama, monkeypatch):
    from sentinel.local_ai import analyze_decompilation
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    stages = []
    result = analyze_decompilation(EVIDENCE, SHA256, ollama["config"], on_progress=lambda *args: stages.append(args))
    assert result["verdict"] == "suspicious"
    assert result["sha256"] == SHA256
    assert result["ai_model_ran"] is True
    assert result["processing_location"] == "local"
    assert result["model"] == "qwen3:4b" and result["model_digest"] == DIGEST
    evidence = result["findings"][0]["evidence"][0]
    assert evidence["evidence_id"] == "F1" and evidence["address"] == "00401000"
    assert evidence["quote"] == "WriteProcessMemory(target, buffer, size)"
    assert result["findings"][0]["status"] == "review_required"
    assert ("analysing", 65) in stages and ("validating", 90) in stages
    request = next(body for path, body in ollama["requests"] if path == "/api/chat")
    assert request["think"] is False and request["stream"] is False
    assert request.get("tools", []) == []
    assert request["format"]["type"] == "object"
    assert request["options"]["num_predict"] <= 1536
    assert request["options"]["num_ctx"] <= 8192
    assert request["truncate"] is False
    assert request["messages"][0]["role"] == "system"
    assert "untrusted" in request["messages"][0]["content"].lower()


@pytest.mark.parametrize("url", ["https://127.0.0.1:11434", "http://localhost:11434", "http://0.0.0.0:11434",
    "http://example.test", "http://127.0.0.1.evil.test", "http://user:secret@127.0.0.1", "http://127.0.0.1/api",
    "http://127.0.0.1?host=evil", "http://127.0.0.1#fragment", "http://[::1%25eth0]:11434", "http://2130706433",
    "http://127.0.0.1:0", "http://127.0.0.1\n.evil.test"])
def test_rejects_nonliteral_or_ambiguous_local_endpoints(url):
    from sentinel.local_ai import analyze_decompilation, model_status, LocalAIError
    with pytest.raises(LocalAIError, match="loopback"):
        analyze_decompilation(EVIDENCE, SHA256, {"LOCAL_AI_URL": url})
    assert model_status({"LOCAL_AI_URL": url})["available"] is False


def test_status_checks_installed_local_model_without_inference(ollama):
    from sentinel.local_ai import model_status
    result = model_status(ollama["config"])
    assert result["available"] is True and result["model"] == "qwen3:4b"
    assert all(path != "/api/chat" for path, _ in ollama["requests"])
    ollama["tags"] = {"models": []}
    assert model_status(ollama["config"])["available"] is False


@pytest.mark.parametrize("where", ["tag", "show", "model"])
def test_cloud_aliases_rejected_before_any_evidence_is_sent(ollama, where):
    from sentinel.local_ai import analyze_decompilation, LocalAIError
    if where == "model":
        ollama["config"]["LOCAL_AI_MODEL"] = "qwen3:cloud"
    elif where == "tag":
        ollama["tags"]["models"][0]["remote_host"] = "https://ollama.com"
    else:
        ollama["show"]["remote_model"] = "qwen3:4b"
    with pytest.raises(LocalAIError, match="local|cloud"):
        analyze_decompilation(EVIDENCE, SHA256, ollama["config"])
    assert all(path != "/api/chat" for path, _ in ollama["requests"])


@pytest.mark.parametrize("bad", [finding("F99"), finding(quote="WriteProcessMemory(victim, payload, 999)"),
    finding(quote=""), finding(quote=" "), {**finding(), "severity": "guaranteed"},
    {**finding(), "confidence": 0.99}, {**finding(), "detail": "The file is completely safe and 100% benign."}])
def test_invalid_or_overconfident_findings_cannot_be_confirmed(ollama, bad):
    from sentinel.local_ai import analyze_decompilation
    ollama["report"]["findings"] = [bad]
    result = analyze_decompilation(EVIDENCE, SHA256, ollama["config"])
    assert result["verdict"] == "inconclusive"
    assert result["findings"] == []
    assert result["validation"]["rejected_findings"] == 1


def test_keeps_only_literal_citations_and_never_repeats_model_safety_summary(ollama):
    from sentinel.local_ai import analyze_decompilation
    ollama["report"].update(summary="This file is safe. 100% confidence.", findings=[finding(), finding("F99")])
    result = analyze_decompilation(EVIDENCE, SHA256, ollama["config"])
    assert len(result["findings"]) == 1
    assert "100%" not in result["summary"] and "file is safe" not in result["summary"]
    assert result["validation"]["rejected_findings"] == 1


@pytest.mark.parametrize("verdict", ["safe", "malicious", "no_indicators", "inconclusive"])
def test_no_model_safety_verdict_can_hide_existing_suspicious_findings(ollama, verdict):
    from sentinel.local_ai import analyze_decompilation
    ollama["report"]["verdict"] = verdict
    result = analyze_decompilation(EVIDENCE, SHA256, ollama["config"])
    assert result["verdict"] in {"suspicious", "inconclusive"}


def test_small_evidence_no_indicators_still_has_explicit_static_limitations(ollama):
    from sentinel.local_ai import analyze_decompilation
    ollama["report"] = {"verdict": "no_indicators", "findings": []}
    result = analyze_decompilation(EVIDENCE, SHA256, ollama["config"])
    assert result["verdict"] == "no_indicators"
    assert result["coverage"]["scope"] == "selected_static_evidence"
    assert result["coverage"]["full_binary_review"] is False
    assert "selected evidence" in result["summary"].lower()
    assert any("does not" in item.lower() and "safe" in item.lower() for item in result["limitations"])


def test_context_is_bounded_and_coverage_counts_omissions_and_unavailable_bodies(ollama):
    from sentinel.local_ai import analyze_decompilation
    evidence = copy.deepcopy(EVIDENCE)
    evidence["functions"] += [{"name": "f" + str(i), "address": str(i), "decompiled": "x" * 10000} for i in range(40)]
    evidence["functions"] += [{"name": "stub", "decompiled": None, "body_skipped": True}]
    evidence["strings"] = ["z" * 5000] * 100
    evidence["metadata"]["decompile_time_skipped_count"] = 1
    result = analyze_decompilation(evidence, SHA256, ollama["config"])
    coverage = result["coverage"]
    assert coverage["partial"] is True
    assert coverage["functions_total"] == 42 and coverage["functions_unavailable"] == 1
    assert 0 < coverage["functions_selected"] < 42
    assert coverage["functions_omitted"] == 42 - coverage["functions_selected"]
    assert coverage["decompile_time_skipped_count"] == 1
    assert coverage["truncated_items"] > 0
    body = next(body for path, body in ollama["requests"] if path == "/api/chat")
    assert len(body["messages"][1]["content"].encode()) <= 16000
    assert all(len(e["text"].encode()) <= 3000 for e in result["evidence"])


def test_cannot_cite_text_removed_by_context_truncation(ollama):
    from sentinel.local_ai import analyze_decompilation
    evidence = copy.deepcopy(EVIDENCE)
    evidence["functions"][0]["decompiled"] = "x" * 10000 + "PAYLOAD_ONLY_IN_OMITTED_SUFFIX"
    ollama["report"]["findings"] = [finding(quote="PAYLOAD_ONLY_IN_OMITTED_SUFFIX")]
    result = analyze_decompilation(evidence, SHA256, ollama["config"])
    assert result["findings"] == [] and result["verdict"] == "inconclusive"


@pytest.mark.parametrize("mutation", ["missing_done", "truncated", "tools", "invalid_json", "not_object", "cloud"])
def test_incomplete_or_invalid_model_responses_are_errors(ollama, mutation):
    from sentinel.local_ai import analyze_decompilation, LocalAIError
    response = {"model": "qwen3:4b", "done": True, "done_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(ollama["report"])}}
    if mutation == "missing_done":
        response.pop("done")
    elif mutation == "truncated":
        response["done_reason"] = "length"
    elif mutation == "tools":
        response["message"]["tool_calls"] = [{"function": {"name": "shell", "arguments": {}}}]
    elif mutation == "invalid_json":
        response["message"]["content"] = "```json\n{}\n```"
    elif mutation == "not_object":
        response["message"]["content"] = "[]"
    else:
        response["remote_host"] = "https://ollama.com"
    ollama["response"] = response
    with pytest.raises(LocalAIError):
        analyze_decompilation(EVIDENCE, SHA256, ollama["config"])


@pytest.mark.parametrize("status", [302, 307, 401, 500])
def test_does_not_follow_redirects_or_echo_upstream_error_secrets(ollama, status):
    from sentinel.local_ai import analyze_decompilation, LocalAIError
    ollama["status"] = status
    ollama["raw"] = b'{"error":"PRIVATE-UPSTREAM-SECRET"}'
    with pytest.raises(LocalAIError) as error:
        analyze_decompilation(EVIDENCE, SHA256, ollama["config"])
    assert "PRIVATE-UPSTREAM-SECRET" not in str(error.value)
    assert [path for path, _ in ollama["requests"]] == ["/api/tags"]


def test_response_size_limit_stops_unbounded_server_body(ollama):
    from sentinel.local_ai import analyze_decompilation, LocalAIError
    ollama["raw"] = b"x" * (1024 * 1024)
    with pytest.raises(LocalAIError, match="limit"):
        analyze_decompilation(EVIDENCE, SHA256, ollama["config"])


def test_cancelled_job_never_sends_evidence(ollama):
    from sentinel.local_ai import analyze_decompilation, LocalAICancelled
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(LocalAICancelled):
        analyze_decompilation(EVIDENCE, SHA256, ollama["config"], cancel_event=cancelled)
    assert ollama["requests"] == []


def test_timeout_is_bounded_and_does_not_become_no_indicators(ollama):
    from sentinel.local_ai import analyze_decompilation, LocalAIError
    ollama["delay"] = 0.4
    ollama["config"]["LOCAL_AI_TIMEOUT"] = 0.1
    start = time.monotonic()
    with pytest.raises(LocalAIError, match="time|unavailable"):
        analyze_decompilation(EVIDENCE, SHA256, ollama["config"])
    assert time.monotonic() - start < 1


@pytest.mark.parametrize("evidence, sha", [({}, SHA256), ({"functions": []}, SHA256), (EVIDENCE, "wrong"),
    ({**EVIDENCE, "sentinel_provenance": {"sha256": "c" * 64}}, SHA256)])
def test_rejects_missing_evidence_or_incorrect_sample_binding_before_inference(ollama, evidence, sha):
    from sentinel.local_ai import analyze_decompilation, LocalAIError
    with pytest.raises(LocalAIError):
        analyze_decompilation(evidence, sha, ollama["config"])
    assert all(path != "/api/chat" for path, _ in ollama["requests"])
