"""Check real CLI output and exit statuses; requires only Python's standard library."""

import json
import pathlib
import subprocess
import tempfile
import http.server
import os
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT / ".lake/build/bin/casbin"


def run(args, code, env=None):
    result = subprocess.run(
        [str(BINARY), *args], cwd=ROOT, text=True, capture_output=True, check=False, env=env, timeout=30
    )
    assert result.returncode == code, (args, result.returncode, result.stderr)
    return result


demo = run(["demo"], 0)
assert [json.loads(line)["decision"]["allow"] for line in demo.stdout.splitlines()] == [
    True, False, False
]
model, policy = "examples/basic_model.conf", "examples/basic_policy.csv"
assert json.loads(run(["enforce", model, policy, "alice", "data1", "read"], 0).stdout) == {
    "allow": True, "explain": ["alice", "data1", "read"]
}
assert json.loads(run(["enforce", model, policy, "alice", "data1", "write"], 1).stdout) == {
    "allow": False, "explain": []
}
assert "expected 3 fields" in run(["enforce", model, policy, "alice"], 2).stderr
assert "error:" in run(["enforce", "missing.conf", policy, "alice"], 2).stderr
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory) / "requests.json"
    path.write_text(json.dumps([["alice", "data1", "read"], ["alice", "data1", "write"]]))
    assert [d["allow"] for d in json.loads(run(["batch", model, policy, str(path)], 0).stdout)] == [
        True, False
    ]
    path.write_text('[123]')
    assert "error:" in run(["batch", model, policy, str(path)], 2).stderr
    path.write_text(json.dumps(["alice", "data1", "read"]))
    assert json.loads(run(["enforce-json", model, policy, str(path)], 0).stdout)["allow"]
    database = str(pathlib.Path(directory) / "policy.sqlite")
    run(["save-db", model, policy, database], 0)
    assert json.loads(run(["enforce-db", model, database, str(path)], 0).stdout)["allow"]
    assert json.loads(run(["validate", model, policy], 0).stdout)["valid"]
    exported = json.loads(run(["export-js", model, policy, "alice"], 0).stdout)
    assert exported["p"][0] == ["p", "alice", "data1", "read"]
    abac = pathlib.Path(directory) / "abac.conf"
    abac.write_text("[request_definition]\nr = sub, obj, act\n[policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\nm = r.sub.Age >= 18 && r.obj.Owner == r.sub.Name\n")
    empty = pathlib.Path(directory) / "empty.csv"
    empty.write_text("")
    path.write_text(json.dumps([{"Name": "alice", "Age": 21}, {"Owner": "alice"}, "read"]))
    assert json.loads(run(["enforce-json", str(abac), str(empty), str(path)], 0).stdout)["allow"]
    path.write_text(json.dumps([{"Name": "alice", "Age": 17}, {"Owner": "alice"}, "read"]))
    assert not json.loads(run(["enforce-json", str(abac), str(empty), str(path)], 1).stdout)["allow"]

    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append((body, self.headers.get("Authorization")))
            self.send_response(500 if self.path == "/error" else 200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"choices": [{"message": {"content": "Alice is allowed."}}]}).encode())

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        path.write_text(json.dumps(["alice", "data1", "read"]))
        endpoint = f"http://127.0.0.1:{server.server_port}"
        env = {**os.environ, "CASBIN_AI_KEY": "local-test-key"}
        response = run(["explain", model, policy, str(path), endpoint, "local-mock"], 0, env)
        assert json.loads(response.stdout)["explanation"] == "Alice is allowed."
        assert received[0][0]["model"] == "local-mock"
        assert received[0][1] == "Bearer local-test-key"
        context = json.loads(received[0][0]["messages"][1]["content"])
        assert context["allow"] is True and context["request"] == ["alice", "data1", "read"]
        run(["explain", model, policy, str(path), endpoint + "/error", "local-mock"], 2, env)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
print("PASS CLI allow/deny, typed ABAC, batch, validation, frontend, SQLite, and loopback AI transport")
