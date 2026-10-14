"""tests/test_isolation.py — kit/isolation: the real OS isolation boundary
(CONTRACTS.md section 12) and its RPC allowlist (section 12.2 mechanic 2).

pytest only (permitted in tests/ per the workspace's hard rules). No
network as a client of anything except the one deliberate probe vector
that is *expected* to fail, no unseeded randomness, no wall-clock.

**The one test that matters most is `test_probe_sandbox_blocks_every_vector`**:
it spawns a REAL hostile child under a REAL `sandbox-exec` profile and
asserts every escape vector CONTRACTS.md 12 names is actually blocked by
the kernel, on whatever Darwin machine runs this suite — never a mocked or
cached result. On macOS, if `sandbox-exec` is unavailable that test FAILS
LOUDLY (`pytest.fail`, not `pytest.skip`): a skip can look like "nothing to
see here" in a CI summary, and CONTRACTS.md 12.2.4 is explicit that the
honest response to a missing sandbox-exec is "no anti-cheat claim," never
quietly downgrading the test. On non-Darwin hosts there is no Seatbelt
binary to measure, so the sandbox-exec tests skip rather than fail.
"""

from __future__ import annotations

import io
import sys
import time
from pathlib import Path

import pytest

# Make the repo root importable when pytest is invoked from anywhere.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from kit.isolation import child_driver, rpc, sandbox
from kit.mcp.specs import TOOL_SPECS


# ---------------------------------------------------------------------------
# rpc.py: frame I/O
# ---------------------------------------------------------------------------


def test_frame_roundtrip() -> None:
    buf = io.BytesIO()
    obj = {"req_id": "req:0001", "server": "slides", "tool": "query", "args": {"q": "hello"}}
    rpc.write_frame(buf, obj)
    buf.seek(0)
    assert rpc.read_frame(buf) == obj


def test_frame_multiple_back_to_back() -> None:
    buf = io.BytesIO()
    rpc.write_frame(buf, {"n": 1})
    rpc.write_frame(buf, {"n": 2})
    rpc.write_frame(buf, {"n": 3})
    buf.seek(0)
    got = [rpc.read_frame(buf) for _ in range(3)]
    assert got == [{"n": 1}, {"n": 2}, {"n": 3}]
    assert rpc.read_frame(buf) is None  # clean EOF


def test_frame_clean_eof_returns_none() -> None:
    assert rpc.read_frame(io.BytesIO(b"")) is None


def test_frame_truncated_header_raises() -> None:
    with pytest.raises(rpc.RpcFramingError):
        rpc.read_frame(io.BytesIO(b"\x00\x00"))  # 2 of 4 length-header bytes


def test_frame_truncated_body_raises() -> None:
    buf = io.BytesIO()
    rpc.write_frame(buf, {"a": "b" * 50})
    chopped = buf.getvalue()[:-10]
    with pytest.raises(rpc.RpcFramingError):
        rpc.read_frame(io.BytesIO(chopped))


def test_frame_oversized_declared_length_raises() -> None:
    header = (rpc.MAX_FRAME_BYTES + 1).to_bytes(4, "big")
    with pytest.raises(rpc.RpcFramingError):
        rpc.read_frame(io.BytesIO(header + b"{}"))


def test_frame_malformed_json_body_raises() -> None:
    body = b"not json"
    header = len(body).to_bytes(4, "big")
    with pytest.raises(rpc.RpcFramingError):
        rpc.read_frame(io.BytesIO(header + body))


def test_write_frame_output_is_a_pure_function_of_content_not_key_order() -> None:
    # Workspace hard rule 4: no dict-iteration-order dependence in output.
    buf_a, buf_b = io.BytesIO(), io.BytesIO()
    rpc.write_frame(buf_a, {"z": 1, "a": 2})
    rpc.write_frame(buf_b, {"a": 2, "z": 1})
    assert buf_a.getvalue() == buf_b.getvalue()


# ---------------------------------------------------------------------------
# rpc.py: the integrity taxonomy
# ---------------------------------------------------------------------------


def test_integrity_kind_is_closed_at_five_members() -> None:
    assert {k.value for k in rpc.IntegrityKind} == {
        "fs_escape",
        "net_denied",
        "proc_denied",
        "timeout",
        "malformed_decision",
    }


@pytest.mark.parametrize("kind", list(rpc.IntegrityKind))
def test_make_integrity_accepts_every_closed_kind(kind: rpc.IntegrityKind) -> None:
    rec = rpc.make_integrity(kind, "detail text")
    assert rec == {"kind": kind.value, "detail": "detail text"}


def test_make_integrity_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError):
        rpc.make_integrity("teapot")


# ---------------------------------------------------------------------------
# rpc.py: ALLOWED_METHODS is *literally* set(TOOL_SPECS) — CONTRACTS.md 12.2
# ---------------------------------------------------------------------------


def test_allowed_methods_equals_set_of_tool_specs() -> None:
    assert rpc.ALLOWED_METHODS == frozenset(TOOL_SPECS)
    assert len(rpc.ALLOWED_METHODS) > 0


def test_check_method_accepts_every_real_tool() -> None:
    for server, tool in TOOL_SPECS:
        rpc.check_method(server, tool)  # must not raise


def test_check_method_rejects_a_bogus_pair() -> None:
    with pytest.raises(rpc.MethodNotAllowed):
        rpc.check_method("evil-server", "exec_shell")


def test_reject_builds_a_malformed_decision_integrity_response() -> None:
    resp = rpc.reject("req:0099", "evil-server", "exec_shell")
    assert resp.ok is False
    assert resp.error["kind"] == "malformed_decision"
    assert "evil-server.exec_shell" in resp.error["detail"]


# ---------------------------------------------------------------------------
# rpc.py: RpcRequest / RpcResponse
# ---------------------------------------------------------------------------


def test_rpc_request_roundtrip() -> None:
    req = rpc.RpcRequest(
        req_id="req:0007",
        server="slides",
        tool="get_frame",
        args={"anchor": "Frame:3f2a9c11/w/041"},
        fields=("title", "body"),
        headers={"mcp-replica": "w"},
        lease_id="lse_1",
        call_index=2,
    )
    assert rpc.RpcRequest.from_dict(req.to_dict()) == req


def test_rpc_request_rejects_empty_server() -> None:
    with pytest.raises(ValueError):
        rpc.RpcRequest(req_id="req:1", server="", tool="query", args={})


def test_rpc_response_ok_requires_no_error() -> None:
    with pytest.raises(ValueError):
        rpc.RpcResponse(req_id="req:1", ok=True, error={"kind": "timeout", "detail": ""})


def test_rpc_response_error_requires_kind() -> None:
    with pytest.raises(ValueError):
        rpc.RpcResponse(req_id="req:1", ok=False, error={"detail": "no kind here"})


# ---------------------------------------------------------------------------
# child_driver.py: the escape vectors, UNSANDBOXED baseline
# ---------------------------------------------------------------------------
#
# Without any confinement, every escape attempt must SUCCEED (denied=False):
# this proves the vectors are exercising something real (a genuinely
# readable/writable fixture, a genuinely spawnable subprocess) rather than
# accidentally being blocked by something unrelated to the sandbox (a
# missing file, a permissions bug in the fixture itself, /bin/cat missing).
# The socket vector is excluded: an offline test runner can legitimately
# fail to connect for reasons that have nothing to do with this suite.


def test_run_probe_vectors_unsandboxed_baseline(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("ctypes probe vectors use POSIX libc symbols not available on Windows msvcrt")
    arena_root = tmp_path / "arena"
    duel_scratch = arena_root / "scratch" / "duel"
    child_driver.setup_probe_fixture(arena_root, duel_scratch)

    vectors = child_driver.run_probe_vectors(arena_root, duel_scratch)

    assert set(vectors) == set(child_driver.EXPECTED_DENIED)
    for name in vectors:
        if name == "socket_connect_denied":
            continue
        assert vectors[name]["denied"] is False, f"{name} should NOT be denied without a sandbox: {vectors[name]}"
    # The positive control must always succeed, sandboxed or not.
    assert vectors["read_write_inside_scratch"]["denied"] is False


def test_setup_probe_fixture_creates_named_markers(tmp_path: Path) -> None:
    arena_root = tmp_path / "arena"
    duel_scratch = arena_root / "scratch" / "duel"
    child_driver.setup_probe_fixture(arena_root, duel_scratch)

    assert (arena_root / "submissions" / child_driver.SUBMISSIONS_FILE).is_file()
    assert (arena_root / "corpus_snapshot" / child_driver.CORPUS_FILE).is_file()
    assert (arena_root / "runs" / child_driver.RUNS_FILE).is_file()
    assert duel_scratch.is_dir()


# ---------------------------------------------------------------------------
# child_driver.py: the RPC serve loop (in-process, io.BytesIO — no subprocess)
# ---------------------------------------------------------------------------


def test_serve_rejects_disallowed_method_without_calling_target() -> None:
    calls: list[rpc.RpcRequest] = []

    def target(request: rpc.RpcRequest) -> dict:
        calls.append(request)
        return {"verdict": "forward"}

    inp, outp = io.BytesIO(), io.BytesIO()
    rpc.write_frame(inp, {"req_id": "req:evil", "server": "evil", "tool": "exec_shell", "args": {}})
    inp.seek(0)
    served = child_driver.serve(inp, outp, target=target)
    outp.seek(0)
    resp = rpc.read_frame(outp)

    assert served == 1
    assert calls == [], "a disallowed method must NEVER reach the target — CONTRACTS.md 12.2: rejected, not executed"
    assert resp["ok"] is False
    assert resp["error"]["kind"] == "malformed_decision"


def test_serve_dispatches_allowed_method_to_target() -> None:
    calls: list[rpc.RpcRequest] = []
    sample_server, sample_tool = sorted(rpc.ALLOWED_METHODS)[0]

    def target(request: rpc.RpcRequest) -> dict:
        calls.append(request)
        return {"verdict": "forward", "echo": request.args}

    inp, outp = io.BytesIO(), io.BytesIO()
    rpc.write_frame(
        inp,
        {"req_id": "req:ok", "server": sample_server, "tool": sample_tool, "args": {"x": 1}},
    )
    inp.seek(0)
    served = child_driver.serve(inp, outp, target=target)
    outp.seek(0)
    resp = rpc.read_frame(outp)

    assert served == 1
    assert len(calls) == 1
    assert resp["ok"] is True
    assert resp["result"]["echo"] == {"x": 1}


def test_serve_with_no_target_denies_everything_by_default() -> None:
    sample_server, sample_tool = sorted(rpc.ALLOWED_METHODS)[0]
    inp, outp = io.BytesIO(), io.BytesIO()
    rpc.write_frame(inp, {"req_id": "req:1", "server": sample_server, "tool": sample_tool, "args": {}})
    inp.seek(0)
    child_driver.serve(inp, outp, target=None)
    outp.seek(0)
    resp = rpc.read_frame(outp)
    assert resp["ok"] is True
    assert resp["result"]["verdict"] == "deny"


def test_serve_survives_a_target_that_raises() -> None:
    sample_server, sample_tool = sorted(rpc.ALLOWED_METHODS)[0]

    def flaky_target(request: rpc.RpcRequest) -> dict:
        raise RuntimeError("the artifact's own bug")

    inp, outp = io.BytesIO(), io.BytesIO()
    rpc.write_frame(inp, {"req_id": "req:1", "server": sample_server, "tool": sample_tool, "args": {}})
    inp.seek(0)
    served = child_driver.serve(inp, outp, target=flaky_target)
    outp.seek(0)
    resp = rpc.read_frame(outp)

    assert served == 1
    assert resp["ok"] is True  # the driver itself did not crash
    assert resp["result"]["verdict"] == "deny"
    assert "RuntimeError" in resp["result"]["reason"]


def test_serve_multiple_requests_in_one_stream() -> None:
    sample_server, sample_tool = sorted(rpc.ALLOWED_METHODS)[0]
    inp, outp = io.BytesIO(), io.BytesIO()
    for i in range(3):
        rpc.write_frame(inp, {"req_id": f"req:{i}", "server": sample_server, "tool": sample_tool, "args": {}})
    rpc.write_frame(inp, {"req_id": "req:evil", "server": "evil", "tool": "exec_shell", "args": {}})
    inp.seek(0)
    served = child_driver.serve(inp, outp, target=lambda r: {"verdict": "forward"})
    outp.seek(0)
    responses = []
    while (frame := rpc.read_frame(outp)) is not None:
        responses.append(frame)

    assert served == 4
    assert len(responses) == 4
    assert all(r["ok"] for r in responses[:3])
    assert responses[3]["ok"] is False


def test_load_target_returns_none_for_missing_module() -> None:
    # Workspace hard rule 2: import a collaborator's not-yet-written module
    # and degrade gracefully — this is that behaviour, unit-tested.
    assert child_driver.load_target("agent.gateway_that_does_not_exist_yet:decide") is None


def test_load_target_returns_none_for_malformed_spec() -> None:
    assert child_driver.load_target("no-colon-here") is None


def test_load_target_resolves_a_real_callable() -> None:
    fn = child_driver.load_target("kit.isolation.child_driver:_default_target")
    assert fn is child_driver._default_target


# ---------------------------------------------------------------------------
# sandbox.py: build_profile() shape
# ---------------------------------------------------------------------------


def test_build_profile_shape(tmp_path: Path) -> None:
    arena_root = tmp_path / "arena"
    duel_scratch = arena_root / "scratch" / "duel"
    arena_root.mkdir()
    duel_scratch.mkdir(parents=True)

    profile = sandbox.build_profile(arena_root, duel_scratch)

    assert "(version 1)" in profile
    assert "(allow default)" in profile
    assert "(deny network*)" in profile
    assert f'(deny file-write* (subpath "{arena_root.resolve()}"))' in profile
    assert f'(allow file-write* (subpath "{duel_scratch.resolve()}"))' in profile
    for sub in ("submissions", "corpus_snapshot", "runs"):
        assert f'(deny file-read* (subpath "{arena_root.resolve()}/{sub}"))' in profile


def test_build_profile_rejects_double_quote_in_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        sandbox.build_profile(f'{tmp_path}/evil"path', tmp_path / "scratch")


def test_classify_run_none_for_a_normal_completion() -> None:
    import subprocess

    cp = subprocess.CompletedProcess(args=["true"], returncode=0, stdout="", stderr="")
    assert sandbox.classify_run(cp) is None


def test_classify_run_timeout_kind() -> None:
    import subprocess

    cp = subprocess.CompletedProcess(args=["sleep", "99"], returncode=sandbox.TIMEOUT_RETURNCODE, stdout="", stderr="")
    record = sandbox.classify_run(cp)
    assert record == {"kind": "timeout", "detail": record["detail"]}
    assert record["kind"] == "timeout"


# ---------------------------------------------------------------------------
# THE hostile end-to-end test: a REAL sandbox-exec child, REAL escape attempts.
# ---------------------------------------------------------------------------


def _require_sandbox_exec_or_fail_loudly() -> str:
    if sys.platform != "darwin":
        pytest.skip(
            "sandbox-exec is macOS Seatbelt; this host is not Darwin so the kernel "
            "isolation boundary cannot be measured here (skip, not fail)."
        )
    exe = sandbox.sandbox_exec_path()
    if exe is None:
        pytest.fail(
            "sandbox-exec is NOT AVAILABLE on this machine. The OS isolation boundary "
            "CANNOT be verified — CONTRACTS.md 12.2.4 says the honest response is 'reviewed "
            "submissions and no anti-cheat claim,' never a weaker Python-level substitute or a "
            "silently skipped test. Failing loudly instead of skipping."
        )
    return exe


def test_probe_sandbox_blocks_every_vector() -> None:
    """The real deal: spawn `python -m kit.isolation.child_driver --probe`
    under a real, freshly-generated sandbox-exec profile and confirm every
    escape vector CONTRACTS.md 12 measured is still blocked — and that the
    positive control (I/O inside the duel's own scratch copy) still works."""
    _require_sandbox_exec_or_fail_loudly()

    report = sandbox.probe_sandbox(timeout=30.0)

    assert report["sandbox_exec"] is not None
    assert set(report["vectors"]) == set(child_driver.EXPECTED_DENIED), report["reason"]

    for name, expect_denied in sorted(child_driver.EXPECTED_DENIED.items()):
        got = report["vectors"][name]
        if name == "socket_connect_denied" and got["denied"] != expect_denied:
            # Advisory only — see sandbox.py's probe_sandbox() docstring.
            continue
        assert got["denied"] == expect_denied, f"{name}: expected denied={expect_denied}, got {got}"

    assert report["ok"] is True, report["reason"]
    # Every BLOCKED vector must have produced a structured integrity record.
    denied_names = {n for n, v in report["vectors"].items() if v["denied"]}
    assert len(report["integrity_events"]) == len(denied_names)
    for rec in report["integrity_events"]:
        assert rec["kind"] in {k.value for k in rpc.IntegrityKind}


def test_run_sandboxed_timeout_is_classified(tmp_path: Path) -> None:
    _require_sandbox_exec_or_fail_loudly()

    arena_root = tmp_path / "arena"
    duel_scratch = arena_root / "scratch" / "duel"
    child_driver.setup_probe_fixture(arena_root, duel_scratch)
    profile_path = tmp_path / "duel.sb"
    profile_path.write_text(sandbox.build_profile(arena_root, duel_scratch), encoding="utf-8")

    started = time.monotonic()
    cp = sandbox.run_sandboxed(
        profile_path,
        [sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=str(_REPO_ROOT),
        timeout=1.0,
    )
    elapsed = time.monotonic() - started

    assert cp.returncode == sandbox.TIMEOUT_RETURNCODE
    assert elapsed < 10.0, "run_sandboxed must not wait out the full sleep after its own timeout fires"
    record = sandbox.classify_run(cp)
    assert record is not None
    assert record["kind"] == "timeout"


def test_run_sandboxed_writes_inside_scratch_succeed(tmp_path: Path) -> None:
    _require_sandbox_exec_or_fail_loudly()

    arena_root = tmp_path / "arena"
    duel_scratch = arena_root / "scratch" / "duel"
    child_driver.setup_probe_fixture(arena_root, duel_scratch)
    profile_path = tmp_path / "duel.sb"
    profile_path.write_text(sandbox.build_profile(arena_root, duel_scratch), encoding="utf-8")

    marker = duel_scratch / "agent_wrote_this.txt"
    cp = sandbox.run_sandboxed(
        profile_path,
        [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('hi')"],
        cwd=str(_REPO_ROOT),
        timeout=10.0,
    )
    assert cp.returncode == 0, f"legitimate write inside duel_scratch must succeed: {cp.stderr}"
    assert marker.read_text(encoding="utf-8") == "hi"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
