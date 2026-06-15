"""Tests for the Custom MCP Server — function correctness AND the architectural guarantee.

Run: python3 mcp_server/tests/test_server.py   (needs the case data on the box; uses the
configured injected bodyfile + structured renders).

The headline test is test_no_write_or_exec_capability: it proves the evidence-integrity claim
is architectural — the server simply has no tool that could modify evidence.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tools  # noqa: E402

FORBIDDEN = ("shell", "exec", "run", "write", "delete", "rm", "edit", "mount", "chmod",
             "dd", "spawn", "popen", "system", "eval", "modify", "set_", "put", "upload")


def test_no_write_or_exec_capability():
    # 1) the exposed tool names are all read-only getters
    for name in tools.READ_ONLY_TOOLS:
        assert name.startswith(("get_", "detect_")), name
        assert not any(bad in name.lower() for bad in FORBIDDEN), f"{name} looks mutating"
    # 2) the MCP server registers EXACTLY this read-only set — nothing else
    import server
    registered = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert registered == set(tools.READ_ONLY_TOOLS), registered
    # 3) the server module exposes no shell/exec/write entry point
    for bad in ("run_shell", "exec_command", "write_file", "delete_file", "system"):
        assert not hasattr(server, bad)


def test_detect_timestomps_catches_inj01():
    res = tools.detect_timestomps("high")
    confirmed = [f for f in res["findings"] if f["verdict"] == "confirmed_timestomp"]
    assert any("onedrive.exe" in f["path"].lower() for f in confirmed), "INJ-01 not caught"
    f = confirmed[0]
    assert len(f["provenance"]) == 2  # disk $MFT + memory _EPROCESS
    assert f["memory"] and f["memory"]["matched_pid"]


def test_get_mft_timestamps_shows_backdating():
    r = tools.get_mft_timestamps("Microsoft/OneDrive/OneDrive.exe")
    target = [f for f in r["files"] if f["mft_entry"] == "104046"]
    assert target, "entry 104046 not found"
    assert target[0]["si_creation"] != target[0]["fn_creation"]  # injected backdate visible


def test_every_call_is_audited():
    tmp = tempfile.NamedTemporaryFile(suffix=".log", delete=False).name
    tools.AUDIT_LOG = tmp
    tools.get_process_start(9648)
    import json
    lines = [json.loads(l) for l in open(tmp)]
    assert lines and lines[-1]["tool"] == "get_process_start"
    assert "ts" in lines[-1] and "artifacts" in lines[-1]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} passed")
