#!/usr/bin/env python3
"""Phase 6 containment verification for the Banko V2 live lab boundary.

This does not describe the boundary, it exercises it. A deliberately hostile payload
is executed inside a real Tier C sandbox and each containment property is asserted
against what the payload actually observed.

Run from the host, where Docker is available.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from versioned.v2 import lab_runner


SANDBOX_IMAGE = "banko-app-runtime:verified"

# Attempts host egress, DNS, database access, project disclosure, rootfs tampering,
# and privilege inspection, then reports what actually happened.
HOSTILE_PAYLOAD = r"""
import json, os, socket
r = {}

try:
    socket.getaddrinfo("example.com", 80)
    r["dns"] = "RESOLVED"
except Exception as e:
    r["dns"] = "blocked:" + type(e).__name__

for label, host, port in (("egress", "1.1.1.1", 53), ("db", "127.0.0.1", 26257)):
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((host, port))
        r[label] = "CONNECTED"
    except Exception as e:
        r[label] = "blocked:" + type(e).__name__
    finally:
        s.close()

r["project_visible"] = os.path.exists("/app/versioned/v2/vaba_lab.py")
r["repo_visible"] = os.path.exists("/root/Documents/ML-AI-Banking-App")
r["docker_sock_visible"] = os.path.exists("/var/run/docker.sock")

try:
    with open("/pwned", "w") as fh:
        fh.write("x")
    r["rootfs_write"] = "ALLOWED"
except Exception as e:
    r["rootfs_write"] = "denied:" + type(e).__name__

r["uid"] = os.getuid()
r["gid"] = os.getgid()

# GPG_KEY is the python base image's public package-signing fingerprint, not a
# credential, so classify by name AND by value shape.
BENIGN = {"GPG_KEY"}
r["secret_env"] = sorted(
    k for k in os.environ
    if k not in BENIGN
    and any(t in k.upper() for t in ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "URI", "DSN"))
)
r["secret_valued_env"] = sorted(
    k for k, v in os.environ.items()
    if v.startswith("sk-") or "cockroachdb://" in v or "postgres://" in v
)
print(json.dumps(r))
"""


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_tier_contracts() -> None:
    """The runner must refuse anything that would weaken a tier boundary."""
    try:
        lab_runner.build_run_spec("NOPE99", "vulnerable")
        raise AssertionError("unregistered lab was accepted")
    except lab_runner.LabRunnerError:
        pass

    for lab_id in ("LIVE06", "LIVE04"):
        try:
            lab_runner.build_run_spec(lab_id, "vulnerable", env={"API_KEY": "sk-test"})
            raise AssertionError(f"{lab_id} accepted a credential")
        except lab_runner.LabRunnerError:
            pass
        try:
            lab_runner.build_run_spec(lab_id, "vulnerable", env={"BANKO_V2_DATABASE_URI": "x"})
            raise AssertionError(f"{lab_id} accepted a database URI")
        except lab_runner.LabRunnerError:
            pass
        try:
            lab_runner.build_run_spec(lab_id, "vulnerable", mounts=["/root:/root"])
            raise AssertionError(f"{lab_id} accepted a host mount")
        except lab_runner.LabRunnerError:
            pass

    # Tier A may hold a credential and reach the model API, but it is still sandboxed:
    # the app must never execute a lab payload, regardless of tier.
    tier_a = lab_runner.build_run_spec("LIVE01", "vulnerable", env={"API_KEY": "sk-test"})
    assert_true(tier_a["tier"] == "A", "LIVE01 should be Tier A")
    assert_true(tier_a["requires_sandbox"], "Tier A must still run in a sandbox")
    tier_a_args = " ".join(tier_a["sandbox_args"])
    for required in ("--read-only", "--rm", "--cap-drop ALL", "no-new-privileges", "--user 65534:65534"):
        assert_true(required in tier_a_args, f"Tier A sandbox args missing {required!r}")
    assert_true("--network none" not in tier_a_args, "Tier A needs egress to reach the model API")
    assert_true(
        all(not lab_runner.get_tier(t)["requires_sandbox"] is False for t in lab_runner.TIERS),
        "every tier must require a sandbox; the app never executes lab payloads",
    )

    spec = lab_runner.build_run_spec("LIVE06", "vulnerable")
    assert_true(spec["tier"] == "C", "LIVE06 should be Tier C")
    assert_true(spec["network_policy"] == "none", "Tier C must be network-denied")
    assert_true(not spec["executed_in_app_container"], "no spec may run in the app container")
    args = " ".join(spec["sandbox_args"])
    for required in ("--network none", "--read-only", "--rm", "--cap-drop ALL",
                     "no-new-privileges", "--user 65534:65534", "--pids-limit"):
        assert_true(required in args, f"Tier C sandbox args missing {required!r}")

    every_lab_has_a_tier = all(
        lab["tier"] in lab_runner.TIERS for lab in lab_runner.LAB_REGISTRY.values()
    )
    assert_true(every_lab_has_a_tier, "a registered lab has an unknown tier")


def check_spool_isolation() -> None:
    """The app writes specs; it never executes them.

    This verifier runs on the host, where a Docker socket necessarily exists, so the
    property is asserted where it actually matters: inside the app container.
    """
    proc = subprocess.run(
        ["docker", "exec", "banko-app", "python", "-c",
         "from versioned.v2 import lab_runner; print(lab_runner.app_can_execute_sandboxes())"],
        capture_output=True, text=True, timeout=120,
    )
    assert_true(proc.returncode == 0, f"could not query the app container: {proc.stderr.strip()[:200]}")
    assert_true(
        proc.stdout.strip() == "False",
        "a Docker socket is visible inside banko-app; the app must not be able to start containers",
    )
    with tempfile.TemporaryDirectory(prefix="labspool-") as temp_dir:
        spec = lab_runner.build_run_spec("LIVE06", "vulnerable", user={"id": 1, "username": "johndoe"})
        path = lab_runner.submit_spec(spec, spool_dir=Path(temp_dir))
        assert_true(path.exists(), "spec was not spooled")
        spooled = lab_runner.list_specs(spool_dir=Path(temp_dir))
        assert_true(len(spooled) == 1, "spooled spec not listed")
        assert_true(spooled[0]["run_id"] == spec["run_id"], "spooled spec mismatch")
        removed = lab_runner.reset_lab_state(spool_dir=Path(temp_dir), result_dir=Path(temp_dir))
        assert_true(removed["specs"] == 1, "lab spool reset failed")


def run_hostile_payload() -> dict:
    """Execute the hostile payload inside a real Tier C sandbox."""
    spec = lab_runner.build_run_spec("LIVE06", "vulnerable")
    cmd = ["docker", "run"] + spec["sandbox_args"] + [spec["sandbox_image"], "python", "-c", HOSTILE_PAYLOAD]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise AssertionError(f"sandbox run failed: {proc.stderr.strip()[:400]}")
    observed = json.loads(proc.stdout.strip().splitlines()[-1])
    return {"spec": spec, "observed": observed}


def check_sandbox_containment(result: dict) -> None:
    o = result["observed"]

    assert_true(o["dns"].startswith("blocked"), f"sandbox resolved DNS: {o['dns']}")
    assert_true(o["egress"].startswith("blocked"), f"sandbox reached the internet: {o['egress']}")
    assert_true(o["db"].startswith("blocked"), f"sandbox reached the database: {o['db']}")
    assert_true(not o["project_visible"], "sandbox could read the project source")
    assert_true(not o["repo_visible"], "sandbox could read the host repository path")
    assert_true(not o["docker_sock_visible"], "sandbox could see the Docker socket")
    assert_true(o["rootfs_write"].startswith("denied"), f"sandbox wrote to its rootfs: {o['rootfs_write']}")
    assert_true(o["uid"] == 65534, f"sandbox ran as uid {o['uid']}, expected 65534")
    assert_true(o["gid"] == 65534, f"sandbox ran as gid {o['gid']}, expected 65534")
    assert_true(not o["secret_env"], f"sandbox received secret-shaped env: {o['secret_env']}")
    assert_true(
        not o["secret_valued_env"],
        f"sandbox received a real credential value in: {o['secret_valued_env']}",
    )


def check_teardown(result: dict) -> None:
    """--rm must leave nothing behind."""
    name = f"banko-lab-{result['spec']['run_id']}"
    proc = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={name}", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=60,
    )
    assert_true(not proc.stdout.strip(), f"sandbox container survived teardown: {proc.stdout.strip()}")


def check_deployment_posture() -> None:
    """The app container itself must stay unprivileged and loopback-published."""
    def inspect(fmt: str, container: str = "banko-app") -> str:
        proc = subprocess.run(
            ["docker", "inspect", container, "--format", fmt],
            capture_output=True, text=True, timeout=60,
        )
        return proc.stdout.strip()

    assert_true(inspect("{{.Config.User}}") == "1000:1000", "banko-app is not running as uid 1000")

    netmode = inspect("{{.HostConfig.NetworkMode}}")
    assert_true(netmode != "host", "banko-app is back on host networking")

    app_nets = set(inspect("{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}").split())
    db_nets = set(
        inspect("{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}", "banko-cockroach").split()
    )
    assert_true(
        app_nets == {"banko-lab", "banko-data"},
        f"banko-app networks are {sorted(app_nets)}, expected banko-lab and banko-data",
    )
    assert_true(
        db_nets == {"banko-data"},
        f"banko-cockroach is on {sorted(db_nets)}; it must be on the internal network only",
    )

    internal = subprocess.run(
        ["docker", "network", "inspect", "banko-data", "--format", "{{.Internal}}"],
        capture_output=True, text=True, timeout=60,
    ).stdout.strip()
    assert_true(internal == "true", "banko-data is not an internal network; the database has egress")
    assert_true(
        "no-new-privileges" in inspect("{{json .HostConfig.SecurityOpt}}"),
        "banko-app is missing no-new-privileges",
    )
    assert_true(
        "ALL" in inspect("{{json .HostConfig.CapDrop}}"),
        "banko-app did not drop capabilities",
    )
    binds = inspect("{{json .HostConfig.Binds}}")
    assert_true(
        "/root/Documents/ML-AI-Banking-App:/app" not in binds,
        "banko-app still mounts the whole project",
    )
    assert_true("/app/versioned:ro" in binds, "banko-app code mount is not read-only")

    app_ports = inspect("{{json .NetworkSettings.Ports}}")
    assert_true("127.0.0.1" in app_ports, "gateway port is not published to loopback")
    assert_true(
        '"HostIp":"0.0.0.0"' not in app_ports.replace(" ", ""),
        "the gateway port is published on all interfaces",
    )
    db_ports = inspect("{{json .NetworkSettings.Ports}}", "banko-cockroach")
    assert_true(
        '"HostIp"' not in db_ports,
        f"the database publishes a host port: {db_ports}",
    )


def check_v1_untouched() -> None:
    """V1 must remain the frozen baseline: V2 adds routes, never removes or changes them."""
    route_pattern = re.compile(r"@app\.route\('([^']+)'")
    v1_routes = set(route_pattern.findall(Path("versioned/v1/app.py").read_text(encoding="utf-8")))
    v2_routes = set(route_pattern.findall(Path("versioned/v2/app.py").read_text(encoding="utf-8")))

    missing = v1_routes - v2_routes
    assert_true(not missing, f"V2 dropped V1 routes: {sorted(missing)}")
    # V2 may add routes; it may never remove or alter a V1 one. This set is the
    # allowlist of V2-only additions and must be extended deliberately.
    added = v2_routes - v1_routes
    expected_v2_only = {
        "/vaba", "/vaba/<scenario_id>", "/vaba/<scenario_id>/run",
        "/vaba/reset", "/vaba/evidence/<run_id>",
        "/labs", "/labs/<lab_id>", "/labs/<lab_id>/run", "/labs/evidence/<run_id>",
        "/labs/<lab_id>/compare", "/labs/compare/<comparison_id>",
        "/catalog",
    }
    assert_true(
        added == expected_v2_only,
        f"unexpected V2-only routes: {sorted(added - expected_v2_only)}; "
        f"missing: {sorted(expected_v2_only - added)}",
    )

    v1_source = Path("versioned/v1/app.py").read_text(encoding="utf-8")
    for forbidden in ("lab_runner", "lab_evidence", "vaba_lab"):
        assert_true(forbidden not in v1_source, f"V1 imports the V2 lab module {forbidden}")

    proc = subprocess.run(
        ["docker", "exec", "banko-app", "python", "-c",
         "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:5055/v1/login',timeout=10).status)"],
        capture_output=True, text=True, timeout=120,
    )
    assert_true(proc.stdout.strip() == "200", f"V1 login did not respond 200: {proc.stdout.strip()}")


def check_no_reserved_port_conflicts() -> None:
    """The lab must not claim ports reserved by SMART-PT or the DVAA lab."""
    reserved = set(range(7001, 7009)) | set(range(7010, 7019)) | {7020, 7021, 9000, 8111}
    proc = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
        capture_output=True, text=True, timeout=60,
    )
    for line in proc.stdout.strip().splitlines():
        if not line.startswith(("banko-app", "banko-cockroach")):
            continue
        for host_port in re.findall(r"127\.0\.0\.1:(\d+)->", line):
            assert_true(
                int(host_port) not in reserved,
                f"Banko published reserved port {host_port}",
            )
        assert_true("0.0.0.0:" not in line, f"Banko published on all interfaces: {line}")


def main() -> int:
    check_tier_contracts()
    check_spool_isolation()
    check_deployment_posture()
    check_v1_untouched()
    check_no_reserved_port_conflicts()
    result = run_hostile_payload()
    check_sandbox_containment(result)
    check_teardown(result)

    o = result["observed"]
    print("Tier C sandbox observations:")
    for key in ("dns", "egress", "db", "rootfs_write", "uid", "gid"):
        print(f"  {key:14} {o[key]}")
    print(f"  {'project_visible':14} {o['project_visible']}")
    print(f"  {'docker_sock':14} {o['docker_sock_visible']}")
    print(
        "\nPASS: VABA Phase 6 tier contracts, credential boundary, spool isolation, "
        "hardened deployment posture, Tier C sandbox containment, and teardown verified"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise
