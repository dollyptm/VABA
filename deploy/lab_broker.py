#!/usr/bin/env python3
"""Host-side broker for Banko V2 live labs.

The application container cannot start containers: it holds no Docker socket. It writes
a run spec to the spool, and this broker — running on the host, where Docker is
available — consumes it.

The security-critical rule here is that the broker **never trusts the spool**. A spec is
data written by the application, and the application is the component most likely to be
compromised in a lab whose entire purpose is demonstrating LLM attacks. So the broker:

  1. re-resolves the lab from its own registry, ignoring any tier claimed in the spec
  2. recomputes the sandbox arguments from the tier, ignoring spec["sandbox_args"]
  3. re-applies the credential and mount boundary checks
  4. injects credentials itself, only for tiers permitted to hold them
  5. checks the spend cap before a Tier A run can send a request

Usage:
  python3 deploy/lab_broker.py --once            drain the spool once and exit
  python3 deploy/lab_broker.py --watch           poll the spool until interrupted
  python3 deploy/lab_broker.py --run LIVE01 --mode vulnerable
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from versioned.v2 import lab_budget, lab_evidence, lab_llm, lab_runner  # noqa: E402


# Default image. Tier B overrides it because it needs the MCP SDK; see lab_runner.TIERS.
DEFAULT_SANDBOX_IMAGE = "banko-app-runtime:verified"
PAYLOADS = {
    "LIVE01": REPO / "versioned" / "v2" / "labs" / "live01_prompt_injection.py",
    "LIVE02": REPO / "versioned" / "v2" / "labs" / "live02_indirect_injection.py",
    "LIVE03": REPO / "versioned" / "v2" / "labs" / "live03_info_disclosure.py",
    "MODEL01": REPO / "versioned" / "v2" / "labs" / "model01_tier_escalation.py",
    "MODEL02": REPO / "versioned" / "v2" / "labs" / "model02_capability_laundering.py",
    "MODEL03": REPO / "versioned" / "v2" / "labs" / "model03_router_manipulation.py",
    "MODEL04": REPO / "versioned" / "v2" / "labs" / "model04_guardrail_asymmetry.py",
    "MODEL05": REPO / "versioned" / "v2" / "labs" / "model05_context_bleed.py",
    "MODEL06": REPO / "versioned" / "v2" / "labs" / "model06_identity_spoofing.py",
    "LIVE10": REPO / "versioned" / "v2" / "labs" / "live10_multiturn_escalation.py",
    "LIVE11": REPO / "versioned" / "v2" / "labs" / "live11_notification_injection.py",
    "LIVE12": REPO / "versioned" / "v2" / "labs" / "live12_model_dos.py",
    "LIVE04": REPO / "versioned" / "v2" / "labs" / "live04_mcp_tool_injection.py",
    "LIVE05": REPO / "versioned" / "v2" / "labs" / "live05_mcp_rug_pull.py",
    "LIVE08": REPO / "versioned" / "v2" / "labs" / "live08_garak_probes.py",
    "LIVE06": REPO / "versioned" / "v2" / "labs" / "live06_pickle_backdoor.py",
    "LIVE07": REPO / "versioned" / "v2" / "labs" / "live07_model_poisoning.py",
    "LIVE09": REPO / "versioned" / "v2" / "labs" / "live09_supply_chain_signing.py",
}
CONFIG_PATH = REPO / "config.py"
ROUTER_PATH = REPO / "versioned" / "v2" / "lab_llm.py"
SECRETS_DIR = REPO / ".secrets"


class BrokerError(RuntimeError):
    pass


# The broker runs as root on the host; the app runs as uid 1000 in its container. Files
# the broker creates must be owned by the app, or the app cannot list or reset them and
# /v2/vaba/reset fails. Keep this in sync with APP_UID/APP_GID in run-hardened.sh.
APP_UID = int(os.environ.get("BANKO_APP_UID", "1000"))
APP_GID = int(os.environ.get("BANKO_APP_GID", "1000"))


def chown_for_app(path: Path) -> None:
    """Hand a broker-created path to the application user, when running as root."""
    if os.geteuid() != 0:
        return
    try:
        os.chown(path, APP_UID, APP_GID)
    except OSError:
        pass


def load_api_key(name: str = "API_KEY") -> str:
    """Read a named key from config.py without importing the app."""
    try:
        text = CONFIG_PATH.read_text(encoding="utf-8")
    except Exception:
        return ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(name) and "=" in stripped:
            _, _, value = stripped.partition("=")
            return value.strip().strip('"').strip("'")
    return ""


def read_secret_file(name: str) -> str:
    """Read a credential from the gitignored secrets directory.

    Preferred over config.py for new credentials: config.py is tracked in git with a
    placeholder, so a real key there is one `git commit -a` from being published.
    """
    path = SECRETS_DIR / name
    try:
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def revalidate(spec: dict) -> dict:
    """Rebuild the authoritative execution plan from the broker's own registry."""
    lab_id = spec.get("lab_id")
    mode = spec.get("mode")
    if mode not in {"vulnerable", "secure"}:
        raise BrokerError(f"invalid mode in spec: {mode!r}")

    lab = lab_runner.get_lab(lab_id)          # refuses unregistered labs
    tier_id = lab["tier"]                     # authoritative tier, not the spec's claim
    tier = lab_runner.get_tier(tier_id)

    if spec.get("tier") != tier_id:
        print(f"  ! spec claimed tier {spec.get('tier')!r}; registry says {tier_id!r}. Using registry.")

    # The spec's own env and mounts are re-checked, then discarded: the broker supplies
    # everything itself so a forged spec cannot smuggle a credential or a host path.
    lab_runner.assert_credential_boundary(tier_id, spec.get("env"))
    lab_runner.assert_no_host_mounts(tier_id, spec.get("mounts"))

    # The preset name is re-resolved here too, against the broker's own table, so a
    # forged spec cannot claim "local_only" routing while its resolved role map still
    # names a metered backend, or vice versa.
    preset_name = spec.get("preset") or lab_llm.DEFAULT_PRESET
    lab_llm.get_preset(preset_name)  # raises if unknown, ignoring anything spec-forged
    local_only = lab_llm.preset_is_local_only(preset_name)

    run_id = spec.get("run_id") or lab_runner._now_iso()
    sandbox_args = lab_runner.sandbox_docker_args(tier_id, run_id, local_only=local_only)  # recomputed, not trusted

    return {
        "run_id": run_id,
        "lab_id": lab_id,
        "lab_title": lab["title"],
        "tier": tier_id,
        "tier_name": tier["name"],
        "mode": mode,
        "credentials_allowed": tier["credentials_allowed"],
        "sandbox_image": tier.get("image_overrides", {}).get(lab_id, tier.get("image", DEFAULT_SANDBOX_IMAGE)),
        "comparison_id": spec.get("comparison_id"),
        "preset": preset_name,
        "sandbox_args": sandbox_args,
        "inputs": spec.get("inputs") or {},
        "user": spec.get("user") or {},
    }


def build_sandbox_source(payload_path: Path) -> str:
    """Combine the router and the lab payload into one inlinable source blob.

    Sandboxes take no mounts, so `lab_llm` cannot be imported from disk. It is embedded
    as a string and registered in `sys.modules` before the payload runs, which keeps the
    payload's plain `import lab_llm` working and the sandbox mount-free.
    """
    router_source = ROUTER_PATH.read_text(encoding="utf-8")
    payload_source = payload_path.read_text(encoding="utf-8")
    bootstrap = (
        "import sys as _sys, types as _types\n"
        f"_router_src = {router_source!r}\n"
        "_router = _types.ModuleType('lab_llm')\n"
        "exec(compile(_router_src, 'lab_llm.py', 'exec'), _router.__dict__)\n"
        "_sys.modules['lab_llm'] = _router\n"
    )
    # `from __future__` must be the first statement in a module, so hoist it out of the
    # payload and emit it once at the top of the combined source. The router keeps its
    # own copy because it is compiled separately as its own module.
    payload_source = re.sub(r"^from __future__ import .*$", "", payload_source, flags=re.MULTILINE)
    return "from __future__ import annotations\n" + bootstrap + "\n" + payload_source


def role_env_args(credentials_allowed: bool, preset: str | None = None) -> tuple[list[str], dict]:
    """Forward role routing to the sandbox, and credentials only where permitted.

    A spec may name a *preset*, never a raw backend:model string, and the preset is
    resolved here against the broker's own table rather than trusted from the spool.
    Whoever picks the route picks how weak the model handling untrusted input is, so
    that choice is an allowlist lookup, not a passthrough.
    """
    args: list[str] = []
    role_env: dict[str, str] = {}

    if preset:
        try:
            role_env = lab_llm.preset_role_env(preset)
        except lab_llm.LabLLMError as exc:
            raise BrokerError(str(exc)) from exc
    else:
        for name, value in os.environ.items():
            if name.startswith("BANKO_ROLE_"):
                role_env[name] = value

    for name, value in os.environ.items():
        if name in ("OLLAMA_CLOUD_HOST", "OLLAMA_LOCAL_HOST"):
            role_env.setdefault(name, value)
    for name, value in role_env.items():
        args += ["-e", f"{name}={value}"]

    # Resolve routing under the same environment the sandbox will see.
    saved = {k: os.environ.get(k) for k in role_env}
    os.environ.update(role_env)
    try:
        routing = lab_llm.describe_routing()
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    metered = any(role.get("metered") for role in routing.values())

    if metered:
        if not credentials_allowed:
            raise BrokerError(
                "role routing requires a metered backend, but this tier may not hold credentials"
            )

        # Inject only the credentials the resolved backends actually need. Passing every
        # key we happen to hold would hand a sandbox a credential it has no use for,
        # which is precisely the boundary this component exists to enforce.
        backends = {entry["backend"] for entry in routing.values()}
        supplied: list[str] = []

        if "openai" in backends:
            openai_key = load_api_key("API_KEY") or read_secret_file("openai_api_key")
            if not openai_key:
                raise BrokerError("routing uses the openai backend but no OpenAI key is available")
            args += ["-e", f"OPENAI_API_KEY={openai_key}"]
            supplied.append("OPENAI_API_KEY")

        if "ollama_cloud" in backends:
            ollama_key = read_secret_file("ollama_api_key") or load_api_key("OLLAMA_API_KEY")
            if not ollama_key:
                raise BrokerError(
                    "routing uses ollama_cloud but no key is present at .secrets/ollama_api_key"
                )
            args += ["-e", f"OLLAMA_API_KEY={ollama_key}"]
            supplied.append("OLLAMA_API_KEY")

        if not supplied:
            raise BrokerError("a metered backend is configured but no credential was supplied")
        return args, {"routing": routing, "metered": metered, "credentials_supplied": supplied}

    return args, {"routing": routing, "metered": metered, "credentials_supplied": []}


def execute(plan: dict) -> dict:
    payload_path = PAYLOADS.get(plan["lab_id"])
    if not payload_path or not payload_path.exists():
        raise BrokerError(f"no payload registered for {plan['lab_id']}")

    request = dict(plan["inputs"])
    request["mode"] = plan["mode"]
    model = request.get("model", lab_budget.DEFAULT_MODEL)
    request["model"] = model

    env_args, routing_note = role_env_args(plan["credentials_allowed"], plan.get("preset"))

    # Unconditional, regardless of backend or cost: an unbounded generation length is a
    # resource-exhaustion vector against the free, unthrottled local backend just as much
    # as a cost one against a metered API. This is what LIVE12 (Model DoS) demonstrated
    # was missing -- the checks below this one are cost/volume caps that only make sense
    # for metered or volume-tracked backends, but a raw ceiling applies to every backend.
    lab_budget.assert_output_ceiling(int(request.get("max_output_tokens", 800)))

    # Only metered routing touches the spend cap. A stub or local-only role map runs free,
    # which is what removes the API-credit dependency from verification.
    #
    # Authorise every metered model in the role map, not the request's default: the lab
    # chooses its own role at runtime, so the broker cannot know in advance which one it
    # will call and must clear all of them.
    budget_note = None
    if routing_note["metered"]:
        metered_models = sorted(
            {e["model"] for e in routing_note["routing"].values() if e.get("metered")}
        )
        budget_note = {
            m: lab_budget.assert_within_budget(
                model=m,
                max_output_tokens=int(request.get("max_output_tokens", 800)),
            )
            for m in metered_models
        }

    cmd = (
        ["docker", "run"]
        + plan["sandbox_args"]
        + env_args
        + [plan["sandbox_image"], "python", "-c", build_sandbox_source(payload_path),
           json.dumps(request)]
    )
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired as exc:
        # subprocess.run's timeout kills its own wait, not the process it was waiting
        # for: `docker run` (and, via --rm, the container it started) keeps executing on
        # the host, orphaned and invisible to anything that comes after. Found by
        # hitting it directly with a slow local-model garak run: the container was still
        # burning CPU five minutes after the broker had already given up on it. Every
        # sandbox is named deterministically as banko-lab-<run_id>, so it can be found
        # and stopped without parsing the command line back out of the exception.
        container_name = f"banko-lab-{plan['run_id']}"
        subprocess.run(["docker", "stop", "--time", "5", container_name],
                        capture_output=True, timeout=30)
        raise BrokerError(
            f"sandbox exceeded 300s and was stopped: {exc}"
        ) from exc
    if proc.returncode != 0:
        raise BrokerError(f"sandbox failed: {proc.stderr.strip()[:400]}")

    try:
        observed = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as exc:
        raise BrokerError(f"sandbox produced no JSON result: {exc}") from exc

    usage_note = None
    if routing_note["metered"] and observed.get("llm_called"):
        # Attribute usage to the model that actually served the call, which the lab
        # reports back, rather than to whatever the request happened to name.
        served = (observed.get("model_call") or {}).get("model") or model
        usage_note = lab_budget.record_usage(
            run_id=plan["run_id"],
            model=served,
            input_tokens=int(observed.get("input_tokens") or 0),
            output_tokens=int(observed.get("output_tokens") or 0),
        )

    return {
        "observed": observed,
        "budget_authorisation": budget_note,
        "budget_usage": usage_note,
        "routing": routing_note["routing"],
    }


def capture_evidence(plan: dict, outcome: dict) -> dict:
    evidence = {
        "run_id": lab_evidence.new_run_id("lab"),
        "kind": "live",
        "created_at": lab_evidence.now_iso(),
        "lab_id": plan["lab_id"],
        "lab_title": plan["lab_title"],
        "tier": plan["tier"],
        "mode": plan["mode"],
        "user": plan["user"],
        "broker_run_id": plan["run_id"],
        "sandbox_args": plan["sandbox_args"],
        "events": [outcome["observed"]],
        "budget": {
            "authorisation": outcome["budget_authorisation"],
            "usage": outcome["budget_usage"],
        },
        "model_routing": outcome.get("routing"),
        "preset": plan.get("preset"),
        "comparison_id": plan.get("comparison_id"),
        "executed_in_app_container": False,
    }
    lab_evidence.write_run(evidence)
    chown_for_app(lab_evidence.EVIDENCE_DIR / f"{evidence['run_id']}.json")

    spool_dir, result_dir = lab_runner.ensure_dirs()
    for directory in (spool_dir, result_dir, lab_evidence.EVIDENCE_DIR):
        chown_for_app(directory)

    result_path = result_dir / f"{plan['run_id']}.json"
    with result_path.open("w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
        handle.write("\n")
    chown_for_app(result_path)
    if lab_budget.BUDGET_PATH.exists():
        chown_for_app(lab_budget.BUDGET_PATH)
    return evidence


def process_spec(spec: dict) -> dict:
    plan = revalidate(spec)
    print(f"  running {plan['lab_id']} tier {plan['tier']} mode {plan['mode']}")
    outcome = execute(plan)
    evidence = capture_evidence(plan, outcome)
    print(f"  evidence {evidence['run_id']} outcome={outcome['observed'].get('outcome')}")
    return evidence


def drain_spool() -> int:
    lab_runner.ensure_dirs()
    specs = lab_runner.list_specs()
    if not specs:
        return 0
    handled = 0
    for spec in specs:
        try:
            process_spec(spec)
            handled += 1
        except Exception as exc:
            print(f"  ! {spec.get('run_id')}: {exc}", file=sys.stderr)
        finally:
            path = lab_runner.SPOOL_DIR / f"{spec.get('run_id')}.json"
            if path.exists():
                path.unlink()
    return handled


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="drain the spool once and exit")
    parser.add_argument("--watch", action="store_true", help="poll the spool until interrupted")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--run", help="run a lab directly, bypassing the spool")
    parser.add_argument("--mode", default="vulnerable", choices=["vulnerable", "secure"])
    parser.add_argument("--preset", default=None, help="model preset name")
    parser.add_argument(
        "--inputs",
        default=None,
        help="JSON inputs for --run; defaults to the lab's registered default_inputs",
    )
    args = parser.parse_args()

    if args.run:
        # Falling back to an empty dict would silently run the lab with no PoC at all,
        # which looks like a passing run that demonstrates nothing.
        inputs = (
            json.loads(args.inputs)
            if args.inputs is not None
            else (lab_runner.get_lab(args.run).get("default_inputs") or {})
        )
        spec = lab_runner.build_run_spec(args.run, args.mode, inputs=inputs, preset=args.preset)
        process_spec(spec)
        return 0

    if args.watch:
        print("broker watching spool; Ctrl-C to stop")
        try:
            while True:
                drain_spool()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0

    handled = drain_spool()
    print(f"broker drained {handled} spec(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
