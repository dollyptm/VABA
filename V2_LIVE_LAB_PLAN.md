# Banko V2 Live Lab Plan

## Purpose

V2 currently teaches agentic AI security through **simulation**. The VABA module (Phases 1-5) proves
its point with in-process fakes: no socket opens, no shell runs, no model loads. That was the right
call for a publicly reachable lab, and it stays.

This plan adds a second, **genuinely executing** tier so learners see real outcomes: a real LLM that
actually follows an injected instruction, a real MCP client that actually reads a file it was told to
read, a real `torch.load` that actually runs an attacker's code. Simulation teaches the shape of a
failure. Execution teaches that it is not hypothetical.

Source material is the `LLM-Security-main` corpus extracted to `llmlab/`: 92 files across
OffensiveLabs, DefensiveLabs, LLM-Basics, SupplyChainSecurity, and ThreatModel.

## The design principle that changes

`V2_VABA_ATTACK_PATH_PLAN.md` states:

> Keep public exposure safe: no real shell execution, no real metadata theft, no arbitrary
> unsandboxed host access.

That principle is **not being dropped**. It is being re-scoped from *"nothing executes"* to
*"nothing executes outside a boundary built for it."* The replacement principle:

> Dangerous behavior may execute genuinely, but only inside a disposable, unprivileged,
> network-restricted sandbox that holds no credentials, no project source, and no host access.
> The public surface stays simulation-only.

This matters because the current Phase 6 checklist contains the item *"Confirm no arbitrary shell
commands or unrestricted outbound SSRF behavior are exposed."* Under the new direction that item is
obsolete as written. Phase 6 is therefore rewritten below from a **verification** phase into an
**enablement** phase: it builds the boundary that every later phase depends on.

## Containment posture BEFORE Phase 6 (historical baseline)

> This table records what was measured before the hardening, and is kept because it explains
> why Phase 6 was rescoped. It is **no longer the current state**: `banko-app` now runs
> non-root on a private network with targeted read-only mounts, and the database sits on an
> internal network with no egress. See `deploy/README.md` for the current posture.


| Property | Current value | Implication |
|---|---|---|
| `banko-app` network mode | `host` | Container shares the host network namespace entirely |
| `banko-app` user | `uid=0(root)` | Anything it runs, runs as root |
| `banko-app` mounts | `/root/Documents/ML-AI-Banking-App:/app` read-write | The whole project, including git history |
| `banko-app` rootfs | read-write | Persistent tampering possible |
| Gateway bind | `APP_HOST=127.0.0.1`, port 5055 | Localhost-only today |
| nginx | proxies `:80`/`:443` to `127.0.0.1:8111` (SMART-PT) only | Banko is **not** publicly proxied |
| Host public IP | `187.124.212.89` bound locally; sshd, nginx on `0.0.0.0` | Host is internet-facing |
| `verify_v2_routes.py` default `--base` | `http://187.124.212.89:5055/v2` | Assumes a public bind that is not currently active |

Two conclusions:

1. **The lab is not publicly reachable right now.** Good. But it is one `APP_HOST=0.0.0.0` away from
   being so, and the verify script's default already points at the public address.
2. **`banko-app` is the worst possible place to execute attack code.** Root, host network, project
   mounted read-write. A Tier C pickle payload run there would execute as root against the user's real
   source tree with unrestricted network. No live lab may run inside this container.

## Risk tiers

Every lab is classified before it is built. The tier determines where it runs.

### Tier A — Model-level, no host effect

Real LLM API calls. Untrusted text changes model behavior. Nothing touches the host.

- Prompt injection (`OffensiveLabs/Prompt-Injection` — essay evaluator, score override)
- Indirect prompt injection (`OffensiveLabs/Indirect-Prompt-Injection` — email summarizer, hidden HTML directives)
- Sensitive information disclosure (`OffensiveLabs/Sensitive-information-disclosure` — help desk bot, cross-ticket leakage)
- Insecure output handling (indirect-PI exfil via `<img src=...?q=base64>` beaconing)

**Runs in:** a sandbox, like every other tier. Phase 7 settled this: the first non-negotiable below
is that the app never executes a lab payload, and "no host side effect" is not the same as "safe to
run in the app". Tier A differs from B and C only by holding a credential and having egress. Real
cost is OpenAI spend, capped by `lab_budget`.
**Genuine outcome shown:** the model actually returns the attacker's score; the summarizer actually
emits the tracking pixel; the bot actually reveals another user's ticket.

### Tier B — Process, file, and network effects

Real subprocesses, real file reads, real sockets. Bounded blast radius, but genuine side effects.

- MCP tool-description injection (`LLM-Basics/MCP/MCP-Server/malicious-mcp-server.py` — hidden
  `<IMPORTANT>` block instructs the client to read `~/Desktop/financials_2025.txt` and exfiltrate it
  as a `sidenote` parameter)
- MCP rug pull (`mcp_rugpull_attack.py` — runs `os.system("touch ~/.mcp-triggered")`, then mutates its
  own tool docstring on the next start so the approved tool is not the tool that runs)
- Automated red-teaming (`OffensiveLabs/garak/payload.json` — garak `RestGenerator` fires probe
  batches at a live endpoint)
- Agent tool abuse with real tools (`LLM-Basics/Agents/*nmap*`, `sql-agent.py`)

**Runs in:** a dedicated sidecar with a synthetic `$HOME` containing planted decoy files, no project
mount, no credentials, and an egress allowlist restricted to the lab network.
**Genuine outcome shown:** the decoy file's contents actually arrive in the tool call; the tool
definition actually changes between runs; garak actually reports which probes succeeded.

### Tier C — Arbitrary code execution

Attacker code runs on deserialization or training. Highest value, highest risk.

- Pickle model backdoor (`OffensiveLabs/Model-Backdoor/` — `pickle_codeinjection.py` embeds
  `os.system`/`exec`/`eval`/`runpy` payloads that fire on `torch.load`; the shipped payload runs
  `cat /etc/passwd`)
- Model poisoning (`OffensiveLabs/Model-Poisoning/model-training.py` — label-flipped training data)
- Supply chain pipeline (`SupplyChainSecurity/ModelTraining-HF/` — basic vs `secure-pipeline` with
  `modelscan`, `model_signing`, MLflow lineage, dependency pinning)

**Runs in:** a disposable container, `--network none`, read-only rootfs, tmpfs workdir, non-root,
memory and PID capped, `--rm`, no mounts, no environment secrets. Destroyed after every run.
**Genuine outcome shown:** `modelscan` actually flags the unsafe operator; the payload actually
executes inside the sandbox and its output is captured as evidence; the signed pipeline actually
refuses the tampered artifact.

## Execution boundary architecture

```
  browser ──> banko-app (V2 Flask)          simulation only, no attack code, holds the API key
                    │
                    │ lab dispatch: scenario_id + tier + mode
                    ▼
              lab_runner.py                 builds the run spec, never executes payloads itself
                    │
        ┌───────────┼────────────┐
        ▼           ▼            ▼
   Tier A       Tier B        Tier C
   sidecar      sidecar       sandbox
   net: egress  net: lab-only net: none
   API key: yes API key: no   API key: no
   mounts: none mounts: fake  mounts: none
                $HOME         rootfs: ro
                              --rm, non-root
                    │
                    ▼
         evidence JSON  ──>  existing VABA evidence store + /v2 evidence viewer
```

Non-negotiable properties:

1. `banko-app` never executes lab payloads. It only builds a run spec and reads back evidence.
2. Tier C containers get `--network none`, `--read-only`, `--user`, `--pids-limit`, `--memory`,
   `--rm`, and zero mounts. Nothing survives the run except the evidence file.
3. No sandbox receives `API_KEY`. Tier A is the only tier with a key, and Tier A runs no attacker code.
4. `banko-app` moves off host networking onto a bridge network with an explicit `-p 127.0.0.1:5055:5055`
   publish, drops to non-root, and mounts only what it needs rather than the whole project.
5. A guard test fails the build if the gateway is bound to anything other than loopback.

## Virtual environment plan

Three environments, none of which touch the app's runtime dependencies. Import analysis of the corpus:

| Environment | Purpose | Key packages | Approx weight |
|---|---|---|---|
| `.venv-llmbasics` | LLM-Basics, ThreatModel, Tier A/B labs | `openai`, `langchain`, `langchain_community`, `langchain_openai`, `langchain_text_splitters`, `faiss-cpu`, `mcp`, `requests`, `beautifulsoup4`, `flask`, `flask-cors`, `python-dotenv`, `langsmith`, `colorama`, `sqlalchemy` | light |
| `.venv-mlsupply` | Tier C only, container-side | `torch`, `transformers`, `datasets`, `accelerate`, `scipy`, `scikit-learn`, `pandas`, `mlflow`, `modelscan`, `model-signing` | heavy (multi-GB) |
| `.venv-guard` | Secure-mode scanners — **deferred, not built yet** | `llm-guard` (pulls `transformers`) | heavy |

Notes:

- **This is the environment the request asked for.** `.venv-llmbasics` covers LLM-Basics and is
  deliberately free of `torch`, so it stays small and fast to rebuild.
- `llm-guard` is a real constraint worth surfacing early: `DefensiveLabs/Defending-Prompt-Injection/app-secure-v2.py`
  imports it for `PromptInjection`, `Toxicity`, and `TokenLimit` scanners. It drags in the heavy
  transformer stack, so the *defensive* half of a Tier A lab is heavier than the offensive half.
  Per the decision above, secure mode starts with the regex and prompt-hardening defenses from
  `strategies.txt`, so `.venv-guard` is not built during Phases 6-7.
- Nothing is installed until the venv layout is approved.

## Revised Phase 6: Execution Boundary, Reset, and Guardrails

Replaces the current Phase 6 checklist.

- [ ] Move `banko-app` off `network_mode: host` to a bridge network with `127.0.0.1:5055:5055`.
- [ ] Drop `banko-app` to a non-root user and replace the whole-project bind mount with targeted mounts.
- [ ] Add `versioned/v2/lab_runner.py`: builds run specs, dispatches by tier, never executes payloads in-process.
- [ ] Add the Tier C sandbox profile (`--network none`, `--read-only`, non-root, `--rm`, capped, unmounted) and a containment self-test that proves each property.
- [ ] Generalize VABA evidence capture into a shared `lab_evidence` module so simulated and live runs share one store, one viewer, and one reset.
- [ ] Extend V2 reset to cover live-lab artifacts, sandbox scratch, uploaded VABA docs, and optional seeded demo balances.
- [ ] Add a guard test that fails if the gateway binds a non-loopback address, and fix the `verify_v2_routes.py` default `--base`.
- [ ] Confirm V1 routes and the `bank` database remain unchanged; record the check used.
- [ ] Confirm no SMART-PT reserved ports are introduced.
- [ ] Document the credential boundary: `API_KEY` reaches Tier A only.

**Exit criterion:** a deliberately hostile payload placed in the Tier C sandbox can be shown to have
no path to the host, the project, the database, or the network.

## Phase 7: Tier A live labs

- [ ] Port the essay-evaluator prompt injection as a Banko-native scenario with a real LLM call.
- [ ] Port indirect prompt injection using Banko statements/documents as the untrusted carrier.
- [ ] Port sensitive information disclosure against Banko's own ticket/profile data.
- [ ] Wire each to the existing `vulnerable | secure` toggle, using the paired `app-secure-v1/v2` implementations as secure mode.
- [ ] Capture real request, real model response, and the decision delta between modes as evidence.
- [ ] Add per-scenario API cost accounting and a run budget.

## Phase 8: Local model router and multi-model attack paths

### Why this belongs in the plan

Three reasons, in order of importance:

1. **It removes the dependency that is currently blocking Tier A.** Every live lab is stalled on an
   OpenAI account with no credits. A local backend makes runs free, offline, and unlimited.
2. **It makes VABA02's multi-agent chain real.** Today `customer_agent -> banker_agent ->
   tool_gateway -> mock_mcp_tool` is in-process fakes. With a router assigning a different model per
   agent role, the chain becomes genuine message passing between models that actually differ.
3. **Model asymmetry is itself an attack surface, and it is under-taught.** Most LLM security
   material treats "the model" as one thing. A system with a weak reasoner and a strong orchestrator
   has a trust gradient that behaves exactly like a classic privilege boundary — and almost nobody
   defends it as one.

### Hardware reality on this host

Measured, not assumed: **2 CPU cores, ~3 GB RAM available, no GPU, 24 GB free disk.**

| Model class | Approx RAM | Viable here |
|---|---|---|
| 1B–1.5B quantised (`llama3.2:1b`, `qwen2.5:1.5b`) | 1–1.5 GB | Yes |
| 3B quantised (`llama3.2:3b`) | ~2 GB | Tight; one at a time |
| 7B quantised | ~4.5 GB | **No** — would swap or OOM the running lab |

Consequence: **the "higher model for orchestration" role cannot be filled by a local model on this
host.** A 7B does not fit beside CockroachDB and the app, and a 7B is not a strong orchestrator in
any case. The asymmetry is still achievable — just not with both halves local.

### The design that survives the constraint

The valuable component is **the router, not the local models**. Add `versioned/v2/lab_llm.py`: a
provider abstraction with pluggable backends and per-role model assignment.

```
  lab payload
      │  chat(role="reasoner", messages=[...])
      ▼
  lab_llm router          role -> (backend, model) from config
      │
  ┌───┴────┬──────────┬─────────────┐
  ▼        ▼          ▼             ▼
 stub    ollama     openai      (future)
 free    local      metered
 offline free       capped
 determ. offline
```

Roles, not model names, appear in lab code. Which model serves a role is deployment configuration,
so the same lab runs against a stub in CI, a local 1B on this host, and a strong model elsewhere.

Backends:

- **`stub`** — deterministic scripted responses. Free, offline, reproducible. This is what lets
  verification assert exact outcomes; a real model makes assertions probabilistic. Ships first.
- **`ollama_cloud`** — hosted Ollama. Serves the large-model roles that this host cannot run.
  Metered and credentialed, so it is governed by `lab_budget` and the Tier A boundary.
- **`ollama_local`** — local inference, added when hardware allows. Free, unlimited, and
  **egress-free**, so garak can run exhaustively without a spend cap.
- **`openai`** — the existing metered path, unchanged.

**Ollama Cloud and local Ollama expose the same API surface.** That is the load-bearing detail: a
single Ollama adapter with a configurable base URL and optional bearer token serves both. Moving a
role from cloud to local after a hardware upgrade is a configuration change, not a rewrite.

### Role assignment and migration path

Roles are the stable abstraction; the backend behind each role moves over time.

| Role | Now (no hardware upgrade) | After hardware upgrade |
|---|---|---|
| `reasoner` (customer_agent) | `ollama_cloud`, small model | `ollama_local`, 1B–3B |
| `orchestrator` (banker_agent) | `ollama_cloud`, large model | `ollama_cloud` (stays) |
| `judge` (secure-mode reviewer) | `ollama_cloud`, large model | `ollama_cloud` (stays) |
| verification / CI | `stub` | `stub` |

This unblocks the work immediately: neither OpenAI credit nor a hardware upgrade is on the critical
path. The capability asymmetry that MODEL01–MODEL06 depend on is achieved on day one by assigning
different model sizes within the same provider, and sharpens later when local models arrive.

### What each backend costs, and how it is capped

`lab_budget` already refuses to run against a model with no declared price, which is the right
default here. Ollama Cloud pricing is not hard-coded into this plan, because inventing a price is
worse than refusing to run.

- `stub`, `ollama_local` — free. Exempt from the cap, but still counted for run accounting.
- `openai` — USD cap as today.
- `ollama_cloud` — **cap by request count and token count** until a verified USD price is supplied,
  then switch to the USD cap. A run-count ceiling is honest when the price is unknown; a guessed
  dollar figure is not.

### Containment differs by backend, and that is a teaching point

| Backend | Network | Credential | Tier profile |
|---|---|---|---|
| `stub` | none | none | any tier |
| `ollama_local` | `banko-models`, **internal, no egress** | none | strictest |
| `ollama_cloud` | egress required | bearer token | Tier A |
| `openai` | egress required | API key | Tier A |

`ollama_local` is strictly more contained than either hosted backend: no credential to leak and no
route off the box. That difference is itself the MODEL04 lesson — moving inference local removes a
provider-side safety layer that the surrounding system may silently have depended on.

The Ollama Cloud token is handled exactly like the OpenAI key: broker-injected, Tier A only, never
passed to Tier B or C. The existing `SECRET_NAME_PATTERN` in `lab_runner` already matches
`OLLAMA_API_KEY`, so the refusal is enforced without new code.

### Which attack paths work before the hardware upgrade

Five of the six are fully demonstrable with two cloud model sizes:

| Path | Cloud-only (now) | Needs `ollama_local` |
|---|---|---|
| MODEL01 tier privilege escalation | yes | — |
| MODEL02 capability laundering | yes | — |
| MODEL03 router manipulation | yes | — |
| MODEL04 guardrail asymmetry | partial | **fully** — a local model has no provider safety layer at all |
| MODEL05 cross-model context bleed | yes | — |
| MODEL06 model identity in evidence | yes | — |

MODEL04 is the one that genuinely improves after the upgrade, because the sharpest version of that
lesson requires a backend with no provider guardrails whatsoever.

### Containment

Ollama has **no authentication by default**, so network placement is the only control. It must not
become a hole in the Phase 6 boundary.

- Runs as its own container on a dedicated `banko-models` network.
- `banko-models` is `--internal`: the model server has **no internet egress**.
- Not published to the host. Nothing outside the lab networks can reach `11434`.
- Tier A sandboxes join `banko-models` instead of `banko-lab` when their role map is local-only,
  which means those labs need no egress and no credential at all.
- Memory-capped (`--memory`) so a model load cannot OOM CockroachDB or the app.
- `OLLAMA_KEEP_ALIVE` kept short and one model resident at a time, given 3 GB headroom.
- Port 11434 confirmed free and outside the SMART-PT/DVAA reserved ranges.

### New attack paths this unlocks

These are the reason to do it, beyond cost. Each is genuinely demonstrable only with heterogeneous
models, and each maps onto a VABA02 path that is currently simulated.

- **MODEL01 — Model-tier privilege escalation.** Compromise the weak reasoner; its output is
  consumed as trusted input by the orchestrator. A confused deputy across capability tiers.
- **MODEL02 — Capability laundering.** The orchestrator refuses a request directly, but the weak
  reasoner complies, and the orchestrator trusts the reasoner's summary. The refusal is bypassed by
  routing rather than by prompt.
- **MODEL03 — Router manipulation.** If routing is influenced by user input or model output, an
  attacker steers their request to the weakest model. "Use the fast model for this" as an injection.
- **MODEL04 — Guardrail asymmetry.** A local model has **no provider-side safety layer**. A system
  that implicitly relied on the API refusing things breaks silently the moment a request is routed
  local. This is the most under-appreciated risk in the list.
- **MODEL05 — Cross-model context bleed.** Shared conversation state between models at different
  trust levels leaks privileged context downward.
- **MODEL06 — Model identity spoofing in evidence.** If evidence does not record which model
  actually served a role, a result cannot be interpreted or reproduced.

### The pedagogical hazard to design around

A small local model may fail secure mode **because it is too weak to follow the hardening
instructions**, not because the defence is unsound. That would teach the opposite of the intended
lesson.

Mitigations, all required:

- Every evidence record stores backend, model name, and digest. `MODEL06` above exists precisely so
  this is enforced rather than assumed.
- Secure mode records whether the model followed the instruction *format*, separating "defence
  failed" from "model could not comply".
- Structural defences — server-side filtering, stripping, delimiting — are asserted independently of
  model behaviour, exactly as LIVE03 already does. Those assertions hold on any backend.

### Checklist

**8a — router and stub (no credentials, no hardware needed)**

- [ ] Add `versioned/v2/lab_llm.py` with role-based routing and the `stub` backend.
- [ ] Re-point LIVE01, LIVE02, and LIVE03 at the router instead of calling `openai` directly.
- [ ] Make verification assert exact vulnerable-mode outcomes against `stub`, removing the API-credit dependency from CI.
- [ ] Record backend, model, and digest in every evidence record.

**8b — Ollama Cloud (needs an API key)**

- [ ] Add the shared Ollama adapter: configurable base URL, optional bearer token, same code path for cloud and local.
- [ ] Wire `ollama_cloud` into the Tier A profile so the broker injects the token and the boundary still refuses it for Tiers B and C.
- [ ] Discover and pin the available cloud models rather than hard-coding names; record the resolved model and digest per run.
- [ ] Extend `lab_budget` with request-count and token-count caps for backends whose USD price is not declared.
- [ ] Assign `reasoner` to a small cloud model and `orchestrator`/`judge` to a large one.

**8c — multi-model attack paths**

- [ ] Implement MODEL01, MODEL02, MODEL03, MODEL05, and MODEL06 against the cloud role split.
- [ ] Implement MODEL04 partially now; complete it when a local backend exists.
- [ ] Upgrade VABA02 to optionally drive the real router instead of mock agents, keeping simulation as the default.

**8d — local backend (after hardware upgrade)**

- [ ] Add `ollama_local` plus the `--internal` `banko-models` network with a memory-capped server.
- [ ] Pull a 1B–3B model and record measured latency before building labs on it.
- [ ] Move the `reasoner` role from cloud to local by configuration only, proving the abstraction held.
- [ ] Complete MODEL04 using a backend with no provider-side safety layer.
- [ ] Re-run garak exhaustively against the free local backend.

## Phase 9: Tier B live labs

- [ ] Stand up the malicious MCP server and a real MCP client in the Tier B sidecar with a synthetic `$HOME` and planted decoy files.
- [ ] Demonstrate tool-description injection: show the decoy file's contents arriving in the `sidenote` parameter.
- [ ] Demonstrate the rug pull: show the tool definition changing between the approved run and the executed run.
- [ ] Replace VABA02's mock MCP manifests with an option to target the real server, keeping the simulated path as the default.
- [ ] Add garak `RestGenerator` runs against the Tier A endpoints with probe results as evidence.

## Phase 10: Tier C supply chain labs

- [ ] Build the safe/unsafe model pair and run `torch.load` inside the sandbox, capturing the payload's actual output.
- [ ] Run `modelscan` in both modes and show the detection delta.
- [ ] Port the secure pipeline: signing, verification, MLflow lineage, dependency pinning.
- [ ] Demonstrate a tampered artifact being refused by signature verification.
- [ ] Add model poisoning with before/after accuracy on the poisoned class.

## Phase 11: Unified catalog and verification

- [ ] Merge VABA, the existing LLM01-LLM10/ADV01-ADV02 catalog, and the live labs into one browsable index with tier and execution badges.
- [ ] Extend `verify_v2_routes.py` to cover every new route.
- [ ] Add `verify_live_labs.py` asserting tier placement, credential boundaries, and sandbox teardown.
- [ ] Confirm the public surface remains simulation-only.

## Integration with existing V2

The corpus fits the existing architecture unusually well:

- **Paired implementations map onto the existing mode toggle.** Every offensive lab ships a defensive
  twin (`app.py` vs `app-secure-v1.py`/`app-secure-v2.py`). That is exactly V2's
  `mode=vulnerable|secure` control, so secure mode gets real implementations instead of prose.
- **Evidence capture already exists.** `create_evidence_run` has run IDs, timestamps, user context,
  events, outcomes, and reset. Live labs emit events into the same store; the viewer works unchanged.
- **The catalog pattern already exists.** `vaba_scenarios.json` validation, required fields, and ID
  format carry over directly.
- **VABA02 already models MCP.** Phase 8 upgrades it from mock manifests to a real server behind a
  flag, so the simulated path stays the default and the live path is opt-in.
- **VABA becomes the safe tier.** Simulation-only remains the publicly demonstrable surface; live labs
  are the gated tier behind the execution boundary.

## Decisions taken

1. **Containment scope: harden `banko-app` and add tiered sidecars.** The app container moves to a
   bridge network with `127.0.0.1:5055:5055` published, drops to a non-root user, and replaces the
   whole-project bind mount with targeted mounts. Live labs run in tiered sandboxes beside it. This
   requires one planned `banko-app` restart and must be scheduled explicitly.
2. **Secure-mode defenses: start light.** Secure mode begins with the regex, prompt-hardening, and
   output-escaping techniques from `DefensiveLabs/*/strategies.txt` and `strategy.txt`. No heavy
   dependencies. `llm-guard` scanners are deferred to a later phase, so `.venv-guard` is **not**
   built during Phases 6-7 and `.venv-llmbasics` stays `torch`-free.

3. **Catalog shape: a separate `/v2/labs` section.** Genuinely executing labs cost money and
   run real sandboxes, so they stay visually and structurally distinct from simulation-only
   VABA rather than merging into `/v2/llm-vulns`. Both are cross-linked.
4. **API budget: $5.00 total, $0.10 per run.** Enforced by `versioned/v2/lab_budget.py` as a hard
   stop checked before any request is sent, with declared per-model prices and token ceilings.
   Garak still needs its own probe cap when Phase 8 lands.

5. **Where the model-driven half of Tier B runs: on the stub.** Tier B has no egress and
   holds no credentials, and both properties are verified rather than assumed. Rather than
   weaken the tier so its labs could call a hosted model, the model-facing step in LIVE04
   runs on the deterministic stub, and LIVE05 needs no model at all. The genuinely executing
   part of Tier B is the server process, the stdio handshake, the manifest, the file read,
   and the exfiltrated parameter, none of which need a model. If a real model is wanted in
   the loop later, the correct move is to split the decision hop into Tier A rather than to
   give Tier B egress.

## Open decisions

None outstanding. Phase 8 will need a decision on how far the MCP client integration goes:
a real MCP client against the malicious server, or a scripted client that exercises the same
trust boundary.

## Acceptance criteria

- The public surface remains simulation-only; live labs are gated.
- Every live lab declares a tier, and its tier is enforced at dispatch rather than by convention.
- No sandbox holds credentials, project source, or host network access.
- Each scenario shows a genuine outcome and a genuine secure-mode block, both captured as evidence.
- Reset removes all live-lab state without touching V1.
- V1 stays frozen; `bank` is never reachable from a live lab.
- `verify_v2_routes.py` and `verify_live_labs.py` pass.
