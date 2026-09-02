# Banko V2 VABA Attack Path Improvement Plan

## Purpose

V2 should become the improved vulnerable lab while V1 remains the frozen baseline. The next improvement track is a VABA-focused agentic AI security module that teaches how banking assistants fail when agents, tools, MCP orchestration, retrieval, and output handling are trusted too much.

For this plan, VABA means the V2 Banko agentic banking assistant lab. The scenarios must stay educational, observable, resettable, and safe to run publicly. Dangerous behaviors should be simulated or constrained to local lab-only effects.

## Scope

V2 keeps everything V1 already has:

- Existing banking pages, users, CockroachDB-backed accounts, transfers, statements, benefits, profile/KYC, admin panel, Banko chat, docs upload, RAG index, and LLM vulnerability catalog.
- V2 database isolation through `bank_v2`.
- V2 knowledge-base isolation through `versioned/v2/data/docs` and `versioned/v2/data/chroma_index`.
- V2 routes under `/v2/...`.

The VABA work adds a new scenario layer on top of V2:

- A VABA scenario catalog under `/v2/llm-vulns` or a dedicated `/v2/vaba` view.
- Agent/tool simulation services under `versioned/v2`.
- Attack-path evidence capture so learners can see which step failed.
- Reset controls for V2-only database, uploaded docs, vector index, and scenario state.

## Design Principles

- Keep V1 unchanged.
- Keep public exposure safe: no real shell execution, no real metadata theft, no arbitrary unsandboxed host access.
- Demonstrate impact through Banko lab state, fake internal services, synthetic secrets, and controlled network targets.
- Make every scenario reproducible with a clear objective, PoC prompt, expected evidence, vulnerable behavior, and secure fix.
- Prefer explicit scenario IDs and JSON metadata so UI, tests, and docs stay synchronized.
- Add route verification after every milestone with `verify_v2_routes.py`.

## Proposed VABA Scenario Catalog

### VABA01: Agentic Tool Abuse

Theme: The assistant has too much authority over tools.

Covered attack paths:

- Excessive permission: the agent can call high-risk banking tools without role checks.
- Confused deputy: a normal user persuades the agent to perform an admin-only action.
- Shared rule set between agents: one agent's broad permission policy leaks into another agent's task.
- Unsandboxed execution: the agent appears able to run host-level actions.

Lab implementation:

- Add a simulated tool registry with safe fake tools such as `credit_account`, `transfer_funds`, `read_admin_report`, `run_diagnostic`.
- Add vulnerable mode where tool authorization is decided from model output or scenario state instead of server-side user role.
- Add secure comparison mode where each tool call requires server-side policy checks, tool-specific scopes, and explicit confirmation for money movement.
- Simulate unsandboxed execution by returning canned command output from an allowlisted demo command set. Do not run arbitrary commands.

Evidence to show:

- User identity and role.
- Tool requested by the model.
- Permission policy used.
- Whether the server enforced ownership or admin role.
- Resulting account, transaction, or synthetic report effect.

### VABA02: Agentic Orchestration and MCP Trust Abuse

Theme: Multi-agent orchestration breaks when agents trust each other and tool servers too much.

Covered attack paths:

- Agent loop authentication: downstream agent/tool calls are accepted without fresh auth context.
- Cross-agent confused deputy: Agent A convinces Agent B to use stronger privileges.
- MCP tool trust abuse: a tool manifest or tool result is treated as trusted instruction.
- Tool output injection: a tool response contains text that changes the next agent's behavior.
- Vector scan: retrieved documents are scanned or poisoned to locate sensitive instructions or trigger behavior.

Lab implementation:

- Add a lightweight simulated orchestrator, not a real external MCP server.
- Model the flow as `customer_agent -> banker_agent -> tool_gateway -> mock_mcp_tool`.
- Let vulnerable mode pass a shared mutable instruction/rule set between agents.
- Let vulnerable mode accept tool output containing instructions like `SYSTEM_OVERRIDE` or `CALL_TOOL`.
- Let the vector scan scenario retrieve poisoned KB chunks from V2 docs and display how they influenced the orchestration loop.
- Add secure comparison mode with signed/static tool manifests, per-agent scopes, fresh auth context, output labeling, and instruction/data separation.

Evidence to show:

- Agent chain.
- Auth context at each hop.
- Tool manifest or tool output consumed.
- Retrieved KB chunks used in the decision.
- The exact point where instruction/data boundaries failed.

### VABA03: Insecure Output Handling and SSRF via Agent

Theme: The application treats model or tool output as safe application instructions.

Covered attack paths:

- Insecure output handling: model output becomes HTML, JavaScript, redirects, or tool instructions.
- SSRF via the agent: the assistant fetches a URL chosen by the user or by a poisoned tool/document response.

Lab implementation:

- Add a safe `fetch_url` demo tool with an allowlist in secure mode.
- In vulnerable mode, allow requests only to controlled lab endpoints such as a fake metadata route, fake internal admin route, and local mock service route.
- Add a fake metadata endpoint returning synthetic values like `BANKO_FAKE_INSTANCE_TOKEN`.
- Show how prompt injection or poisoned RAG can cause the agent to fetch internal resources.
- Secure mode should block private IPs, loopback, link-local addresses, metadata hostnames, unsupported schemes, redirects to blocked hosts, and large responses.

Evidence to show:

- Requested URL.
- Resolved host classification.
- Redirect chain, if any.
- Whether the URL was user-supplied, model-supplied, tool-supplied, or RAG-supplied.
- Sanitized output vs raw output rendering.

## Proposed V2 Routes

- `GET /v2/vaba`: scenario dashboard.
- `GET /v2/vaba/<scenario_id>`: scenario detail, objective, PoC, evidence, and secure fix.
- `POST /v2/vaba/<scenario_id>/run`: execute the selected lab step in vulnerable or secure mode.
- `POST /v2/vaba/reset`: reset V2-only scenario state and synthetic evidence.
- `GET /v2/vaba/evidence/<run_id>`: view a captured run trace.

These can also be linked from the existing `/v2/llm-vulns` page to avoid splitting the learning experience.

## Proposed V2 Files

- `versioned/v2/vaba_scenarios.json`: scenario metadata, PoCs, learning objectives, secure fixes.
- `versioned/v2/vaba_lab.py`: simulation services for tools, orchestration, evidence capture, and SSRF guards.
- `versioned/v2/templates/vaba.html`: scenario list and current learner progress.
- `versioned/v2/templates/vaba_scenario.html`: scenario runner and evidence view.
- `versioned/v2/data/docs/VABA_Poisoned_Tool_Output_Demo.txt`: controlled RAG poison sample.
- `versioned/v2/data/docs/VABA_MCP_Trust_Demo.txt`: controlled orchestration/RAG sample.
- `verify_v2_routes.py`: extend route checks for VABA pages and safe POST handlers.

## Data Model Options

Start simple with JSON evidence files under `versioned/v2/data/vaba_runs`:

- Lower risk and no migration dependency.
- Easy to reset.
- Good enough for early lab work.

Move to CockroachDB tables later if we need learner progress persistence:

- `vaba_runs`
- `vaba_events`
- `vaba_scenario_state`

## Implementation Checklist

Implementation progress is tracked in `V2_VABA_IMPLEMENTATION_TRACKER.md`.

### Phase 1: Scenario Foundation

- [ ] Create `versioned/v2/vaba_scenarios.json` with VABA01, VABA02, and VABA03.
- [ ] Add `versioned/v2/vaba_lab.py` with safe simulation primitives.
- [ ] Add evidence capture with run IDs, timestamps, current user, scenario ID, mode, inputs, tool decisions, and outcomes.
- [ ] Add V2-only data directory `versioned/v2/data/vaba_runs`.
- [ ] Add unit-level smoke tests for scenario loading and evidence writing.

### Phase 2: Routes and UI

- [ ] Add V2 routes for `/vaba`, `/vaba/<scenario_id>`, `/vaba/<scenario_id>/run`, `/vaba/reset`, and `/vaba/evidence/<run_id>`.
- [ ] Add templates that follow the existing Banko navigation and V2 `request.script_root` routing pattern.
- [ ] Link the VABA dashboard from `/v2/llm-vulns`.
- [ ] Show each scenario with objective, attack path, PoC, result, evidence, and secure fix.
- [ ] Add vulnerable/secure mode controls per run.

### Phase 3: Agentic Tool Abuse Scenario

- [ ] Implement a simulated tool registry.
- [ ] Implement vulnerable policy mode where model/tool directives can trigger high-risk tools.
- [ ] Implement secure policy mode with server-side role and ownership checks.
- [ ] Add PoCs for excessive permission, confused deputy, shared rules, and simulated unsandboxed execution.
- [ ] Capture before/after account or synthetic report impact as evidence.

### Phase 4: Agentic Orchestration and MCP Scenario

- [ ] Implement a simulated multi-agent chain with customer, banker, tool gateway, and mock MCP tool roles.
- [ ] Implement vulnerable shared-rule propagation between agents.
- [ ] Implement tool output injection using controlled mock tool responses.
- [ ] Add vector-scan behavior that retrieves V2 KB chunks and marks retrieved text as untrusted.
- [ ] Implement secure mode with per-agent scopes, fresh auth context, signed/static tool metadata, and instruction/data separation.

### Phase 5: Insecure Output Handling and SSRF Scenario

- [ ] Implement controlled fake internal endpoints for metadata/admin/service responses.
- [ ] Implement vulnerable `fetch_url` behavior limited to controlled lab endpoints.
- [ ] Implement secure URL guard for scheme, DNS/IP class, redirects, response size, and content type.
- [ ] Add PoCs where direct prompt, tool output injection, and poisoned RAG trigger URL fetches.
- [ ] Show raw vs sanitized rendering behavior without enabling real browser-impacting XSS beyond the lab demo.

### Phase 6: Reset, Verification, and Guardrails

- [ ] Add V2 reset for VABA evidence, scenario state, uploaded VABA docs, and optional seeded demo balances.
- [ ] Extend `verify_v2_routes.py` to cover VABA GET routes, safe POST handlers, and link mapping.
- [ ] Confirm V1 routes and database remain unchanged.
- [ ] Confirm no SMART-PT reserved ports are introduced.
- [ ] Confirm no arbitrary shell commands or unrestricted outbound SSRF behavior are exposed.

## First Build Slice

Begin with the smallest useful VABA increment:

1. Add the scenario JSON.
2. Add the scenario dashboard and detail pages.
3. Add evidence capture to JSON files.
4. Implement VABA01 with simulated tools only.
5. Extend `verify_v2_routes.py`.
6. Run the V2 verification script.

This gives us a visible learner-facing feature quickly, keeps public exposure controlled, and creates the pattern for VABA02 and VABA03.

## Acceptance Criteria

- `/v2/vaba` is reachable after login.
- Each VABA scenario has a clear objective, PoC, attack path, expected evidence, and fix.
- Vulnerable mode demonstrates the failure using only lab-safe effects.
- Secure mode explains or demonstrates the blocking control.
- Evidence is captured per run and visible to the learner.
- Reset removes V2 VABA state without touching V1.
- `verify_v2_routes.py` passes.
- Existing `/v2/login`, `/v2/home`, `/v2/banko`, `/v2/docs`, and `/v2/llm-vulns` routes continue to map correctly.
