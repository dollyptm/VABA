# Banko Deployment

> **Host:** the project now runs on `srv1889753` (191.215.36.245), Debian 13. The original
> host is untouched. Remote commands go through `deploy/remote.py`, which reads credentials
> from the gitignored `.secrets/new_host`.
>
> The gateway is bound to `127.0.0.1:5055` and is **not** reachable from the internet;
> an nftables ruleset in `/etc/nftables.conf` enforces that independently of Docker, so a
> misconfiguration cannot silently expose it. Reach the UI with an SSH tunnel:
>
> ```
> ssh -L 5055:127.0.0.1:5055 root@191.215.36.245
> ```

Phase 6 replaced the original ad-hoc containers with a hardened, reproducible deployment.
There were no Dockerfiles or compose files before this; the containers had been created by hand.

## Scripts

| Script | Purpose |
|---|---|
| `run-hardened.sh` | Start the hardened deployment. Idempotent — recreates both containers. |
| `verify-live.sh` | Run live route verification in a throwaway container. |
| `revert-to-host-network.sh` | Emergency rollback to the original unhardened posture. |

## What changed

| Property | Before | After |
|---|---|---|
| App user | `root` | `1000:1000` |
| App network | `host` | private namespace, no host access |
| App mounts | whole project, read-write | code read-only, data read-write, nothing else |
| App capabilities | all | `--cap-drop ALL`, `no-new-privileges` |
| DB network | host loopback | internal network, **no internet egress** |
| Gateway publish | none (host network) | `127.0.0.1:5055` only |
| Test tooling in app | whole repo present | none |

Before hardening, the app could reach every service on the host loopback — redis, SMART-PT,
sshd, the CockroachDB admin UI. It now reaches none of them. Verified by
`verify_lab_containment.py`.

## Architecture

```
        host 127.0.0.1:5055
              │  (loopback-only publish)
              ▼
  banko-data (internal, NO egress)        banko-lab (egress)
    ┌─────────────────┐                   ┌──────────────┐
    │ banko-cockroach │◄──── banko-app ──►│  internet    │
    │ 26257           │                   │  (OpenAI)    │
    └─────────────────┘                   └──────────────┘

  Lab sandboxes join NEITHER network:
    Tier B: banko-lab-isolated
    Tier C: --network none, --read-only, uid 65534, --rm, no mounts, no secrets
```

The database sits on an `--internal` Docker network. It is reachable only from
`banko-data` members, and it cannot reach the internet at all. The app bridges the two
networks because it needs the database on one side and the LLM API on the other.

### The cockroach entrypoint bypass

The image's `/cockroach/cockroach.sh` wrapper rejects any `--listen-addr` whose hostname
is not `127.0.0.1` or `localhost`:

```
error: hostname of listen_addr must be "127.0.0.1" or "localhost"
```

That check lives in the **wrapper script, not the cockroach binary** — upstream
CockroachDB documents `--listen-addr=:26257` as a supported "listen on all interfaces"
value. `run-hardened.sh` therefore invokes `/cockroach/cockroach` directly. Without this,
the database cannot be addressed by container name and the two-network layout is impossible.

### Restarting the database

The app survives a database restart. The first request afterwards may fail while the
stale connection pool recycles, then subsequent requests succeed. If you want a clean
state, re-run `run-hardened.sh`.

## The lab execution boundary

The app container holds **no Docker socket**. It cannot start a sandbox even with arbitrary
code execution inside it. Live labs are dispatched by writing a validated run spec to
`versioned/v2/data/lab_spool`, which a host-side broker consumes.

`versioned/v2/lab_runner.py` enforces the tier contract at spec-build time:

- Tier A may hold credentials and runs no attacker code.
- Tier B and C are refused any secret-shaped environment variable or host mount.
- Unregistered labs are refused outright, so a new lab cannot inherit a weaker boundary
  by omission.

## Verification

```bash
./deploy/verify-all.sh fast   # simulation phases + registry audit, seconds
./deploy/verify-all.sh live   # adds Tier C containment and live routes, about a minute
./deploy/verify-all.sh        # adds the behavioural lab suite, several minutes
```

Staged because the suite outgrew a single command: `verify_labs.py` spawns a container per
lab run. Staging means a failure surfaces as early and as cheaply as possible.

`verify_lab_containment.py` executes a hostile payload in a real Tier C sandbox and asserts
what it actually observed: DNS blocked, egress blocked, database unreachable, project
invisible, Docker socket invisible, rootfs read-only, uid 65534, no credentials, container
removed on exit.
