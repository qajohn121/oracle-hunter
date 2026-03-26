# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Oracle Cloud Free Tier ARM instance capture bot running on VPS at `ubuntu@170.9.254.97`.
Hammers the OCI LaunchInstance API until capacity opens; sends Telegram alerts on capture.

**Dashboard:** `http://170.9.254.97:3001`

## Deployment

The only deployable file is `hunter.py`.

```bash
# Deploy and restart
scp -i ~/.ssh/oracle_key hunter.py ubuntu@170.9.254.97:~/oracle-hunter/hunter.py
ssh -i ~/.ssh/oracle_key ubuntu@170.9.254.97 "pkill -9 -f hunter.py; sleep 2; cd ~/oracle-hunter && source venv/bin/activate && nohup python hunter.py > /dev/null 2>&1 & disown"

# Tail logs
ssh -i ~/.ssh/oracle_key ubuntu@170.9.254.97 "tail -f ~/oracle-hunter/hunter.log"
```

**Note:** `pkill -f hunter.py` kills the current SSH session — reconnect after 2-3 seconds.

## Architecture

`hunter.py` is a single-file async application (FastAPI + asyncio + ThreadPoolExecutor). Key sections:

- **Config block (top ~80 lines):** All tunable constants — `PROFILES`, `OCPU_CYCLE`, intervals, `FAULT_DOMAINS`, `SAFE_CALLS_PER_MIN`, `SPRINT_INTERVAL`, `SENSOR_POLL_SEC`
- **`RateBudget` class:** Rolling 60-second window tracking API calls + post-429 ramp-up state machine
- **`check_quota()`:** Queries `oci.limits.LimitsClient.get_resource_availability()` for free A1 OCPUs. Called at startup to gate OCPU cap.
- **`load_profile(name)`:** Loads one OCI profile from `~/.oci/config` on VPS, discovers subnet + Ubuntu image, caches to `disc_{name}.json`.
- **`try_launch(res, ad, ..., fault_domain)`:** Single `launch_instance` call inside ThreadPool. Returns `{"ok", "err", "fatal", "ad", "fd"}`. Only `AUTH_ERROR` is fatal.
- **`capacity_sensor(profile_name, res, st)`:** Background async task per profile. Polls `CreateComputeCapacityReport` every 60s. Sets `st["sprint_mode"] = True` when `AVAILABLE` detected — hunt loop drops to 3s for next cycle.
- **`hunt_profile(profile_name, res)`:** Main hunt loop. Fires 3 ADs × 3 FDs = 9 parallel `try_launch` calls per cycle via `asyncio.gather`. Sorts ADs by hot-slot score (success ratio) before each cycle. `LIMIT_EXCEEDED` drops OCPU to 1.
- **`run_all()`:** Loads all profiles from `PROFILES` list (skips missing gracefully), starts parallel `hunt_profile` tasks + builds Telegram startup summary.
- **FastAPI (port 3001):** `/` HTML dashboard (auto-refresh 10s), `/api/status` JSON, `/api/captured` JSON.

## 7-Layer Strategy

| Layer | What it does | Key constant |
|-------|-------------|--------------|
| L1 | 3 ADs × 3 FDs = 9 simultaneous API calls | `FAULT_DOMAINS` |
| L2 | Backoff only on 429, never on NO_CAPACITY | `RL_START`, `RL_MAX` |
| L3 | Always 1 OCPU — most commonly freed size | `OCPU_CYCLE = [1]` |
| L4 | 24/7 — no slow hours; PEAK 7s (2–11 UTC + midnight + month-end) | `PEAK_HOURS`, `PEAK_INTERVAL` |
| L5 | Rolling 60s rate budget + gradual ×3→×1 ramp-up after 429 | `SAFE_CALLS_PER_MIN = 60` |
| L6 | Pre-flight quota check; skips profile if 0 free OCPUs | `check_quota()` |
| L7 | Capacity sensor (sprint 3s on detection) + per-AD hot-slot AD sort | `SPRINT_INTERVAL`, `SENSOR_POLL_SEC` |

## OCI Profiles

Named sections in `~/.oci/config` on the VPS. `PROFILES` list in config block controls which are tried (missing ones skipped). Currently configured: `DEFAULT` (us-phoenix-1), `CHICAGO` (us-chicago-1). `ASHBURN` and `SANJOSE` are listed but not yet configured.

Per-profile discovery cached to `disc_{name_lowercase}.json` on VPS (e.g., `disc_default.json`).

## Environment Variables (VPS `~/oracle-hunter/.env`)

```
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
```

## Error Taxonomy

- `NO_CAPACITY` — normal; keep hammering, no backoff
- `RATE_LIMITED` (429) — backoff with exponential wait + gradual ramp-up
- `LIMIT_EXCEEDED` — quota exceeded for requested size; hunt loop drops to 1 OCPU and retries
- `AUTH_ERROR` — fatal; stops that profile only
