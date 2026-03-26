#!/usr/bin/env python3
"""
Oracle Free Tier Hunter v7.2 — 6-Layer Strategy (quota-aware)

Layer 1: PARALLEL AD requests (ThreadPoolExecutor + asyncio.gather)
Layer 2: Smart polling (only backoff on 429, never on NO_CAPACITY)
Layer 3: OCPU cycling [1,1,2,1,1,4] weighted toward 1
Layer 4: Enhanced peak detection (Tue/Wed 2-6AM, midnight, month/quarter-end)
Layer 5: Rolling rate budget + GRADUAL ramp-up after 429 recovery
"""

import os
import sys
import json
import asyncio
import subprocess
import logging
import logging.handlers
import random
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

import oci
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

load_dotenv()

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TG_CHAT = os.getenv("TELEGRAM_CHAT_ID", "")

# Profiles to try — missing ones are skipped gracefully at startup
PROFILES = ["DEFAULT", "CHICAGO", "ASHBURN", "SANJOSE"]

# Layer 3: OCPU cycling — weighted toward 1 (most freed capacity)
OCPU_CYCLE = [1, 1, 2, 1, 1, 4]
MEMORY_PER_OCPU = 6

SHAPE = "VM.Standard.A1.Flex"
BOOT_GB = 50

# Layer 2: Polling intervals
PEAK_INTERVAL = 7         # 6-8s as strategy recommends
NORMAL_INTERVAL = 15
SLOW_INTERVAL = 30        # off-peak: 30-60s

# Layer 5: Rate limiting
RL_START = 45
RL_MAX = 300              # never exceed 5 min
RL_MULT = 1.5
RL_RESET_AFTER = 3
SAFE_CALLS_PER_MIN = 20

# Layer 5 FIX: Gradual ramp-up after 429 recovery
RAMP_UP_CYCLES = 5        # how many cycles to gradually speed up
RAMP_UP_MULTIPLIER = 3.0  # first cycle after 429: interval × 3, then × 2.5, × 2, × 1.5, × 1

# Layer 4: Time windows
PEAK_HOURS = set(range(2, 11))
SLOW_HOURS = set(range(18, 24))

MAX_PER_PROFILE = 4

# Thread pool for Layer 1 parallel launches
THREAD_POOL = ThreadPoolExecutor(max_workers=6)

# ═══════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════

logger = logging.getLogger("hunter")
logger.setLevel(logging.INFO)
_c = logging.StreamHandler()
_f = logging.handlers.RotatingFileHandler(
    'hunter.log', maxBytes=10*1024*1024, backupCount=3
)
_fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                         datefmt='%Y-%m-%d %H:%M:%S')
_c.setFormatter(_fmt)
_f.setFormatter(_fmt)
logger.addHandler(_c)
logger.addHandler(_f)

# ═══════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════

START_TIME = datetime.now()
CAPTURED = []
API_CALLS = 0
PROFILE_STATE = {}
ACTIVE = True

# ═══════════════════════════════════════════════════════════════
# LAYER 5: RATE BUDGET + RAMP-UP TRACKER
# ═══════════════════════════════════════════════════════════════

class RateBudget:
    """
    Rolling 60-second window tracking API calls.
    Also tracks post-429 ramp-up state for gradual speed recovery.
    """

    def __init__(self, max_per_min):
        self.max_per_min = max_per_min
        self.timestamps = deque()
        # Ramp-up state: after a 429, don't jump straight to full speed
        self.ramp_remaining = 0  # cycles left in ramp-up period

    def record(self, n=1):
        now = time.time()
        for _ in range(n):
            self.timestamps.append(now)
        self._prune()

    def _prune(self):
        cutoff = time.time() - 60
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()

    def used(self):
        self._prune()
        return len(self.timestamps)

    def headroom(self, need=3):
        return self.used() + need <= self.max_per_min

    def start_ramp_up(self):
        """Called after a 429 backoff completes — begin gradual ramp-up."""
        self.ramp_remaining = RAMP_UP_CYCLES

    def get_ramp_multiplier(self):
        """
        Returns interval multiplier for gradual ramp-up.
        First cycle after 429: ×3, then ×2.5, ×2, ×1.5, ×1 (full speed).
        """
        if self.ramp_remaining <= 0:
            return 1.0
        # Linear ramp from RAMP_UP_MULTIPLIER down to 1.0
        progress = self.ramp_remaining / RAMP_UP_CYCLES
        mult = 1.0 + (RAMP_UP_MULTIPLIER - 1.0) * progress
        self.ramp_remaining -= 1
        if self.ramp_remaining <= 0:
            logger.info("  📈 Ramp-up complete — back to full speed")
        return mult

# ═══════════════════════════════════════════════════════════════
# TELEGRAM
# ═══════════════════════════════════════════════════════════════

async def tg(text):
    if not TG_TOKEN or not TG_CHAT:
        return
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                json={"chat_id": TG_CHAT, "text": text[:4000]}
            )
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════
# SSH KEY
# ═══════════════════════════════════════════════════════════════

def get_ssh_key():
    kp = Path.home() / ".ssh" / "oracle_hunter_key"
    pub = Path(str(kp) + ".pub")
    if not pub.exists():
        kp.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(kp), "-N", "", "-q"],
            check=True
        )
    return pub.read_text().strip()

# ═══════════════════════════════════════════════════════════════
# QUOTA CHECK
# ═══════════════════════════════════════════════════════════════

def check_quota(profile_name, config, tid):
    """
    Query remaining A1 OCPU quota for this tenancy+region.
    Returns {"free_ocpus": N, "used_ocpus": N} or None values on failure.
    """
    try:
        limits_client = oci.limits.LimitsClient(config)
        avail = limits_client.get_resource_availability(
            service_name="compute",
            limit_name="standard-a1-core-count",
            compartment_id=tid,
            availability_domain=None
        ).data
        free = int(avail.available) if avail.available is not None else None
        used = int(avail.used) if avail.used is not None else None
        logger.info(f"[{profile_name}] Quota: {used} used / {(used or 0) + (free or 0)} limit → {free} free OCPUs")
        return {"free_ocpus": free, "used_ocpus": used}
    except Exception as e:
        logger.warning(f"[{profile_name}] Quota check failed (will assume 1 free): {e}")
        return {"free_ocpus": None, "used_ocpus": None}


# ═══════════════════════════════════════════════════════════════
# OCI PROFILE LOADING
# ═══════════════════════════════════════════════════════════════

def load_profile(name):
    config = oci.config.from_file(profile_name=name)
    identity = oci.identity.IdentityClient(config)
    compute = oci.core.ComputeClient(config)
    network = oci.core.VirtualNetworkClient(config)
    tid = config["tenancy"]
    region = config.get("region", "unknown")

    ads = identity.list_availability_domains(tid).data
    ad_names = [ad.name for ad in ads]

    disc_path = Path(f"disc_{name.lower()}.json")
    disc = {}
    if disc_path.exists():
        try:
            disc = json.loads(disc_path.read_text())
        except Exception:
            disc = {}

    subnet_id = disc.get("subnet_id", "")
    image_id = disc.get("image_id", "")

    if not subnet_id:
        try:
            for vcn in network.list_vcns(tid).data:
                for s in network.list_subnets(tid, vcn_id=vcn.id).data:
                    if not s.prohibit_public_ip_on_vnic:
                        subnet_id = s.id
                        break
                if subnet_id:
                    break
        except Exception as e:
            logger.warning(f"[{name}] Subnet discovery: {e}")

    if not image_id:
        for os_name, os_ver in [
            ("Canonical Ubuntu", "22.04"),
            ("Canonical Ubuntu", "24.04"),
            ("Oracle Linux", "9"),
        ]:
            try:
                imgs = compute.list_images(
                    tid, operating_system=os_name,
                    operating_system_version=os_ver,
                    shape=SHAPE, sort_by="TIMECREATED",
                    sort_order="DESC", limit=1
                ).data
                if imgs:
                    image_id = imgs[0].id
                    break
            except Exception:
                continue

    disc.update({
        "subnet_id": subnet_id, "image_id": image_id,
        "ads": ad_names, "region": region,
        "updated": datetime.now().isoformat()
    })
    disc_path.write_text(json.dumps(disc, indent=2))

    return {
        "config": config, "compute": compute, "network": network,
        "tid": tid, "cid": tid,
        "ads": ad_names, "subnet_id": subnet_id,
        "image_id": image_id, "ssh_key": get_ssh_key(),
        "profile": name, "region": region,
    }

# ═══════════════════════════════════════════════════════════════
# LAYER 1: LAUNCH ATTEMPT (accepts OCPU params for Layer 3)
# ═══════════════════════════════════════════════════════════════

def try_launch(res, ad, display_name, ocpus, memory_gb):
    """Single API call — runs inside ThreadPool for parallel execution."""
    try:
        resp = res["compute"].launch_instance(
            oci.core.models.LaunchInstanceDetails(
                availability_domain=ad,
                compartment_id=res["cid"],
                display_name=display_name,
                shape=SHAPE,
                shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                    ocpus=float(ocpus),
                    memory_in_gbs=float(memory_gb)
                ),
                source_details=oci.core.models.InstanceSourceViaImageDetails(
                    source_type="image",
                    image_id=res["image_id"],
                    boot_volume_size_in_gbs=BOOT_GB
                ),
                create_vnic_details=oci.core.models.CreateVnicDetails(
                    assign_public_ip=True,
                    subnet_id=res["subnet_id"]
                ),
                metadata={"ssh_authorized_keys": res["ssh_key"]},
                is_pv_encryption_in_transit_enabled=True
            )
        )
        return {"ok": True, "instance": resp.data, "ad": ad}

    except oci.exceptions.ServiceError as e:
        code = getattr(e, 'code', '') or ''
        msg = str(getattr(e, 'message', '') or e)
        status = getattr(e, 'status', 0) or 0

        # DEBUG: Log the actual error
        logger.error(f"[{ad}] Oracle error: code={code}, msg={msg[:100]}, status={status}")


        if "OutOfCapacity" in code or "Out of host capacity" in msg or ("InternalError" in code and "capacity" in msg.lower()):
            return {"ok": False, "err": "NO_CAPACITY", "ad": ad}
        elif status == 429 or "TooManyRequests" in code:
            return {"ok": False, "err": "RATE_LIMITED", "ad": ad}
        elif "LimitExceeded" in code and "capacity" not in msg.lower():
            # NOT fatal — means requested OCPU size exceeds remaining quota.
            # Hunt loop will drop to 1 OCPU and retry.
            return {"ok": False, "err": "LIMIT_EXCEEDED", "fatal": False, "ad": ad}
        elif "NotAuthorized" in code or "NotAuthenticated" in code:
            return {"ok": False, "err": "AUTH_ERROR", "fatal": True, "ad": ad}
        elif "InternalError" in code or status >= 500:
            return {"ok": False, "err": "OCI_ERROR", "ad": ad}
        else:
            return {"ok": False, "err": f"{code}:{msg[:60]}", "ad": ad}

    except Exception as e:
        return {"ok": False, "err": str(e)[:80], "ad": ad}


async def get_ip(res, iid, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            vnics = res["compute"].list_vnic_attachments(
                compartment_id=res["cid"], instance_id=iid
            ).data
            for va in vnics:
                if va.lifecycle_state == "ATTACHED":
                    v = res["network"].get_vnic(va.vnic_id).data
                    if v.public_ip:
                        return v.public_ip
        except Exception:
            pass
        await asyncio.sleep(10)
    return "pending"

# ═══════════════════════════════════════════════════════════════
# LAYER 4: ENHANCED PEAK DETECTION
# ═══════════════════════════════════════════════════════════════

def utc_hour():
    return datetime.now(timezone.utc).hour

def mode():
    """
    Layer 4 peak windows:
    - 2-6 AM UTC Tue/Wed → PEAK (US maintenance)
    - 2-10 AM UTC any day → PEAK (general maintenance)
    - 23:00-01:00 UTC → PEAK (billing cycles)
    - Month-end/start (d>=28 or d<=2) → PEAK (trial expirations)
    - Quarter-end months (Mar,Jun,Sep,Dec) + boundaries → PEAK
    - Tue/Wed slow hours → upgraded to NORMAL
    """
    now = datetime.now(timezone.utc)
    h = now.hour
    wd = now.weekday()  # 0=Mon
    d = now.day
    m = now.month

    # Core maintenance window
    if h in PEAK_HOURS:
        return "PEAK"

    # Midnight UTC ±1h (billing cycles)
    if h in (23, 0, 1):
        return "PEAK"

    # Month boundaries (trial expirations, billing)
    if d <= 2 or d >= 28:
        if h not in SLOW_HOURS:
            return "PEAK"

    # Quarter-end months get extra peak coverage
    if m in (3, 6, 9, 12) and d >= 25:
        return "PEAK"

    # Tue/Wed evenings: upgrade from SLOW to NORMAL
    if wd in (1, 2) and h in SLOW_HOURS:
        return "NORMAL"

    if h in SLOW_HOURS:
        return "SLOW"
    return "NORMAL"

def interval():
    m = mode()
    if m == "PEAK":
        return PEAK_INTERVAL
    if m == "SLOW":
        return SLOW_INTERVAL
    return NORMAL_INTERVAL

# ═══════════════════════════════════════════════════════════════
# HUNT LOOP — ALL 5 LAYERS INTEGRATED
# ═══════════════════════════════════════════════════════════════

async def hunt_profile(profile_name, res):
    """
    Per-profile hunter implementing all 5 layers:

    Every cycle:
      Layer 3: Pick OCPU from rotation [1,1,2,1,1,4]
      Layer 5: Check rolling 60s rate budget
      Layer 1: Fire ALL ADs simultaneously (ThreadPool)
      Layer 2: If NO_CAPACITY → keep hammering (no backoff)
               If 429 → backoff, then gradual ramp-up (Layer 5)
      Layer 4: Interval adapts to time-of-day/week/month
    """
    region = res["region"]
    ads = res["ads"]

    if not ads or not res["subnet_id"] or not res["image_id"]:
        logger.error(f"[{profile_name}] Missing config — cannot hunt")
        await tg(f"❌ [{profile_name}] Missing subnet/image — fix config")
        return

    st = {
        "profile": profile_name,
        "region": region,
        "cycles": 0,
        "api_calls": 0,
        "captured": 0,
        "errors": defaultdict(int),
        "status": "hunting",
        "current_ad": "ALL (parallel)",
        "current_ocpu": 1,
        "last_error": "",
        "rl_streak": 0,
        "clean_streak": 0,
        "budget_used": 0,
        "ramp_status": "",         # shows ramp-up state on dashboard
    }
    PROFILE_STATE[profile_name] = st

    budget = RateBudget(SAFE_CALLS_PER_MIN)
    ocpu_idx = 0
    captured_count = 0

    # ── Pre-flight quota check (Fix 2) ──
    quota = check_quota(profile_name, res["config"], res["tid"])
    free_ocpus = quota.get("free_ocpus")
    if free_ocpus is not None and free_ocpus <= 0:
        msg = f"[{profile_name}] No free OCPUs remaining (quota full). Skipping."
        logger.warning(msg)
        await tg(f"⚠️ {msg}")
        st["status"] = "quota_full"
        return
    # Cap OCPU cycle to what fits in remaining quota
    max_ocpu = free_ocpus if free_ocpus and free_ocpus > 0 else 4
    effective_cycle = [x for x in OCPU_CYCLE if x <= max_ocpu] or [1]

    logger.info(
        f"[{profile_name}] 🚀 Hunt v7.1 started: {region}, "
        f"{len(ads)} ADs (PARALLEL), "
        f"Free OCPUs: {free_ocpus if free_ocpus is not None else 'unknown'}, "
        f"OCPU cycle: {effective_cycle}"
    )

    while ACTIVE and st["status"] == "hunting":
        st["cycles"] += 1

        if captured_count >= MAX_PER_PROFILE:
            st["status"] = "complete"
            logger.info(f"[{profile_name}] All {captured_count} instances captured!")
            await tg(f"✅ [{profile_name}] All {captured_count} instances captured!")
            return

        # ── Layer 5: Rate budget gate ──
        if not budget.headroom(len(ads)):
            st["budget_used"] = budget.used()
            await asyncio.sleep(3)
            continue

        # ── Layer 3: OCPU rotation (capped to available quota) ──
        ocpus = effective_cycle[ocpu_idx % len(effective_cycle)]
        memory_gb = ocpus * MEMORY_PER_OCPU
        ocpu_idx += 1
        st["current_ocpu"] = ocpus

        # Log every 30 cycles
        if st["cycles"] % 30 == 1:
            ramp = f" RAMP({budget.ramp_remaining})" if budget.ramp_remaining > 0 else ""
            logger.info(
                f"[{profile_name}] #{st['cycles']} | "
                f"{mode()} ({interval()}s) | "
                f"{ocpus}cpu/{memory_gb}gb | "
                f"API: {st['api_calls']} | "
                f"Budget: {budget.used()}/{budget.max_per_min} | "
                f"RL: {st['rl_streak']} | "
                f"Cap: {captured_count}{ramp}"
            )

        # ═════════════════════════════════════════════════
        # LAYER 1: FIRE ALL ADs SIMULTANEOUSLY
        # All API calls launch at the same moment via ThreadPool
        # ═════════════════════════════════════════════════

        name = f"free-{profile_name.lower()[:3]}-{captured_count + 1}"

        budget.record(len(ads))
        st["api_calls"] += len(ads)
        global API_CALLS
        API_CALLS += len(ads)
        st["budget_used"] = budget.used()

        loop = asyncio.get_event_loop()
        parallel_tasks = [
            loop.run_in_executor(
                THREAD_POOL, try_launch, res, ad, name, ocpus, memory_gb
            )
            for ad in ads
        ]
        raw_results = await asyncio.gather(*parallel_tasks, return_exceptions=True)

        # ── Process parallel results ──
        success_result = None
        hit_rate_limit = False
        hit_fatal = False
        fatal_err = ""
        cap_count = 0

        hit_limit_exceeded = False

        for result in raw_results:
            if isinstance(result, Exception):
                st["errors"]["EXCEPTION"] += 1
                st["last_error"] = str(result)[:60]
                continue

            ad = result.get("ad", "?")
            ad_short = ad.split(":")[-1] if ":" in ad else ad[-15:]

            if result["ok"]:
                if not success_result:  # take first success only
                    success_result = result
                cap_count += 1
                continue

            err = result.get("err", "unknown")
            st["last_error"] = err
            st["errors"][err] += 1

            if result.get("fatal"):
                hit_fatal = True
                fatal_err = err
            elif err == "RATE_LIMITED":
                hit_rate_limit = True
            elif err == "LIMIT_EXCEEDED":
                hit_limit_exceeded = True

        # ── Fatal → stop ──
        if hit_fatal:
            logger.error(f"[{profile_name}] FATAL: {fatal_err}")
            st["status"] = f"fatal:{fatal_err}"
            await tg(f"❌ [{profile_name}] Fatal: {fatal_err}")
            return

        # ── Success → capture ──
        if success_result:
            inst = success_result["instance"]
            sad = success_result.get("ad", "?")
            sad_short = sad.split(":")[-1] if ":" in sad else sad[-15:]
            logger.info(
                f"[{profile_name}] 🎉 CAPTURED in {sad_short}! "
                f"({ocpus}cpu/{memory_gb}gb)"
            )

            ip = await get_ip(res, inst.id)
            captured_count += 1
            st["captured"] = captured_count
            st["rl_streak"] = 0
            st["clean_streak"] = 0
            budget.ramp_remaining = 0

            CAPTURED.append({
                "profile": profile_name,
                "region": region,
                "id": inst.id,
                "ip": ip or "pending",
                "ad": sad_short,
                "ocpus": ocpus,
                "memory_gb": memory_gb,
                "name": name,
                "time": datetime.now().isoformat(),
                "cycle": st["cycles"],
                "api_calls": st["api_calls"],
            })

            await tg(
                f"🎉🎉🎉 CAPTURED! 🎉🎉🎉\n\n"
                f"Profile: {profile_name}\n"
                f"Region: {region}\n"
                f"IP: {ip or 'pending'}\n"
                f"AD: {sad_short}\n"
                f"Shape: {ocpus}cpu / {memory_gb}GB\n"
                f"ID: {inst.id}\n\n"
                f"SSH: ssh -i ~/.ssh/oracle_hunter_key ubuntu@{ip}\n\n"
                f"Captured: {captured_count}/{MAX_PER_PROFILE}\n"
                f"After {st['cycles']} cycles, {st['api_calls']} API calls"
            )
            await asyncio.sleep(3)
            continue

        # ═════════════════════════════════════════════════
        # LAYER 2: SMART ERROR HANDLING
        # 429 → backoff + gradual ramp-up (Layer 5)
        # NO_CAPACITY → NO backoff, keep hammering
        # ═════════════════════════════════════════════════

        if hit_rate_limit:
            st["rl_streak"] += 1
            st["clean_streak"] = 0

            wait = min(
                RL_START * (RL_MULT ** (st["rl_streak"] - 1)),
                RL_MAX
            )
            wait += random.uniform(2, 8)

            logger.warning(
                f"[{profile_name}] ⚠️ 429 Rate Limited "
                f"(streak: {st['rl_streak']}) — waiting {wait:.0f}s, "
                f"then gradual ramp-up over {RAMP_UP_CYCLES} cycles"
            )
            st["ramp_status"] = f"backoff {wait:.0f}s"
            await asyncio.sleep(wait)

            # Layer 5: Start gradual ramp-up (don't jump to full speed)
            budget.start_ramp_up()
            st["ramp_status"] = f"ramping({budget.ramp_remaining})"
            continue

        # ── LIMIT_EXCEEDED → shrink OCPU size, keep hunting ──
        if hit_limit_exceeded and not hit_rate_limit:
            logger.warning(
                f"[{profile_name}] ⚠️ Quota exceeded for {ocpus} OCPU "
                f"— dropping to 1 OCPU and continuing"
            )
            max_ocpu = 1
            effective_cycle = [1]
            st["current_ocpu"] = 1
            await asyncio.sleep(5)
            continue

        # NO_CAPACITY path: track clean streak, reset RL if enough clean
        st["clean_streak"] += 1
        if st["clean_streak"] >= RL_RESET_AFTER:
            if st["rl_streak"] > 0:
                logger.info(
                    f"[{profile_name}] RL streak reset (was {st['rl_streak']})"
                )
            st["rl_streak"] = 0

        # Status telegram every 300 cycles
        if st["cycles"] % 300 == 0:
            h = (datetime.now() - START_TIME).total_seconds() / 3600
            rate = st["api_calls"] / max(h, 0.01)
            rl_pct = st["errors"].get("RATE_LIMITED", 0) / max(st["api_calls"], 1) * 100
            no_cap = st["errors"].get("NO_CAPACITY", 0)
            await tg(
                f"📊 [{profile_name}] v7.1 #{st['cycles']}\n"
                f"Region: {region}\n"
                f"API: {st['api_calls']} ({rate:.0f}/hr)\n"
                f"Mode: {mode()} | OCPU: {ocpus}\n"
                f"Budget: {budget.used()}/{budget.max_per_min}\n"
                f"No Cap: {no_cap} | RL: {st['errors'].get('RATE_LIMITED', 0)} ({rl_pct:.1f}%)\n"
                f"Captured: {captured_count}/{MAX_PER_PROFILE}\n"
                f"Running: {h:.1f}h"
            )

        # ═════════════════════════════════════════════════
        # LAYER 5: INTERVAL WITH RAMP-UP MULTIPLIER
        # After a 429, ramp_multiplier starts at 3× and
        # decreases to 1× over RAMP_UP_CYCLES cycles
        # ═════════════════════════════════════════════════
        base = interval()
        ramp_mult = budget.get_ramp_multiplier()
        actual_interval = base * ramp_mult
        jitter = random.uniform(0, 2)

        if ramp_mult > 1.0:
            st["ramp_status"] = f"ramping({budget.ramp_remaining}) ×{ramp_mult:.1f}"
            logger.info(
                f"[{profile_name}]   ⏱ ramp-up: {actual_interval:.0f}s "
                f"(base {base}s × {ramp_mult:.1f})"
            )
        else:
            st["ramp_status"] = ""

        await asyncio.sleep(actual_interval + jitter)

    logger.info(f"[{profile_name}] Hunt ended. Captured: {captured_count}")


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

async def run_all():
    global ACTIVE

    logger.info("=" * 60)
    logger.info("  ORACLE HUNTER v7.1 — 5-Layer Strategy (all verified)")
    logger.info("=" * 60)

    resources = {}
    for p in PROFILES:
        try:
            res = load_profile(p)
            resources[p] = res
            logger.info(
                f"  [{p}] {res['region']} | "
                f"ADs: {len(res['ads'])} | "
                f"subnet: {'✅' if res['subnet_id'] else '❌'} | "
                f"image: {'✅' if res['image_id'] else '❌'}"
            )
        except Exception as e:
            logger.error(f"  [{p}] FAILED: {e}")
            await tg(f"⚠️ [{p}] Load failed: {e}")

    if not resources:
        logger.error("No profiles loaded!")
        await tg("❌ Hunter failed — no OCI profiles loaded")
        return

    # Build summary with quota info
    summary_lines = []
    for p, r in resources.items():
        quota = check_quota(p, r["config"], r["tid"])
        free = quota.get("free_ocpus")
        quota_str = f"{free} free OCPUs" if free is not None else "quota unknown"
        summary_lines.append(f"  {p}: {r['region']} ({len(r['ads'])} ADs) — {quota_str}")
    summary = "\n".join(summary_lines)

    await tg(
        f"🎯 Hunter v7.2 — All 5 Layers + Quota-Aware\n\n"
        f"⚡ L1: Parallel AD fire (simultaneous)\n"
        f"⏱ L2: {PEAK_INTERVAL}s/{NORMAL_INTERVAL}s/{SLOW_INTERVAL}s (429-only backoff)\n"
        f"🔄 L3: OCPU cycling {OCPU_CYCLE} (capped to free quota)\n"
        f"📅 L4: Peak: maintenance+midnight+month-end+quarter\n"
        f"📊 L5: Budget {SAFE_CALLS_PER_MIN}/min + gradual ramp-up\n"
        f"🔢 L6: Pre-flight quota check + auto OCPU downsize\n\n"
        f"Profiles:\n{summary}\n"
        f"Target: {MAX_PER_PROFILE}/profile"
    )

    tasks = []
    for i, (p, res) in enumerate(resources.items()):
        if i > 0:
            await asyncio.sleep(3)
        task = asyncio.create_task(hunt_profile(p, res), name=p)
        tasks.append(task)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception):
            logger.error(f"Hunter task exception: {r}")

    cap_text = "\n".join(
        f"  {c['profile']}: {c['ip']} ({c['region']}, {c['ad']}, {c['ocpus']}cpu)"
        for c in CAPTURED
    ) or "  None"

    h = (datetime.now() - START_TIME).total_seconds() / 3600
    await tg(
        f"🏁 Hunter v7.1 finished\n"
        f"Runtime: {h:.1f}h | API: {API_CALLS}\n"
        f"Captured: {len(CAPTURED)}\n{cap_text}"
    )


# ═══════════════════════════════════════════════════════════════
# WEB DASHBOARD
# ═══════════════════════════════════════════════════════════════

app = FastAPI(title="Oracle Hunter v7.1")

@app.get("/", response_class=HTMLResponse)
async def home():
    h = (datetime.now() - START_TIME).total_seconds() / 3600
    up = str(datetime.now() - START_TIME).split('.')[0]
    rate = API_CALLS / max(h, 0.01)
    m = mode()
    utch = utc_hour()

    profiles_html = ""
    for pname, st in sorted(PROFILE_STATE.items()):
        icon = {
            "hunting": "🟢", "complete": "🎉",
        }.get(st["status"], "🔴" if "fatal" in st["status"] else "🟡")

        rl = st["errors"].get("RATE_LIMITED", 0)
        nocp = st["errors"].get("NO_CAPACITY", 0)
        rl_pct = rl / max(st["api_calls"], 1) * 100
        ramp = f" {st.get('ramp_status', '')}" if st.get('ramp_status') else ""

        profiles_html += (
            f"  {icon} {pname:10s} | {st['region']:16s} | "
            f"Cyc: {st['cycles']:5d} | "
            f"API: {st['api_calls']:5d} | "
            f"OCPU: {st.get('current_ocpu', '?')} | "
            f"Bgt: {st.get('budget_used', 0):2d}/{SAFE_CALLS_PER_MIN} | "
            f"NoCap: {nocp:5d} | "
            f"RL: {rl:3d}({rl_pct:.0f}%) s:{st['rl_streak']} | "
            f"Cap: {st['captured']}/{MAX_PER_PROFILE}{ramp}\n"
        )

    cap_html = ""
    if CAPTURED:
        for c in CAPTURED:
            cap_html += (
                f"  🎉 {c['profile']:10s} | {c['ip']:15s} | "
                f"{c['region']:16s} | {c['ad']} | {c['ocpus']}cpu\n"
            )
    else:
        cap_html = "  Hunting..."

    return f"""<html>
<head>
    <title>Hunter v7.1</title>
    <meta http-equiv="refresh" content="10">
</head>
<body style="font-family:monospace;padding:20px;background:#0a0a1a;color:#0f0;font-size:14px;">
<h1>🎯 Oracle Hunter v7.1 — 5-Layer Strategy</h1>
<pre>
Uptime:     {up}
UTC Hour:   {utch} ({m})
API Calls:  {API_CALLS} ({rate:.0f}/hr)
Interval:   {interval()}s

All 5 Layers Active:
  ⚡ L1: Parallel AD fire (all ADs simultaneously via ThreadPool)
  ⏱  L2: {PEAK_INTERVAL}s peak / {NORMAL_INTERVAL}s norm / {SLOW_INTERVAL}s slow (429-only backoff)
  🔄 L3: OCPU cycling {OCPU_CYCLE}
  📅 L4: Peak = maintenance + midnight + month-end + quarter-end
  📊 L5: Rolling budget {SAFE_CALLS_PER_MIN}/min + gradual ramp-up after 429

Profiles:
{profiles_html}
Captured ({len(CAPTURED)}):
{cap_html}
</pre>
</body></html>"""


@app.get("/api/status")
async def api_status():
    h = (datetime.now() - START_TIME).total_seconds() / 3600
    return {
        "version": "7.1",
        "layers": {
            "1_parallel_ads": True,
            "2_smart_polling": True,
            "3_ocpu_cycling": OCPU_CYCLE,
            "4_timing_windows": True,
            "5_rate_budget_ramp": True,
        },
        "uptime_hours": round(h, 2),
        "api_calls": API_CALLS,
        "api_rate": round(API_CALLS / max(h, 0.01)),
        "mode": mode(),
        "interval": interval(),
        "captured": CAPTURED,
        "profiles": {
            k: {**v, "errors": dict(v["errors"])}
            for k, v in PROFILE_STATE.items()
        },
    }


@app.get("/api/captured")
async def api_captured():
    return {"captured": CAPTURED, "total": len(CAPTURED)}


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

async def main():
    asyncio.create_task(run_all())
    config = uvicorn.Config(
        app, host="0.0.0.0", port=3006,
        log_level="warning",
        access_log=False
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Hunter stopped by user")
    except Exception as e:
        logger.error(f"Hunter crashed: {e}")
        import traceback
        traceback.print_exc()
