# ─── Two-Axis Admiralty Grading ───────────────────────────────────────────────
# Adapts the 70-year-old NATO Admiralty grading system to AI model output.
# Original use: grading human-sourced intelligence (source reliability +
# information credibility). Novel application: grading ML model predictions.
# Used in: MISP, OpenCTI, Palo Alto Unit 42 — but never applied to ML output.
#
# Axis 1 — Credibility (per flow, 6 tiers, Admiralty-inspired)
# Axis 2 — Reliability (per model, rolling 500 predictions, grades A-E)
#
# Collapse formula for dashboard:
# flow_trust = min(normalized_credibility, normalized_reliability)
# Worst axis governs — neither a good model nor a good single check
# can excuse the other.
#
# Per-device aggregation:
# device_trust = min(flow_trust) across all flows in 5-second window
# NOT averaged — one real attack diluted by clean flows is still an attack.
#
# Idle device handling:
# Grace period (2 cycles ~10s) → hold last score
# Then decay toward neutral 0.5 — not zero, not trusted
# Extended silence after recent activity = weak suspicion signal

import sys
import os
import time
from collections import defaultdict, deque

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import (
    TRUST_TRUSTED, TRUST_SUSPICIOUS,
    RELIABILITY_WINDOW, PSI_DRIFT_THRESHOLD,
    FLAGGED_RATE_THRESHOLD, IDLE_GRACE_CYCLES, IDLE_DECAY_TARGET
)

# ─── Credibility Tier Definitions ─────────────────────────────────────────────
# Tier 1 = fully credible (1.0), Tier 6 = confirmed threat (0.0)
CREDIBILITY_TIERS = {
    1: 1.00,   # No flags — prediction stands as-is
    2: 0.80,   # One minor flag (margin OR fragile SHAP)
    3: 0.60,   # Two minor flags stacked
    4: 0.40,   # Ghost model disagrees
    5: 0.20,   # Multiple strong signals
    6: 0.05    # Honeytoken hit OR OTX confirmed — certainty override
}

# ─── Reliability Grade Definitions ────────────────────────────────────────────
# Grade A = fully reliable (1.0), Grade E = degraded (0.2)
RELIABILITY_GRADES = {
    "A": 1.00,
    "B": 0.80,
    "C": 0.60,
    "D": 0.40,
    "E": 0.20
}

GRADE_ORDER = ["A", "B", "C", "D", "E"]

# ─── Model reliability state ───────────────────────────────────────────────────
model_state = {
    "grade": "A",
    "prediction_window": deque(maxlen=RELIABILITY_WINDOW),
    "flagged_count": 0,
    "clean_streak": 0,
    "last_probability_dist": None,
    "locked": True  # temporary — remove when real data arrives
}

# ─── Device trust state ───────────────────────────────────────────────────────
device_state = defaultdict(lambda: {
    "last_trust_score": 0.5,
    "last_seen": None,
    "idle_cycles": 0,
    "recent_activity": False
})

def compute_credibility_tier(shap_result, ghost_result, honeytoken_result, otx_result):
    """
    Axis 1 — Credibility grading per flow.
    Starts at tier 1, downgrades based on signal stack.
    Honeytoken/OTX confirmed = immediate override to tier 6.
    """
    # Immediate override conditions
    if honeytoken_result and honeytoken_result.get("honeytoken_hit"):
        return 6, "honeytoken_override"

    if otx_result and otx_result.get("otx_found") and otx_result.get("otx_pulse_count", 0) > 0:
        return 6, "otx_confirmed_override"

    # Start at tier 1 and downgrade
    tier = 1
    reasons = []

    # SHAP margin flag → one tier down
    if shap_result and shap_result.get("margin_flagged"):
        tier += 1
        reasons.append("shap_margin")

    # Fragile SHAP flag → one more tier down (stacks with margin)
    if shap_result and shap_result.get("fragile_shap_flagged"):
        tier += 1
        reasons.append("shap_fragile")

    # Ghost model disagrees → multiple tiers down
    if ghost_result and not ghost_result.get("models_agree"):
        tier += 2
        reasons.append("ghost_disagree")

    # OTX not found but internally flagged → one tier down
    if otx_result and not otx_result.get("otx_found") and otx_result.get("otx_confidence", 0) > 0.7:
        tier += 1
        reasons.append("otx_unseen_infrastructure")

    tier = min(tier, 5)  # cap at 5 unless override
    return tier, reasons

def compute_psi_drift(current_probs):
    """
    Population Stability Index — measures if model's probability
    distribution has shifted significantly from baseline.
    PSI > 0.2 = significant drift (industry standard threshold).
    """
    if model_state["last_probability_dist"] is None:
        model_state["last_probability_dist"] = current_probs
        return 0.0

    baseline = model_state["last_probability_dist"]
    current = current_probs

    if not baseline or not current:
        return 0.0

    # Simplified PSI — compare mean probability shift
    baseline_mean = sum(baseline) / len(baseline)
    current_mean = sum(current) / len(current)

    psi_approx = abs(current_mean - baseline_mean)
    model_state["last_probability_dist"] = current_probs
    return round(psi_approx, 4)

def update_reliability_grade(flagged_this_batch, current_probs):
    """
    Axis 2 — Reliability grading per model, rolling window.
    Degrades on: high flagged rate, PSI drift.
    Recovers on: sustained clean windows.
    """
    if model_state.get("locked"):
        return model_state["grade"], 0.0, 0.0
    
    current_grade = model_state["grade"]
    current_index = GRADE_ORDER.index(current_grade)

    # Add to rolling window
    model_state["prediction_window"].extend(
        [1 if f else 0 for f in flagged_this_batch]
    )
    model_state["flagged_count"] = sum(model_state["prediction_window"])

    # Compute flagged rate in current window
    window_size = len(model_state["prediction_window"])
    flagged_rate = model_state["flagged_count"] / window_size if window_size > 0 else 0

    # Check PSI drift
    psi = compute_psi_drift(current_probs)

    # Degrade conditions
    degraded = False
    if flagged_rate > FLAGGED_RATE_THRESHOLD:
        current_index = min(current_index + 1, len(GRADE_ORDER) - 1)
        degraded = True
        print(f"  [Grading] Reliability degraded: flagged_rate={flagged_rate:.1%} "
              f"> threshold {FLAGGED_RATE_THRESHOLD:.0%}")

    if psi > PSI_DRIFT_THRESHOLD:
        current_index = min(current_index + 1, len(GRADE_ORDER) - 1)
        degraded = True
        print(f"  [Grading] Reliability degraded: PSI drift={psi:.3f} "
              f"> threshold {PSI_DRIFT_THRESHOLD}")

    # Recovery condition — sustained clean window
    if not degraded and flagged_rate < FLAGGED_RATE_THRESHOLD * 0.5:
        model_state["clean_streak"] += 1
        if model_state["clean_streak"] >= 3:
            current_index = max(current_index - 1, 0)
            model_state["clean_streak"] = 0
            print(f"  [Grading] Reliability recovered after clean streak")
    else:
        model_state["clean_streak"] = 0

    model_state["grade"] = GRADE_ORDER[current_index]
    return model_state["grade"], flagged_rate, psi

def collapse_to_trust_score(credibility_tier, reliability_grade,
                             honeytoken_hit=False):
    """
    Collapse two axes into one float 0.0-1.0 for dashboard contract.
    Formula: flow_trust = min(normalized_credibility, normalized_reliability)
    Worst axis governs.
    Honeytoken/OTX override hard-floors to 0.05.
    """
    if honeytoken_hit:
        return 0.05

    normalized_credibility = CREDIBILITY_TIERS[credibility_tier]
    normalized_reliability = RELIABILITY_GRADES[reliability_grade]

    flow_trust = min(normalized_credibility, normalized_reliability)
    return round(flow_trust, 4)

def get_trust_status(trust_score):
    """Map trust score to status string matching dashboard contract."""
    if trust_score >= TRUST_TRUSTED:
        return "trusted"
    elif trust_score >= TRUST_SUSPICIOUS:
        return "suspicious"
    else:
        return "malicious"

def handle_idle_device(device_ip):
    """
    Idle device handling — decay toward neutral 0.5.
    Grace period: hold last score for IDLE_GRACE_CYCLES cycles.
    Then decay toward 0.5 — not zero, not trusted.
    Extended silence after recent activity = weak suspicion signal.
    """
    state = device_state[device_ip]
    state["idle_cycles"] += 1

    if state["idle_cycles"] <= IDLE_GRACE_CYCLES:
        # Grace period — hold last score
        return state["last_trust_score"], False

    # Decay toward neutral
    current = state["last_trust_score"]
    decayed = current + (IDLE_DECAY_TARGET - current) * 0.1
    state["last_trust_score"] = round(decayed, 4)

    # Extended silence after recent activity = weak suspicion
    suspicious_silence = state["recent_activity"] and state["idle_cycles"] > 10

    return state["last_trust_score"], suspicious_silence

def grade_flow(flow, shap_result=None, ghost_result=None,
               honeytoken_result=None, otx_result=None):
    """
    Main grading function for a single flow.
    Takes all module results, produces trust score and status.
    """
    device_ip = flow.get("src_ip", "unknown")

    # Compute credibility tier
    credibility_tier, reasons = compute_credibility_tier(
        shap_result, ghost_result, honeytoken_result, otx_result
    )

    # Honeytoken override check
    honeytoken_hit = honeytoken_result and honeytoken_result.get("honeytoken_hit", False)

    # Collapse to trust score
    trust_score = collapse_to_trust_score(
        credibility_tier,
        model_state["grade"],
        honeytoken_hit=honeytoken_hit
    )

    status = get_trust_status(trust_score)

    # Update device state
    state = device_state[device_ip]
    state["last_trust_score"] = trust_score
    state["last_seen"] = time.time()
    state["idle_cycles"] = 0
    state["recent_activity"] = True

    print(f"  [Grading] {device_ip} | tier={credibility_tier} | "
          f"reliability={model_state['grade']} | "
          f"trust={trust_score} | status={status}")

    return {
        "device_ip": device_ip,
        "trust_score": trust_score,
        "status": status,
        "credibility_tier": credibility_tier,
        "reliability_grade": model_state["grade"],
        "reasons": reasons,
        "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }

def aggregate_device_trust(flow_results):
    """
    Per-device aggregation across 5-second window.
    Uses minimum trust score — NOT average.
    One real attack diluted by clean flows is still an attack.
    """
    device_scores = defaultdict(list)

    for result in flow_results:
        device_ip = result["device_ip"]
        device_scores[device_ip].append(result["trust_score"])

    aggregated = {}
    for device_ip, scores in device_scores.items():
        min_score = min(scores)
        status = get_trust_status(min_score)
        aggregated[device_ip] = {
            "device_ip": device_ip,
            "trust_score": min_score,
            "status": status,
            "flow_count": len(scores),
            "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        print(f"  [Grading] Device {device_ip}: "
              f"min_trust={min_score} ({len(scores)} flows) → {status}")

    return aggregated

if __name__ == "__main__":
    print("=== Two-Axis Grading Test ===\n")

    # Scenario 1: Clean flow — no flags
    print("--- Scenario 1: Clean flow ---")
    clean_flow = {"src_ip": "10.0.0.2", "probability_malicious": 0.12}
    result1 = grade_flow(clean_flow)
    print(f"  trust={result1['trust_score']} | status={result1['status']}\n")

    # Scenario 2: SHAP flags both doors
    print("--- Scenario 2: SHAP margin + fragile flags ---")
    shap_result = {
        "margin_flagged": True,
        "fragile_shap_flagged": True,
        "needs_deeper_inspection": True
    }
    flagged_flow = {"src_ip": "10.0.0.3", "probability_malicious": 0.52}
    result2 = grade_flow(flagged_flow, shap_result=shap_result)
    print(f"  trust={result2['trust_score']} | status={result2['status']}\n")

    # Scenario 3: Ghost model disagrees
    print("--- Scenario 3: Ghost model disagrees ---")
    ghost_result = {
        "models_agree": False,
        "ghost_prob_malicious": 0.85,
        "ai_prob_malicious": 0.30
    }
    ghost_flow = {"src_ip": "10.0.0.4", "probability_malicious": 0.30}
    result3 = grade_flow(ghost_flow, ghost_result=ghost_result)
    print(f"  trust={result3['trust_score']} | status={result3['status']}\n")

    # Scenario 4: Honeytoken hit — certainty override
    print("--- Scenario 4: Honeytoken hit ---")
    honeytoken_result = {
        "honeytoken_hit": True,
        "trust_override": True,
        "action_taken": "isolate"
    }
    honey_flow = {"src_ip": "10.0.0.7", "probability_malicious": 0.43}
    result4 = grade_flow(honey_flow, honeytoken_result=honeytoken_result)
    print(f"  trust={result4['trust_score']} | status={result4['status']}\n")

    # Scenario 5: Per-device aggregation
    print("--- Scenario 5: Device aggregation (min not average) ---")
    batch_results = [
        {"device_ip": "10.0.0.5", "trust_score": 0.90},
        {"device_ip": "10.0.0.5", "trust_score": 0.85},
        {"device_ip": "10.0.0.5", "trust_score": 0.10},  # one bad flow
        {"device_ip": "10.0.0.5", "trust_score": 0.88},
        {"device_ip": "10.0.0.6", "trust_score": 0.92},
    ]
    aggregated = aggregate_device_trust(batch_results)
    print(f"\n  10.0.0.5 final trust: {aggregated['10.0.0.5']['trust_score']} "
          f"(not averaged — minimum governs)")