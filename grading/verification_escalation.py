# ─── Verification Escalation ──────────────────────────────────────────────────
# Handles flows that land in the suspicious zone (0.50–0.79).
# These are flows where AI team said malicious but we need stronger evidence.
# We don't leave uncertain flows open — we demand more evidence.
#
# Three escalation checks:
# 1. OTX — is this IP in any known threat feed?
# 2. Pattern accumulation — does behavior strengthen over time?
# 3. Honeytoken — did this source ever touch a decoy asset?
#
# After checks:
# - Evidence strengthens → confirm malicious (trust drops below 0.49)
# - Evidence clears it → trust improves (trust rises above 0.80)
# - Still uncertain → quarantine pending more data

import sys
import os
import time
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import TRUST_SUSPICIOUS, TRUST_TRUSTED

# ─── Escalation tracking ──────────────────────────────────────────────────────
# Tracks flows pending verification
pending_verification = {}  # flow_id/src_ip → escalation record

# Evidence accumulation per source IP
ip_evidence = defaultdict(lambda: {
    "suspicious_count": 0,
    "clean_count": 0,
    "otx_flagged": False,
    "honeytoken_hit": False,
    "first_seen": None,
    "last_seen": None,
    "flows": []
})

def should_escalate(trust_score, ai_prediction):
    """
    Decide if a flow needs escalation.
    Escalate when:
    - Trust score in suspicious zone (0.50–0.79)
    - AND AI team said it was malicious
    """
    in_suspicious_zone = TRUST_SUSPICIOUS <= trust_score <= 0.79
    ai_says_malicious = ai_prediction not in ["normal", "allow", None, ""]
    return in_suspicious_zone and ai_says_malicious

def accumulate_evidence(src_ip, trust_score, otx_result=None,
                        honeytoken_result=None, flow=None):
    """
    Accumulate evidence for a suspicious source IP over time.
    Each new flow from this IP adds to the evidence picture.
    """
    now = time.time()
    evidence = ip_evidence[src_ip]

    if evidence["first_seen"] is None:
        evidence["first_seen"] = now
    evidence["last_seen"] = now

    # Track suspicious vs clean flows from this source
    if trust_score <= 0.79:
        evidence["suspicious_count"] += 1
    else:
        evidence["clean_count"] += 1

    # OTX corroboration
    if otx_result and otx_result.get("otx_found") and \
       otx_result.get("otx_pulse_count", 0) > 0:
        evidence["otx_flagged"] = True

    # Honeytoken certainty
    if honeytoken_result and honeytoken_result.get("honeytoken_hit"):
        evidence["honeytoken_hit"] = True

    if flow:
        evidence["flows"].append(trust_score)
        # Keep last 20 flows only
        if len(evidence["flows"]) > 20:
            evidence["flows"] = evidence["flows"][-20:]

    return evidence

def make_escalation_decision(src_ip, current_trust, evidence):
    """
    Make final decision on uncertain flow based on accumulated evidence.

    Returns:
    - final_trust: adjusted trust score
    - verdict: "confirmed_malicious" | "cleared" | "quarantine_pending"
    - reason: explanation
    """
    suspicious_count = evidence["suspicious_count"]
    clean_count = evidence["clean_count"]
    otx_flagged = evidence["otx_flagged"]
    honeytoken_hit = evidence["honeytoken_hit"]
    total_flows = suspicious_count + clean_count

    # ── Certainty signals — immediate confirmation ─────────────────────────
    if honeytoken_hit:
        return 0.05, "confirmed_malicious", "honeytoken_hit_confirms_threat"

    if otx_flagged:
        return 0.10, "confirmed_malicious", "otx_corroborates_ai_prediction"

    # ── Pattern strengthening — accumulated suspicious behavior ────────────
    if total_flows >= 5:
        suspicious_ratio = suspicious_count / total_flows

        if suspicious_ratio >= 0.80:
            # 80%+ of flows from this IP are suspicious — confirm malicious
            return 0.20, "confirmed_malicious", \
                f"pattern_confirmed_{suspicious_count}/{total_flows}_suspicious_flows"

        elif suspicious_ratio <= 0.20:
            # 80%+ of flows are clean — clear it
            return 0.90, "cleared", \
                f"pattern_cleared_{clean_count}/{total_flows}_clean_flows"

    # ── Still uncertain — quarantine pending more data ─────────────────────
    if total_flows < 5:
        reason = f"insufficient_evidence_{total_flows}_flows_seen"
    else:
        reason = f"mixed_signals_{suspicious_count}suspicious_{clean_count}clean"

    return current_trust, "quarantine_pending", reason

def run_escalation(flow, trust_score, ai_prediction,
                   otx_result=None, honeytoken_result=None):
    """
    Main escalation entry point.
    Called when a flow lands in the suspicious zone.
    Returns escalation result with verdict and adjusted trust score.
    """
    src_ip = flow.get("src_ip", "unknown")

    print(f"  [Escalation] UNCERTAIN flow from {src_ip} | "
          f"trust={trust_score} | AI said: {ai_prediction}")

    # Accumulate evidence
    evidence = accumulate_evidence(
        src_ip, trust_score,
        otx_result=otx_result,
        honeytoken_result=honeytoken_result,
        flow=flow
    )

    # Make decision based on accumulated evidence
    final_trust, verdict, reason = make_escalation_decision(
        src_ip, trust_score, evidence
    )

    print(f"  [Escalation] Verdict: {verdict} | "
          f"final_trust={final_trust} | reason={reason}")
    print(f"  [Escalation] Evidence: "
          f"{evidence['suspicious_count']} suspicious, "
          f"{evidence['clean_count']} clean flows | "
          f"OTX: {evidence['otx_flagged']} | "
          f"Honeytoken: {evidence['honeytoken_hit']}")

    return {
        "src_ip": src_ip,
        "original_trust": trust_score,
        "final_trust": final_trust,
        "verdict": verdict,
        "reason": reason,
        "evidence_summary": {
            "suspicious_flows": evidence["suspicious_count"],
            "clean_flows": evidence["clean_count"],
            "otx_flagged": evidence["otx_flagged"],
            "honeytoken_hit": evidence["honeytoken_hit"],
            "total_flows_seen": evidence["suspicious_count"] + evidence["clean_count"]
        },
        "requires_human_review": verdict == "quarantine_pending",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }

if __name__ == "__main__":
    print("=== Verification Escalation Test ===\n")

    # Scenario 1: OTX confirms the AI team's malicious verdict
    print("--- Scenario 1: OTX corroborates malicious prediction ---")
    flow1 = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1"}
    otx_hit = {"otx_found": True, "otx_pulse_count": 15}
    result1 = run_escalation(flow1, 0.60, "malicious_post", otx_result=otx_hit)
    print(f"  Final trust: {result1['final_trust']} | "
          f"Verdict: {result1['verdict']}\n")

    # Scenario 2: Pattern accumulation confirms after 5 flows
    print("--- Scenario 2: Pattern accumulation over multiple flows ---")
    flow2 = {"src_ip": "10.0.0.7", "dst_ip": "10.0.0.1"}
    for i in range(6):
        result2 = run_escalation(flow2, 0.65, "syn_flood")
    print(f"  Final trust: {result2['final_trust']} | "
          f"Verdict: {result2['verdict']}\n")

    # Scenario 3: Insufficient evidence — quarantine pending
    print("--- Scenario 3: Not enough evidence yet ---")
    flow3 = {"src_ip": "10.0.0.9", "dst_ip": "10.0.0.1"}
    result3 = run_escalation(flow3, 0.55, "malicious_post")
    print(f"  Final trust: {result3['final_trust']} | "
          f"Verdict: {result3['verdict']}\n")

    # Scenario 4: Honeytoken certainty — immediate confirmation
    print("--- Scenario 4: Honeytoken hit — immediate confirmation ---")
    flow4 = {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.99"}
    honey_hit = {"honeytoken_hit": True}
    result4 = run_escalation(flow4, 0.70, "malicious_post",
                             honeytoken_result=honey_hit)
    print(f"  Final trust: {result4['final_trust']} | "
          f"Verdict: {result4['verdict']}\n")