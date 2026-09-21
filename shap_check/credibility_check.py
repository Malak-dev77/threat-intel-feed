# ─── SHAP Credibility Check ───────────────────────────────────────────────────
# Two independent doors — both always run, neither gates the other.
# Door 1: Probability margin check — is the model confident?
# Door 2: Fragile SHAP check — is that confidence built on fakeable features?
# Either door flagging = flow needs deeper inspection downstream.

import sys
import os
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import (
    PROBABILITY_MARGIN_LOW,
    PROBABILITY_MARGIN_HIGH,
    FRAGILE_SHAP_THRESHOLD
)

# Features an attacker can fake in a single crafted packet — zero cost
FRAGILE_FEATURES = {
    "ttl", "timestamp", "src_port", "dst_port",
    "packet_length", "payload_length", "src_mac", "dst_mac", "switch"
}

# Features requiring sustained real behavior over time to fake
ROBUST_FEATURES = {
    "flow_duration", "total_pkts", "total_bytes", "packet_rate",
    "byte_rate", "avg_packet_size", "tcp", "udp", "icmp", "arp",
    "http", "https", "dns", "ssh", "telnet", "smtp",
    "syn_flag_number", "ack_flag_number", "fin_flag_number",
    "rst_flag_number", "psh_flag_number"
}

def check_probability_margin(flow):
    """
    Door 1 — Margin check.
    If probability sits in ambiguous band (0.35–0.65), model wasn't confident.
    Returns True if flagged.
    """
    prob_malicious = flow.get("probability_malicious", 0.5)
    flagged = PROBABILITY_MARGIN_LOW <= prob_malicious <= PROBABILITY_MARGIN_HIGH
    if flagged:
        print(f"  [SHAP] Margin flag: probability_malicious={prob_malicious} "
              f"sits in ambiguous band ({PROBABILITY_MARGIN_LOW}–{PROBABILITY_MARGIN_HIGH})")
    return flagged

def check_fragile_shap(flow, shap_values=None):
    """
    Door 2 — Fragile SHAP check.
    If fragile features account for >30% of total SHAP contribution, flag it.
    Uses real SHAP values if available, falls back to mock values for now.
    Returns True if flagged, plus the fragile contribution percentage.
    """
    if shap_values is None:
        # Surrogate SHAP values — random mock until AI team provides model file
        # Each feature gets a random contribution weight
        all_features = list(FRAGILE_FEATURES | ROBUST_FEATURES)
        raw = np.abs(np.random.uniform(0.01, 0.5, len(all_features)))
        shap_values = dict(zip(all_features, raw))

    total_weight = sum(abs(v) for v in shap_values.values())
    if total_weight == 0:
        return False, 0.0

    fragile_weight = sum(
        abs(shap_values.get(f, 0)) for f in FRAGILE_FEATURES
    )
    fragile_pct = fragile_weight / total_weight

    flagged = fragile_pct > FRAGILE_SHAP_THRESHOLD
    if flagged:
        print(f"  [SHAP] Fragile flag: {fragile_pct:.1%} of SHAP weight "
              f"on attacker-manipulable features (threshold: {FRAGILE_SHAP_THRESHOLD:.0%})")
    return flagged, fragile_pct

def run_credibility_check(flow):
    """
    Run both doors on a single flow.
    Returns a result dictionary with flags and details.
    """
    print(f"  [SHAP] Checking flow: {flow['src_ip']} → {flow['dst_ip']} "
          f"| malicious={flow['probability_malicious']}")

    margin_flagged = check_probability_margin(flow)
    fragile_flagged, fragile_pct = check_fragile_shap(flow)

    result = {
        "flow": flow,
        "margin_flagged": margin_flagged,
        "fragile_shap_flagged": fragile_flagged,
        "fragile_shap_pct": round(fragile_pct, 4),
        "needs_deeper_inspection": margin_flagged or fragile_flagged
    }

    if result["needs_deeper_inspection"]:
        print(f"  [SHAP] → FLAGGED for deeper inspection")
    else:
        print(f"  [SHAP] → CLEAN — no flags")

    return result

if __name__ == "__main__":
    # Test with three hand-built flows covering all cases
    test_flows = [
        {   # Case 1: Ambiguous margin — should trigger Door 1
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "probability_malicious": 0.52, "probability_benign": 0.48,
            "ttl": 64, "timestamp": "2026-09-20T10:00:00Z",
            "src_port": 12345, "dst_port": 80
        },
        {   # Case 2: Confident but potentially fragile — tests Door 2
            "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4",
            "probability_malicious": 0.92, "probability_benign": 0.08,
            "ttl": 64, "timestamp": "2026-09-20T10:00:01Z",
            "src_port": 54321, "dst_port": 443
        },
        {   # Case 3: Clean — confident and should pass
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6",
            "probability_malicious": 0.08, "probability_benign": 0.92,
            "ttl": 128, "timestamp": "2026-09-20T10:00:02Z",
            "src_port": 8080, "dst_port": 22
        }
    ]

    print("=== SHAP Credibility Check Test ===\n")
    for i, flow in enumerate(test_flows):
        print(f"--- Flow {i+1} ---")
        result = run_credibility_check(flow)
        print(f"  Result: margin_flagged={result['margin_flagged']} | "
              f"fragile_flagged={result['fragile_shap_flagged']} | "
              f"fragile_pct={result['fragile_shap_pct']:.1%}\n")