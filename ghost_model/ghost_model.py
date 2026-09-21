# ─── Ghost Model ──────────────────────────────────────────────────────────────
# Independent second model — different algorithm, different feature set.
# Closes 5 documented gaps in commercial/academic SDN IoT detection systems:
# Gap 1: Single flow dependency → uses cross-flow rolling window features only
# Gap 2: Flash crowd false positives → destination diversity distinguishes them
# Gap 3: Blind to early attack signals → builds pattern from first packet
# Gap 4: Stealthy low-rate evasion → rate variance + inter-arrival variance
# Gap 5: Individual packet data leakage → all features require multiple flows
#
# Triggered by OR logic: SHAP Door 1 OR risk-weighted sampler Door 2
# Agreement with AI team model → credibility holds
# Disagreement → credibility drops multiple tiers (strongest signal in pipeline)

import sys
import os
import time
import numpy as np
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─── Cross-flow behavioral memory ─────────────────────────────────────────────
# Tracks patterns ACROSS flows per source IP.
# An attacker studying the public UNB CIC IoT 2023 schema sees per-flow
# features only. These rolling statistics are invisible to them.

flow_history = defaultdict(list)        # src_ip → list of recent flows
arrival_times = defaultdict(list)       # src_ip → list of flow arrival timestamps

def extract_ghost_features(flow, src_ip):
    """
    Build 7-feature ghost vector from cross-flow behavioral patterns.
    All 7 features require observing multiple flows over time.
    None appear in the AI team's published feature schema.
    """
    recent = flow_history[src_ip][-10:]
    times = arrival_times[src_ip][-10:]

    # Feature 1 — Burst rate
    # How many flows from this source in the last window
    # Closes Gap 3: catches early attack buildup before flow matures
    burst_rate = len(recent)

    # Feature 2 — Port diversity
    # How many unique destination ports used across recent flows
    # Closes Gap 2: flash crowd hits many ports, targeted flood hits one
    port_diversity = len(set(f.get("dst_port", 0) for f in recent)) if recent else 0

    # Feature 3 — Protocol consistency
    # Does this source stick to one protocol or mix them?
    # Closes Gap 4: hybrid attacks blend protocols to evade single-protocol rules
    tcp_ratio = (sum(f.get("tcp", 0) for f in recent) / len(recent)) if recent else 0

    # Feature 4 — Packet rate variance
    # Is traffic suspiciously uniform? Real traffic varies naturally.
    # Closes Gap 4: low-rate stealthy floods maintain unnaturally constant rate
    rates = [f.get("packet_rate", 0) for f in recent]
    rate_variance = (max(rates) - min(rates)) if len(rates) > 1 else 0

    # Feature 5 — SYN to ACK ratio over rolling window
    # High SYN, low ACK across multiple flows = SYN flood pattern
    # Closes Gap 5: requires observing pattern across flows, not single packet
    total_syn = sum(f.get("syn_flag_number", 0) for f in recent)
    total_ack = sum(f.get("ack_flag_number", 0) for f in recent)
    syn_ack_ratio = total_syn / (total_ack + 1)  # +1 avoids division by zero

    # Feature 6 — Destination diversity over time
    # How many unique destination IPs contacted across recent flows
    # Closes Gap 2: flash crowd spreads across many destinations, flood targets one
    dst_diversity = len(set(f.get("dst_ip", "") for f in recent)) if recent else 0

    # Feature 7 — Inter-arrival time variance
    # Time between consecutive flows from this source
    # Automated tools produce regular intervals. Real traffic is irregular.
    # Closes Gap 4: attackers cannot easily fake irregular timing across a window
    if len(times) > 1:
        intervals = [times[i] - times[i-1] for i in range(1, len(times))]
        interarrival_variance = max(intervals) - min(intervals)
    else:
        interarrival_variance = 0

    return {
        "burst_rate": burst_rate,
        "port_diversity": port_diversity,
        "tcp_ratio": round(tcp_ratio, 4),
        "rate_variance": round(rate_variance, 4),
        "syn_ack_ratio": round(syn_ack_ratio, 4),
        "dst_diversity": dst_diversity,
        "interarrival_variance": round(interarrival_variance, 4)
    }

def ghost_predict(ghost_features):
    """
    Rule-based heuristic — returns probability AND attack type.
    Attack type feeds /predictions and /alerts endpoints.
    """
    score = 0.0
    attack_type = "unclassified"

    # SYN flood signal — Gap 5
    if ghost_features["syn_ack_ratio"] > 3.0:
        score += 0.30
        attack_type = "syn_flood"

    # Stealthy uniform rate — Gap 4
    if ghost_features["rate_variance"] < 10.0 and ghost_features["burst_rate"] > 3:
        score += 0.20
        if attack_type == "unclassified":
            attack_type = "low_rate_flood"

    # Automated regular timing — Gap 4
    if ghost_features["interarrival_variance"] < 0.05 and ghost_features["burst_rate"] > 3:
        score += 0.20
        if attack_type == "unclassified":
            attack_type = "automated_flood"

    # Targeted flood — Gap 2
    if ghost_features["burst_rate"] > 7 and ghost_features["dst_diversity"] == 1:
        score += 0.20
        if attack_type == "unclassified":
            attack_type = "targeted_flood"

    # Port scan — Gap 2
    if ghost_features["port_diversity"] > 5:
        score += 0.15
        if attack_type == "unclassified":
            attack_type = "port_scan"

    # Hybrid protocol blending — Gap 4
    if 0.3 < ghost_features["tcp_ratio"] < 0.7 and ghost_features["burst_rate"] > 5:
        score += 0.10
        if attack_type == "unclassified":
            attack_type = "hybrid_flood"

    # If score is low — benign
    if score < 0.3:
        attack_type = "benign"

    return min(round(score, 4), 1.0), attack_type

def run_ghost_check(flow):
    """
    Main entry point — called when SHAP Door 1 OR sampler Door 2 triggers.
    Updates flow history, extracts 7 ghost features, predicts, compares.
    Returns agreement status and ghost probability for grading module.
    """
    src_ip = flow.get("src_ip", "unknown")
    now = time.time()

    # Update rolling history
    flow_history[src_ip].append(flow)
    arrival_times[src_ip].append(now)

    # Keep only last 20 flows per IP to avoid memory growth
    if len(flow_history[src_ip]) > 20:
        flow_history[src_ip] = flow_history[src_ip][-20:]
        arrival_times[src_ip] = arrival_times[src_ip][-20:]

    ghost_features = extract_ghost_features(flow, src_ip)
    ghost_prob_malicious, attack_type = ghost_predict(ghost_features)
    ai_prob_malicious = flow.get("probability_malicious", 0.5)

    # Agreement: both models agree on which side of 0.5 the flow sits
    ai_says_malicious = ai_prob_malicious > 0.5
    ghost_says_malicious = ghost_prob_malicious > 0.5
    models_agree = ai_says_malicious == ghost_says_malicious

    status = "AGREE" if models_agree else "DISAGREE ← credibility drops multiple tiers"
    print(f"  [Ghost] src={src_ip} | AI={ai_prob_malicious:.3f} | "
          f"Ghost={ghost_prob_malicious:.3f} | {status}")

    return {
        "ghost_prob_malicious": ghost_prob_malicious,
        "ghost_features": ghost_features,
        "models_agree": models_agree,
        "ai_prob_malicious": ai_prob_malicious,
        "attack_type": attack_type
    }

if __name__ == "__main__":
    print("=== Ghost Model Test — 3 Scenarios ===\n")

    # Scenario 1: SYN flood — AI uncertain, ghost should catch it
    print("--- Scenario 1: SYN Flood (AI uncertain at 0.45) ---")
    for i in range(10):
        flow = {
            "src_ip": "10.0.0.3", "dst_ip": "10.0.0.1",
            "probability_malicious": 0.45, "probability_benign": 0.55,
            "syn_flag_number": 8, "ack_flag_number": 1,
            "dst_port": 80, "tcp": 1, "packet_rate": 950.0,
        }
        result = run_ghost_check(flow)
        time.sleep(0.01)  # simulate regular inter-arrival (automated tool)
    print(f"  Ghost probability: {result['ghost_prob_malicious']}")
    print(f"  Models agree: {result['models_agree']}")
    print(f"  Ghost features: {result['ghost_features']}\n")

    # Scenario 2: Flash crowd — should NOT be flagged as attack
    print("--- Scenario 2: Flash Crowd (many destinations, varied rates) ---")
    for i in range(10):
        flow = {
            "src_ip": "10.0.0.5", "dst_ip": f"10.0.0.{i+1}",
            "probability_malicious": 0.55, "probability_benign": 0.45,
            "syn_flag_number": 1, "ack_flag_number": 3,
            "dst_port": 80 + i, "tcp": 1,
            "packet_rate": 100.0 + (i * 47.3),  # varied rate
        }
        result = run_ghost_check(flow)
        time.sleep(0.1 + (i * 0.03))  # irregular inter-arrival (real traffic)
    print(f"  Ghost probability: {result['ghost_prob_malicious']}")
    print(f"  Models agree: {result['models_agree']}")
    print(f"  Ghost features: {result['ghost_features']}\n")

    # Scenario 3: Stealthy low-rate evasion — constant rate, single target
    print("--- Scenario 3: Stealthy Low-Rate Evasion ---")
    for i in range(10):
        flow = {
            "src_ip": "10.0.0.7", "dst_ip": "10.0.0.2",
            "probability_malicious": 0.38, "probability_benign": 0.62,
            "syn_flag_number": 2, "ack_flag_number": 1,
            "dst_port": 443, "tcp": 1,
            "packet_rate": 45.0,  # suspiciously constant low rate
        }
        result = run_ghost_check(flow)
        time.sleep(0.05)  # very regular timing
    print(f"  Ghost probability: {result['ghost_prob_malicious']}")
    print(f"  Models agree: {result['models_agree']}")
    print(f"  Ghost features: {result['ghost_features']}\n")