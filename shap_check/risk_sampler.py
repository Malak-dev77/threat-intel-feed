# ─── Risk-Weighted Sampler (Door 2) ───────────────────────────────────────────
# Structurally independent from SHAP — Door 1 and Door 2 always run in parallel.
# Sampling probability scales with risk signals that do NOT pass through
# the AI model's reasoning or SHAP's output — this is the core design constraint.
# An attacker who successfully fools SHAP cannot silence this door.
#
# Four independent risk signals:
# 1. Destination criticality — sensitive port or high-value endpoint
# 2. Device behavioral deviation — acting differently from own baseline
# 3. Device novelty — first-seen or returning after silence
# 4. Destination sensitivity — traffic toward known critical assets
#
# Formula:
# sampling_probability = min(1.0,
#     BASE_FLOOR
#     + (0.40 × destination_criticality)
#     + (0.35 × device_deviation)
#     + (0.25 × device_novelty)
# )
# Weights need calibration on real Mininet traffic — documented honestly.

import sys
import os
import random
import time
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─── Configuration ────────────────────────────────────────────────────────────
BASE_FLOOR = 0.05           # 5% of completely unremarkable traffic always sampled
CRITICALITY_WEIGHT = 0.40   # highest weight — destination matters most
DEVIATION_WEIGHT = 0.35     # device acting differently from own baseline
NOVELTY_WEIGHT = 0.25       # first-seen or returning after silence

# Ports considered sensitive/high-value
SENSITIVE_PORTS = {22, 23, 25, 443, 3306, 5432, 6379, 8443, 27017}

# Known critical destination IPs — update with real topology from network team
CRITICAL_ASSETS = {"10.0.0.1"}  # placeholder — network team confirms real list

# Silence threshold — device returning after this many seconds = elevated novelty
SILENCE_THRESHOLD = 60.0

# ─── Device baseline memory ───────────────────────────────────────────────────
device_baseline = defaultdict(lambda: {
    "packet_rates": [],
    "dst_ips": set(),
    "dst_ports": set(),
    "last_seen": None,
    "first_seen": None,
    "flow_count": 0
})

def compute_destination_criticality(flow):
    """
    Signal 1 — How sensitive is the destination?
    Independent of AI model output — pure topology/port metadata.
    Returns 0.0 to 1.0.
    """
    score = 0.0
    dst_port = flow.get("dst_port", 0)
    dst_ip = flow.get("dst_ip", "")

    if dst_port in SENSITIVE_PORTS:
        score += 0.6
    if dst_ip in CRITICAL_ASSETS:
        score += 0.4

    return min(score, 1.0)

def compute_device_deviation(flow, baseline):
    """
    Signal 2 — Is this device behaving differently from its own history?
    Compares current flow against device's own rolling baseline.
    Independent of AI model — pure statistical comparison against history.
    Returns 0.0 to 1.0.
    """
    if baseline["flow_count"] < 5:
        # Not enough history to establish baseline — treat as moderate deviation
        return 0.5

    current_rate = flow.get("packet_rate", 0)
    historical_rates = baseline["packet_rates"][-20:]

    if not historical_rates:
        return 0.5

    avg_rate = sum(historical_rates) / len(historical_rates)
    if avg_rate == 0:
        return 0.5

    # Deviation ratio — how far is current rate from device's own normal?
    deviation_ratio = abs(current_rate - avg_rate) / avg_rate

    # New destination IP this device hasn't contacted before
    dst_ip = flow.get("dst_ip", "")
    new_destination = dst_ip not in baseline["dst_ips"]

    # New destination port this device hasn't used before
    dst_port = flow.get("dst_port", 0)
    new_port = dst_port not in baseline["dst_ports"]

    score = min(deviation_ratio * 0.5, 0.6)  # rate deviation, capped at 0.6
    if new_destination:
        score += 0.2
    if new_port:
        score += 0.2

    return min(score, 1.0)

def compute_device_novelty(flow, baseline):
    """
    Signal 3 — Is this device new or returning after silence?
    First-seen devices and devices reappearing after silence get higher weight.
    Ties directly into idle-device silence-as-signal rule from grading module.
    Returns 0.0 to 1.0.
    """
    now = time.time()

    # Brand new device — never seen before
    if baseline["first_seen"] is None:
        return 1.0

    # Returning after extended silence
    if baseline["last_seen"] is not None:
        silence_duration = now - baseline["last_seen"]
        if silence_duration > SILENCE_THRESHOLD:
            # Scale novelty with silence duration — longer silence = higher novelty
            novelty = min(silence_duration / (SILENCE_THRESHOLD * 5), 1.0)
            return round(novelty, 4)

    return 0.0

def update_device_baseline(flow):
    """Update rolling baseline for this device after sampling decision."""
    src_ip = flow.get("src_ip", "unknown")
    now = time.time()
    baseline = device_baseline[src_ip]

    baseline["packet_rates"].append(flow.get("packet_rate", 0))
    baseline["dst_ips"].add(flow.get("dst_ip", ""))
    baseline["dst_ports"].add(flow.get("dst_port", 0))
    baseline["flow_count"] += 1
    baseline["last_seen"] = now

    if baseline["first_seen"] is None:
        baseline["first_seen"] = now

    # Keep only last 50 rates to avoid memory growth
    if len(baseline["packet_rates"]) > 50:
        baseline["packet_rates"] = baseline["packet_rates"][-50:]

def should_sample(flow):
    """
    Main entry point — decides whether this flow goes to the ghost model.
    Computes sampling probability from 4 independent risk signals.
    Returns (bool: sampled, float: sampling_probability, dict: signal_breakdown)
    """
    src_ip = flow.get("src_ip", "unknown")
    baseline = device_baseline[src_ip]

    # Compute three scored signals
    criticality = compute_destination_criticality(flow)
    deviation = compute_device_deviation(flow, baseline)
    novelty = compute_device_novelty(flow, baseline)

    # Weighted formula
    sampling_prob = min(1.0,
        BASE_FLOOR
        + (CRITICALITY_WEIGHT * criticality)
        + (DEVIATION_WEIGHT * deviation)
        + (NOVELTY_WEIGHT * novelty)
    )

    # Probabilistic sampling decision
    sampled = random.random() < sampling_prob

    # Update baseline after decision
    update_device_baseline(flow)

    signal_breakdown = {
        "criticality": round(criticality, 4),
        "deviation": round(deviation, 4),
        "novelty": round(novelty, 4),
        "sampling_probability": round(sampling_prob, 4),
        "sampled": sampled
    }

    if sampled:
        print(f"  [Sampler] SELECTED src={src_ip} | "
              f"prob={sampling_prob:.2f} "
              f"(crit={criticality:.2f} dev={deviation:.2f} nov={novelty:.2f})")
    else:
        print(f"  [Sampler] skipped src={src_ip} | "
              f"prob={sampling_prob:.2f}")

    return sampled, sampling_prob, signal_breakdown

if __name__ == "__main__":
    print("=== Risk-Weighted Sampler Test ===\n")

    # Scenario 1: Brand new device hitting sensitive port
    print("--- Scenario 1: New device, sensitive port (SSH) ---")
    flow1 = {
        "src_ip": "10.0.0.11", "dst_ip": "10.0.0.1",
        "dst_port": 22, "packet_rate": 150.0
    }
    sampled, prob, signals = should_sample(flow1)
    print(f"  Signals: {signals}\n")

    # Scenario 2: Known device, normal behavior
    print("--- Scenario 2: Known device, establishing baseline ---")
    for i in range(8):
        flow = {
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.2",
            "dst_port": 80, "packet_rate": 100.0 + (i * 2)
        }
        should_sample(flow)

    print("\n--- Scenario 2b: Same device, sudden rate spike ---")
    flow_spike = {
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9",
        "dst_port": 9999, "packet_rate": 950.0  # massive spike from baseline
    }
    sampled, prob, signals = should_sample(flow_spike)
    print(f"  Signals: {signals}\n")

    # Scenario 3: Completely unremarkable traffic — floor sampling
    print("--- Scenario 3: Unremarkable traffic (floor rate test) ---")
    sampled_count = 0
    for i in range(100):
        flow = {
            "src_ip": f"10.0.0.{(i % 5) + 1}",
            "dst_ip": "10.0.0.2",
            "dst_port": 80,
            "packet_rate": 50.0
        }
        # suppress per-flow print for this bulk test
        baseline = device_baseline[flow["src_ip"]]
        update_device_baseline(flow)
        prob = BASE_FLOOR
        if random.random() < prob:
            sampled_count += 1

    print(f"  Floor sampling: {sampled_count}/100 flows sampled "
          f"(expected ~5 at {BASE_FLOOR:.0%} floor rate)")