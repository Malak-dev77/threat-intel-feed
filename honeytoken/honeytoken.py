# ─── Honeytoken Correlation ───────────────────────────────────────────────────
# The only certainty signal in the pipeline — not probabilistic.
# A honeytoken is a decoy asset with NO legitimate reason to ever be touched.
# Any interaction = proof. Zero false positives by design.
#
# Two gaps closed vs commercial honeytoken products:
# Gap 1: Commercial tools alert but lack context — we cross-reference hit
#         against exact flow behavioral data already in the pipeline, free.
# Gap 2: Commercial tools treat each hit in isolation — our reliability grade
#         tracks patterns over rolling window, hits fold in automatically.
#
# Known limitation (from academic literature, documented honestly):
# Generic/templated honeytokens can become recognizable to sophisticated
# attackers who learn to spot the pattern. Not solved here — worth noting
# in the paper as an open weakness in the category.
#
# Deployment: inside Network team's Mininet topology — not our infrastructure.
# Honeytoken types: fake credentials, fake endpoints, fake device IPs.

import sys
import os
import time
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─── Honeytoken Registry ──────────────────────────────────────────────────────
# These are decoy assets deployed in the Mininet topology.
# Any flow touching these IPs/ports is immediately suspicious.
# Update with real values once Network team confirms deployment.

HONEYTOKEN_IPS = {
    "10.0.0.99",   # fake device — no legitimate traffic should ever reach this
    "10.0.0.100",  # fake server — placeholder
}

HONEYTOKEN_PORTS = {
    9999,   # fake service port — nothing legitimate runs here
    65535,  # fake management port
}

HONEYTOKEN_CREDENTIALS = {
    "admin:honeypass123",   # fake credential pair — if seen in payload, proof
    "root:fakeroot456",
}

# ─── Hit log — for rolling window correlation ─────────────────────────────────
honeytoken_hits = []  # list of {timestamp, src_ip, flow, hit_type}
hits_by_src = defaultdict(list)  # src_ip → list of hit timestamps

def is_honeytoken_hit(flow):
    """
    Check if this flow touches any honeytoken asset.
    Returns (bool: is_hit, str: hit_type)
    Hit types: 'honeytoken_ip', 'honeytoken_port', 'both'
    """
    dst_ip = flow.get("dst_ip", "")
    dst_port = flow.get("dst_port", 0)

    ip_hit = dst_ip in HONEYTOKEN_IPS
    port_hit = dst_port in HONEYTOKEN_PORTS

    if ip_hit and port_hit:
        return True, "both"
    elif ip_hit:
        return True, "honeytoken_ip"
    elif port_hit:
        return True, "honeytoken_port"
    return False, None

def get_flow_context(flow, hit_type):
    """
    Cross-reference honeytoken hit against flow behavioral data.
    This is Gap 1 closure — commercial tools give alert with no context.
    We attach the full behavioral signature at the moment of the hit.
    """
    return {
        "hit_type": hit_type,
        "src_ip": flow.get("src_ip", "unknown"),
        "dst_ip": flow.get("dst_ip", "unknown"),
        "dst_port": flow.get("dst_port", 0),
        "packet_rate": flow.get("packet_rate", 0),
        "byte_rate": flow.get("byte_rate", 0),
        "flow_duration": flow.get("flow_duration", 0),
        "syn_flag_number": flow.get("syn_flag_number", 0),
        "ack_flag_number": flow.get("ack_flag_number", 0),
        "total_pkts": flow.get("total_pkts", 0),
        "ai_probability_malicious": flow.get("probability_malicious", 0),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        # Novel threat intelligence flag — if no OTX record exists for this
        # src_ip, this hit represents threat intel nobody else has yet
        "novel_threat_candidate": True  # OTX module will update this
    }

def check_repeated_hits(src_ip, window_seconds=300):
    """
    Gap 2 closure — commercial tools treat hits in isolation.
    We track whether this source has hit honeytokens before
    within a rolling time window. Repeated hits = persistent attacker.
    Returns count of hits from this source in the window.
    """
    now = time.time()
    recent_hits = [
        t for t in hits_by_src[src_ip]
        if now - t < window_seconds
    ]
    return len(recent_hits)

def run_honeytoken_check(flow):
    """
    Main entry point — runs on every flow from the pipeline.
    Returns result dictionary for the grading module.
    A hit overrides trust score to near-zero regardless of other signals.
    """
    is_hit, hit_type = is_honeytoken_hit(flow)
    src_ip = flow.get("src_ip", "unknown")

    if not is_hit:
        return {
            "honeytoken_hit": False,
            "hit_type": None,
            "context": None,
            "repeated_hits": 0,
            "trust_override": False
        }

    # Hit confirmed — log it
    now = time.time()
    hit_record = {
        "timestamp": now,
        "src_ip": src_ip,
        "flow": flow,
        "hit_type": hit_type
    }
    honeytoken_hits.append(hit_record)
    hits_by_src[src_ip].append(now)

    # Cross-reference with flow behavioral context
    context = get_flow_context(flow, hit_type)

    # Check for repeated hits from same source
    repeated = check_repeated_hits(src_ip)

    print(f"  [Honeytoken] HIT CONFIRMED src={src_ip} | "
          f"type={hit_type} | repeated_hits={repeated}")
    print(f"  [Honeytoken] Context: rate={context['packet_rate']} "
          f"pkts={context['total_pkts']} "
          f"AI_prob={context['ai_probability_malicious']:.3f}")
    print(f"  [Honeytoken] → Trust override to 0.05 | "
          f"Alert queued for /alerts endpoint")

    return {
        "honeytoken_hit": True,
        "hit_type": hit_type,
        "context": context,
        "repeated_hits": repeated,
        "trust_override": True,
        "trust_score_floor": 0.05,  # hard floor — matches dashboard contract
        "alert_type": "honeytoken_access",
        "severity": "critical",
        "action_taken": "isolate"  # matches dashboard contract exactly
    }

if __name__ == "__main__":
    print("=== Honeytoken Test — 3 Scenarios ===\n")

    # Scenario 1: Clean flow — no honeytoken contact
    print("--- Scenario 1: Clean flow ---")
    clean_flow = {
        "src_ip": "10.0.0.3", "dst_ip": "10.0.0.2",
        "dst_port": 80, "packet_rate": 150.0,
        "byte_rate": 45000.0, "flow_duration": 2.5,
        "syn_flag_number": 1, "ack_flag_number": 3,
        "total_pkts": 50, "probability_malicious": 0.12
    }
    result = run_honeytoken_check(clean_flow)
    print(f"  Result: hit={result['honeytoken_hit']}\n")

    # Scenario 2: Flow hitting honeytoken IP
    print("--- Scenario 2: Honeytoken IP hit ---")
    honey_flow = {
        "src_ip": "10.0.0.7", "dst_ip": "10.0.0.99",
        "dst_port": 80, "packet_rate": 890.0,
        "byte_rate": 125000.0, "flow_duration": 0.8,
        "syn_flag_number": 12, "ack_flag_number": 1,
        "total_pkts": 450, "probability_malicious": 0.43
    }
    result = run_honeytoken_check(honey_flow)
    print(f"  Trust override: {result['trust_override']} | "
          f"Floor: {result.get('trust_score_floor')} | "
          f"Action: {result.get('action_taken')}\n")

    # Scenario 3: Same source hits again — repeated hit detection
    print("--- Scenario 3: Same source, repeated hit ---")
    honey_flow2 = {
        "src_ip": "10.0.0.7", "dst_ip": "10.0.0.100",
        "dst_port": 9999, "packet_rate": 920.0,
        "byte_rate": 130000.0, "flow_duration": 0.5,
        "syn_flag_number": 15, "ack_flag_number": 0,
        "total_pkts": 600, "probability_malicious": 0.38
    }
    result = run_honeytoken_check(honey_flow2)
    print(f"  Repeated hits from same source: {result['repeated_hits']}")
    print(f"  Novel threat candidate: "
          f"{result['context']['novel_threat_candidate']}")