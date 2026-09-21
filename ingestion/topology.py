# ─── Topology Validation ──────────────────────────────────────────────────────
# Validates device_ip against network team's /topology/hosts endpoint.
# Dashboard contract: topology refreshes every 30s, flows every 5s.
# Unrecognized device_ip → held in pending buffer, not discarded.
# Could be brand new legitimate device OR spoofed IP — can't tell on first sight.
#
# NOTE: Depends on network team's Mininet environment being live.
# TOPOLOGY_URL below must be updated when they confirm their endpoint.
# Until then: all IPs pass through as "unvalidated" — safe for local testing.

import sys
import os
import requests
import time
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─── Configuration ────────────────────────────────────────────────────────────
TOPOLOGY_URL = "http://localhost:8081/topology/hosts"  # update with real URL
TOPOLOGY_REFRESH_INTERVAL = 30  # seconds — matches dashboard contract

# ─── Topology state ───────────────────────────────────────────────────────────
known_hosts = set()           # IPs confirmed in topology
pending_buffer = {}           # device_ip → {flow, first_seen, retry_count}
last_topology_refresh = 0     # Unix timestamp of last successful refresh

def refresh_topology():
    """
    Pull latest known hosts from network team's /topology/hosts endpoint.
    Refreshes every 30 seconds per dashboard contract.
    Returns True if successful, False if endpoint unavailable.
    """
    global known_hosts, last_topology_refresh

    try:
        response = requests.get(TOPOLOGY_URL, timeout=5)
        if response.status_code == 200:
            data = response.json()
            hosts = data.get("hosts", [])
            known_hosts = set(h.get("ip", "") for h in hosts)
            last_topology_refresh = time.time()
            print(f"  [Topology] Refreshed — {len(known_hosts)} known hosts")
            return True
        else:
            print(f"  [Topology] Refresh failed — HTTP {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        # Network team endpoint not available yet — expected in local testing
        print(f"  [Topology] Endpoint unavailable — running unvalidated mode")
        return False
    except Exception as e:
        print(f"  [Topology] Error: {e}")
        return False

def should_refresh():
    """Check if topology refresh is due."""
    return time.time() - last_topology_refresh > TOPOLOGY_REFRESH_INTERVAL

def validate_device(flow):
    """
    Check if flow's src_ip is a known topology host.
    Returns validation status:
    - 'known'       → IP confirmed in topology, process normally
    - 'pending'     → IP not in topology yet, held in buffer
    - 'unvalidated' → topology endpoint unavailable, pass through
    """
    global last_topology_refresh

    # Refresh topology if due
    if should_refresh():
        refresh_topology()

    src_ip = flow.get("src_ip", "unknown")

    # If topology unavailable — unvalidated mode, pass through
    if not known_hosts and last_topology_refresh == 0:
        return "unvalidated", flow

    # Known host — process normally
    if src_ip in known_hosts:
        return "known", flow

    # Unknown host — add to pending buffer
    if src_ip not in pending_buffer:
        pending_buffer[src_ip] = {
            "flow": flow,
            "first_seen": time.time(),
            "retry_count": 0
        }
        print(f"  [Topology] Unknown IP {src_ip} → pending buffer "
              f"(could be new device or spoofed)")
        return "pending", None

    # Already in pending — increment retry
    pending_buffer[src_ip]["retry_count"] += 1

    # After 3 retries — treat as suspicious unknown
    if pending_buffer[src_ip]["retry_count"] >= 3:
        print(f"  [Topology] {src_ip} persists as unknown after 3 cycles "
              f"→ flagging as suspicious")
        flow["topology_suspicious"] = True
        return "suspicious_unknown", flow

    return "pending", None

def flush_pending_buffer():
    """
    Re-check pending buffer against latest topology.
    Called after each topology refresh.
    Returns list of flows that can now be processed.
    """
    released = []
    still_pending = {}

    for ip, record in pending_buffer.items():
        if ip in known_hosts:
            print(f"  [Topology] {ip} now recognized — releasing from buffer")
            released.append(record["flow"])
        else:
            still_pending[ip] = record

    pending_buffer.clear()
    pending_buffer.update(still_pending)
    return released

if __name__ == "__main__":
    print("=== Topology Validation Test ===\n")

    # Test with endpoint unavailable — should run in unvalidated mode
    print("--- Test 1: Endpoint unavailable ---")
    flow = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1",
            "probability_malicious": 0.3}
    status, validated_flow = validate_device(flow)
    print(f"  Status: {status} | Flow passed through: {validated_flow is not None}\n")

    # Simulate known hosts loaded
    print("--- Test 2: Known host ---")
    known_hosts.add("10.0.0.5")
    last_topology_refresh = time.time()
    status, validated_flow = validate_device(flow)
    print(f"  Status: {status} | Flow passed through: {validated_flow is not None}\n")

    # Test unknown host
    print("--- Test 3: Unknown host → pending buffer ---")
    unknown_flow = {"src_ip": "10.0.0.99", "dst_ip": "10.0.0.1",
                    "probability_malicious": 0.7}
    status, validated_flow = validate_device(unknown_flow)
    print(f"  Status: {status} | Flow passed through: {validated_flow is not None}")
    print(f"  Pending buffer size: {len(pending_buffer)}")