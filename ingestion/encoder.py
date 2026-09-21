# ─── Flow Encoder ─────────────────────────────────────────────────────────────
# Converts raw ingested flow data into clean numeric format.
# Raw flows contain string timestamps, MAC addresses, switch IDs —
# none of these are numeric and SHAP/ghost model need clean numbers.
# This step runs between ingestion and credibility check.

import sys
import os
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fields to keep as-is for routing/identification — not fed to models
IDENTIFIER_FIELDS = {"src_ip", "dst_ip", "src_mac", "dst_mac",
                     "probability_malicious", "probability_benign",
                     "attack_type"}

# Numeric fields — pass through directly
NUMERIC_FIELDS = {
    "ttl", "tcp", "udp", "icmp", "arp", "http", "https", "dns",
    "ssh", "telnet", "smtp", "syn_flag_number", "ack_flag_number",
    "fin_flag_number", "rst_flag_number", "psh_flag_number",
    "packet_length", "payload_length", "flow_duration", "total_pkts",
    "total_bytes", "packet_rate", "byte_rate", "avg_packet_size",
    "src_port", "dst_port"
}

def encode_timestamp(ts_string):
    """
    Convert ISO timestamp string to Unix epoch float.
    Example: "2026-09-20T10:00:00Z" → 1758340800.0
    """
    try:
        dt = datetime.strptime(ts_string, "%Y-%m-%dT%H:%M:%SZ")
        return dt.timestamp()
    except Exception:
        return 0.0

def encode_mac(mac_string):
    """
    Convert MAC address string to integer.
    Example: "00:00:00:00:00:07" → 7
    """
    try:
        return int(mac_string.replace(":", ""), 16)
    except Exception:
        return 0

def encode_flow(flow):
    """
    Convert one raw flow dict into clean numeric format.
    Keeps identifier fields intact for routing.
    Returns encoded flow dict ready for SHAP and ghost model.
    """
    encoded = {}

    for key, value in flow.items():
        if key in IDENTIFIER_FIELDS:
            # Keep as-is — used for routing, not model input
            encoded[key] = value

        elif key == "timestamp":
            encoded["timestamp_epoch"] = encode_timestamp(str(value))

        elif key in ("src_mac", "dst_mac"):
            # Already in IDENTIFIER_FIELDS but encode numeric version too
            encoded[f"{key}_int"] = encode_mac(str(value))

        elif key == "switch":
            # Switch ID — keep as integer
            encoded["switch"] = int(value) if value else 0

        elif key in NUMERIC_FIELDS:
            # Numeric fields — ensure float
            try:
                encoded[key] = float(value)
            except (ValueError, TypeError):
                encoded[key] = 0.0

        else:
            # Unknown field — pass through as-is
            encoded[key] = value

    return encoded

def encode_batch(flows):
    """
    Encode a batch of flows.
    Returns list of encoded flow dicts.
    """
    encoded_flows = []
    for flow in flows:
        encoded = encode_flow(flow)
        encoded_flows.append(encoded)
    return encoded_flows

if __name__ == "__main__":
    print("=== Flow Encoder Test ===\n")

    raw_flow = {
        "timestamp": "2026-09-20T10:00:00Z",
        "switch": 3,
        "src_mac": "00:00:00:00:00:05",
        "dst_mac": "00:00:00:00:00:07",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 45218,
        "dst_port": 80,
        "ttl": 64,
        "tcp": 1,
        "udp": 0,
        "icmp": 0,
        "arp": 0,
        "http": 1,
        "https": 0,
        "dns": 0,
        "ssh": 0,
        "telnet": 0,
        "smtp": 0,
        "syn_flag_number": 2,
        "ack_flag_number": 5,
        "fin_flag_number": 0,
        "rst_flag_number": 0,
        "psh_flag_number": 1,
        "packet_length": 512,
        "payload_length": 480,
        "flow_duration": 2.5,
        "total_pkts": 150,
        "total_bytes": 76800,
        "packet_rate": 60.0,
        "byte_rate": 30720.0,
        "avg_packet_size": 512.0,
        "probability_malicious": 0.12,
        "probability_benign": 0.88
    }

    print("Raw flow:")
    for k, v in raw_flow.items():
        print(f"  {k}: {v} ({type(v).__name__})")

    print("\nEncoded flow:")
    encoded = encode_flow(raw_flow)
    for k, v in encoded.items():
        print(f"  {k}: {v} ({type(v).__name__})")

    print(f"\nRaw fields: {len(raw_flow)} → Encoded fields: {len(encoded)}")