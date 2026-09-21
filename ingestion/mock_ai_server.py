# ─── Mock AI Server ───────────────────────────────────────────────────────────
# Pretends to be the AI team's Random Forest prediction API.
# Returns fake flows in the exact same format the real API will use.
# When real API is ready: change AI_TEAM_URL in config/settings.py only.

from flask import Flask, jsonify
import random
import time

app = Flask(__name__)

# These are the exact feature names from the AI team's schema
FEATURES = [
    "timestamp", "switch", "src_mac", "dst_mac", "src_ip", "dst_ip",
    "src_port", "dst_port", "ttl", "tcp", "udp", "icmp", "arp",
    "http", "https", "dns", "ssh", "telnet", "smtp",
    "syn_flag_number", "ack_flag_number", "fin_flag_number",
    "rst_flag_number", "psh_flag_number", "packet_length",
    "payload_length", "flow_duration", "total_pkts", "total_bytes",
    "packet_rate", "byte_rate", "avg_packet_size"
]

def generate_fake_flow():
    """Generate one fake flow that looks like real SDN traffic processed by RF model."""
    src_ip = f"10.0.0.{random.randint(1, 10)}"
    
    # Random Forest output — probability vector
    prob_malicious = round(random.uniform(0.0, 1.0), 4)
    prob_benign = round(1.0 - prob_malicious, 4)
    
    return {
        # Flow features
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "switch": random.randint(1, 3),
        "src_mac": f"00:00:00:00:00:0{random.randint(1,9)}",
        "dst_mac": f"00:00:00:00:00:0{random.randint(1,9)}",
        "src_ip": src_ip,
        "dst_ip": f"10.0.0.{random.randint(1, 10)}",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 22, 23, 25, 53]),
        "ttl": random.randint(32, 128),
        "tcp": random.randint(0, 1),
        "udp": random.randint(0, 1),
        "icmp": random.randint(0, 1),
        "arp": random.randint(0, 1),
        "http": random.randint(0, 1),
        "https": random.randint(0, 1),
        "dns": random.randint(0, 1),
        "ssh": random.randint(0, 1),
        "telnet": random.randint(0, 1),
        "smtp": random.randint(0, 1),
        "syn_flag_number": random.randint(0, 5),
        "ack_flag_number": random.randint(0, 10),
        "fin_flag_number": random.randint(0, 3),
        "rst_flag_number": random.randint(0, 2),
        "psh_flag_number": random.randint(0, 5),
        "packet_length": random.randint(40, 1500),
        "payload_length": random.randint(0, 1460),
        "flow_duration": round(random.uniform(0.001, 10.0), 4),
        "total_pkts": random.randint(1, 1000),
        "total_bytes": random.randint(40, 150000),
        "packet_rate": round(random.uniform(1.0, 1000.0), 2),
        "byte_rate": round(random.uniform(40.0, 150000.0), 2),
        "avg_packet_size": round(random.uniform(40.0, 1500.0), 2),
        
        # Random Forest probability output
        "probability_benign": prob_benign,
        "probability_malicious": prob_malicious
    }

@app.route("/predictions", methods=["GET"])
def predictions():
    """Return a batch of 5 fake flow predictions."""
    batch = [generate_fake_flow() for _ in range(5)]
    return jsonify({"flows": batch, "count": len(batch)})

if __name__ == "__main__":
    print("Mock AI Server running on http://localhost:8080")
    print("Endpoint: GET /predictions")
    app.run(host="0.0.0.0", port=8080, debug=False)
    