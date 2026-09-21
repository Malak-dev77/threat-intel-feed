# ─── Dashboard API ────────────────────────────────────────────────────────────
# Serves three endpoints matching the web team's dashboard contract exactly.
# Polled by the dashboard — no auth, CORS enabled, GET only.
#
# /predictions  → polled every 5s — raw AI predictions received and processed
# /trust_scores → polled every 5s — graded trust score per device (0.0-1.0)
# /alerts       → polled every 2s — critical alerts with action_taken: isolate
#
# Trust score bands (from dashboard contract):
# 0.80-1.00 → trusted  → green  → traffic flows
# 0.50-0.79 → suspicious → yellow → monitored
# 0.00-0.49 → malicious → red   → DROP

import sys
import os
import time
from flask import Flask, jsonify
from flask_cors import CORS

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import SERVE_PORT

app = Flask(__name__)
CORS(app)  # enable CORS — dashboard contract requirement

# ─── In-memory stores ─────────────────────────────────────────────────────────
latest_predictions = []
latest_trust_scores = {}
alerts_queue = []

def update_predictions(flows):
    """Called by main pipeline — stores latest raw predictions."""
    global latest_predictions
    latest_predictions = flows

def update_trust_scores(aggregated_scores):
    """Called by main pipeline — stores latest graded device trust scores."""
    global latest_trust_scores
    latest_trust_scores = aggregated_scores

def queue_alert(device_ip, alert_type, severity=None, action_taken="isolate",
                context=None, credibility_tier=None):
    """
    Called by pipeline when honeytoken hits or OTX confirms malicious.
    Severity derived from credibility tier if not explicitly provided.
    Matches dashboard contract exactly.
    """
    # Derive severity from credibility tier if not provided
    if severity is None:
        if credibility_tier is None or credibility_tier <= 2:
            severity = "low"
        elif credibility_tier <= 3:
            severity = "medium"
        elif credibility_tier <= 4:
            severity = "high"
        else:
            severity = "critical"

    alert = {
        "alert_id": f"a{len(alerts_queue) + 1}",
        "device_ip": device_ip,
        "alert_type": alert_type,
        "severity": severity,
        "action_taken": action_taken,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "context": context or {}
    }
    alerts_queue.append(alert)
    return alert

# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.route("/predictions", methods=["GET"])
def predictions():
    """
    Raw AI predictions — what we received from the AI team this cycle.
    Dashboard polls every 5 seconds.
    """
    return jsonify({
        "flows": latest_predictions,
        "count": len(latest_predictions),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    })

@app.route("/trust_scores", methods=["GET"])
def trust_scores():
    """
    Graded trust scores per device — our verified output.
    One float 0.0-1.0 per device, with status string.
    Dashboard polls every 5 seconds.
    Matches dashboard contract exactly.
    """
    scores_list = list(latest_trust_scores.values())

    if not scores_list:
        return jsonify({
            "trust_scores": [],
            "count": 0,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
        })

    return jsonify({
        "trust_scores": scores_list,
        "count": len(scores_list),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    })

@app.route("/alerts", methods=["GET"])
def alerts():
    """
    Critical alerts — honeytoken hits and OTX confirmed threats.
    Dashboard polls every 2 seconds.
    action_taken: isolate → triggers DROP on the switch.
    Matches dashboard contract exactly.
    """
    recent_alerts = alerts_queue[-50:] if alerts_queue else []

    return jsonify({
        "alerts": recent_alerts,
        "count": len(recent_alerts),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    })

@app.route("/health", methods=["GET"])
def health():
    """Health check — confirms pipeline is running."""
    return jsonify({
        "status": "running",
        "predictions_cached": len(latest_predictions),
        "devices_tracked": len(latest_trust_scores),
        "alerts_total": len(alerts_queue),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    })

if __name__ == "__main__":
    print("=== Dashboard API Test ===")
    print(f"Seeding test data and starting server on port {SERVE_PORT}\n")

    update_predictions([
        {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
         "probability_malicious": 0.12, "probability_benign": 0.88,
         "attack_type": "benign"},
        {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.1",
         "probability_malicious": 0.87, "probability_benign": 0.13,
         "attack_type": "probable_threat"}
    ])

    update_trust_scores({
        "10.0.0.2": {
            "device_ip": "10.0.0.2",
            "trust_score": 0.95,
            "status": "trusted",
            "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "10.0.0.3": {
            "device_ip": "10.0.0.3",
            "trust_score": 0.05,
            "status": "malicious",
            "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ")
        }
    })

    queue_alert(
        device_ip="10.0.0.7",
        alert_type="honeytoken_access",
        action_taken="isolate",
        credibility_tier=6,
        context={"hit_type": "honeytoken_ip", "packet_rate": 890.0}
    )

    print("Test data seeded. Starting Flask server...")
    print(f"  http://localhost:{SERVE_PORT}/predictions")
    print(f"  http://localhost:{SERVE_PORT}/trust_scores")
    print(f"  http://localhost:{SERVE_PORT}/alerts")
    print(f"  http://localhost:{SERVE_PORT}/health\n")

    app.run(host="0.0.0.0", port=SERVE_PORT, debug=False)