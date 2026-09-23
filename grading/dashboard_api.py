# ─── Dashboard API ────────────────────────────────────────────────────────────
import sys
import os
import time
from flask import Flask, jsonify
from flask_cors import CORS

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import SERVE_PORT

app = Flask(__name__)
CORS(app)

# ─── Shared state object — avoids module import instance issues ───────────────
state = {
    "predictions": [],
    "trust_scores": {},
    "alerts": []
}

def update_predictions(flows):
    state["predictions"] = flows

def update_trust_scores(aggregated_scores):
    state["trust_scores"] = aggregated_scores

def queue_alert(device_ip, alert_type, severity=None, action_taken="isolate",
                context=None, credibility_tier=None):
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
        "alert_id": f"a{len(state['alerts']) + 1}",
        "device_ip": device_ip,
        "alert_type": alert_type,
        "severity": severity,
        "action_taken": action_taken,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "context": context or {}
    }
    state["alerts"].append(alert)
    return alert

@app.route("/predictions", methods=["GET"])
def predictions():
    return jsonify({
        "flows": state["predictions"],
        "count": len(state["predictions"]),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    })

@app.route("/trust_scores", methods=["GET"])
def trust_scores():
    scores_list = list(state["trust_scores"].values())
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
    recent_alerts = state["alerts"][-50:] if state["alerts"] else []
    return jsonify({
        "alerts": recent_alerts,
        "count": len(recent_alerts),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "running",
        "predictions_cached": len(state["predictions"]),
        "devices_tracked": len(state["trust_scores"]),
        "alerts_total": len(state["alerts"]),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=SERVE_PORT, debug=False)