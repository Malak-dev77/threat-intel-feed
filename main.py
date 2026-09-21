# ─── Threat Intel Feed — Main Pipeline ───────────────────────────────────────
# Wires every module together into one running pipeline.
# Run this file only — everything else starts automatically.
#
# Flow:
# Ingestion → SHAP (Door 1) + Sampler (Door 2) → Ghost Model → OTX
#           → Honeytoken → Grading → Dashboard API
#
# ⚠ BEFORE CONNECTING REAL AI TEAM API:
# 1. Change AI_TEAM_URL in config/settings.py to their real endpoint
# 2. Replace surrogate SHAP in shap_check/credibility_check.py
#    with real model file from AI team (.pkl)
# 3. Stop running mock_ai_server.py
# 4. Run this file only — ignore all test blocks in individual modules

import sys
import os
import time
import threading
from flask import Flask
from flask_cors import CORS

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import all modules
from config.settings import AI_TEAM_BATCH_INTERVAL, SERVE_PORT
from ingestion.client import fetch_predictions
from ingestion.encoder import encode_batch
from ingestion.topology import validate_device, flush_pending_buffer
from shap_check.credibility_check import run_credibility_check
from shap_check.risk_sampler import should_sample
from ghost_model.ghost_model import run_ghost_check
from honeytoken.honeytoken import run_honeytoken_check
from otx.otx_check import run_otx_check
from grading.grading import grade_flow, aggregate_device_trust, update_reliability_grade, handle_idle_device, device_state
from grading.dashboard_api import (
    app, update_predictions, update_trust_scores, queue_alert
)

def process_flow(flow):
    """
    Run one flow through the complete pipeline.
    Returns graded result for aggregation.
    """
    src_ip = flow.get("src_ip", "unknown")
    triggered = False
    trigger_reason = None
    shap_result = None
    ghost_result = None
    otx_result = None

    # ── Step 1: SHAP Check (Door 1) ──────────────────────────────────────────
    shap_result = run_credibility_check(flow)
    if shap_result["needs_deeper_inspection"]:
        triggered = True
        trigger_reason = "shap_flag"

    # ── Step 2: Risk Sampler (Door 2) — independent of SHAP ──────────────────
    sampled, sample_prob, sample_signals = should_sample(flow)
    if sampled and not triggered:
        triggered = True
        trigger_reason = "risk_sampler"

    # ── Step 3: Ghost Model — triggered by Door 1 OR Door 2 ──────────────────
        # ── Step 3: Ghost Model — triggered by Door 1 OR Door 2 ──────────────────
    if triggered:
        ghost_result = run_ghost_check(flow)
    
    # Attack type — from ghost model if triggered, fallback if not
    attack_type = "unclassified"
    if ghost_result and ghost_result.get("attack_type"):
        attack_type = ghost_result["attack_type"]
    elif not triggered:
        # Flow never triggered either door — classify by AI probability alone
        ai_prob = flow.get("probability_malicious", 0.5)
        if ai_prob < 0.35:
            attack_type = "benign"
        elif ai_prob > 0.65:
            attack_type = "probable_threat"
        else:
            attack_type = "unclassified"
    
    # Add attack_type to flow for dashboard endpoints
    flow["attack_type"] = attack_type

    # ── Step 4: Honeytoken — runs on EVERY flow ───────────────────────────────
    honeytoken_result = run_honeytoken_check(flow)

    # ── Step 5: OTX — triggered by any internal signal ───────────────────────
    if triggered or honeytoken_result["honeytoken_hit"]:
        if not trigger_reason:
            trigger_reason = "honeytoken_hit"
        otx_result = run_otx_check(
            flow,
            trigger_reason=trigger_reason,
            honeytoken_hit=honeytoken_result["honeytoken_hit"]
        )

    # ── Step 6: Queue alert if honeytoken hit ─────────────────────────────────
        # ── Step 6: Queue alert if honeytoken hit ─────────────────────────────────
    if honeytoken_result["honeytoken_hit"]:
        queue_alert(
            device_ip=src_ip,
            alert_type="honeytoken_access",
            action_taken="isolate",
            credibility_tier=6,
            context=honeytoken_result.get("context", {})
        )

    # ── Step 7: Queue alert if OTX confirmed malicious ───────────────────────
    if otx_result and otx_result["otx_found"] and otx_result["otx_pulse_count"] > 0:
        queue_alert(
            device_ip=src_ip,
            alert_type="otx_confirmed_malicious",
            action_taken="isolate",
            credibility_tier=5,
            context={"pulse_count": otx_result["otx_pulse_count"]}
        )

    # ── Step 8: Grade the flow ────────────────────────────────────────────────
    grade_result = grade_flow(
        flow,
        shap_result=shap_result,
        ghost_result=ghost_result,
        honeytoken_result=honeytoken_result,
        otx_result=otx_result
    )

    return grade_result

def pipeline_loop():
    """
    Main pipeline loop — runs every 5 seconds.
    Pulls flows, processes each one, updates dashboard.
    """
    print("[Pipeline] Starting — polling AI server every "
          f"{AI_TEAM_BATCH_INTERVAL}s\n")

    cycle = 0
    while True:
        cycle += 1
        print(f"\n{'='*60}")
        print(f"[Pipeline] Cycle {cycle} — "
              f"{time.strftime('%Y-%m-%dT%H:%M:%SZ')}")
        print(f"{'='*60}")

        # Pull flows from AI team
        flows = fetch_predictions()

        if not flows:
            print("[Pipeline] No flows received — waiting...")
            time.sleep(AI_TEAM_BATCH_INTERVAL)
            continue

        # Update /predictions endpoint immediately
        update_predictions(flows)

        # Encode flows — convert raw strings to numeric format
        flows = encode_batch(flows)

        # Process each flow through full pipeline
        flow_results = []
        flagged_this_batch = []

                # Process each flow through full pipeline
        flow_results = []
        flagged_this_batch = []

        # Release any flows from pending buffer that are now recognized
        released_flows = flush_pending_buffer()
        if released_flows:
            print(f"[Pipeline] Releasing {len(released_flows)} flows from pending buffer")
            flows = released_flows + flows

        for i, flow in enumerate(flows):
            # Topology validation — check if device is known
            topo_status, validated_flow = validate_device(flow)
            if validated_flow is None:
                print(f"[Pipeline] Flow {i+1} src={flow.get('src_ip')} "
                      f"→ held in topology pending buffer")
                continue

            flow = validated_flow
            print(f"\n[Pipeline] Flow {i+1}/{len(flows)} "
                  f"src={flow.get('src_ip')} → "
                  f"dst={flow.get('dst_ip')} | "
                  f"malicious={flow.get('probability_malicious', 0):.3f} "
                  f"| topo={topo_status}")
            print("-" * 40)

            result = process_flow(flow)
            flow_results.append(result)
            flagged_this_batch.append(
                result["credibility_tier"] >= 3
            )

        # Update reliability grade based on this batch
        current_probs = [f.get("probability_malicious", 0.5) for f in flows]
        reliability_grade, flagged_rate, psi = update_reliability_grade(
            flagged_this_batch, current_probs
        )

        # Aggregate per-device trust scores
                # Aggregate per-device trust scores
        print(f"\n[Pipeline] Aggregating device trust scores...")
        aggregated = aggregate_device_trust(flow_results)

        # Handle idle devices — decay toward neutral 0.5
        active_devices = set(r["device_ip"] for r in flow_results)
        for device_ip in list(device_state.keys()):
            if device_ip not in active_devices:
                decayed_score, suspicious_silence = handle_idle_device(device_ip)
                if device_ip in aggregated:
                    aggregated[device_ip]["trust_score"] = decayed_score
                else:
                    aggregated[device_ip] = {
                        "device_ip": device_ip,
                        "trust_score": decayed_score,
                        "status": "suspicious" if suspicious_silence else "idle",
                        "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                if suspicious_silence:
                    print(f"  [Pipeline] Device {device_ip} suspicious silence detected")

        # Update /trust_scores endpoint
        update_trust_scores(aggregated)

        print(f"\n[Pipeline] Cycle {cycle} complete | "
              f"Flows: {len(flows)} | "
              f"Reliability: {reliability_grade} | "
              f"Flagged rate: {flagged_rate:.1%}")

        time.sleep(AI_TEAM_BATCH_INTERVAL)

def start_pipeline():
    """Start pipeline loop in background thread."""
    thread = threading.Thread(target=pipeline_loop, daemon=True)
    thread.start()
    print("[Pipeline] Background pipeline thread started.")

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════╗")
    print("║       Threat Intel Feed — Starting Up        ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║  Dashboard API → http://localhost:{SERVE_PORT}      ║")
    print(f"║  Endpoints: /predictions /trust_scores       ║")
    print(f"║             /alerts /health                  ║")
    print("╚══════════════════════════════════════════════╝\n")

    # Start pipeline in background
    start_pipeline()

    # Start dashboard API in foreground
    print(f"[Dashboard] Starting on port {SERVE_PORT}...")
    port = int(os.environ.get("PORT", SERVE_PORT))
    app.run(host="0.0.0.0", port=port, debug=False)