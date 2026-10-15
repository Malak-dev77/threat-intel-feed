# ─── Calibration Pass ─────────────────────────────────────────────────────────
# Tests Threat Intel Feed verification against AI team's labeled predictions.
# Builds realistic synthetic flows per attack type so SHAP and ghost model
# can actually distinguish between normal and malicious traffic.

import sys
import os
import csv
import random
import io
from contextlib import redirect_stdout
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shap_check.credibility_check import run_credibility_check
from ghost_model.ghost_model import run_ghost_check
from grading.grading import grade_flow, model_state
from collections import deque
from config.settings import RELIABILITY_WINDOW
from grading.verification_escalation import should_escalate, run_escalation

CSV_PATH = "ai_team_data/batch_predictions_for_testing.csv"

def build_realistic_flow(labeled_flow):
    """
    Build a realistic synthetic flow based on attack type.
    Each attack type gets realistic feature values so SHAP
    and ghost model can actually distinguish them.
    """
    prediction = labeled_flow["prediction"]
    confidence = labeled_flow["confidence"]
    flow_id = labeled_flow["flow_id"]

    # Base flow
    flow = {
        "src_ip": f"10.0.0.{random.randint(1,10)}",
        "dst_ip": "10.0.0.1",
        "flow_id": flow_id,
        "prediction_label": prediction
    }

    if prediction == "normal":
        # Normal traffic — low rate, long duration, varied ports
        flow.update({
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 53, 22]),
            "ip_proto": "TCP",
            "flow_duration": random.uniform(1.0, 10.0),
            "total_pkts": random.randint(5, 50),
            "packet_rate": random.uniform(1.0, 50.0),
            "avg_packet_size": random.uniform(400.0, 1400.0),
            "probability_malicious": round(1.0 - confidence, 4),
            "probability_benign": round(confidence, 4),
            "syn_flag_number": random.randint(1, 2),
            "ack_flag_number": random.randint(3, 10),
        })

    elif prediction == "syn_flood":
        # SYN flood — very high packet rate, short duration, high SYN count
        flow.update({
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443]),
            "ip_proto": "TCP",
            "flow_duration": random.uniform(0.05, 0.5),
            "total_pkts": random.randint(500, 2000),
            "packet_rate": random.uniform(1000.0, 5000.0),
            "avg_packet_size": random.uniform(40.0, 80.0),
            "probability_malicious": round(confidence, 4),
            "probability_benign": round(1.0 - confidence, 4),
            "syn_flag_number": random.randint(8, 20),
            "ack_flag_number": random.randint(0, 2),
        })

    elif prediction == "malicious_post":
        # Malicious POST — moderate rate, targets financial endpoints
        flow.update({
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 5000, 8000]),
            "ip_proto": "TCP",
            "flow_duration": random.uniform(0.1, 2.0),
            "total_pkts": random.randint(50, 300),
            "packet_rate": random.uniform(100.0, 500.0),
            "avg_packet_size": random.uniform(200.0, 600.0),
            "probability_malicious": round(confidence, 4),
            "probability_benign": round(1.0 - confidence, 4),
            "syn_flag_number": random.randint(1, 5),
            "ack_flag_number": random.randint(2, 8),
        })

    elif prediction == "port_scan":
        # Port scan — many different destination ports, low packets per flow
        flow.update({
            "src_port": random.randint(1024, 65535),
            "dst_port": random.randint(1, 65535),
            "ip_proto": "TCP",
            "flow_duration": random.uniform(0.001, 0.1),
            "total_pkts": random.randint(1, 5),
            "packet_rate": random.uniform(200.0, 800.0),
            "avg_packet_size": random.uniform(40.0, 100.0),
            "probability_malicious": round(confidence, 4),
            "probability_benign": round(1.0 - confidence, 4),
            "syn_flag_number": random.randint(1, 3),
            "ack_flag_number": 0,
        })

    return flow

def run_calibration(sample_size=500):
    print("=" * 70)
    print("Threat Intel Feed — Calibration Pass")
    print("=" * 70)

    # Load AI team's labeled predictions
    flows = []
    with open(CSV_PATH, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            flows.append({
                "flow_id": row["flow_id"],
                "prediction": row["prediction"],
                "confidence": float(row["confidence"]),
                "trust_score_ai": float(row["trust_score"]),
                "recommended_action": row["recommended_action"]
            })

    print(f"Loaded {len(flows)} labeled predictions from AI team\n")

    # Class distribution
    by_class = defaultdict(list)
    for f in flows:
        by_class[f["prediction"]].append(f)

    print("Class distribution:")
    for cls, items in by_class.items():
        print(f"  {cls}: {len(items)}")

    # Sample proportionally
    random.seed(42)
    sample = []
    for cls, items in by_class.items():
        n = min(len(items), max(10, int(sample_size * len(items) / len(flows))))
        sample.extend(random.sample(items, n))

    random.shuffle(sample)
    print(f"\nCalibrating on {len(sample)} sampled flows...\n")

    # Results tracking
    results = defaultdict(lambda: {
        "correct": 0, "total": 0,
        "scores": [], "flagged_by_shap": 0,
        "flagged_by_ghost": 0
    })

    for labeled in sample:
        flow = build_realistic_flow(labeled)
        prediction = labeled["prediction"]

        with redirect_stdout(io.StringIO()):
            shap_result = run_credibility_check(flow)
            ghost_result = run_ghost_check(flow)
            grade_result = grade_flow(
                flow,
                shap_result=shap_result,
                ghost_result=ghost_result
            )

        trust_score = grade_result["trust_score"]
        ai_prediction = labeled["prediction"]

        if should_escalate(trust_score, {"probability_malicious": flow["probability_malicious"]}):
            escalation_result = run_escalation(
                flow, trust_score, ai_prediction,
                otx_result=None, honeytoken_result=None
            )
            trust_score = escalation_result["final_trust"]
            grade_result["trust_score"] = trust_score
            
        trust_score = grade_result["trust_score"]
        results[prediction]["total"] += 1
        results[prediction]["scores"].append(trust_score)



        if shap_result["needs_deeper_inspection"]:
            results[prediction]["flagged_by_shap"] += 1

        if not ghost_result["models_agree"]:
            results[prediction]["flagged_by_ghost"] += 1

        # Check if landed in correct band
        if prediction == "normal":
            correct = trust_score >= 0.80
        else:
            correct = trust_score <= 0.49

        if correct:
            results[prediction]["correct"] += 1

    # ── Print results ──────────────────────────────────────────────────────
    print("=" * 70)
    print("CALIBRATION RESULTS")
    print("=" * 70)
    print(f"\n{'Class':<18} {'Total':<7} {'Correct':<9} {'Accuracy':<10} "
          f"{'Avg Score':<11} {'SHAP%':<8} {'Ghost%':<8} Status")
    print("-" * 80)

    overall_correct = 0
    overall_total = 0

    for cls in ["normal", "malicious_post", "syn_flood", "port_scan"]:
        data = results[cls]
        if data["total"] == 0:
            continue

        avg_score = sum(data["scores"]) / len(data["scores"])
        accuracy = data["correct"] / data["total"] * 100
        shap_pct = data["flagged_by_shap"] / data["total"] * 100
        ghost_pct = data["flagged_by_ghost"] / data["total"] * 100
        overall_correct += data["correct"]
        overall_total += data["total"]

        if cls == "normal":
            target = "≥0.80"
            status = "✅ PASS" if accuracy >= 80 else "❌ FAIL"
        else:
            target = "≤0.49"
            status = "✅ PASS" if accuracy >= 70 else "❌ FAIL"

        print(f"{cls:<18} {data['total']:<7} {data['correct']:<9} "
              f"{accuracy:.1f}%{'':<5} {avg_score:.3f} ({target}){'':<2} "
              f"{shap_pct:.0f}%{'':<4} {ghost_pct:.0f}%{'':<4} {status}")

    overall_accuracy = overall_correct / overall_total * 100 if overall_total > 0 else 0
    print(f"\n{'OVERALL':<18} {overall_total:<7} {overall_correct:<9} "
          f"{overall_accuracy:.1f}%")

    print("\n" + "=" * 70)
    print("VERIFICATION ANALYSIS")
    print("=" * 70)

    normal_scores = results["normal"]["scores"]
    malicious_scores = (
        results["malicious_post"]["scores"] +
        results["syn_flood"]["scores"] +
        results["port_scan"]["scores"]
    )

    if normal_scores:
        avg_normal = sum(normal_scores) / len(normal_scores)
        print(f"\nNormal flows   → avg trust: {avg_normal:.3f} "
              f"(target ≥ 0.80) "
              f"{'✅' if avg_normal >= 0.80 else '❌'}")

    if malicious_scores:
        avg_malicious = sum(malicious_scores) / len(malicious_scores)
        print(f"Malicious flows → avg trust: {avg_malicious:.3f} "
              f"(target ≤ 0.49) "
              f"{'✅' if avg_malicious <= 0.49 else '❌'}")

    # Show where verification adds value
    print("\nWhere your assurance layer adds value:")
    for cls in ["malicious_post", "syn_flood", "port_scan"]:
        data = results[cls]
        if data["total"] == 0:
            continue
        shap_caught = data["flagged_by_shap"]
        ghost_caught = data["flagged_by_ghost"]
        print(f"  {cls}: SHAP flagged {shap_caught}/{data['total']} "
              f"| Ghost flagged {ghost_caught}/{data['total']}")

    print("\nCalibration complete.")

if __name__ == "__main__":
    run_calibration(sample_size=500)