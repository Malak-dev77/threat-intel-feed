# ─── SHAP Credibility Check ───────────────────────────────────────────────────
# Two independent doors — both always run, neither gates the other.
# Door 1: Probability margin check — is the model confident?
# Door 2: Fragile SHAP check — is confidence built on fakeable features?
#
# Model-agnostic — works with XGBoost AND Random Forest.
# TreeExplainer supports both. Only change MODEL_PATH in settings.py
# when AI team confirms final model.

import sys
import os
import numpy as np
import pickle
import warnings
warnings.filterwarnings("ignore")

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import (
    PROBABILITY_MARGIN_LOW,
    PROBABILITY_MARGIN_HIGH,
    FRAGILE_SHAP_THRESHOLD_REAL,
    FRAGILE_FEATURES_REAL,
    ROBUST_FEATURES_REAL,
    MODEL_PATH,
    MODEL_FEATURES,
    MODEL_CLASSES
)

# ─── Load real model once at import ──────────────────────────────────────────
_model = None
_explainer = None

def get_model_and_explainer():
    global _model, _explainer
    if _model is None:
        try:
            import shap
            with open(MODEL_PATH, "rb") as f:
                _model = pickle.load(f)
            _explainer = shap.TreeExplainer(_model)
            print(f"[SHAP] Real model loaded: {type(_model).__name__}")
            print(f"[SHAP] Features: {MODEL_FEATURES}")
            print(f"[SHAP] Classes: {MODEL_CLASSES}")
        except Exception as e:
            print(f"[SHAP] WARNING: Could not load real model: {e}")
            print("[SHAP] Falling back to surrogate SHAP values")
            _model = None
            _explainer = None
    return _model, _explainer

def extract_model_features(flow):
    """
    Extract the model features from a flow dict.
    Returns numpy array ready for model input.
    """
    features = []
    for feat in MODEL_FEATURES:
        val = flow.get(feat, 0)
        if feat == "ip_proto":
            if isinstance(val, str):
                proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
                val = proto_map.get(val.upper(), 0)
        try:
            features.append(float(val))
        except (ValueError, TypeError):
            features.append(0.0)
    return np.array(features).reshape(1, -1)

def check_probability_margin(flow):
    """
    Door 1 — Margin check.
    If probability sits in ambiguous band (0.35–0.65), model wasn't confident.
    Returns True if flagged.
    """
    prob_malicious = flow.get("probability_malicious", 0.5)
    flagged = PROBABILITY_MARGIN_LOW <= prob_malicious <= PROBABILITY_MARGIN_HIGH
    if flagged:
        print(f"  [SHAP] Margin flag: probability_malicious={prob_malicious:.4f} "
              f"in ambiguous band ({PROBABILITY_MARGIN_LOW}–{PROBABILITY_MARGIN_HIGH})")
    return flagged

def check_fragile_shap(flow):
    """
    Door 2 — Fragile SHAP check using real model.
    Groups features by attacker manipulability — novel mechanism.
    Works with XGBoost and Random Forest via TreeExplainer.
    Returns (flagged, fragile_pct)
    """
    model, explainer = get_model_and_explainer()

    if explainer is not None:
        try:
            features = extract_model_features(flow)
            shap_values = explainer.shap_values(features)

                       # Handle multiclass output from XGBoost TreeExplainer
            # Returns 3D array: (n_samples, n_features, n_classes)
            if hasattr(shap_values, 'values'):
                # New SHAP API — Explanation object
                sv = shap_values.values
            else:
                sv = shap_values

            if isinstance(sv, np.ndarray):
                if sv.ndim == 3:
                    # Shape: (1, n_features, n_classes) — take malicious class
                    prob_malicious = float(flow.get("probability_malicious", 0.5))
                    class_idx = 1 if prob_malicious > 0.5 else 0
                    shap_array = sv[0, :, class_idx]
                elif sv.ndim == 2:
                    # Shape: (1, n_features)
                    shap_array = sv[0]
                else:
                    shap_array = sv
            elif isinstance(sv, list):
                prob_malicious = float(flow.get("probability_malicious", 0.5))
                class_idx = 1 if prob_malicious > 0.5 else 0
                shap_array = np.array(sv[class_idx])[0]
            else:
                shap_array = np.array(sv)[0]

            # Map SHAP values to feature names
            shap_dict = dict(zip(MODEL_FEATURES, np.abs(shap_array)))

            total_weight = sum(shap_dict.values())
            if total_weight == 0:
                return False, 0.0

            fragile_weight = sum(
                shap_dict.get(f, 0) for f in FRAGILE_FEATURES_REAL
            )
            fragile_pct = fragile_weight / total_weight
            flagged = fragile_pct > FRAGILE_SHAP_THRESHOLD_REAL

            if flagged:
                print(f"  [SHAP] Fragile flag: {fragile_pct:.1%} of SHAP weight "
                      f"on attacker-manipulable features "
                      f"(threshold: {FRAGILE_SHAP_THRESHOLD_REAL:.0%})")
                print(f"  [SHAP] Feature breakdown: "
                      f"{', '.join(f'{k}={v:.4f}' for k,v in shap_dict.items())}")

            return flagged, fragile_pct

        except Exception as e:
            print(f"  [SHAP] Real SHAP failed: {e} — using surrogate")

    # ─── Surrogate fallback ────────────────────────────────────────────────
    all_features = list(FRAGILE_FEATURES_REAL | ROBUST_FEATURES_REAL)
    raw = np.abs(np.random.uniform(0.01, 0.5, len(all_features)))
    shap_mock = dict(zip(all_features, raw))
    total_weight = sum(shap_mock.values())
    fragile_weight = sum(shap_mock.get(f, 0) for f in FRAGILE_FEATURES_REAL)
    fragile_pct = fragile_weight / total_weight
    flagged = fragile_pct > FRAGILE_SHAP_THRESHOLD_REAL
    if flagged:
        print(f"  [SHAP] Fragile flag (surrogate): {fragile_pct:.1%}")
    return flagged, fragile_pct

def run_credibility_check(flow):
    """
    Run both doors on a single flow.
    Returns result dictionary with flags and details.
    """
    print(f"  [SHAP] Checking flow: {flow.get('src_ip','?')} → "
          f"{flow.get('dst_ip','?')} | "
          f"malicious={flow.get('probability_malicious', 0):.3f}")

    margin_flagged = check_probability_margin(flow)
    fragile_flagged, fragile_pct = check_fragile_shap(flow)

    result = {
        "flow": flow,
        "margin_flagged": margin_flagged,
        "fragile_shap_flagged": fragile_flagged,
        "fragile_shap_pct": round(fragile_pct, 4),
        "needs_deeper_inspection": margin_flagged or fragile_flagged
    }

    if result["needs_deeper_inspection"]:
        print(f"  [SHAP] → FLAGGED for deeper inspection")
    else:
        print(f"  [SHAP] → CLEAN — no flags")

    return result

if __name__ == "__main__":
    print("=== SHAP Credibility Check — Real Model Test ===\n")

    test_flows = [
        {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 12345, "dst_port": 80,
            "ip_proto": "TCP", "flow_duration": 0.5,
            "total_pkts": 950, "packet_rate": 1900.0,
            "avg_packet_size": 60.0,
            "probability_malicious": 0.95
        },
        {
            "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4",
            "src_port": 54321, "dst_port": 443,
            "ip_proto": "TCP", "flow_duration": 5.0,
            "total_pkts": 50, "packet_rate": 10.0,
            "avg_packet_size": 512.0,
            "probability_malicious": 0.52
        },
        {
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6",
            "src_port": 8080, "dst_port": 22,
            "ip_proto": "TCP", "flow_duration": 2.0,
            "total_pkts": 10, "packet_rate": 5.0,
            "avg_packet_size": 256.0,
            "probability_malicious": 0.08
        }
    ]

    for i, flow in enumerate(test_flows):
        print(f"--- Flow {i+1} ---")
        result = run_credibility_check(flow)
        print(f"  Result: margin={result['margin_flagged']} | "
              f"fragile={result['fragile_shap_flagged']} | "
              f"fragile_pct={result['fragile_shap_pct']:.1%}\n")