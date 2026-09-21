# ─── OTX Cross-Reference ──────────────────────────────────────────────────────
# Queries AlienVault OTX for external threat intelligence on suspicious IPs.
# Triggered by OR logic — any single internal signal activates a query:
# - SHAP Door 1 flag (margin or fragile)
# - Risk sampler Door 2 selection
# - Honeytoken hit
#
# Key interpretation rule (your original design decision):
# - Found + flagged malicious → strong corroboration
# - Found + benign → weak signal, doesn't clear internal suspicion
# - NOT FOUND → elevated suspicion, not reassurance
#   (unseen infrastructure = brand new or deliberately unburned)
#
# Novel threat intelligence output:
# Confirmed-malicious cases with no OTX record get logged explicitly
# as threat intel your system generated that nobody else's feed has yet.

import sys
import os
import requests
import time
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import OTX_API_KEY, OTX_URL

# ─── Cache to avoid hammering OTX API ────────────────────────────────────────
# Same IP queried multiple times in a session returns cached result
otx_cache = {}
novel_threats = []  # IPs flagged internally but not found in OTX

def query_otx(ip):
    """
    Query OTX for a source IP.
    Returns dict with found status, malicious indicator count, and pulse count.
    Caches results to avoid redundant API calls.
    """
    if ip in otx_cache:
        print(f"  [OTX] Cache hit for {ip}")
        return otx_cache[ip]

    if not OTX_API_KEY:
        print(f"  [OTX] WARNING: No API key configured — skipping query for {ip}")
        return {"found": False, "malicious_count": 0, "pulse_count": 0, "error": "no_key"}

    url = OTX_URL.format(ip=ip)
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            malicious_count = data.get("validation", [])
            malicious_count = len([v for v in malicious_count if v.get("source")])

            result = {
                "found": pulse_count > 0,
                "pulse_count": pulse_count,
                "malicious_count": malicious_count,
                "raw_summary": data.get("type_title", "unknown"),
                "error": None
            }

        elif response.status_code == 404:
            result = {
                "found": False,
                "pulse_count": 0,
                "malicious_count": 0,
                "raw_summary": "not_in_otx",
                "error": None
            }
        else:
            result = {
                "found": False,
                "pulse_count": 0,
                "malicious_count": 0,
                "error": f"http_{response.status_code}"
            }

        otx_cache[ip] = result
        return result

    except requests.exceptions.Timeout:
        print(f"  [OTX] Timeout querying {ip}")
        return {"found": False, "pulse_count": 0, "malicious_count": 0, "error": "timeout"}
    except Exception as e:
        print(f"  [OTX] Error querying {ip}: {e}")
        return {"found": False, "pulse_count": 0, "malicious_count": 0, "error": str(e)}

def interpret_otx_result(otx_result, internal_signal_strength, honeytoken_hit=False):
    """
    Interpret OTX result in context of what triggered the query.
    
    Key rule: NOT FOUND = elevated suspicion, not reassurance.
    Confidence weighting differs by which signal triggered the check:
    - Honeytoken hit stays near-certain regardless of OTX (honeytokens 
      don't produce false positives by design)
    - SHAP-only ambiguity with no OTX corroboration stays weaker
    
    Returns otx_confidence: float 0.0-1.0 contribution to credibility grade
    """
    if honeytoken_hit:
        # Honeytoken is proof — OTX result doesn't change certainty much
        if otx_result["found"] and otx_result["pulse_count"] > 0:
            print(f"  [OTX] Known malicious IP + honeytoken hit → maximum certainty")
            return 1.0
        else:
            print(f"  [OTX] Unknown IP + honeytoken hit → still near-certain (novel threat)")
            return 0.95

    if otx_result.get("error"):
        print(f"  [OTX] Query error — treating as inconclusive")
        return internal_signal_strength  # fall back to internal signal only

    if otx_result["found"] and otx_result["pulse_count"] > 0:
        # Strong corroboration — known bad actor
        confidence = min(0.95, 0.6 + (otx_result["pulse_count"] * 0.05))
        print(f"  [OTX] KNOWN MALICIOUS — {otx_result['pulse_count']} pulses → "
              f"confidence={confidence:.2f}")
        return confidence

    elif otx_result["found"] and otx_result["pulse_count"] == 0:
        # Found but no malicious indicators — weak signal
        print(f"  [OTX] Found but no malicious indicators → weak corroboration")
        return internal_signal_strength * 0.8

    else:
        # NOT FOUND — elevated suspicion, not reassurance
        # Fresh infrastructure = deliberate or brand new
        elevated = min(internal_signal_strength + 0.15, 0.85)
        print(f"  [OTX] NOT IN OTX → elevated suspicion "
              f"(unseen infrastructure) → confidence={elevated:.2f}")
        return elevated

def run_otx_check(flow, trigger_reason, honeytoken_hit=False):
    """
    Main entry point — triggered by any internal signal.
    Queries OTX, interprets result, logs novel threats.
    Returns result dictionary for grading module.
    """
    src_ip = flow.get("src_ip", "unknown")
    ai_prob = flow.get("probability_malicious", 0.5)

    print(f"  [OTX] Querying {src_ip} | trigger={trigger_reason}")

    otx_result = query_otx(src_ip)

    # Internal signal strength — how suspicious were we before OTX?
    internal_signal_strength = min(ai_prob + 0.1, 0.9)

    otx_confidence = interpret_otx_result(
        otx_result,
        internal_signal_strength,
        honeytoken_hit=honeytoken_hit
    )

    # Log novel threat if internally flagged but not in OTX
    # This is a stated research output — threat intel nobody else has yet
    if not otx_result["found"] and ai_prob > 0.6:
        novel_record = {
            "src_ip": src_ip,
            "ai_probability": ai_prob,
            "trigger": trigger_reason,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "note": "Flagged internally — no OTX record — potential novel threat"
        }
        novel_threats.append(novel_record)
        print(f"  [OTX] → NOVEL THREAT LOGGED: {src_ip} not in any known feed")

    return {
        "src_ip": src_ip,
        "otx_found": otx_result["found"],
        "otx_pulse_count": otx_result.get("pulse_count", 0),
        "otx_confidence": round(otx_confidence, 4),
        "novel_threat": not otx_result["found"] and ai_prob > 0.6,
        "trigger_reason": trigger_reason,
        "error": otx_result.get("error")
    }

if __name__ == "__main__":
    print("=== OTX Cross-Reference Test ===\n")

    # Scenario 1: Known malicious IP (use a real known-bad IP for testing)
    print("--- Scenario 1: Query a known suspicious IP ---")
    flow1 = {
        "src_ip": "185.220.101.1",  # known Tor exit node — likely in OTX
        "dst_ip": "10.0.0.1",
        "dst_port": 443,
        "probability_malicious": 0.87
    }
    result1 = run_otx_check(flow1, trigger_reason="shap_margin_flag")
    print(f"  Result: found={result1['otx_found']} | "
          f"pulses={result1['otx_pulse_count']} | "
          f"confidence={result1['otx_confidence']}\n")

    # Scenario 2: Unknown/private IP — not in OTX
    print("--- Scenario 2: Private IP — not in OTX ---")
    flow2 = {
        "src_ip": "10.0.0.7",
        "dst_ip": "10.0.0.99",
        "dst_port": 9999,
        "probability_malicious": 0.43
    }
    result2 = run_otx_check(flow2, trigger_reason="honeytoken_hit",
                             honeytoken_hit=True)
    print(f"  Result: found={result2['otx_found']} | "
          f"confidence={result2['otx_confidence']} | "
          f"novel={result2['novel_threat']}\n")

    # Scenario 3: Suspicious IP not in OTX — novel threat candidate
    print("--- Scenario 3: High AI probability, not in OTX ---")
    flow3 = {
        "src_ip": "192.168.100.50",
        "dst_ip": "10.0.0.1",
        "dst_port": 22,
        "probability_malicious": 0.78
    }
    result3 = run_otx_check(flow3, trigger_reason="risk_sampler")
    print(f"  Result: found={result3['otx_found']} | "
          f"confidence={result3['otx_confidence']} | "
          f"novel={result3['novel_threat']}")

    if novel_threats:
        print(f"\n  Novel threats logged this session: {len(novel_threats)}")
        for t in novel_threats:
            print(f"  → {t['src_ip']} | prob={t['ai_probability']} | "
                  f"trigger={t['trigger']}")