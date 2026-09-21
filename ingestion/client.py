# ─── Ingestion Client ─────────────────────────────────────────────────────────
# Polls the AI team's API every 5 seconds and pulls flow predictions.
# Hands each batch to the pipeline for processing.
# When real AI API is ready: update AI_TEAM_URL in config/settings.py only.

import requests
import time
import sys
import os

# Add project root to path so we can import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import AI_TEAM_URL, AI_TEAM_BATCH_INTERVAL

def fetch_predictions():
    """
    Pull one batch of flow predictions from the AI team's API.
    Returns a list of flow dictionaries, or empty list on failure.
    """
    try:
        response = requests.get(AI_TEAM_URL, timeout=5)
        response.raise_for_status()
        data = response.json()
        flows = data.get("flows", [])
        print(f"[Ingestion] Received {len(flows)} flows")
        return flows
    except requests.exceptions.ConnectionError:
        print("[Ingestion] ERROR: Cannot reach AI server. Is it running?")
        return []
    except requests.exceptions.Timeout:
        print("[Ingestion] ERROR: AI server timed out.")
        return []
    except Exception as e:
        print(f"[Ingestion] ERROR: {e}")
        return []

def run_ingestion_loop(callback=None):
    """
    Continuously poll the AI server every 5 seconds.
    If a callback function is provided, pass each batch to it for processing.
    """
    print(f"[Ingestion] Starting — polling {AI_TEAM_URL} every {AI_TEAM_BATCH_INTERVAL}s")
    while True:
        flows = fetch_predictions()
        if flows and callback:
            callback(flows)
        time.sleep(AI_TEAM_BATCH_INTERVAL)

if __name__ == "__main__":
    # Test mode — just print what we receive
    def print_flows(flows):
        for i, flow in enumerate(flows):
            print(f"  Flow {i+1}: src={flow['src_ip']} → dst={flow['dst_ip']} "
                  f"| malicious={flow['probability_malicious']}")

    run_ingestion_loop(callback=print_flows)