# ─── Threat Intel Feed — Central Configuration ───────────────────────────────

# AI Team API
AI_TEAM_URL = "http://localhost:8080/predictions"  # replace with real URL later
AI_TEAM_BATCH_INTERVAL = 5  # seconds — unconfirmed, placeholder

# SHAP Thresholds
PROBABILITY_MARGIN_LOW = 0.35   # standard borrowed value
PROBABILITY_MARGIN_HIGH = 0.65  # standard borrowed value
FRAGILE_SHAP_THRESHOLD = 0.30   # >30% fragile feature contribution = flag
                                 # NOTE: needs sensitivity analysis on real data

# Reliability Window
RELIABILITY_WINDOW = 500        # rolling predictions per model grade
PSI_DRIFT_THRESHOLD = 0.20      # industry standard cutoff
FLAGGED_RATE_THRESHOLD = 0.60   # roughest guess — validate in calibration

# Trust Score Bands
TRUST_TRUSTED = 0.80            # >= this → trusted (green)
TRUST_SUSPICIOUS = 0.50         # >= this → suspicious (yellow), else malicious

# Idle Device Handling
IDLE_GRACE_CYCLES = 2           # hold last score for this many cycles (~10s)
IDLE_DECAY_TARGET = 0.50        # decay toward neutral, not zero

# OTX
OTX_API_KEY = ""                # get free key from otx.alienvault.com
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

# Dashboard Endpoints (what YOU serve)
SERVE_PORT = 5000
import os

# dotenv (python-dotenv) may not be available in all environments (linting/CI).
# Fall back to a no-op loader to avoid import errors while allowing env var usage.
try:
    from dotenv import load_dotenv
except Exception:
    def load_dotenv(path: str = ".env") -> None:
        """No-op fallback for load_dotenv when python-dotenv is unavailable."""
        return

load_dotenv()
OTX_API_KEY="41254caac15e75ae68f8d0d7714f436bfbcb37880709e44353914970d881bab6"
OTX_API_KEY = os.getenv("OTX_API_KEY", "41254caac15e75ae68f8d0d7714f436bfbcb37880709e44353914970d881bab6")