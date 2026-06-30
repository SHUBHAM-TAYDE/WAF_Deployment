import os
import pickle
import logging
import sqlite3
import json
import requests
from fastapi import FastAPI, BackgroundTasks, Response, status
from pydantic import BaseModel, Field

import feature_pipeline
import redis_features
import threat_score

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 1. Enforce strict model loading at boot initialization
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
XGB_PATH = os.path.join(BASE_DIR, "models/xgboost.pkl")
ISO_PATH = os.path.join(BASE_DIR, "models/isolation_forest.pkl")

if not os.path.exists(XGB_PATH) or not os.path.exists(ISO_PATH):
    logger.critical("Model binaries missing at startup! Partial model loading is forbidden.")
    raise FileNotFoundError("Missing classification binaries (models/xgboost.pkl and models/isolation_forest.pkl). Crash looping.")

try:
    with open(XGB_PATH, "rb") as f:
        xgb_model = pickle.load(f)
    with open(ISO_PATH, "rb") as f:
        iso_model = pickle.load(f)
    logger.info("Successfully loaded XGBoost and Isolation Forest models into memory.")
except Exception as e:
    logger.critical(f"Failed to load model binaries: {e}")
    raise SystemExit(1)

# 2. SQLite client configuration
DB_PATH = "/opt/ModSecurity/WAF_GUI/backend/app/data/ml_events.db"

def init_sqlite_db():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ml_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                unique_id TEXT,
                crs_score REAL,
                matched_vars TEXT,
                uri TEXT,
                args TEXT,
                method TEXT,
                body_len REAL,
                ct TEXT,
                ua TEXT,
                remote_addr TEXT,
                redis_rpm REAL,
                redis_rep REAL,
                xgb_prob REAL,
                iso_score REAL,
                threat_score REAL,
                decision TEXT,
                abuse_score REAL DEFAULT 0.0
            )
        """)
        conn.commit()
        
        # Dynamic schema update for existing tables
        try:
            cursor.execute("SELECT abuse_score FROM ml_events LIMIT 1;")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE ml_events ADD COLUMN abuse_score REAL DEFAULT 0.0;")
            conn.commit()

        try:
            cursor.execute("SELECT unique_id FROM ml_events LIMIT 1;")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE ml_events ADD COLUMN unique_id TEXT;")
            conn.commit()
            
        conn.close()
        try:
            os.chmod(DB_PATH, 0o666)
        except Exception:
            pass
        logger.info("Successfully initialized ML events SQLite database with abuse_score column.")
    except Exception as e:
        logger.error(f"Failed to initialize SQLite database: {e}")

init_sqlite_db()

# Initialize FastAPI App
app = FastAPI(title="ML-Enhanced WAF Prediction Daemon")

class RequestTelemetry(BaseModel):
    unique_id: str = Field(default="", description="Unique request/transaction ID")
    crs_score: float = Field(default=0.0, description="Anomaly score calculated by OWASP CRS")
    matched_vars: str = Field(default="", description="Variables matched by ModSecurity rules")
    uri: str = Field(default="", description="Request URI path")
    args: str = Field(default="", description="Query arguments or POST payload parameters")
    method: str = Field(default="", description="HTTP Request Method")
    body_len: float = Field(default=0.0, description="Content-Length of the request body")
    ct: str = Field(default="", description="Content-Type header value")
    ua: str = Field(default="", description="User-Agent header value")
    remote_addr: str = Field(default="", description="IP address of the client")

def write_to_sqlite(event: dict):
    """Asynchronous analytics ingestion handler using SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("""
            INSERT INTO ml_events (
                unique_id, crs_score, matched_vars, uri, args, method, body_len, ct, ua, remote_addr,
                redis_rpm, redis_rep, xgb_prob, iso_score, threat_score, decision, abuse_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("unique_id", ""),
            event.get("crs_score", 0.0),
            event.get("matched_vars", ""),
            event.get("uri", ""),
            event.get("args", ""),
            event.get("method", ""),
            event.get("body_len", 0.0),
            event.get("ct", ""),
            event.get("ua", ""),
            event.get("remote_addr", ""),
            event.get("redis_rpm", 0.0),
            event.get("redis_rep", 0.0),
            event.get("xgb_prob", 0.0),
            event.get("iso_score", 0.0),
            event.get("threat_score", 0.0),
            event.get("decision", ""),
            event.get("abuse_score", 0.0)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to insert ML event to SQLite: {e}")

@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    """Service health state endpoint."""
    return {"status": "healthy", "models_loaded": True}

SETTINGS_PATH = "/opt/ModSecurity/WAF_GUI/backend/app/config/settings.json"

def fetch_abuseipdb_score(ip: str):
    """
    Asynchronous background task to fetch IP reputation from AbuseIPDB API
    and cache the result in Redis. Skipped for internal subnet scopes.
    """
    # Exclude internal / RFC1918 IPs
    if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        redis_features.save_abuse_score(ip, 0.0)
        return

    try:
        if not os.path.exists(SETTINGS_PATH):
            logger.warning(f"Settings JSON not found at {SETTINGS_PATH}. Cannot query AbuseIPDB.")
            return

        with open(SETTINGS_PATH, "r") as f:
            settings = json.load(f)
        
        abuse_cfg = settings.get("abuseipdb", {})
        if not abuse_cfg.get("enabled", False):
            return
            
        api_key = abuse_cfg.get("api_key", "")
        if not api_key:
            logger.warning("AbuseIPDB API key missing in settings configuration.")
            return

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        
        # Safe timeout to avoid blocking resources
        response = requests.get(url, headers=headers, params=params, timeout=5.0)
        if response.status_code == 200:
            res_json = response.json()
            score = float(res_json.get("data", {}).get("abuseConfidenceScore", 0.0))
            redis_features.save_abuse_score(ip, score)
            logger.info(f"Successfully fetched and cached AbuseIPDB score for IP {ip}: {score}%")
        else:
            logger.warning(f"AbuseIPDB request failed for IP {ip}: HTTP {response.status_code}")
    except Exception as e:
        logger.error(f"Error querying AbuseIPDB for IP {ip}: {e}")

@app.post("/predict")
def predict(payload: RequestTelemetry, background_tasks: BackgroundTasks, response: Response):
    """
    Main evaluation pipeline endpoint.
    Retrieves Redis behavioral metrics, constructs the feature vector,
    scores the request, updates Redis counters, and schedules logging.
    """
    ip = payload.remote_addr or "unknown"
    
    # 1. Fetch live Redis behavioral telemetry
    redis_rpm, redis_rep, abuse_score = redis_features.get_redis_metrics(ip)
    
    # Trigger background intelligence check on cache miss
    if abuse_score is None:
        background_tasks.add_task(fetch_abuseipdb_score, ip)
        abuse_score = 0.0 # Default to clean for the current request
    
    # 2. Map payload telemetry to data dictionary for the feature pipeline
    data_map = payload.model_dump()
    data_map['redis_rpm'] = redis_rpm
    data_map['redis_rep'] = redis_rep
    
    # 3. Process numerical feature vector
    try:
        features = feature_pipeline.build_features(data_map)
    except Exception as e:
        logger.error(f"Feature engineering failed: {e}")
        # Default to safe allow, letting ModSecurity's base rules decide
        response.status_code = status.HTTP_200_OK
        return {"decision": "allow", "threat_score": 0.0}

    # 4. Perform machine learning inference
    try:
        # Supervised probability of threat
        xgb_prob = float(xgb_model.predict_proba(features)[0][1])
        # Unsupervised anomaly/novelty score
        iso_score = float(iso_model.score_samples(features)[0])
    except Exception as e:
        logger.error(f"ML Inference failed: {e}")
        response.status_code = status.HTTP_200_OK
        return {"decision": "allow", "threat_score": 0.0}

    # 5. Calculate normalized combined threat score
    score = threat_score.calculate_threat_score(payload.crs_score, xgb_prob, iso_score, redis_rep, abuse_score)
    decision = threat_score.get_routing_outcome(score, payload.crs_score)

    # 6. Update Redis behavioral metrics and IP reputation counters based on outcome
    # Run requests tracker for every evaluation
    background_tasks.add_task(redis_features.increment_request_counters, ip)

    if decision == "block":
        # ML hard block -> increment reputation penalty heavily
        background_tasks.add_task(redis_features.increment_reputation, ip)
        response.status_code = status.HTTP_401_UNAUTHORIZED

    elif decision == "rate_limit":
        # Partial threat (score 0.70-0.85) -> return 429, also penalise reputation
        # so that repeated rate-limited requests escalate toward a hard block.
        background_tasks.add_task(redis_features.increment_reputation, ip)
        response.status_code = status.HTTP_429_TOO_MANY_REQUESTS

    else:
        # "log" or "allow" -> clean or low-risk request, slowly decay reputation
        background_tasks.add_task(redis_features.decay_reputation, ip)
        response.status_code = status.HTTP_200_OK

    # 7. Schedule asynchronous event logging to SQLite
    event_data = {
        **payload.model_dump(),
        "redis_rpm": redis_rpm,
        "redis_rep": redis_rep,
        "xgb_prob": xgb_prob,
        "iso_score": iso_score,
        "threat_score": score,
        "decision": decision,
        "abuse_score": abuse_score
    }
    background_tasks.add_task(write_to_sqlite, event_data)

    return {"decision": decision, "threat_score": score}
