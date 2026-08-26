import os
import math
import re
import pickle
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np

ML_DIR = Path(__file__).resolve().parent
MODEL_PATH = ML_DIR / "model.pkl"
SCALER_PATH = ML_DIR / "scaler.pkl"

# Patterns for feature extraction from raw HTTP/network logs
SUSPICIOUS_KEYWORDS = [
    r"\.\./",
    r"/etc/passwd",
    r"cmd\.exe",
    r"powershell",
    r"whoami",
    r"eval\(",
    r"exec\(",
    r"system\(",
    r"passthru\(",
    r"<script",
    r"javascript:",
    r"base64_decode",
    r"SELECT\s+.*\s+FROM",
    r"UNION\s+ALL\s+SELECT",
    r"UNION\s+SELECT",
    r"OR\s+1\s*=\s*1",
    r"DROP\s+TABLE",
    r"SLEEP\(\d+\)",
    r"BENCHMARK\(\d+",
    r"xp_cmdshell",
]
SUSPICIOUS_REGEX = re.compile("|".join(SUSPICIOUS_KEYWORDS), re.IGNORECASE)

SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))(\s*)((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|(\'))(\s*)union",
    r"exec(\s|\+)+(s|x)p\w+",
    r"information_schema",
]
SQLI_REGEX = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]

UNUSUAL_UA_PATTERNS = [
    r"sqlmap",
    r"nikto",
    r"nmap",
    r"masscan",
    r"gobuster",
    r"dirbuster",
    r"hydra",
    r"python-requests",
    r"curl/",
    r"wget/",
    r"postmanruntime",
    r"censys",
    r"shodan",
]
UNUSUAL_UA_REGEX = re.compile("|".join(UNUSUAL_UA_PATTERNS), re.IGNORECASE)


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a given string payload."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


class EdgeFilter:
    """
    EdgeFilter loads the trained XGBoost model and feature scaler to score
    incoming raw logs in real time, returning an anomaly/threat probability between 0.0 and 1.0.
    """

    def __init__(self, model_path: Optional[Path] = None, scaler_path: Optional[Path] = None):
        self.model_path = model_path or MODEL_PATH
        self.scaler_path = scaler_path or SCALER_PATH
        self.model = None
        self.scaler = None
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Loads model and scaler from disk if available."""
        if self.model_path.exists() and self.scaler_path.exists():
            try:
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                with open(self.scaler_path, "rb") as f:
                    self.scaler = pickle.load(f)
            except Exception as e:
                print(f"[EdgeFilter] Warning: Failed to load ML artifacts: {e}")
                self.model = None
                self.scaler = None
        else:
            print(f"[EdgeFilter] ML artifacts not found at {self.model_path} or {self.scaler_path}. Will use fallback heuristics until trained.")

    def extract_features(self, raw_log: Dict[str, Any]) -> List[float]:
        """
        Extracts the 8 required model features from a raw log dictionary.
        Supports both raw structured logs and pre-calculated feature payloads.
        """
        # 1. request_rate_per_sec
        request_rate = float(raw_log.get("request_rate_per_sec", raw_log.get("rate", 1.0)))

        # Extract text representations of path, body, headers, query
        path = str(raw_log.get("path", raw_log.get("uri", raw_log.get("url", "/"))))
        body = str(raw_log.get("body", raw_log.get("payload", raw_log.get("data", ""))))
        query = str(raw_log.get("query_params", raw_log.get("query", "")))
        headers = raw_log.get("headers", {})
        user_agent = str(headers.get("user-agent", raw_log.get("user_agent", "")))

        full_payload = f"{path} {query} {body}"

        # 2. payload_entropy
        if "payload_entropy" in raw_log:
            payload_entropy = float(raw_log["payload_entropy"])
        else:
            payload_entropy = calculate_shannon_entropy(body if body else full_payload)

        # 3. failed_auth_count
        if "failed_auth_count" in raw_log:
            failed_auth = float(raw_log["failed_auth_count"])
        else:
            status_code = int(raw_log.get("status_code", raw_log.get("status", 200)))
            failed_auth = 1.0 if status_code in (401, 403) else 0.0

        # 4. path_depth
        if "path_depth" in raw_log:
            path_depth = float(raw_log["path_depth"])
        else:
            path_depth = float(len([seg for seg in path.split("/") if seg]))

        # 5. body_length
        if "body_length" in raw_log:
            body_length = float(raw_log["body_length"])
        else:
            body_length = float(len(body))

        # 6. suspicious_keywords_flag
        if "suspicious_keywords_flag" in raw_log:
            suspicious_flag = float(raw_log["suspicious_keywords_flag"])
        else:
            suspicious_flag = 1.0 if SUSPICIOUS_REGEX.search(full_payload) else 0.0

        # 7. sql_injection_score
        if "sql_injection_score" in raw_log:
            sqli_score = float(raw_log["sql_injection_score"])
        else:
            matches = sum(1 for pattern in SQLI_REGEX if pattern.search(full_payload))
            sqli_score = min(1.0, float(matches) * 0.35)

        # 8. unusual_user_agent
        if "unusual_user_agent" in raw_log:
            unusual_ua = float(raw_log["unusual_user_agent"])
        else:
            if not user_agent or UNUSUAL_UA_REGEX.search(user_agent):
                unusual_ua = 1.0
            else:
                unusual_ua = 0.0

        return [
            request_rate,
            payload_entropy,
            failed_auth,
            path_depth,
            body_length,
            suspicious_flag,
            sqli_score,
            unusual_ua,
        ]

    def _fallback_heuristic_score(self, features: List[float]) -> float:
        """Heuristic fallback score if ML model is not yet loaded."""
        rate, entropy, failed_auth, path_depth, body_len, susp_flag, sqli_score, unusual_ua = features
        score = 0.0
        if susp_flag > 0:
            score += 0.40
        if sqli_score > 0.3:
            score += 0.35
        if unusual_ua > 0:
            score += 0.15
        if failed_auth > 3:
            score += 0.30
        if rate > 20:
            score += 0.20
        if entropy > 5.5:
            score += 0.15
        return min(1.0, float(score))

    async def score_log(self, raw_log: Dict[str, Any]) -> float:
        """
        Extracts features from an incoming raw log payload and returns
        an anomaly probability score between 0.0 (Benign) and 1.0 (High-Confidence Threat).
        """
        # Ensure artifacts are loaded
        if self.model is None or self.scaler is None:
            self._load_artifacts()

        features = self.extract_features(raw_log)

        if self.model is None or self.scaler is None:
            return self._fallback_heuristic_score(features)

        # Run model inference in async executor to prevent blocking
        def _predict():
            import pandas as pd
            feature_names = [
                "request_rate_per_sec",
                "payload_entropy",
                "failed_auth_count",
                "path_depth",
                "body_length",
                "suspicious_keywords_flag",
                "sql_injection_score",
                "unusual_user_agent",
            ]
            X_df = pd.DataFrame([features], columns=feature_names)
            X_scaled = self.scaler.transform(X_df)
            prob = self.model.predict_proba(X_scaled)[0, 1]
            return float(prob)

        try:
            prob = await asyncio.to_thread(_predict)
            return round(prob, 4)
        except Exception as e:
            print(f"[EdgeFilter] Inference error: {e}, falling back to heuristics")
            return self._fallback_heuristic_score(features)
