import difflib
import re
from dataclasses import dataclass
from typing import Dict, Optional
from .request_engine import HttpObservation

@dataclass
class Classification:
    label: str
    reason: str
    confidence: float
    features: Dict[str, object]

class ResponseClassifier:
    FILTER_PATTERNS = [
        r"access denied",
        r"forbidden",
        r"request blocked",
        r"not acceptable",
        r"malicious request",
        r"mod_security",
        r"modsecurity",
        r"anomaly score",
        r"coreruleset",
        r"owasp crs",
    ]
    SERVER_ERROR_PATTERNS = [
        r"exception", r"traceback", r"stack trace", r"warning:", r"fatal error",
        r"sqlstate", r"database", r"syntax error", r"server error",
    ]

    def __init__(self) -> None:
        self.baselines: Dict[str, Optional[HttpObservation]] = {
            "normal": None,
            "empty": None,
            "filtered": None,
        }

    def register_baselines(
        self,
        normal: HttpObservation,
        empty: HttpObservation,
        filtered: Optional[HttpObservation] = None,
    ) -> None:
        self.baselines["normal"] = normal
        self.baselines["empty"] = empty
        self.baselines["filtered"] = filtered

    def classify(self, obs: HttpObservation) -> Classification:
        features = self._features(obs)
        status = obs.status
        body = obs.body or ""

        if status in {"TIMEOUT", "CONNECTION_ERROR"}:
            return Classification("TRANSPORT_ANOMALY", str(status), 0.95, features)
        if status == "REQUEST_ERROR":
            return Classification("CLIENT_ERROR", "REQUEST_LIBRARY_ERROR", 0.95, features)

        if features["same_as_normal"]:
            return Classification("NO_EFFECT", "NORMAL_BASELINE_MATCH", 0.90, features)
        if features["same_as_empty"]:
            return Classification("NO_EFFECT", "EMPTY_BASELINE_MATCH", 0.88, features)

        if isinstance(status, int) and status in (401, 403, 406, 429):
            reason = self._classify_filter_reason(obs, body)
            return Classification("FILTERED", reason, 0.95, features)
        if self._matches(body, self.FILTER_PATTERNS):
            reason = self._classify_filter_reason(obs, body)
            return Classification("FILTERED", reason, 0.90, features)

        if isinstance(status, int) and status >= 500:
            return Classification("SERVER_ANOMALY", "HTTP_5XX", 0.90, features)
        if self._matches(body, self.SERVER_ERROR_PATTERNS):
            return Classification("SERVER_ANOMALY", "ERROR_PATTERN_IN_BODY", 0.85, features)
        if features["length_delta"] or features["fingerprint_delta"]:
            return Classification("BEHAVIOR_CHANGE", "RESPONSE_SHAPE_CHANGED", 0.70, features)
        if features["latency_delta"]:
            return Classification("PERFORMANCE_ANOMALY", "LATENCY_DELTA", 0.70, features)

        return Classification("NO_EFFECT", "LOW_VARIANCE_RESPONSE", 0.55, features)

    def _features(self, obs: HttpObservation) -> Dict[str, object]:
        normal = self.baselines.get("normal")
        empty = self.baselines.get("empty")
        filtered = self.baselines.get("filtered")

        normal_similarity = self._similarity(normal.body, obs.body) if normal else 0.0
        empty_similarity = self._similarity(empty.body, obs.body) if empty else 0.0
        filtered_similarity = self._similarity(filtered.body, obs.body) if filtered else 0.0

        normal_len = normal.length if normal else 0
        empty_len = empty.length if empty else 0
        normal_elapsed = normal.elapsed if normal else 0.0

        same_as_normal = bool(
            normal
            and obs.fingerprint
            and normal.fingerprint
            and obs.fingerprint == normal.fingerprint
        )
        same_as_empty = bool(
            empty
            and obs.fingerprint
            and empty.fingerprint
            and obs.fingerprint == empty.fingerprint
        )

        return {
            "status": obs.status,
            "length": obs.length,
            "elapsed": round(obs.elapsed, 5),
            "normal_similarity": round(normal_similarity, 4),
            "empty_similarity": round(empty_similarity, 4),
            "filtered_similarity": round(filtered_similarity, 4),
            "same_as_normal": same_as_normal,
            "same_as_empty": same_as_empty,
            "exact_normal_fingerprint": same_as_normal,
            "exact_empty_fingerprint": same_as_empty,
            "length_delta": bool(normal_len and abs(obs.length - normal_len) > 40),
            "length_delta_from_empty": bool(empty_len and abs(obs.length - empty_len) > 40),
            "latency_delta": bool(normal_elapsed and obs.elapsed > max(normal_elapsed * 4, normal_elapsed + 2.0)),
            "fingerprint_delta": bool(normal and obs.fingerprint and normal.fingerprint and obs.fingerprint != normal.fingerprint),
        }

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    @staticmethod
    def _matches(body: str, patterns: list[str]) -> bool:
        return any(re.search(p, body, re.IGNORECASE) for p in patterns)
    
    def _classify_filter_reason(self, obs: HttpObservation, body: str) -> str:
        if obs.modsec_verdict is not None:
            return obs.modsec_verdict.primary_category()

        if obs.status == 429:
            return "RATE_LIMITED"
        
        headers = {k.lower(): v for k, v in obs.headers.items()}

        if "x-mod-security" in headers or re.search(r"anomaly score", body, re.I):
            return "ANOMALY_SCORE_EXCEEDED"

        if re.search(r"rule|pattern|signature|matched", body, re.I):
            return "SIGNATURE_MATCHED"

        if re.search(r"your ip|ip address|ip.{0,20}block", body, re.I):
            return "IP_BLOCKED"

        if re.search(r"cloudflare|cf-ray", body + str(headers), re.I):
            return "CLOUDFLARE_BLOCK"

        if obs.status == 403 and re.search(r"<center>nginx</center>", body, re.I):
            return "SIGNATURE_MATCHED"
        
        return "GENERIC_BLOCK"
