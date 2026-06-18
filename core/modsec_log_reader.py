import docker
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ModSecMatch:
    rule_id: str
    message: str
    matched_data: str
    severity: str
    tags: list[str]

@dataclass
class ModSecVerdict:
    unique_id: Optional[str]
    is_interrupted: bool
    anomaly_score: Optional[int]
    matches: list[ModSecMatch] = field(default_factory=list)

    def primary_category(self) -> str:
        rule_ids = [m.rule_id for m in self.matches]
        if "942100" in rule_ids:
            return "SIGNATURE_MATCHED_LIBINJECTION"
        if any(rid.startswith("9421") or rid.startswith("9423") for rid in rule_ids):
            return "SIGNATURE_MATCHED_SQLI_PATTERN"
        if any(rid.startswith("920") for rid in rule_ids):
            return "PROTOCOL_VIOLATION"
        if any(rid.startswith("933") for rid in rule_ids):
            return "SIGNATURE_MATCHED_PHP"
        if self.anomaly_score is not None and self.anomaly_score >= 10:
            return "ANOMALY_SCORE_EXCEEDED"
        return "GENERIC_BLOCK"

class ModSecLogReader:
    def __init__(self, container_name: str = "modsec_waf", max_cache: int = 2000):
        self.container_name = container_name
        self.max_cache = max_cache
        self._cache: dict[str, dict] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._client = docker.from_env()
        self._container = self._client.containers.get(container_name)
        self._thread: Optional[threading.Thread] = None
        self._started = False
        self._buffer = ""

    def start(self) -> None:
        if self._started:
            return
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()
        self._started = True

    def _read_loop(self) -> None:
        try:
            for chunk in self._container.logs(stream=True, follow=True, tail=0):
                text = chunk.decode("utf-8", errors="ignore")
                self._buffer += text

                while "\n" in self._buffer:
                    line, self._buffer = self._buffer.split("\n", 1)
                    line = line.strip()
                    if not line.startswith('{"transaction"'):
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    uri = data.get("transaction", {}).get("request", {}).get("uri", "")
                    if not uri:
                        continue

                    with self._lock:
                        self._cache[uri] = data
                        self._order.append(uri)
                        if len(self._order) > self.max_cache:
                            oldest = self._order.pop(0)
                            self._cache.pop(oldest, None)
        except Exception as e:
            import traceback
            print(f"[ModSecLogReader] _read_loop crashed: {e}")
            traceback.print_exc()

    def get_verdict_for_uri(self, full_uri: str, wait: float = 0.5, poll_interval: float = 0.02) -> Optional[ModSecVerdict]:
        import time
        deadline = time.time() + wait
        while time.time() < deadline:
            with self._lock:
                data = self._cache.get(full_uri)
            if data is not None:
                return self._parse(data)
            time.sleep(poll_interval)
        return None

    def _parse(self, data: dict) -> ModSecVerdict:
        tx = data.get("transaction", {})
        messages = tx.get("messages", [])

        matches = []
        anomaly_score = None
        for m in messages:
            details = m.get("details", {})
            matches.append(ModSecMatch(
                rule_id=details.get("ruleId", ""),
                message=m.get("message", ""),
                matched_data=details.get("data", ""),
                severity=details.get("severity", ""),
                tags=details.get("tags", []),
            ))
            score_match = re.search(r"Total Score:\s*(\d+)", m.get("message", ""))
            if score_match:
                anomaly_score = int(score_match.group(1))

        return ModSecVerdict(
            unique_id=tx.get("unique_id"),
            is_interrupted=tx.get("is_interrupted", False),
            anomaly_score=anomaly_score,
            matches=matches,
        )