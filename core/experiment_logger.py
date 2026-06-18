import csv
import json
from pathlib import Path
from .request_engine import HttpObservation
from .response_classifier import Classification
from .policy_engine import TestCase

class ExperimentLogger:
    def __init__(self, out_dir: str = "logs") -> None:
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.csv_path = self.out_dir / "events.csv"
        self.jsonl_path = self.out_dir / "events.jsonl"
        self.jsonl_path.write_text("")
        self._init_csv()

    def _init_csv(self) -> None:
        # if self.csv_path.exists():
        #     return
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "depth", "category", "label", "reason", "confidence",
                "status", "length", "elapsed", "input_preview", "parent_preview",
            ])

    def log(self, case: TestCase, obs: HttpObservation, cls: Classification) -> None:
        modsec_info = None
        if obs.modsec_verdict is not None:
            modsec_info = {
                "unique_id": obs.modsec_verdict.unique_id,
                "anomaly_score": obs.modsec_verdict.anomaly_score,
                "rule_ids": [m.rule_id for m in obs.modsec_verdict.matches],
                "primary_category": obs.modsec_verdict.primary_category(),
            }

        row = {
            "depth": case.depth,
            "category": case.category,
            "label": cls.label,
            "reason": cls.reason,
            "confidence": cls.confidence,
            "status": obs.status,
            "length": obs.length,
            "elapsed": round(obs.elapsed, 5),
            "input_preview": case.value[:120],
            "parent_preview": (case.parent or "")[:120],
            "features": cls.features,
            "url": obs.url,
            "body_preview": (obs.body or "")[:300],
            "modsec": modsec_info,
        }

        with self.csv_path.open("a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                row["depth"], row["category"], row["label"], row["reason"], row["confidence"],
                row["status"], row["length"], row["elapsed"], row["input_preview"], row["parent_preview"],
            ])
        with self.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
