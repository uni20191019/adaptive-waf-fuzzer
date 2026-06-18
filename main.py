import argparse
import csv
import hashlib
from collections import Counter
from pathlib import Path

from core.experiment_logger import ExperimentLogger
from core.policy_engine import PolicyEngine
from core.request_engine import RequestEngine
from core.response_classifier import ResponseClassifier

LOG_DIR = "logs"

def load_seeds(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return ["1", "0", "99999999", "abc", "", "A" * 64]

    seeds = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip("\n")
        if line and not line.startswith("#"):
            seeds.append(line)

    return list(dict.fromkeys(seeds))

def preview(value: str, limit: int = 120) -> str:
    value = value.replace("\n", "\\n").replace("\r", "\\r")
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."

def sha1_text(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()

def score_result(label: str, reason: str) -> int:
    if label == "BEHAVIOR_CHANGE":
        return 100
    if label == "PERFORMANCE_ANOMALY":
        return 90
    if label == "SERVER_ANOMALY":
        return 80
    if label == "TRANSPORT_ANOMALY":
        return 70
    if label == "NO_EFFECT" and reason == "NORMAL_BASELINE_MATCH":
        return 30
    if label == "NO_EFFECT" and reason == "EMPTY_BASELINE_MATCH":
        return 20
    if label == "FILTERED":
        return 10
    return 0

def is_better_candidate(candidate: dict, current: dict | None) -> bool:
    if current is None:
        return True

    if candidate["score"] != current["score"]:
        return candidate["score"] > current["score"]

    if candidate["best_depth"] != current["best_depth"]:
        return candidate["best_depth"] < current["best_depth"]

    return candidate["elapsed"] < current["elapsed"]

def build_best_candidate(root_id: str, original_value: str, case, obs, cls) -> dict:
    return {
        "root_id": root_id,
        "original_sha1": sha1_text(original_value),
        "original_preview": preview(original_value),
        "best_sha1": sha1_text(case.value),
        "input_preview": preview(case.value),
        "best_depth": case.depth,
        "best_category": case.category,
        "label": cls.label,
        "reason": cls.reason,
        "status": obs.status,
        "length": obs.length,
        "elapsed": round(obs.elapsed, 5),
        "score": score_result(cls.label, cls.reason),
    }

def write_best_cases(log_dir: str, best_by_root: dict) -> Path:
    out_path = Path(log_dir) / "best_cases.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "root_id",
        "original_sha1",
        "original_preview",
        "best_sha1",
        "input_preview",
        "best_depth",
        "best_category",
        "label",
        "reason",
        "status",
        "length",
        "elapsed",
        "score",
    ]

    rows = list(best_by_root.values())

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return out_path

def attach_lineage(case, root_id: str, original_value: str, lineage_map: dict) -> None:
    try:
        case.root_id = root_id
        case.original_value = original_value
    except Exception:
        pass

    lineage_map[id(case)] = {
        "root_id": root_id,
        "original_value": original_value,
    }

def get_lineage(case, lineage_map: dict) -> tuple[str, str]:
    root_id = getattr(case, "root_id", None)
    original_value = getattr(case, "original_value", None)

    if root_id is not None and original_value is not None:
        return root_id, original_value

    saved = lineage_map.get(id(case))
    if saved:
        return saved["root_id"], saved["original_value"]

    fallback_root = f"unknown_{sha1_text(case.value)[:12]}"
    return fallback_root, case.value

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Adaptive security tester for authorized lab targets"
    )
    parser.add_argument("--target", default="http://localhost/vulnerabilities/sqli/")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--param", default="id")
    parser.add_argument("--seeds", default="datasets/test_seed.txt")
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument(
        "--cookie",
        action="append",
        default=[],
        help="Cookie as name=value; repeatable",
    )
    args = parser.parse_args()

    cookies = dict(item.split("=", 1) for item in args.cookie if "=" in item)

    engine = RequestEngine(args.target, method=args.method, cookies=cookies or None)
    classifier = ResponseClassifier()
    policy = PolicyEngine(max_depth=args.max_depth)
    logger = ExperimentLogger(LOG_DIR)

    print("[*] Registering baselines")

    normal = engine.send_input(
        "1",
        param_name=args.param,
        category="baseline_normal",
    )
    empty = engine.send_input(
        "99999999",
        param_name=args.param,
        category="baseline_empty",
    )

    classifier.register_baselines(normal, empty, None)

    print(f"    normal: status={normal.status}, length={normal.length}, elapsed={normal.elapsed:.4f}s")
    print(f"    empty : status={empty.status}, length={empty.length}, elapsed={empty.elapsed:.4f}s")
    print(f"    normal fingerprint: {normal.fingerprint}")
    print(f"    empty  fingerprint: {empty.fingerprint}")

    if normal.length == empty.length and normal.fingerprint != empty.fingerprint:
        print(
            "    [!] normal/empty length is identical, but body fingerprint differs. "
            "Using fingerprint/similarity instead of length-only matching."
        )

    seeds = load_seeds(args.seeds)
    initial_queue = policy.initial_queue(seeds)

    queue = initial_queue
    lineage_map = {}

    for idx, case in enumerate(queue, 1):
        root_id = f"seed_{idx:05d}"
        attach_lineage(case, root_id, case.value, lineage_map)

    seen = set()

    raw_counts = Counter()
    best_by_root = {}

    events = 0

    while queue:
        case = queue.popleft()

        root_id, original_value = get_lineage(case, lineage_map)

        key = (root_id, case.value, case.depth, case.category)
        if key in seen:
            continue

        seen.add(key)

        obs = engine.send_input(
            case.value,
            param_name=args.param,
            category=case.category,
            extra_headers=case.extra_headers,
        )
        cls = classifier.classify(obs)

        logger.log(case, obs, cls)

        if case.category.startswith("evasion_"):
            strategy_name = case.category.removeprefix("evasion_")
            success = cls.label in {"BEHAVIOR_CHANGE", "SERVER_ANOMALY", "PERFORMANCE_ANOMALY"}
            policy.mutator.record_result(strategy_name, success)

        raw_counts[cls.label] += 1
        events += 1

        candidate = build_best_candidate(
            root_id=root_id,
            original_value=original_value,
            case=case,
            obs=obs,
            cls=cls,
        )

        current_best = best_by_root.get(root_id)
        best_updated = is_better_candidate(candidate, current_best)

        if best_updated:
            best_by_root[root_id] = candidate

        print(
            f"[{events:04d}] root={root_id:<10} depth={case.depth} "
            f"category={case.category:<22} "
            f"label={cls.label:<20} reason={cls.reason:<24} "
            f"score={candidate['score']:<3} "
            f"best={'UPDATED' if best_updated else 'KEEP':<7} "
            f"status={obs.status} len={obs.length} "
            f"time={obs.elapsed:.4f}s input={case.value[:60]!r}"
        )

        for nxt in policy.next_cases(case, cls):
            attach_lineage(nxt, root_id, original_value, lineage_map)
            queue.append(nxt)

    best_path = write_best_cases(LOG_DIR, best_by_root)

    best_counts = Counter(row["label"] for row in best_by_root.values())
    best_reason_counts = Counter(row["reason"] for row in best_by_root.values())

    print("\n=== Raw Event Summary ===")
    print(f"Total raw events: {events}")
    for label, count in raw_counts.most_common():
        print(f"{label:>22}: {count}")

    print("\n=== Best-Per-Payload Summary ===")
    print(f"Total original payload families: {len(best_by_root)}")
    for label, count in best_counts.most_common():
        print(f"{label:>22}: {count}")

    print("\n=== Best Reason Summary ===")
    for reason, count in best_reason_counts.most_common():
        print(f"{reason:>28}: {count}")

    print("\nlogs/events.csv and logs/events.jsonl written")
    print(f"{best_path} written")

    print("\n=== Evasion Strategy Success Rates ===")
    rates = policy.mutator.get_success_rates()
    if rates:
        for strategy, rate in sorted(rates.items(), key=lambda x: x[1], reverse=True):
            bar = "█" * int(rate * 20)
            print(f"  {strategy:<22} {rate:.3f}  {bar}")
    else:
        print("  (no evasion attempts recorded)")

if __name__ == "__main__":
    main()