from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, List, Optional
import time
from .response_classifier import Classification
from .mutation_engine import MutationEngine

@dataclass
class TestCase:
    value: str
    category: str
    parent: Optional[str] = None
    depth: int = 0
    extra_headers: Optional[dict] = None

class PolicyEngine:
    def __init__(self, max_depth: int = 3, max_cases_per_seed: int = 4) -> None:
        self.max_depth = max_depth
        self.max_cases_per_seed = max_cases_per_seed
        self.stats: Dict[str, int] = defaultdict(int)
        self.mutator = MutationEngine() 

    def initial_queue(self, seeds: Iterable[str]) -> Deque[TestCase]:
        q: Deque[TestCase] = deque()
        for seed in seeds:
            q.append(TestCase(seed, category="seed", depth=0))
        return q

    def next_cases(self, case: TestCase, classification: Classification) -> List[TestCase]:
        if case.depth >= self.max_depth:
            return []

        label = classification.label
        reason = classification.reason

        if label == "FILTERED":
            return self._evasion_cases(case, reason)

        if label == "NO_EFFECT":
            return []

        if label in {"BEHAVIOR_CHANGE", "PERFORMANCE_ANOMALY"}:
            return self._make_cases(
                self._nearby_variants(case.value), "stability_probe", case
            )

        if label in {"SERVER_ANOMALY", "TRANSPORT_ANOMALY"}:
            return self._make_cases(
                self._minimize_variants(case.value), "anomaly_probe", case
            )

        return []

    def _evasion_cases(self, case: TestCase, filter_reason: str) -> List[TestCase]:
        mutations = self.mutator.get_mutations(case.value, filter_reason)
        results = []
        seen = set()
        for mutated_value, strategy_name in mutations:
            is_payload_unchanged = (strategy_name in ("header_spoof", "slow_rate"))

            if mutated_value in seen:
                continue
            if mutated_value == case.value and not is_payload_unchanged:
                continue
            seen.add(mutated_value)

            extra_headers = None
            if strategy_name == "header_spoof":
                extra_headers = {
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "X-Originating-IP": "127.0.0.1",
                }

            if strategy_name == "slow_rate":
                time.sleep(3.0)

            results.append(TestCase(
                value=mutated_value,
                category=f"evasion_{strategy_name}",
                parent=case.value,
                depth=case.depth + 1,
                extra_headers=extra_headers,
            ))
        return results

    def _make_cases(self, values: List[str], category: str, parent_case: TestCase) -> List[TestCase]:
        seen = set()
        result = []
        for v in values:
            if v in seen:
                continue
            seen.add(v)
            result.append(TestCase(
                value=v,
                category=category,
                parent=parent_case.value,
                depth=parent_case.depth + 1,
            ))
        return result

    @staticmethod
    def _minimize_variants(value: str) -> List[str]:
        mid = max(1, len(value) // 2)
        return [value[:mid], value[mid:], value.strip(), value[:1]]

    @staticmethod
    def _nearby_variants(value: str) -> List[str]:
        return [value, value + " ", value.strip(), value.upper(), value.lower()]