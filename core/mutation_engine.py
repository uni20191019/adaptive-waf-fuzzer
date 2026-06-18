import urllib.parse
import random
import re

class MutationEngine:
    STRATEGIES = {
        "SIGNATURE_MATCHED_LIBINJECTION": [
            "double_encode", "unicode_encode", "whitespace_substitute", "case_mutation", "comment_insert",
        ],
        "SIGNATURE_MATCHED_SQLI_PATTERN": [
            "double_encode", "comment_insert", "case_mutation", "unicode_encode",
        ],
        "PROTOCOL_VIOLATION": [
            "double_encode",
        ],
        "SIGNATURE_MATCHED_PHP": [
            "double_encode", "unicode_encode",
        ],
        "ANOMALY_SCORE_EXCEEDED": [
            "comment_insert", "benign_prefix", "whitespace_substitute",
        ],
        "RATE_LIMITED": [
            "slow_rate",
        ],
        "IP_BLOCKED": [
            "header_spoof",
        ],
        "GENERIC_BLOCK": [
            "double_encode", "unicode_encode",
        ],
    }

    def __init__(self):
        self.success_rates: dict[str, float] = {}

    def record_result(self, strategy: str, success: bool) -> None:
        alpha = 0.1
        prev = self.success_rates.get(strategy, 0.5)
        self.success_rates[strategy] = alpha * (1.0 if success else 0.0) + (1 - alpha) * prev

    def get_mutations(self, value: str, filter_reason: str) -> list[tuple[str, str]]:
        strategies = self.STRATEGIES.get(filter_reason, ["unicode_encode"])
        strategies = sorted(
            strategies,
            key=lambda s: self.success_rates.get(s, 0.5),
            reverse=True,
        )

        results = []
        for strategy in strategies:
            fn = getattr(self, f"_mut_{strategy}", None)
            if fn:
                results.append((fn(value), strategy))
        return results

    def get_success_rates(self) -> dict[str, float]:
        return dict(self.success_rates)

    def _mut_unicode_encode(self, p: str) -> str:
        result = []
        for c in p:
            if c.isalpha() and random.random() < 0.4:
                result.append(f"%{ord(c):02x}")
            else:
                result.append(c)
        return "".join(result)

    def _mut_double_encode(self, p: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(p))

    def _mut_case_mutation(self, p: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p))

    def _mut_comment_insert(self, p: str) -> str:
        SQL_KEYWORDS = (
            r'UNION|SELECT|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|'
            r'GROUP|ORDER|BY|HAVING|LIMIT|JOIN|AS|NULL|NOT|LIKE|IN|'
            r'EXISTS|BETWEEN|CASE|WHEN|THEN|ELSE|DISTINCT|INTO|VALUES|'
            r'SLEEP|BENCHMARK|EXTRACTVALUE|UPDATEXML|CONCAT|SUBSTRING|'
            r'CONVERT|CAST|COUNT|VERSION|DATABASE|USER|SCHEMA'
        )

        def replacer(match):
            keyword = match.group(1)
            trailing_space = match.group(2)
 
            if len(keyword) >= 2:
                split_idx = random.randint(1, len(keyword) - 1)
                mutated = keyword[:split_idx] + '/**/' + keyword[split_idx:]
            else:
                mutated = keyword
                
            return mutated + trailing_space

        return re.sub(
            rf'\b({SQL_KEYWORDS})(\s*)',
            replacer,
            p,
            flags=re.IGNORECASE,
        )

    def _mut_benign_prefix(self, p: str) -> str:
        return f"1 AND 1=1 AND {p}"

    def _mut_header_spoof(self, p: str) -> str:
        return p

    def _mut_slow_rate(self, p: str) -> str:
        return p
    
    def _mut_whitespace_substitute(self, p: str) -> str:
        replacements = ["\t", "\n", "/**/", "%09", "%0a", "+"]
        result = []
        for ch in p:
            if ch == " " and random.random() < 0.7:
                result.append(random.choice(replacements))
            else:
                result.append(ch)
        return "".join(result)