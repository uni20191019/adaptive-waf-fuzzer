# Adaptive WAF Fuzzer

An adaptive, feedback-driven SQL injection fuzzer for testing ModSecurity/OWASP CRS.

Unlike static payload lists, this tool parses ModSecurity's real-time audit log
to determine *why* a request was blocked, then applies a targeted evasion
strategy (encoding, comment insertion, case mutation, etc.) based on that
specific reason. Strategy success rates are learned online, so the system
adapts toward whatever techniques actually work against the target WAF.

## Setup

```bash
docker compose up -d
pip install requests docker
```

Log into DVWA (security level: low) and grab your `PHPSESSID` cookie.
- username: admin
- password: password

## Run

```bash
python main.py \
  --target http://localhost/vulnerabilities/sqli/ \
  --param id \
  --seeds datasets/test_seed.txt \
  --max-depth 3 \
  --cookie "PHPSESSID=<your_session>" \
  --cookie "security=low"
```

## Output

- `logs/events.csv` / `logs/events.jsonl` — every request, classification, and matched ModSecurity rule
- `logs/best_cases.csv` — best outcome per seed payload
- Console summary — success rate per evasion strategy

## Structure

- `core/` — request engine, classifier, mutation engine, policy engine

- `datasets/` — seed payloads (unmutated)

- `main.py` — entry point

- `docker-compose.yml` — DVWA + ModSecurity/CRS lab

## Disclaimer

For authorized security research only. Use only against systems you own or have permission to test.