import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
import requests
from requests.adapters import HTTPAdapter
from .modsec_log_reader import ModSecLogReader, ModSecVerdict

@dataclass
class HttpObservation:
    status: Any
    elapsed: float
    body: str
    length: int
    headers: Dict[str, str]
    history: list[int]
    url: str
    fingerprint: Optional[str]
    input_value: str
    input_category: str
    modsec_verdict: Optional[ModSecVerdict] = None

class RequestEngine:
    def __init__(
        self,
        target_url: str,
        method: str = "GET",
        timeout: Tuple[float, float] = (2.0, 5.0),
        cookies: Optional[Dict[str, str]] = None,
        verify_tls: bool = False,
        modsec_container: str | None = "modsec_waf"
    ) -> None:
        self.target_url = target_url
        self.method = method.upper()
        self.timeout = timeout
        self.cookies = cookies or {}
        self.verify_tls = verify_tls
        self.thread_local = threading.local()
        self.modsec_reader = ModSecLogReader(modsec_container) if modsec_container else None
        if self.modsec_reader:
            self.modsec_reader.start()
            time.sleep(0.5)

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=0)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": "AdaptiveSecurityTester/1.0 (authorized lab)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cache-Control": "no-cache",
        })
        if self.cookies:
            session.cookies.update(self.cookies)
        return session

    def _get_session(self) -> requests.Session:
        if not hasattr(self.thread_local, "session"):
            self.thread_local.session = self._create_session()
        return self.thread_local.session

    @staticmethod
    def _fingerprint(body: str) -> Optional[str]:
        if not body:
            return None
        normalized = " ".join(body.split())
        return hashlib.sha1(normalized.encode(errors="ignore")).hexdigest()

    def send_input(self, value: str, *, param_name: str = "id", category: str = "unknown", extra_headers: dict | None = None,) -> HttpObservation:
        session = self._get_session()
        params = {param_name: value, "Submit": "Submit"}

        headers = {}
        if extra_headers:
            headers.update(extra_headers)

        start = time.perf_counter()
        try:
            if self.method == "GET":
                response = session.get(
                    self.target_url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    allow_redirects=True,
                )
            elif self.method == "POST":
                response = session.post(
                    self.target_url,
                    data=params,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    allow_redirects=True,
                )
            else:
                raise ValueError(f"Unsupported method: {self.method}")

            elapsed = time.perf_counter() - start
            body = response.text or ""

            modsec_verdict = None
            if self.modsec_reader:
                full_uri = self._extract_full_uri(response.url)
                modsec_verdict = self.modsec_reader.get_verdict_for_uri(full_uri)

            return HttpObservation(
                status=response.status_code,
                elapsed=elapsed,
                body=body,
                length=len(response.content),
                headers=dict(response.headers),
                history=[r.status_code for r in response.history],
                url=response.url,
                fingerprint=self._fingerprint(body),
                input_value=value,
                input_category=category,
                modsec_verdict=modsec_verdict
            )
        except requests.exceptions.Timeout:
            elapsed = time.perf_counter() - start
            return HttpObservation("TIMEOUT", elapsed, "", 0, {}, [], self.target_url, None, value, category)
        except requests.exceptions.ConnectionError:
            elapsed = time.perf_counter() - start
            return HttpObservation("CONNECTION_ERROR", elapsed, "", 0, {}, [], self.target_url, None, value, category)
        except requests.exceptions.RequestException as exc:
            elapsed = time.perf_counter() - start
            return HttpObservation("REQUEST_ERROR", elapsed, str(exc), 0, {}, [], self.target_url, None, value, category)
        
    @staticmethod
    def _extract_full_uri(full_url: str) -> str:
        from urllib.parse import urlparse
        p = urlparse(full_url)
        return f"{p.path}?{p.query}" if p.query else p.path