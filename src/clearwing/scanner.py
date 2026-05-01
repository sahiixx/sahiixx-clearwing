"""Active vulnerability scanner — HTTP/API fuzzing engine."""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import requests


@dataclass
class ScanResult:
    target: str
    payload_type: str
    payload: str
    endpoint: str
    method: str
    status_code: int
    response_snippet: str
    confidence: float  # 0.0–1.0
    curl_repro: str
    finding: str = ""


class ActiveScanner:
    """Actively probe a target with configurable payloads."""

    DEFAULT_PAYLOADS: dict[str, list[str]] = {
        "sql_injection": [
            "' OR '1'='1",
            "' UNION SELECT null,null--",
            "1; DROP TABLE users--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ],
        "ssrf": [
            "http://169.254.169.254/",
            "http://localhost:22/",
            "file:///etc/passwd",
        ],
        "idor": [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
        ],
        "command_injection": [
            "; cat /etc/passwd",
            "| whoami",
            "`id`",
        ],
    }

    INDICATORS: dict[str, list[str]] = {
        "sql_injection": ["sql syntax", "mysql_fetch", "ora-", "pg_query", "unclosed quotation"],
        "xss": ["<script>", "alert(1)", "onerror="],
        "ssrf": ["root:x:", "ec2-metadata", "internal server"],
        "idor": ["root:x:", "[boot loader]", "windows nt"],
        "command_injection": ["root:", "uid=", "gid="],
    }

    def __init__(
        self,
        target: str,
        timeout: int = 10,
        max_depth: int = 2,
        payloads: Optional[dict[str, list[str]]] = None,
    ) -> None:
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.max_depth = max_depth
        self.payloads = payloads or dict(self.DEFAULT_PAYLOADS)
        self.results: list[ScanResult] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Clearwing/0.1.0 (Security Research)",
        })

    def add_payload(self, category: str, payload: str) -> None:
        self.payloads.setdefault(category, []).append(payload)

    def run(self, endpoints: Optional[list[str]] = None) -> list[ScanResult]:
        """Run all payloads against endpoints."""
        targets = endpoints or ["/", "/api/search", "/api/login", "/api/users"]
        for endpoint in targets:
            for category, payloads in self.payloads.items():
                for payload in payloads:
                    result = self._probe(endpoint, category, payload)
                    if result.confidence >= 0.5:
                        self.results.append(result)
        return self.results

    def _probe(self, endpoint: str, category: str, payload: str) -> ScanResult:
        url = f"{self.target}{endpoint}"
        methods = ["GET", "POST"]
        best: Optional[ScanResult] = None

        for method in methods:
            try:
                if method == "GET":
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}q={urllib.parse.quote(payload)}"
                    resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                else:
                    resp = self.session.post(
                        url,
                        json={"q": payload},
                        timeout=self.timeout,
                        allow_redirects=False,
                    )

                confidence = self._score(category, resp)
                curl = self._to_curl(method, url, payload)
                snippet = resp.text[:500]

                result = ScanResult(
                    target=self.target,
                    payload_type=category,
                    payload=payload,
                    endpoint=endpoint,
                    method=method,
                    status_code=resp.status_code,
                    response_snippet=snippet,
                    confidence=confidence,
                    curl_repro=curl,
                    finding=self._classify(category, confidence),
                )

                if best is None or result.confidence > best.confidence:
                    best = result

            except requests.RequestException:
                continue

        return best or ScanResult(
            target=self.target,
            payload_type=category,
            payload=payload,
            endpoint=endpoint,
            method="GET",
            status_code=0,
            response_snippet="",
            confidence=0.0,
            curl_repro="",
        )

    def _score(self, category: str, resp: requests.Response) -> float:
        text = resp.text.lower()
        indicators = self.INDICATORS.get(category, [])
        hits = sum(1 for ind in indicators if ind.lower() in text)
        base = min(hits / max(len(indicators), 1), 1.0)
        # Boost for interesting status codes
        if resp.status_code in (200, 500, 302):
            base += 0.1
        return min(base, 1.0)

    def _classify(self, category: str, confidence: float) -> str:
        if confidence >= 0.7:
            return f"CRITICAL: Confirmed {category.replace('_', ' ').title()}"
        if confidence >= 0.5:
            return f"HIGH: Probable {category.replace('_', ' ').title()}"
        return ""

    @staticmethod
    def _to_curl(method: str, url: str, payload: str) -> str:
        if method == "GET":
            return f"curl -X GET '{url}?q={urllib.parse.quote(payload)}'"
        return (
            f"curl -X POST '{url}' \\\n"
            f"  -H 'Content-Type: application/json' \\\n"
            f"  -d '{{\"q\": \"{payload.replace(chr(34), chr(92)+chr(34))}\"}}'"
        )
