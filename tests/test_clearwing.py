"""Tests for Clearwing."""

from clearwing.scanner import ActiveScanner


def test_scanner_initialization():
    scanner = ActiveScanner("https://example.com")
    assert scanner.target == "https://example.com"
    assert scanner.timeout == 10
    assert len(scanner.payloads) > 0


def test_add_payload():
    scanner = ActiveScanner("https://example.com")
    scanner.add_payload("custom", "test")
    assert "custom" in scanner.payloads
    assert "test" in scanner.payloads["custom"]


def test_score_sql_indicator():
    scanner = ActiveScanner("https://example.com")

    class MockResp:
        text = "You have an error in your SQL syntax"
        status_code = 500

    score = scanner._score("sql_injection", MockResp())
    assert score > 0.2  # 1 indicator hit + status 500 = ~0.3


def test_classify_finding():
    scanner = ActiveScanner("https://example.com")
    assert "CRITICAL" in scanner._classify("sql_injection", 0.8)
    assert "HIGH" in scanner._classify("xss", 0.6)
    assert scanner._classify("ssrf", 0.3) == ""
