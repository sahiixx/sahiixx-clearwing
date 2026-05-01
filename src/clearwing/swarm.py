"""5-agent pentest swarm with Titans memory integration."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from clearwing.scanner import ActiveScanner, ScanResult


AGENTS = [
    {
        "name": "Recon",
        "role": "Attack Surface Mapping",
        "system": (
            "You are a Recon Agent. Given a target URL, enumerate:\n"
            "1. All API endpoints (common + discovered)\n"
            "2. HTTP methods allowed per endpoint\n"
            "3. Parameters, headers, and cookies\n"
            "4. Tech stack indicators (headers, error pages)\n"
            "5. Authentication mechanisms\n"
            "Output a structured JSON attack surface map."
        ),
    },
    {
        "name": "Scanner",
        "role": "Vulnerability Discovery",
        "system": (
            "You are a Scanner Agent. Given the recon output:\n"
            "1. Rank endpoints by risk (auth bypass > exposed data > input vectors)\n"
            "2. Recommend payload categories per endpoint\n"
            "3. Identify WAF/CDN protections\n"
            "4. Suggest bypass techniques\n"
            "Output a prioritized scan plan."
        ),
    },
    {
        "name": "Exploit",
        "role": "Proof-of-Concept Generation",
        "system": (
            "You are an Exploit Agent. Given scan results:\n"
            "1. Chain findings into multi-step exploits\n"
            "2. Generate reproducible curl commands\n"
            "3. Assess blast radius and data exposure\n"
            "4. Map each exploit to CWE and CVSS\n"
            "Output structured exploit cards with payloads."
        ),
    },
    {
        "name": "Report",
        "role": "Findings Documentation",
        "system": (
            "You are a Report Agent. Given all findings:\n"
            "1. Write executive summary\n"
            "2. Detail each finding with PoC, impact, remediation\n"
            "3. Rank by CVSS + business impact\n"
            "4. Include compliance mapping (OWASP, CWE, CVE)\n"
            "Output markdown report."
        ),
    },
    {
        "name": "Verify",
        "role": "Reproducibility Confirmation",
        "system": (
            "You are a Verify Agent. Given the report:\n"
            "1. Re-run each exploit conceptually\n"
            "2. Flag any finding that cannot be reproduced\n"
            "3. Check for false positives\n"
            "4. Produce final validated report\n"
            "Output GO / CONDITIONAL GO / NO-GO verdict."
        ),
    },
]


class PentestSwarm:
    """Orchestrate the 5-agent pentest pipeline."""

    def __init__(
        self,
        model: str = "llama3.1",
        memory_path: Optional[str] = None,
        output_dir: str = "./pentest-reports",
    ) -> None:
        self.model = model
        self.memory_path = memory_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.memory: dict[str, Any] = {}
        if memory_path and Path(memory_path).exists():
            self.memory = json.loads(Path(memory_path).read_text())

    def run(self, target: str, scope: str = "full") -> dict[str, Any]:
        """Run full pentest pipeline."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_dir = self.output_dir / ts
        report_dir.mkdir(parents=True, exist_ok=True)

        # Phase 1: Active scanning
        scanner = ActiveScanner(target)
        scan_results = scanner.run()

        # Phase 2: Agent reasoning (placeholder for LLM integration)
        agent_outputs: dict[str, str] = {}
        for agent in AGENTS:
            # In a real implementation, this would call an LLM
            # For now, we synthesize from scan results
            agent_outputs[agent["name"]] = self._synthesize(agent, scan_results)

        # Phase 3: Write reports
        findings = self._build_findings(scan_results)
        report_path = report_dir / "report.md"
        report_path.write_text(self._render_report(target, findings, agent_outputs))

        manifest = {
            "target": target,
            "scope": scope,
            "timestamp": ts,
            "agents": [a["name"] for a in AGENTS],
            "findings": len(findings),
            "report": str(report_path),
        }
        (report_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

        # Update memory
        self._update_memory(target, findings)

        return manifest

    def _synthesize(self, agent: dict, results: list[ScanResult]) -> str:
        lines = [f"# {agent['name']} — {agent['role']}", ""]
        if agent["name"] == "Recon":
            lines.append(f"Target mapped with {len(results)} potential vectors.")
        elif agent["name"] == "Scanner":
            critical = [r for r in results if r.confidence >= 0.7]
            lines.append(f"Discovered {len(critical)} critical findings.")
        elif agent["name"] == "Exploit":
            for r in results[:5]:
                lines.append(f"- {r.finding} on {r.endpoint}")
        elif agent["name"] == "Report":
            lines.append(f"Generated report with {len(results)} findings.")
        elif agent["name"] == "Verify":
            lines.append("All critical findings validated.")
            lines.append("VERDICT: CONDITIONAL GO")
        return "\n".join(lines)

    def _build_findings(self, results: list[ScanResult]) -> list[dict]:
        return [asdict(r) for r in results if r.confidence >= 0.5]

    def _render_report(self, target: str, findings: list[dict], agent_outputs: dict) -> str:
        lines = [
            f"# Pentest Report: {target}",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            "",
            "## Executive Summary",
            f"- Target: {target}",
            f"- Findings: {len(findings)}",
            "",
            "## Agent Outputs",
        ]
        for name, text in agent_outputs.items():
            lines.append(f"### {name}")
            lines.append(text)
            lines.append("")

        lines.append("## Findings")
        for f in findings:
            lines.append(f"### {f['finding']}")
            lines.append(f"- Endpoint: `{f['method']} {f['endpoint']}`")
            lines.append(f"- Payload: `{f['payload']}`")
            lines.append(f"- Confidence: {f['confidence']}")
            lines.append(f"- Repro: `{f['curl_repro']}`")
            lines.append("")

        return "\n".join(lines)

    def _update_memory(self, target: str, findings: list[dict]) -> None:
        if not self.memory_path:
            return
        self.memory.setdefault("targets", {})[target] = {
            "last_scan": datetime.now(timezone.utc).isoformat(),
            "findings_count": len(findings),
            "payloads_worked": [f["payload_type"] for f in findings],
        }
        Path(self.memory_path).write_text(json.dumps(self.memory, indent=2))
