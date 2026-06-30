#!/usr/bin/env python3
"""
Nexus Scanner V2 — Bug Bounty & Vulnerability Scanner
======================================================
Uso: python run_nexus_v2.py <url> [url2 url3 ...]

Características:
- ZERO falsos positivos (validação multi-camada)
- Busca intel de bug bounty + 0day em tempo real
- WAF bypass automático (Cloudflare, Akamai, AWS, etc)
- Exploração REAL de vulnerabilidades (não simulação)
- Relatório detalhado com evidências capturadas
"""

import asyncio
import sys
import os
import json
from datetime import datetime

# Adiciona o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.v2_engine import NexusV2Engine, ValidationReport
from core.bugbounty_hunter import BugBountyHunter, NexusV2Orchestrator
from core.real_exploiter import RealExploiter


async def main():
    print(r"""
  ╔═══════════════════════════════════════════════╗
  ║     NEXUS SCANNER ULTIMATE V2                 ║
  ║     Bug Bounty & 0Day Intelligence            ║
  ║     ZERO False Positives Engine               ║
  ╚═══════════════════════════════════════════════╝
    """)

    # Parse targets
    targets = sys.argv[1:] if len(sys.argv) > 1 else []

    if not targets:
        print("USO: python run_nexus_v2.py <url> [url2 url3 ...]")
        print("     python run_nexus_v2.py --scan https://exemplo.com")
        print("     python run_nexus_v2.py --intel (apenas coleta intel)")
        print()
        targets_input = input("Digite a(s) URL(s) alvo (separadas por espaço): ").strip()
        if targets_input:
            targets = targets_input.split()
        else:
            print("Nenhum alvo fornecido. Usando modo intel-only.")
            targets = []

    # ──────────────────────────────────────────────
    # MODO: Apenas coleta de inteligência
    # ──────────────────────────────────────────────
    if "--intel" in sys.argv:
        print("[MODE] Intelligence Collection Only")
        hunter = BugBountyHunter()
        intel = await hunter.collect_all(["exploitdb", "cve", "github"])
        print(f"\n[+] Collected {len(intel)} intelligence items\n")

        for item in intel:
            print(f"[{item.source.upper()}] [{item.severity}] {item.title[:120]}")
            if item.cve_id:
                print(f"       CVE: {item.cve_id}")
            if item.poc_url:
                print(f"       PoC: {item.poc_url}")
            print()
        return

    # ──────────────────────────────────────────────
    # MODO: Scan completo
    # ──────────────────────────────────────────────
    if not targets:
        return

    orchestrator = NexusV2Orchestrator(targets=targets)
    report = await orchestrator.run()

    # Exibe sumário executivo
    print()
    print(report.get("summary", ""))

    # ──────────────────────────────────────────────
    # RELATÓRIO DETALHADO
    # ──────────────────────────────────────────────
    findings = report.get("findings", [])
    intel_items = report.get("intel", [])
    matches = report.get("intel_matches_detail", [])

    print("\n" + "=" * 70)
    print("  RELATÓRIO DETALHADO DE VULNERABILIDADES")
    print("=" * 70)

    if not findings:
        print("\n  ✅ Nenhuma vulnerabilidade confirmada encontrada.")
        print("     (Todos os resultados foram validados contra falsos positivos)")
    else:
        for i, vuln in enumerate(findings, 1):
            print(f"\n  ── FINDING #{i} ──")
            print(f"  Tipo:       {vuln.get('vulnerability_type', vuln.get('vuln_name', 'N/A'))}")
            print(f"  Severidade: {vuln.get('severity', 'N/A')} (CVSS: {vuln.get('cvss_estimate', 'N/A')})")
            print(f"  Alvo:       {vuln.get('target_url', 'N/A')}")
            print(f"  Evidência:  {vuln.get('evidence_found', 'N/A')}")
            print(f"  Payload:    {vuln.get('payload_used', 'N/A')}")
            print(f"  Exploração: {vuln.get('exploitation_output', 'N/A')}")
            print(f"  Status:     {vuln.get('status_code', 'N/A')}")
            print(f"  Confiança:  {vuln.get('evidence_confidence', 'N/A')}")
            if vuln.get('remediation'):
                print(f"  Remediação: {vuln.get('remediation')}")

    # Intel matches
    if matches:
        print(f"\n{'=' * 70}")
        print(f"  CORRELAÇÃO COM INTELIGÊNCIA DE AMEAÇAS ({len(matches)} matches)")
        print(f"{'=' * 70}")
        for vuln, intel in matches[:10]:
            print(f"\n  ── Match ──")
            print(f"  Vulnerabilidade: {vuln.get('vuln_name', 'N/A')}")
            print(f"  Intel: [{intel.get('source', 'N/A')}] {intel.get('title', 'N/A')[:100]}")

    # Intel geral
    if intel_items:
        print(f"\n{'=' * 70}")
        print(f"  INTELIGÊNCIA COLETADA ({len(intel_items)} itens)")
        print(f"{'=' * 70}")
        for item in intel_items[:15]:
            print(f"  [{item.get('source', '?')}] [{item.get('severity', '?')}] {item.get('title', 'N/A')[:120]}")

    # ──────────────────────────────────────────────
    # SALVAR RELATÓRIO
    # ──────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join("relatorios", f"scan_{timestamp}")
    os.makedirs(report_dir, exist_ok=True)

    # JSON
    report_path = os.path.join(report_dir, "report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[✓] Relatório salvo: {report_path}")

    # Markdown
    md_path = os.path.join(report_dir, "report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Nexus Scanner V2 — Relatório de Segurança\n\n")
        f.write(f"**Data:** {datetime.now().isoformat()}\n")
        f.write(f"**Alvos:** {', '.join(targets)}\n\n")
        f.write(f"## Sumário\n\n")
        f.write(f"- Total Vulnerabilidades: {report.get('total_vulnerabilities', 0)}\n")
        f.write(f"- CRÍTICAS: {report.get('critical', 0)}\n")
        f.write(f"- HIGH: {report.get('high', 0)}\n")
        f.write(f"- MEDIUM: {report.get('medium', 0)}\n")
        f.write(f"- Intel Coletada: {report.get('total_intel_collected', 0)}\n")
        f.write(f"- Intel Matches: {report.get('intel_matches', 0)}\n\n")

        for vuln in findings:
            f.write(f"## {vuln.get('vuln_name', 'Finding')}\n\n")
            f.write(f"- **Tipo:** {vuln.get('vulnerability_type', 'N/A')}\n")
            f.write(f"- **Severidade:** {vuln.get('severity', 'N/A')} (CVSS: {vuln.get('cvss_estimate', 'N/A')})\n")
            f.write(f"- **Alvo:** {vuln.get('target_url', 'N/A')}\n")
            f.write(f"- **Evidência:** {vuln.get('evidence_found', 'N/A')}\n")
            f.write(f"- **Payload:** `{vuln.get('payload_used', 'N/A')}`\n")
            f.write(f"- **Exploração:** ```{vuln.get('exploitation_output', 'N/A')}```\n")
            f.write(f"- **Confiança:** {vuln.get('evidence_confidence', 'N/A')}\n")
            f.write(f"- **Remediação:** {vuln.get('remediation', 'N/A')}\n\n")

    print(f"[✓] Relatório Markdown: {md_path}")


if __name__ == "__main__":
    asyncio.run(main())