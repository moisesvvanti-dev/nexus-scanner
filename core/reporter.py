from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
from urllib.parse import urlparse

try:
    from .models import Vulnerability
except ImportError:
    from core.models import Vulnerability


class ReportGenerator:
    """Generate professional reports from confirmed/suspected Nexus findings.

    The report is intentionally evidence-first: it does not claim exploitation,
    zero-day discovery, or CVE attribution unless that data is present in the
    finding itself. Anything that requires manual browser/OOB confirmation is
    shown with false-positive guidance instead of being inflated.
    """

    def __init__(self, findings: list[Vulnerability]):
        self.findings = findings
        self.report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def save_html_report(self, output_dir: str | Path = "relatorios") -> Path:
        """Write the HTML report to output_dir and return the generated path."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        filename = f"nexus_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        output_path = out_dir / filename
        output_path.write_text(self.generate_html(), encoding="utf-8")
        return output_path

    def generate_markdown(self) -> str:
        """Generate a concise Markdown report for text exports."""
        lines = [
            f"# NEXUS+ Relatório Profissional de Segurança",
            f"Gerado em: {self.report_date}",
            "",
            "## Escopo seguro",
            "Somente alvos autorizados devem ser testados. O relatório separa evidência real de suspeita para evitar falso positivo.",
            "",
        ]
        if not self.findings:
            lines.append("Nenhuma vulnerabilidade confirmada foi registrada.")
            return "\n".join(lines)

        for i, finding in enumerate(self.findings, 1):
            lines.extend(
                [
                    f"## {i}. {finding.vuln_type}",
                    f"- Alvo: {finding.target}",
                    f"- Severidade: {finding.severity} / CVSS {finding.cvss_score:.1f}",
                    f"- Confidence: {finding.confidence}",
                    f"- Evidência: {finding.evidence or finding.impact}",
                    f"- Como corrigir: {finding.remediation}",
                    f"- Alerta de falso positivo: {finding.false_positive_note or 'Não informado.'}",
                    "",
                ]
            )
        return "\n".join(lines)

    def generate_governor_report(self) -> str:
        """Safe replacement for the old command-execution styled report."""
        lines = [
            f"# NEXUS+ Relatório Profissional de Segurança - {self.report_date}",
            "",
            "Relatório somente informativo. Links de execução local/remota foram desativados para evitar ações inseguras.",
            "",
        ]
        lines.append(self.generate_markdown())
        return "\n".join(lines)

    def generate_html(self, ai_assistant=None) -> str:
        """Generates a premium, interactive, Disney+ inspired HTML report."""
        severity_counts = self._severity_counts()
        rows = "".join(self._finding_card(finding, i) for i, finding in enumerate(self.findings, 1))
        empty_state = "" if self.findings else """
            <section class="panel empty-state">
                <h2>Nenhuma vulnerabilidade confirmada</h2>
                <p>O scanner não registrou evidência suficiente para confirmar vulnerabilidades. Suspeitas devem aparecer como alerta de falso positivo, não como achado crítico.</p>
            </section>
        """

        total = len(self.findings)
        confirmed = sum(1 for f in self.findings if str(getattr(f, "confidence", "")).upper() in {"CONFIRMED", "HIGH"})
        fp_notes = sum(1 for f in self.findings if getattr(f, "false_positive_note", ""))

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEXUS+ Relatório Profissional de Segurança</title>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300..900;1,9..40,300..900&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #050816;
            --surface: rgba(14, 25, 55, 0.78);
            --surface-strong: #101d42;
            --card: rgba(16, 30, 70, 0.82);
            --blue: #0063e5;
            --blue-2: #00a6ff;
            --cyan: #7dd8ff;
            --green: #1ed760;
            --red: #ff4b6e;
            --orange: #ffb02e;
            --text: #f8fbff;
            --muted: #a9b8d8;
            --line: rgba(145, 171, 255, 0.18);
            --shadow: rgba(0, 0, 0, 0.48) 0 28px 90px;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            font-family: 'DM Sans', system-ui, -apple-system, 'Segoe UI', sans-serif;
            color: var(--text);
            background:
                radial-gradient(circle at 12% 5%, rgba(0, 99, 229, .55), transparent 30%),
                radial-gradient(circle at 82% 0%, rgba(0, 166, 255, .32), transparent 28%),
                linear-gradient(180deg, #020617 0%, #07132d 42%, #030712 100%);
            min-height: 100vh;
        }}
        a {{ color: var(--cyan); word-break: break-word; }}
        .hero {{
            min-height: 360px;
            padding: 42px clamp(20px, 5vw, 72px);
            position: relative;
            overflow: hidden;
            border-bottom: 1px solid var(--line);
        }}
        .hero::after {{
            content: "";
            position: absolute;
            inset: auto -10% -45% -10%;
            height: 250px;
            background: linear-gradient(90deg, transparent, rgba(0,166,255,.28), transparent);
            filter: blur(44px);
            transform: rotate(-4deg);
        }}
        .brand {{ display: flex; align-items: center; gap: 14px; color: #dff4ff; font-weight: 800; letter-spacing: .18em; text-transform: uppercase; }}
        .brand-mark {{ width: 42px; height: 42px; border-radius: 50%; background: linear-gradient(135deg, var(--blue), var(--cyan)); box-shadow: 0 0 32px rgba(0, 166, 255, .55); }}
        .hero h1 {{ max-width: 980px; margin: 50px 0 18px; font-size: clamp(36px, 7vw, 86px); line-height: .92; letter-spacing: -0.055em; }}
        .hero p {{ max-width: 820px; color: var(--muted); font-size: clamp(16px, 2vw, 21px); line-height: 1.65; }}
        .hero-badges {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 28px; }}
        .pill {{ border: 1px solid var(--line); border-radius: 999px; padding: 10px 16px; background: rgba(255,255,255,.06); color: #d9ecff; font-weight: 800; font-size: 12px; letter-spacing: .12em; text-transform: uppercase; }}
        main {{ width: min(1240px, calc(100% - 32px)); margin: -58px auto 80px; position: relative; z-index: 2; }}
        .metrics {{ display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 14px; margin-bottom: 18px; }}
        .metric, .panel, .finding {{ background: var(--surface); border: 1px solid var(--line); border-radius: 24px; box-shadow: var(--shadow); backdrop-filter: blur(22px); }}
        .metric {{ padding: 18px; min-height: 126px; }}
        .metric span {{ color: var(--muted); font-size: 12px; font-weight: 900; letter-spacing: .14em; text-transform: uppercase; }}
        .metric strong {{ display:block; margin-top: 12px; font-size: 42px; line-height: 1; }}
        .metric.critical strong {{ color: var(--red); }} .metric.high strong {{ color: var(--orange); }} .metric.medium strong {{ color: var(--cyan); }} .metric.low strong {{ color: var(--green); }}
        .panel {{ padding: 28px; margin: 18px 0; }}
        .panel h2, .finding h2 {{ margin: 0 0 14px; font-size: 25px; letter-spacing: -0.02em; }}
        .panel p, .panel li {{ color: var(--muted); line-height: 1.65; }}
        .grid-2 {{ display: grid; grid-template-columns: 1.15fr .85fr; gap: 18px; }}
        .chart-bars {{ display: grid; gap: 12px; margin-top: 16px; }}
        .bar-row {{ display: grid; grid-template-columns: 88px 1fr 36px; gap: 12px; align-items: center; color: var(--muted); font-weight: 800; }}
        .bar-track {{ height: 12px; border-radius: 999px; background: rgba(255,255,255,.07); overflow: hidden; }}
        .bar-fill {{ height: 100%; border-radius: 999px; background: linear-gradient(90deg, var(--blue), var(--cyan)); }}
        .finding {{ padding: 0; margin: 18px 0; overflow: hidden; }}
        .finding-header {{ display:flex; gap:16px; justify-content:space-between; align-items:flex-start; padding:24px 26px; background: linear-gradient(100deg, rgba(0,99,229,.18), rgba(255,255,255,.02)); border-bottom: 1px solid var(--line); }}
        .finding-title {{ min-width:0; }}
        .finding-title h2 {{ margin-bottom: 7px; }}
        .finding-target {{ color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }}
        .badge {{ display:inline-flex; align-items:center; border-radius:999px; padding:8px 12px; font-size:11px; font-weight:900; letter-spacing:.12em; text-transform:uppercase; border:1px solid currentColor; white-space:nowrap; }}
        .badge.critical {{ color: var(--red); background: rgba(255,75,110,.12); }} .badge.high {{ color: var(--orange); background: rgba(255,176,46,.12); }} .badge.medium {{ color: var(--cyan); background: rgba(125,216,255,.12); }} .badge.low, .badge.info {{ color: var(--green); background: rgba(30,215,96,.12); }}
        .finding-body {{ display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; padding: 22px; }}
        .section-card {{ background: rgba(255,255,255,.045); border: 1px solid var(--line); border-radius: 18px; padding: 18px; }}
        .section-card.wide {{ grid-column: 1 / -1; }}
        .section-card h3 {{ margin:0 0 10px; color:#eaf7ff; font-size:14px; letter-spacing:.12em; text-transform:uppercase; }}
        .section-card p, .section-card pre {{ color: var(--muted); line-height:1.65; }}
        pre {{ white-space: pre-wrap; overflow-x:auto; background: #020817; border: 1px solid rgba(125,216,255,.18); border-radius: 14px; padding: 14px; color: #b9e7ff !important; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
        .warning {{ border-color: rgba(255,176,46,.35); background: rgba(255,176,46,.09); }}
        footer {{ color: var(--muted); text-align:center; padding: 36px 16px 60px; }}
        @media (max-width: 900px) {{ .metrics {{ grid-template-columns: repeat(2, 1fr); }} .grid-2, .finding-body {{ grid-template-columns: 1fr; }} .section-card.wide {{ grid-column: auto; }} }}
    </style>
</head>
<body>
    <header class="hero">
        <div class="brand"><span class="brand-mark"></span><span>NEXUS+</span></div>
        <h1>Relatório Profissional de Segurança</h1>
        <p>HTML premium, Disney+ inspired, com foco em evidência real, PoC reproduzível, correção prática e alertas explícitos quando um achado pode ser falso positivo.</p>
        <div class="hero-badges">
            <span class="pill">Somente alvos autorizados</span>
            <span class="pill">Sem simulação</span>
            <span class="pill">Sem CVE inventado</span>
            <span class="pill">Gerado em {escape(self.report_date)}</span>
        </div>
    </header>
    <main>
        <section class="metrics">
            {self._metric_card('Total', total)}
            {self._metric_card('Confirmados', confirmed)}
            {self._metric_card('FP alerts', fp_notes)}
            {self._metric_card('Críticos', severity_counts['CRITICAL'], 'critical')}
            {self._metric_card('Altos', severity_counts['HIGH'], 'high')}
            {self._metric_card('Médios', severity_counts['MEDIUM'], 'medium')}
        </section>
        <section class="grid-2">
            <div class="panel">
                <h2>Resumo executivo</h2>
                <p>Foram registrados <strong>{total}</strong> achados. O scanner foi configurado para falhar fechado: uma vulnerabilidade só deve aparecer como confirmada quando houver indicador concreto, evidência rastreável e confiança compatível.</p>
                <p>Solicitações de zero-day real exigem autorização formal do alvo. Este relatório documenta como reproduzir em ambiente autorizado/local e como corrigir as classes de vulnerabilidade sem inflar resultados.</p>
            </div>
            <div class="panel">
                <h2>Distribuição gráfica</h2>
                {self._bar_chart(severity_counts, total)}
            </div>
        </section>
        <section class="grid-2">
            <div class="panel">
                <h2>Como foi feito</h2>
                <ul>
                    <li>Removemos simulações, callbacks falsos e mensagens que afirmavam execução sem prova.</li>
                    <li>Adicionamos baseline anti-soft-404, tokens únicos e validação estrita para CVE.</li>
                    <li>Incluímos campos de evidência, confidence e alerta de falso positivo em cada achado.</li>
                    <li>Validamos com testes automatizados e compile dos módulos alterados.</li>
                </ul>
            </div>
            <div class="panel">
                <h2>Como testar mais fundo com autorização</h2>
                <ul>
                    <li>Defina escopo formal do alvo, janela de teste, rate limit e contatos de emergência.</li>
                    <li>Use ambiente local/lab primeiro; depois rode somente contra domínios autorizados.</li>
                    <li>Configure <code>NEXUS_OOB_CALLBACK</code> real para SSRF/OOB; sem isso, o scanner deve alertar e não simular.</li>
                    <li>Exija reprodução independente: payload/token único, resposta capturada e comparação contra baseline.</li>
                </ul>
            </div>
        </section>
        <section class="panel warning">
            <h2>Alerta operacional</h2>
            <p><strong>Somente alvos autorizados:</strong> não foram executados ataques contra sites de terceiros sem autorização. Para buscar vulnerabilidades críticas/zero-day de forma real, configure um programa autorizado, escopo documentado, janela de teste, rate limit e evidência OOB real.</p>
        </section>
        {empty_state}
        {rows}
    </main>
    <footer>Relatório gerado pelo Nexus Scanner com validação real, evidência rastreável e triagem anti-falso positivo.</footer>
</body>
</html>"""

    def _metric_card(self, label: str, value: int, klass: str = "") -> str:
        return f'<div class="metric {klass}"><span>{escape(label)}</span><strong>{int(value)}</strong></div>'

    def _severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            severity = str(getattr(finding, "severity", "INFO")).upper()
            counts[severity if severity in counts else "INFO"] += 1
        return counts

    def _bar_chart(self, counts: dict[str, int], total: int) -> str:
        labels = [("CRITICAL", "Crítico"), ("HIGH", "Alto"), ("MEDIUM", "Médio"), ("LOW", "Baixo"), ("INFO", "Info")]
        rows = []
        denom = max(total, 1)
        for key, label in labels:
            value = counts.get(key, 0)
            pct = round((value / denom) * 100, 2)
            rows.append(
                f'<div class="bar-row"><span>{label}</span><div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div><b>{value}</b></div>'
            )
        return '<div class="chart-bars">' + ''.join(rows) + '</div>'

    def _finding_card(self, finding: Vulnerability, idx: int) -> str:
        severity = escape(str(getattr(finding, "severity", "INFO")).upper())
        severity_class = severity.lower()
        target = escape(str(getattr(finding, "target", "")))
        vuln_type = escape(str(getattr(finding, "vuln_type", "Unknown")))
        impact = escape(str(getattr(finding, "impact", "")))
        remediation = escape(str(getattr(finding, "remediation", "")))
        evidence = escape(str(getattr(finding, "evidence", "") or getattr(finding, "impact", "")))
        confidence = escape(str(getattr(finding, "confidence", "UNVERIFIED")))
        fp_note = escape(str(getattr(finding, "false_positive_note", "") or "Nenhum alerta adicional registrado."))
        cvss = float(getattr(finding, "cvss_score", 0.0) or 0.0)
        poc = self._build_safe_poc(finding)
        reproduction = self._build_reproduction_steps(finding)

        return f"""
        <article class="finding">
            <div class="finding-header">
                <div class="finding-title">
                    <h2>#{idx} — {vuln_type}</h2>
                    <div class="finding-target">{target}</div>
                </div>
                <span class="badge {severity_class}">{severity} · CVSS {cvss:.1f}</span>
            </div>
            <div class="finding-body">
                <div class="section-card">
                    <h3>Confidence</h3>
                    <p><strong>confidence:</strong> {confidence}</p>
                    <p>Use este campo para diferenciar evidência forte de suspeita que precisa de validação manual.</p>
                </div>
                <div class="section-card">
                    <h3>Impacto técnico</h3>
                    <p>{impact}</p>
                </div>
                <div class="section-card wide">
                    <h3>PoC real e evidência</h3>
                    <pre>{poc}</pre>
                    <p><strong>Evidência capturada:</strong> {evidence}</p>
                </div>
                <div class="section-card">
                    <h3>Como reproduzir com autorização</h3>
                    <pre>{reproduction}</pre>
                </div>
                <div class="section-card">
                    <h3>Como corrigir</h3>
                    <p>{remediation}</p>
                </div>
                <div class="section-card wide warning">
                    <h3>Alerta de falso positivo</h3>
                    <p>{fp_note}</p>
                </div>
            </div>
        </article>
        """

    def _build_safe_poc(self, finding: Vulnerability) -> str:
        target = str(getattr(finding, "target", ""))
        parsed = urlparse(target)
        safe_target = target if parsed.scheme in {"http", "https"} else "https://authorized.example/"
        lines = [
            "# PoC segura: executar somente contra alvo autorizado",
            f"curl -i --max-time 15 {safe_target!r}",
            "# Critério de confirmação: comparar resposta com a evidência abaixo e com baseline anti-soft-404.",
            f"# Evidence: {str(getattr(finding, 'evidence', '') or getattr(finding, 'impact', ''))}",
        ]
        return escape("\n".join(lines))

    def _build_reproduction_steps(self, finding: Vulnerability) -> str:
        return escape("\n".join([
            "1. Confirme autorização formal e escopo do alvo.",
            "2. Configure rate limit, proxy/logs e, se necessário, NEXUS_OOB_CALLBACK real.",
            "3. Execute o scanner contra o alvo autorizado e capture status, headers e corpo da resposta.",
            "4. Repita com um caminho/token aleatório para descartar soft-404 e conteúdo pré-existente.",
            "5. Só marque como confirmado se a evidência for reproduzível e específica do payload/token.",
        ]))
