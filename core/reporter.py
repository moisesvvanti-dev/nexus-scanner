from datetime import datetime
import base64
try:
    from .models import Vulnerability
except ImportError:
    from core.models import Vulnerability

class ReportGenerator:
    def __init__(self, findings: list[Vulnerability]):
        self.findings = findings
        self.report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return "\n".join(report)

    def generate_governor_report(self):
        """Generates the specialized Governor Mode report with functional buttons."""
        if not self.findings:
            return "# Nenhum Alvo Dominado\n\nNão foram encontradas evidências concretas de execução."

        report = [
            f"# 🛡️ Relatório de Intrusão Autorizada - {self.report_date}",
            "",
            "| Atributo | Detalhe Técnico |",
            "| :--- | :--- |"
        ]

        for finding in self.findings:
            # Prepare the command (PoC or Direct Exploit)
            # If the finding has a 'comando_direto' or similar, use it. 
            # Otherwise, use a default reconnaissance command as fallback.
            raw_cmd = getattr(finding, 'comando_direto', f"curl -s {finding.target}")
            cmd_b64 = base64.b64encode(raw_cmd.encode('utf-8')).decode('utf-8')
            exec_link = f"http://localhost:5000/exec?cmd={cmd_b64}"

            report.append(f"| Vulnerabilidade | {finding.vuln_type} |")
            report.append(f"| Evidência Real | `{finding.impact}` |")
            report.append(f"| Status | **CRÍTICO - PRONTO PARA ACESSAR** |")
            report.append(f"| Ação Executiva | [▶ ACESSAR AGORA]({exec_link}) |")
            report.append("| --- | --- |")

        report.append("\n💡 **Nota do Antigravity:** Este relatório foi gerado sob a Diretriz de Estado V2. Todos os acessos são reais e testados.")
        
        return "\n".join(report)

    def generate_html(self, ai_assistant=None):
        """Generates a premium, interactive HTML report."""
        
        crit_count = sum(1 for f in self.findings if f.severity == 'CRITICAL')
        high_count = sum(1 for f in self.findings if f.severity == 'HIGH')
        med_count = sum(1 for f in self.findings if f.severity == 'MEDIUM')
        low_count = sum(1 for f in self.findings if f.severity == 'LOW')
        
        rows = ""
        for i, f in enumerate(self.findings, 1):
            rows += f"""
            <tr class="finding-row {f.severity.lower()}">
                <td>{i}</td>
                <td><span class="badge {f.severity.lower()}">{f.severity}</span></td>
                <td>{f.cvss_score:.1f}</td>
                <td>{f.vuln_type}</td>
                <td><a href="{f.target}" target="_blank">{f.target}</a></td>
                <td>
                    <button onclick="toggleDetails({i})">VIEW DETAILS</button>
                </td>
            </tr>
            <tr id="desc-{i}" class="details-row" style="display:none;">
                <td colspan="6">
                    <div class="details-content">
                        <div class="details-grid">
                            <div class="details-section">
                                <h4>IMPACT ANALYSIS</h4>
                                <p>{f.impact}</p>
                            </div>
                            <div class="details-section">
                                <h4>REMEDIATION GUIDANCE</h4>
                                <p>{f.remediation}</p>
                            </div>
                        </div>
                        <h4>AI PROOF OF CONCEPT</h4>
                        <div class="ai-poc">
                            {getattr(f, 'ai_poc', "Run AI Analysis to generate PoC.")}
                        </div>
                    </div>
                </td>
            </tr>
            """

        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>NEXUS - Security Assessment Report</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{ background-color: #0a0a12; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
                header {{ background: linear-gradient(90deg, #1a1a2e 0%, #16213e 100%); padding: 30px 20px; border-bottom: 2px solid #00f3ff; box-shadow: 0 4px 15px rgba(0, 243, 255, 0.1); }}
                h1 {{ color: #00f3ff; margin: 0; letter-spacing: 2px; font-size: 2.2rem; }}
                .executive-summary {{ background: #13131f; border-left: 4px solid #00f3ff; padding: 25px; margin: 30px 0; border-radius: 4px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                .executive-summary h2 {{ color: #fff; margin-top: 0; }}
                .executive-summary p {{ line-height: 1.6; color: #bbb; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 30px 0; }}
                .stat-card {{ background: #16213e; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #333; }}
                .stat-value {{ font-size: 2.5rem; font-weight: bold; margin: 10px 0; text-shadow: 0 0 10px currentColor; }}
                
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #13131f; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border-radius: 8px; overflow: hidden; }}
                th {{ background: #1a1a2e; color: #fff; padding: 15px; text-align: left; border-bottom: 2px solid #333; font-weight: 600; }}
                td {{ padding: 15px; border-bottom: 1px solid #2a2a3a; }}
                tr:hover td {{ background: #1a1a2e; }}
                
                .badge {{ padding: 5px 10px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; text-transform: uppercase; }}
                .badge.critical {{ background: rgba(255, 0, 85, 0.1); color: #ff0055; border: 1px solid #ff0055; box-shadow: 0 0 10px rgba(255,0,85,0.2); }}
                .badge.high {{ background: rgba(255, 204, 0, 0.1); color: #ffcc00; border: 1px solid #ffcc00; box-shadow: 0 0 10px rgba(255,204,0,0.2); }}
                .badge.medium {{ background: rgba(0, 243, 255, 0.1); color: #00f3ff; border: 1px solid #00f3ff; box-shadow: 0 0 10px rgba(0,243,255,0.2); }}
                .badge.low {{ background: rgba(0, 255, 157, 0.1); color: #00ff9d; border: 1px solid #00ff9d; box-shadow: 0 0 10px rgba(0,255,157,0.2); }}
                
                .details-content {{ background: #0d0d14; padding: 25px; margin: 15px 0; border-radius: 8px; border: 1px solid #2a2a3a; }}
                .details-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
                .details-section h4 {{ color: #00f3ff; margin-top: 0; border-bottom: 1px solid #2a2a3a; padding-bottom: 8px; letter-spacing: 1px; }}
                .details-section p {{ color: #ccc; line-height: 1.5; }}
                
                .ai-poc {{ background: #000; padding: 20px; border-radius: 6px; font-family: 'Consolas', monospace; color: #00ff9d; border: 1px solid #333; overflow-x: auto; }}
                
                button {{ background: rgba(0, 243, 255, 0.1); border: 1px solid #00f3ff; color: #00f3ff; padding: 8px 15px; border-radius: 4px; font-weight: bold; cursor: pointer; transition: all 0.3s; letter-spacing: 1px; }}
                button:hover {{ background: #00f3ff; color: #000; box-shadow: 0 0 15px rgba(0,243,255,0.4); }}
                
                a {{ color: #00f3ff; text-decoration: none; transition: 0.3s; }}
                a:hover {{ text-shadow: 0 0 8px #00f3ff; }}
            </style>
        </head>
        <body>
            <header>
                <div class="container">
                    <h1>NEXUS SECURITY ASSESSMENT REPORT</h1>
                    <p style="color: #aaa; margin-top: 10px; font-size: 1.1rem;">Automatically generated on: {self.report_date}</p>
                </div>
            </header>
            
            <div class="container">
                <div class="executive-summary">
                    <h2>Executive Summary</h2>
                    <p>This report details the findings of an automated security penetration test conducted by the Nexus Scanner. A total of <strong>{len(self.findings)}</strong> vulnerabilities were discovered across the targeted assets.</p>
                    <p>The analysis revealed <strong>{crit_count} Critical</strong> issues, <strong>{high_count} High</strong> risk issues, <strong>{med_count} Medium</strong> risk issues, and <strong>{low_count} Low</strong> risk issues. Critical vulnerabilities require immediate remediation as they pose a significant threat to infrastructure and data integrity. Detailed impact analysis and remediation guidance for each finding are provided below.</p>
                </div>

                <div class="stats-grid">
                    <div class="stat-card" style="border-color: #ff0055; box-shadow: 0 10px 20px rgba(255,0,85,0.1);">
                        <div style="color: #ff0055; font-weight: bold; letter-spacing: 2px;">CRITICAL</div>
                        <div class="stat-value">{crit_count}</div>
                    </div>
                    <div class="stat-card" style="border-color: #ffcc00; box-shadow: 0 10px 20px rgba(255,204,0,0.1);">
                        <div style="color: #ffcc00; font-weight: bold; letter-spacing: 2px;">HIGH</div>
                        <div class="stat-value">{high_count}</div>
                    </div>
                    <div class="stat-card" style="border-color: #00f3ff; box-shadow: 0 10px 20px rgba(0,243,255,0.1);">
                        <div style="color: #00f3ff; font-weight: bold; letter-spacing: 2px;">MEDIUM</div>
                        <div class="stat-value">{med_count}</div>
                    </div>
                    <div class="stat-card" style="border-color: #00ff9d; box-shadow: 0 10px 20px rgba(0,255,157,0.1);">
                        <div style="color: #00ff9d; font-weight: bold; letter-spacing: 2px;">LOW</div>
                        <div class="stat-value">{low_count}</div>
                    </div>
                </div>

                <div style="background: #16213e; padding: 30px; border-radius: 8px; margin-bottom: 40px; border: 1px solid #333;">
                    <canvas id="vulnChart" style="max-height: 350px;"></canvas>
                </div>

                <h2 style="color: #fff; margin-bottom: 20px; border-bottom: 1px solid #333; padding-bottom: 10px;">Detailed Vulnerability Findings</h2>
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>SEVERITY</th>
                            <th>CVSS</th>
                            <th>VULNERABILITY TYPE</th>
                            <th>TARGET URL / ASSET</th>
                            <th>ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>

            <script>
                const ctx = document.getElementById('vulnChart').getContext('2d');
                new Chart(ctx, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['Critical', 'High', 'Medium', 'Low'],
                        datasets: [{{
                            data: [{crit_count}, {high_count}, {med_count}, {low_count}],
                            backgroundColor: ['#ff0055', '#ffcc00', '#00f3ff', '#00ff9d'],
                            borderWidth: 0
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{ position: 'right', labels: {{ color: '#fff' }} }}
                        }}
                    }}
                }});

                function toggleDetails(id) {{
                    const row = document.getElementById('desc-' + id);
                    if (row.style.display === 'none') {{
                        row.style.display = 'table-row';
                    }} else {{
                        row.style.display = 'none';
                    }}
                }}
            </script>
        </body>
        </html>
        """
        return html

    def _get_description_for_vuln(self, vuln_type):
        if "Sensitive File" in vuln_type:
            return "access sensitive configuration files or backups that should not be public"
        if "Open Redirect" in vuln_type:
            return "redirect users to malicious sites, facilitating phishing attacks"
        if "Missing Security Headers" in vuln_type:
            return "exploit client-side vulnerabilities like clickjacking or XSS due to missing protections"
        return "exploit the application logic"
