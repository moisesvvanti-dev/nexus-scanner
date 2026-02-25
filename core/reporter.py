from datetime import datetime
try:
    from .models import Vulnerability
except ImportError:
    from core.models import Vulnerability

class ReportGenerator:
    def __init__(self, findings: list[Vulnerability]):
        self.findings = findings
        self.report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_markdown(self):
        """Generates a comprehensive Markdown report ready for HackerOne."""
        if not self.findings:
            return "# No Vulnerabilities Found\n\nNo issues were detected during the scan."

        report = [
            f"# PentestGPT Security Report - {self.report_date}",
            "",
            "## Summary",
            f"**Total Findings:** {len(self.findings)}",
            f"**Critical Issues:** {sum(1 for f in self.findings if f.severity == 'CRITICAL')}",
            "",
            "---",
            ""
        ]

        for i, finding in enumerate(self.findings, 1):
            report.append(f"## {i}. [{finding.severity}] {finding.vuln_type} on {finding.target}")
            report.append(f"**Target:** `{finding.target}`")
            report.append(f"**Severity:** {finding.severity}")
            report.append(f"**Impact:** {finding.impact}")
            report.append("")
            report.append("### Description")
            report.append(f"The scanner detected a potential {finding.vuln_type} vulnerability. This issue allows an attacker to {self._get_description_for_vuln(finding.vuln_type)}.")
            report.append("")
            report.append("### Steps to Reproduce")
            report.append(f"1. Navigate to `{finding.target}`.")
            if "Sensitive File" in finding.vuln_type:
                report.append("2. Observe that the file is publicly accessible (HTTP 200).")
                report.append("3. Verify the file content contains sensitive information.")
            elif "Open Redirect" in finding.vuln_type:
                report.append("2. Observe the application redirects to an external domain.")
            else:
                report.append("2. Interact with the component as described in the impact section.")
            report.append("")
            report.append("---")
            report.append("")

        return "\n".join(report)

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
                <td>{f.vuln_type}</td>
                <td><a href="{f.target}" target="_blank">{f.target}</a></td>
                <td>
                    <button onclick="toggleDetails({i})">VIEW DETAILS</button>
                </td>
            </tr>
            <tr id="desc-{i}" class="details-row" style="display:none;">
                <td colspan="5">
                    <div class="details-content">
                        <h4>IMPACT ANALYSIS</h4>
                        <p>{f.impact}</p>
                        <h4>AI PROOF OF CONCEPT</h4>
                        <div class="ai-poc">
                            {f.ai_poc if hasattr(f, 'ai_poc') and f.ai_poc else "Run AI Analysis to generate PoC."}
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
            <title>NEXUS - Penetration Test Report</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{ background-color: #0a0a12; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
                header {{ background: linear-gradient(90deg, #1a1a2e 0%, #16213e 100%); padding: 20px; border-bottom: 2px solid #00f3ff; }}
                h1 {{ color: #00f3ff; margin: 0; letter-spacing: 2px; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 30px 0; }}
                .stat-card {{ background: #16213e; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #333; }}
                .stat-value {{ font-size: 2rem; font-weight: bold; margin: 10px 0; }}
                
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #13131f; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                th {{ background: #222; color: #aaa; padding: 12px; text-align: left; border-bottom: 1px solid #444; }}
                td {{ padding: 12px; border-bottom: 1px solid #2a2a3a; }}
                
                .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }}
                .badge.critical {{ background: rgba(255, 0, 85, 0.2); color: #ff0055; border: 1px solid #ff0055; }}
                .badge.high {{ background: rgba(255, 204, 0, 0.2); color: #ffcc00; border: 1px solid #ffcc00; }}
                .badge.medium {{ background: rgba(0, 243, 255, 0.2); color: #00f3ff; border: 1px solid #00f3ff; }}
                .badge.low {{ background: rgba(0, 255, 157, 0.2); color: #00ff9d; border: 1px solid #00ff9d; }}
                
                .details-content {{ background: #1a1a2e; padding: 20px; margin: 10px; border-left: 3px solid #00f3ff; }}
                .ai-poc {{ background: #000; padding: 15px; border-radius: 5px; font-family: monospace; color: #00ff9d; border: 1px solid #333; }}
                
                button {{ background: transparent; border: 1px solid #00f3ff; color: #00f3ff; padding: 5px 10px; cursor: pointer; transition: 0.3s; }}
                button:hover {{ background: #00f3ff; color: #000; }}
                
                a {{ color: #00f3ff; text-decoration: none; }}
            </style>
        </head>
        <body>
            <header>
                <div class="container">
                    <h1>NEXUS // VULNERABILITY REPORT</h1>
                    <p style="color: #888;">Generated: {self.report_date}</p>
                </div>
            </header>
            
            <div class="container">
                <div class="stats-grid">
                    <div class="stat-card" style="border-color: #ff0055;">
                        <div style="color: #ff0055;">CRITICAL</div>
                        <div class="stat-value">{crit_count}</div>
                    </div>
                    <div class="stat-card" style="border-color: #ffcc00;">
                        <div style="color: #ffcc00;">HIGH</div>
                        <div class="stat-value">{high_count}</div>
                    </div>
                    <div class="stat-card" style="border-color: #00f3ff;">
                        <div style="color: #00f3ff;">MEDIUM</div>
                        <div class="stat-value">{med_count}</div>
                    </div>
                    <div class="stat-card" style="border-color: #00ff9d;">
                        <div style="color: #00ff9d;">LOW</div>
                        <div class="stat-value">{low_count}</div>
                    </div>
                </div>

                <div style="background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 30px;">
                    <canvas id="vulnChart" style="max-height: 300px;"></canvas>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>SEVERITY</th>
                            <th>TYPE</th>
                            <th>TARGET</th>
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
