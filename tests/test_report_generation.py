import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.models import Vulnerability
from core.reporter import ReportGenerator


def sample_finding():
    return Vulnerability(
        target="https://authorized.example/search?q=NEXUS_XSS_123",
        vuln_type="Cross-Site Scripting (Reflected XSS)",
        severity="HIGH",
        impact="Unique token NEXUS_XSS_123 reflected without HTML neutralization.",
        remediation="Encode output by context and add CSP.",
        confidence="HIGH",
        evidence="token=NEXUS_XSS_123 reflected in response body",
        false_positive_note="Reflection is confirmed, browser execution still needs manual verification.",
    )


def test_html_report_contains_real_poc_reproduction_fix_and_fp_alerts():
    html = ReportGenerator([sample_finding()]).generate_html()

    required_terms = [
        "NEXUS+ Relatório Profissional de Segurança",
        "PoC real e evidência",
        "Como foi feito",
        "Como testar mais fundo com autorização",
        "Como reproduzir com autorização",
        "Como corrigir",
        "Alerta de falso positivo",
        "NEXUS_XSS_123",
        "confidence",
        "Disney+ inspired",
        "Somente alvos autorizados",
    ]
    for term in required_terms:
        assert term in html

    assert "Payload executed" not in html
    assert "ACESSAR AGORA" not in html
    assert "localhost:5000/exec" not in html


def test_html_report_escapes_untrusted_finding_fields():
    finding = Vulnerability(
        target='https://authorized.example/?x=<script>alert(1)</script>',
        vuln_type='<img src=x onerror=alert(1)>',
        severity="MEDIUM",
        impact='<script>alert("impact")</script>',
        remediation='<b onclick=alert(1)>fix</b>',
        evidence='<svg onload=alert(1)>',
        confidence="MEDIUM",
    )
    html = ReportGenerator([finding]).generate_html()

    assert '<script>alert(1)</script>' not in html
    assert '<img src=x onerror=alert(1)>' not in html
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html
    assert '&lt;svg onload=alert(1)&gt;' in html


def test_save_html_report_writes_inside_relatorios_directory(tmp_path):
    output = ReportGenerator([sample_finding()]).save_html_report(output_dir=tmp_path)

    assert output.exists()
    assert output.parent == tmp_path
    assert re.match(r"nexus_security_report_\d{8}_\d{6}\.html", output.name)
    assert "NEXUS+ Relatório Profissional de Segurança" in output.read_text(encoding="utf-8")
