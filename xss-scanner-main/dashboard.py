import json
import os
from glob import glob

import plotly.express as px
import streamlit as st

# Disney+ inspired premium dark dashboard for Nexus+ Security.
st.set_page_config(page_title="Nexus+ Security", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    :root {
        --nexus-bg: #050816;
        --nexus-card: rgba(16, 30, 70, 0.82);
        --nexus-blue: #0063e5;
        --nexus-cyan: #7dd8ff;
        --nexus-text: #f8fbff;
        --nexus-muted: #a9b8d8;
    }
    .stApp {
        background:
            radial-gradient(circle at 12% 5%, rgba(0, 99, 229, .55), transparent 30%),
            radial-gradient(circle at 82% 0%, rgba(0, 166, 255, .32), transparent 28%),
            linear-gradient(180deg, #020617 0%, #07132d 42%, #030712 100%);
        color: var(--nexus-text);
    }
    .block-container { padding-top: 2rem; padding-bottom: 4rem; }
    .nexus-hero {
        padding: 34px;
        border: 1px solid rgba(145, 171, 255, 0.18);
        border-radius: 24px;
        background: linear-gradient(135deg, rgba(0, 99, 229, .28), rgba(16, 30, 70, .72));
        box-shadow: rgba(0, 0, 0, 0.48) 0 28px 90px;
        margin-bottom: 22px;
    }
    .nexus-hero h1 {
        font-size: clamp(34px, 6vw, 72px);
        line-height: .95;
        letter-spacing: -0.055em;
        margin: 0 0 10px;
    }
    .nexus-hero p { color: var(--nexus-muted); font-size: 18px; line-height: 1.6; }
    .nexus-card {
        padding: 22px;
        border: 1px solid rgba(145, 171, 255, 0.18);
        border-radius: 24px;
        background: var(--nexus-card);
        box-shadow: rgba(0, 0, 0, 0.32) 0 18px 56px;
        margin: 14px 0;
    }
    .nexus-pill {
        display: inline-block;
        border-radius: 999px;
        padding: 8px 13px;
        background: rgba(125, 216, 255, .12);
        border: 1px solid rgba(125, 216, 255, .35);
        color: #dff5ff;
        font-size: 12px;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: .12em;
        margin-right: 8px;
    }
    div[data-testid="stMetric"] {
        background: rgba(16, 30, 70, 0.72);
        border: 1px solid rgba(145, 171, 255, 0.18);
        border-radius: 24px;
        padding: 16px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def get_latest_json_file(directory="."):
    json_files = glob(os.path.join(directory, "*.json"))
    if not json_files:
        return None
    return max(json_files, key=os.path.getctime)


def calculate_risk_index(cve_list):
    risk_score = 0
    cvss_scores = {
        "CVE-2020-11022": 7.5,
        "CVE-2019-11358": 6.0,
        "CVE-2020-7598": 5.5,
    }
    for cve in cve_list:
        risk_score += cvss_scores.get(cve, 0)
    return risk_score / len(cve_list) if cve_list else 0


def classify_severity(cve):
    cvss_scores = {
        "CVE-2020-11022": 7.5,
        "CVE-2019-11358": 6.0,
        "CVE-2020-7598": 5.5,
    }
    score = cvss_scores.get(cve, 0)
    if score >= 7.0:
        return "Alta"
    if score >= 4.0:
        return "Média"
    return "Baixa"


def classify_result_severity(result):
    """Classify only real CVEs; reflected payload without CVE is medium until manually proven."""
    if result.get('cve') not in (None, 'N/A'):
        return classify_severity(result.get('cve'))
    if result.get('reflected_payload') is True and result.get('confidence') in ('HIGH', 'CONFIRMED'):
        return "Média"
    return "Baixa"


def get_recommendations(cve):
    recommendations = {
        "CVE-2020-11022": "Vulnerabilidade de XSS no jQuery. Atualize para a versão mais recente do jQuery. Veja detalhes <a href='https://nvd.nist.gov/vuln/detail/CVE-2020-11022' target='_blank'>aqui</a>.",
        "CVE-2019-11358": "Vulnerabilidade de XSS no jQuery. Recomenda-se atualizar o jQuery para uma versão segura. Veja detalhes <a href='https://nvd.nist.gov/vuln/detail/CVE-2019-11358' target='_blank'>aqui</a>.",
        "CVE-2020-7598": "Vulnerabilidade de XSS através de eventos em imagens (ex.: onerror). Evite usar diretamente atributos inseguros. Veja detalhes <a href='https://nvd.nist.gov/vuln/detail/CVE-2020-7598' target='_blank'>aqui</a>.",
    }
    return recommendations.get(
        cve,
        "Sem CVE real associado. Corrija a classe do problema: encode contextual de saída, validação de entrada, CSP e reteste em navegador autorizado.",
    )


st.markdown(
    """
    <div class='nexus-hero'>
        <span class='nexus-pill'>Nexus+ Security</span>
        <span class='nexus-pill'>Disney+ inspired</span>
        <span class='nexus-pill'>Sem CVE falso</span>
        <h1>Dashboard de Segurança XSS</h1>
        <p>Visual premium, gráficos claros e contagem baseada em evidência real: payload refletido + confiança alta/confirmada.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

latest_json_file = get_latest_json_file()

if latest_json_file:
    st.markdown(f"<div class='nexus-card'>Carregando o arquivo mais recente: <strong>{latest_json_file}</strong></div>", unsafe_allow_html=True)

    try:
        with open(latest_json_file, encoding="utf-8") as f:
            data = json.load(f)

        critical_vulns = [
            result for result in data['detalhes_resultados']
            if result.get('reflected_payload') is True and result.get('confidence') in ('HIGH', 'CONFIRMED')
        ]

        cve_list = [result["cve"] for result in data["detalhes_resultados"] if result.get("cve") not in (None, "N/A")]
        risk_index = calculate_risk_index(cve_list)

        method_counts = {"GET": 0, "POST": 0, "OUTROS": 0}
        for result in data['detalhes_resultados']:
            method = result.get('method', 'OUTROS').upper()
            method_counts[method if method in method_counts else 'OUTROS'] += 1

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("URL analisada", data['url_analisada'])
        col2.metric("Formulários", len(data['detalhes_resultados']))
        col3.metric("Achados confirmáveis", len(critical_vulns))
        col4.metric("Risco CVE real", f"{risk_index:.1f}/10")

        st.markdown("<div class='nexus-card'><h2>Insights gráficos</h2></div>", unsafe_allow_html=True)

        reflected_payloads = [res.get('reflected_payload') for res in data['detalhes_resultados']]
        fig_reflected = px.pie(
            names=["Refletido", "Não Refletido"],
            values=[reflected_payloads.count(True), reflected_payloads.count(False)],
            title="Proporção de Payloads Refletidos",
            color_discrete_sequence=["#0063e5", "#243b6b"],
            hole=0.45,
        )
        fig_reflected.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#f8fbff")
        st.plotly_chart(fig_reflected, use_container_width=True)

        severity_counts = {"Alta": 0, "Média": 0, "Baixa": 0}
        for result in critical_vulns:
            severity_counts[classify_result_severity(result)] += 1

        fig_severity = px.bar(
            x=list(severity_counts.keys()),
            y=list(severity_counts.values()),
            title="Distribuição de Achados Confirmáveis por Criticidade",
            color=list(severity_counts.keys()),
            color_discrete_map={"Alta": "#ff4b6e", "Média": "#ffb02e", "Baixa": "#7dd8ff"},
        )
        fig_severity.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#f8fbff")
        st.plotly_chart(fig_severity, use_container_width=True)

        st.markdown("<div class='nexus-card'><h2>Detalhamento técnico e recomendações</h2></div>", unsafe_allow_html=True)

        severity_order = {"Alta": 0, "Média": 1, "Baixa": 2}
        sorted_results = sorted(critical_vulns, key=lambda res: severity_order.get(classify_result_severity(res), 1))
        color_map = {"Alta": "#ff4b6e", "Média": "#ffb02e", "Baixa": "#7dd8ff"}

        for idx, result in enumerate(sorted_results, 1):
            criticidade = classify_result_severity(result)
            bolinha_html = f"<span style='color:{color_map[criticidade]};font-size:20px;'>&#9679;</span>"
            st.markdown(
                f"""
                <div class='nexus-card'>
                    <h3>{bolinha_html} Item #{idx} [{criticidade}] - {result.get('scan_type', 'XSS')}</h3>
                    <p><strong>Payload:</strong> <code>{result.get('payload', '')}</code></p>
                    <p><strong>Status HTTP:</strong> {result.get('status_code', 'N/A')}</p>
                    <p><strong>Payload Refletido:</strong> {'Sim' if result.get('reflected_payload') else 'Não'}</p>
                    <p><strong>CVE:</strong> {result.get('cve', 'N/A')}</p>
                    <p><strong>Confiança:</strong> {result.get('confidence', 'UNVERIFIED')}</p>
                    <p><strong>Descrição:</strong> {result.get('description', '')}</p>
                    <p><strong>OWASP:</strong> {result.get('owasp_category', 'Categoria OWASP não disponível')}</p>
                    <p><strong>Recomendação:</strong> {get_recommendations(result.get('cve'))}</p>
                    <p><strong>Alerta de falso positivo:</strong> {result.get('false_positive_alert', 'Valide execução no navegador antes de tratar como exploração completa.')}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    except FileNotFoundError:
        st.error(f"Arquivo {latest_json_file} não encontrado. Por favor, verifique o nome e tente novamente.")

else:
    st.error("Nenhum arquivo JSON encontrado no diretório.")
