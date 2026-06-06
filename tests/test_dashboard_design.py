import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DASHBOARD = Path(__file__).resolve().parents[1] / "xss-scanner-main" / "dashboard.py"


def test_streamlit_dashboard_uses_premium_disney_plus_inspired_theme():
    source = DASHBOARD.read_text(encoding="utf-8")

    assert "Disney+ inspired" in source
    assert "st.set_page_config" in source
    assert "Nexus+ Security" in source
    assert "linear-gradient" in source
    assert "#0063e5" in source
    assert "border-radius: 24px" in source


def test_dashboard_does_not_classify_na_cve_as_real_severity():
    source = DASHBOARD.read_text(encoding="utf-8")

    assert "def classify_result_severity" in source
    assert "result.get('cve') not in (None, 'N/A')" in source
    assert "criticidade = classify_result_severity(result)" in source
