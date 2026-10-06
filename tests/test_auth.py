from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

def test_36_auth_module_contains_login():
    text=(Path(__file__).parents[1]/"backend/app.py").read_text()
    assert "analyst_required" in text and "analyst_authenticated" in text

def test_37_env_credentials_documented():
    text=(Path(__file__).parents[1]/".env.example").read_text()
    assert "ANALYST_USERNAME" in text and "ANALYST_PASSWORD" in text

def test_38_login_template_exists():
    assert (Path(__file__).parents[1]/"frontend/templates/login.html").exists()
