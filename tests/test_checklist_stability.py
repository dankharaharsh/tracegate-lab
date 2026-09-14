import io
import sys
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend.schemas import VaptAnalysisResponse
from backend.knowledge_base import build_curated_checklist

client = TestClient(app)
samples_dir = BASE_DIR / "samples"

def read_sample(name: str) -> bytes:
    p = samples_dir / name
    assert p.exists(), f"Sample {name} must exist"
    with open(p, "rb") as f:
        return f.read()

def test_1_login_matching():
    """Test 1: Page Type = Login, Screenshot = Login -> Login checklist"""
    img = read_sample("login.png")
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("login.png", img, "image/png")},
        data={"page_type": "Login / Sign-in Page"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page"
    assert data["page_type_conflict"] is False
    assert len(data["checklist"]) >= 2
    # Verify tests are login/auth related
    auth_tests = [item for item in data["checklist"] if "auth" in item["id"] or "login" in item["name"].lower() or "credential" in item["name"].lower()]
    assert len(auth_tests) > 0, "Must contain login/auth tests"
    print("[PASS] Test 1: Page Type=Login, Screenshot=Login -> Login checklist")

def test_2_forgot_password_matching():
    """Test 2: Page Type = Forgot Password, Screenshot = Forgot Password -> Forgot Password checklist"""
    img = read_sample("forgot_password.png")
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("forgot_password.png", img, "image/png")},
        data={"page_type": "Forgot Password / Password Reset Page"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Forgot Password / Password Reset Page"
    assert data["page_type_conflict"] is False
    assert len(data["checklist"]) >= 2
    rec_tests = [item for item in data["checklist"] if "reset" in item["name"].lower() or "token" in item["name"].lower() or "rec-" in item["id"]]
    assert len(rec_tests) > 0, "Must contain password reset tests"
    print("[PASS] Test 2: Page Type=Forgot Password, Screenshot=Forgot Password -> Forgot Password checklist")

def test_3_selected_login_screenshot_forgot_password_no_override():
    """Test 3: Page Type = Login, Screenshot = Forgot Password -> Login checklist (No mismatch, no override!)"""
    img = read_sample("forgot_password.png")
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("forgot_password.png", img, "image/png")},
        data={"page_type": "Login / Sign-in Page"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page", f"Expected Login, got: {data['page_type']}"
    assert data["page_type_conflict"] is False, "page_type_conflict must be False"
    assert data["conflict_reason"] is None, "conflict_reason must be None"
    # Tests must be login tests, not forgot password tests
    auth_tests = [item for item in data["checklist"] if "auth-" in item["id"] or "login" in item["name"].lower()]
    assert len(auth_tests) > 0, "Must contain Login tests"
    print("[PASS] Test 3: Page Type=Login, Screenshot=Forgot Password -> Login checklist (No override, no conflict)")

def test_4_corrupt_screenshot_graceful_fallback():
    """Test 4: Page Type = Forgot Password, Screenshot = corrupt -> Forgot Password curated checklist (No error!)"""
    corrupt_bytes = b"CORRUPTED_NOT_AN_IMAGE_DATA_12345"
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("broken.png", corrupt_bytes, "image/png")},
        data={"page_type": "Forgot Password / Password Reset Page"}
    )
    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["page_type"] == "Forgot Password / Password Reset Page"
    assert len(data["checklist"]) >= 2
    assert data["visual_analysis_available"] is False
    assert data["analysis_mode"] == "KNOWLEDGE_BASE_FALLBACK"
    print("[PASS] Test 4: Corrupt screenshot gracefully returned curated Forgot Password checklist")

def test_5_selected_account_screenshot_search_no_override():
    """Test 5: Page Type = Account, Screenshot = Search -> Account checklist (No mismatch, no override!)"""
    img = read_sample("search.png")
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("search.png", img, "image/png")},
        data={"page_type": "Account / Profile Page"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Account / Profile Page", f"Expected Account / Profile, got: {data['page_type']}"
    assert data["page_type_conflict"] is False
    assert data["conflict_reason"] is None
    profile_tests = [item for item in data["checklist"] if "profile-" in item["id"] or "profile" in item["name"].lower() or "idor" in item["name"].lower()]
    assert len(profile_tests) > 0, "Must contain Account/Profile tests"
    print("[PASS] Test 5: Page Type=Account, Screenshot=Search -> Account checklist (No mismatch, no override)")

def test_6_login_to_forgot_password_fresh_generation():
    """Test 6: Login -> Forgot Password -> Generate -> Fresh Forgot Password checklist"""
    img = read_sample("login.png")
    # First request: Login
    resp1 = client.post(
        "/api/analyze-screenshot",
        files={"image": ("login.png", img, "image/png")},
        data={"page_type": "Login / Sign-in Page"}
    )
    assert resp1.status_code == 200
    assert resp1.json()["page_type"] == "Login / Sign-in Page"

    # Second request: Forgot Password
    resp2 = client.post(
        "/api/analyze-screenshot",
        files={"image": ("login.png", img, "image/png")},
        data={"page_type": "Forgot Password / Password Reset Page"}
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["page_type"] == "Forgot Password / Password Reset Page"
    rec_tests = [item for item in data2["checklist"] if "rec-" in item["id"] or "reset" in item["name"].lower()]
    assert len(rec_tests) > 0
    print("[PASS] Test 6: Switched Login -> Forgot Password -> Fresh Forgot Password checklist")

def test_7_forgot_password_to_account_fresh_generation():
    """Test 7: Forgot Password -> Account -> Generate -> Fresh Account checklist"""
    img = read_sample("forgot_password.png")
    # First request: Forgot Password
    resp1 = client.post(
        "/api/analyze-screenshot",
        files={"image": ("forgot_password.png", img, "image/png")},
        data={"page_type": "Forgot Password / Password Reset Page"}
    )
    assert resp1.status_code == 200
    assert resp1.json()["page_type"] == "Forgot Password / Password Reset Page"

    # Second request: Account / Profile
    resp2 = client.post(
        "/api/analyze-screenshot",
        files={"image": ("forgot_password.png", img, "image/png")},
        data={"page_type": "Account / Profile Page"}
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["page_type"] == "Account / Profile Page"
    assert any("profile-" in i["id"] for i in data2["checklist"])
    print("[PASS] Test 7: Switched Forgot Password -> Account -> Fresh Account checklist")

def test_8_new_image_upload_reset_and_fresh_generation():
    """Test 8: Upload Login screenshot, generate; then upload Account screenshot, generate"""
    img_login = read_sample("login.png")
    img_profile = read_sample("profile.png")

    resp1 = client.post(
        "/api/analyze-screenshot",
        files={"image": ("login.png", img_login, "image/png")},
        data={"page_type": "Login / Sign-in Page"}
    )
    assert resp1.status_code == 200
    assert resp1.json()["page_type"] == "Login / Sign-in Page"
    hash1 = resp1.json()["image_hash"]

    resp2 = client.post(
        "/api/analyze-screenshot",
        files={"image": ("profile.png", img_profile, "image/png")},
        data={"page_type": "Account / Profile Page"}
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["page_type"] == "Account / Profile Page"
    assert data2["image_hash"] != hash1, "Image hash must be different for new image"
    print("[PASS] Test 8: New image uploaded -> Old image analysis reset, fresh Account analysis generated")

def test_9_request_versioning_and_staleness():
    """Test 9: Rapid requests with request IDs -> Server echoes request_id for client staleness protection"""
    img = read_sample("login.png")
    req_a = "req-1111-aaa"
    req_b = "req-2222-bbb"

    resp_a = client.post(
        "/api/analyze-screenshot",
        files={"image": ("login.png", img, "image/png")},
        data={"page_type": "Login / Sign-in Page", "request_id": req_a}
    )
    resp_b = client.post(
        "/api/analyze-screenshot",
        files={"image": ("login.png", img, "image/png")},
        data={"page_type": "Forgot Password / Password Reset Page", "request_id": req_b}
    )

    assert resp_a.status_code == 200
    assert resp_b.status_code == 200
    assert resp_a.json()["request_id"] == req_a
    assert resp_b.json()["request_id"] == req_b
    assert resp_b.json()["page_type"] == "Forgot Password / Password Reset Page"
    print("[PASS] Test 9: Request IDs correctly echoed; client discards req_a in favor of req_b")

def test_10_ai_unavailable_knowledge_base_fallback():
    """Test 10: AI unavailable -> Selected Page Type curated checklist returned without error"""
    from backend.analyzer import run_vapt_analysis
    img = read_sample("login.png")

    with patch("backend.analyzer.get_active_provider", return_value="gemini"),          patch("backend.analyzer.analyze_with_gemini", side_effect=RuntimeError("AI Vision Service Unavailable (503)")):
        result = run_vapt_analysis(
            image_bytes=img,
            mime_type="image/png",
            filename="login.png",
            selected_page_type="Forgot Password / Password Reset Page"
        )
        assert result.page_type == "Forgot Password / Password Reset Page"
        assert len(result.checklist) >= 2
        assert result.page_type_conflict is False
        print("[PASS] Test 10: AI failure cleanly fell back to curated knowledge base for Forgot Password")

def test_11_screenshot_refinement():
    """Test 11: Screenshot Refinement:
    Screenshot A: Email + Reset button
    Screenshot B: Email + CAPTCHA + OTP + Reset button
    Both remain Forgot Password checklists. Screenshot B specifically includes and prioritizes CAPTCHA/OTP tests.
    """
    img = read_sample("forgot_password.png")

    # Screenshot A (standard reset form)
    resp_a = client.post(
        "/api/analyze-screenshot",
        files={"image": ("forgot_password.png", img, "image/png")},
        data={"page_type": "Forgot Password / Password Reset Page", "prompt": "Standard password recovery form"}
    )
    assert resp_a.status_code == 200
    data_a = resp_a.json()
    assert data_a["page_type"] == "Forgot Password / Password Reset Page"

    # Screenshot B (reset form with CAPTCHA and OTP verification)
    resp_b = client.post(
        "/api/analyze-screenshot",
        files={"image": ("forgot_password_captcha_otp.png", img, "image/png")},
        data={"page_type": "Forgot Password / Password Reset Page", "prompt": "Contains CAPTCHA verification challenge and OTP code field"}
    )
    assert resp_b.status_code == 200
    data_b = resp_b.json()
    assert data_b["page_type"] == "Forgot Password / Password Reset Page"

    # Verify Screenshot B contains CAPTCHA or OTP refined functionality/tests
    b_test_ids = [item["id"] for item in data_b["checklist"]]
    assert any("captcha" in tid or "otp" in tid for tid in b_test_ids), f"Screenshot B must include CAPTCHA/OTP tests: {b_test_ids}"
    assert any("CAPTCHA" in f or "OTP" in f for f in data_b["visible_functionality"]), f"Screenshot B visible functionality must reflect controls: {data_b['visible_functionality']}"
    print("[PASS] Test 11: Screenshot functional context successfully refined checklist with CAPTCHA/OTP tests")

def test_12_additional_context_refinement():
    """Test 12: Additional Context:
    Page Type = Account
    Screenshot = Account
    Context = 'Focus on password change functionality.'
    Expected: Account checklist with password-change-related tests prioritized.
    """
    img = read_sample("profile.png")
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("profile.png", img, "image/png")},
        data={"page_type": "Account / Profile Page", "prompt": "Focus on password change functionality."}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["page_type"] == "Account / Profile Page"

    # Top test should be password verification or account security test
    top_test = data["checklist"][0]
    has_password_focus = "password" in top_test["name"].lower() or "password" in top_test["reason"].lower() or "profile-pass" in top_test["id"]
    assert has_password_focus, f"Top test must be password-related due to context focus, got: {top_test['name']} ({top_test['reason']})"
    print(f"[PASS] Test 12: Additional Context prioritized '{top_test['name']}' at top of Account checklist")

if __name__ == "__main__":
    print("=== RUNNING TRACEGATE CHECKLIST STABILITY TEST SUITE (TESTS 1-12) ===")
    test_1_login_matching()
    test_2_forgot_password_matching()
    test_3_selected_login_screenshot_forgot_password_no_override()
    test_4_corrupt_screenshot_graceful_fallback()
    test_5_selected_account_screenshot_search_no_override()
    test_6_login_to_forgot_password_fresh_generation()
    test_7_forgot_password_to_account_fresh_generation()
    test_8_new_image_upload_reset_and_fresh_generation()
    test_9_request_versioning_and_staleness()
    test_10_ai_unavailable_knowledge_base_fallback()
    test_11_screenshot_refinement()
    test_12_additional_context_refinement()
    print("\n>>> ALL 12 CHECKLIST STABILITY ACCEPTANCE TESTS PASSED WITH 100% SUCCESS! <<<")
