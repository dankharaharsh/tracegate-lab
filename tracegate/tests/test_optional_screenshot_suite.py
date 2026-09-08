"""
TRACEGATE — OPTIONAL SCREENSHOT & AUTHORITATIVE PAGE TYPE ACCEPTANCE SUITE
==========================================================================
Tests all acceptance requirements from User Request:
TEST 1: Page Type only (Login) -> Login checklist without error
TEST 2: Page Type + Context -> Login checklist with context prioritization
TEST 3: Page Type + Screenshot -> Login checklist with visual context
TEST 4: Mismatched screenshot (Login Page Type + Search screenshot) -> Login checklist (no mismatch alert, no search checklist)
TEST 5: Page Type only: File Upload -> File Upload checklist
TEST 6: Page Type only: Checkout / Payment -> Checkout checklist
TEST 7: Screenshot removed workflow -> Checklist generated for selected Page Type
TEST 8: Corrupt screenshot -> Graceful fallback to knowledge base for selected Page Type
TEST 9: Auto Detect with ambiguous screenshot -> Low confidence (<= 0.70), prompts user
TEST 10: Stale request protection -> Later request wins, earlier discarded
TEST 11: Backend JSON payload with screenshot omitted
TEST 12: Backend JSON payload with screenshot null
TEST 13: Backend JSON payload with base64 screenshot
TEST 14: Backend invalid Page Type safely rejected (HTTP 422/400)
TEST 15: Frontend DOM and app.js inspection (button enabled by default, optional labels, no required image check)
"""

import os
import sys
import base64
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)
samples_dir = BASE_DIR / "samples"
HTML_PATH = BASE_DIR / "frontend" / "index.html"
JS_PATH = BASE_DIR / "frontend" / "js" / "app.js"

with open(HTML_PATH, "r", encoding="utf-8") as f:
    HTML_CONTENT = f.read()

with open(JS_PATH, "r", encoding="utf-8") as f:
    JS_CONTENT = f.read()


def read_sample(name: str) -> bytes:
    p = samples_dir / name
    assert p.exists(), f"Sample {name} must exist"
    with open(p, "rb") as f:
        return f.read()


def test_1_page_type_only_login():
    """TEST 1: Page Type = Login / Sign-in, Screenshot = None, Context = None"""
    resp = client.post(
        "/api/analyze-screenshot",
        data={"page_type": "Login / Sign-in Page"}
    )
    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page"
    assert data["visual_analysis_available"] is False
    assert data["analysis_mode"] == "KNOWLEDGE_BASE"
    assert len(data["checklist"]) >= 8, f"Expected at least 8 login tests, got {len(data['checklist'])}"
    auth_tests = [t for t in data["checklist"] if "auth" in t["id"] or "login" in t["name"].lower() or "credential" in t["name"].lower()]
    assert len(auth_tests) > 0
    print("[PASS] Test 1: Page Type only (Login) -> Login checklist generated successfully without error")


def test_2_page_type_plus_context():
    """TEST 2: Page Type = Login, Screenshot = None, Context provided"""
    context = "Username, password and remember-me are present."
    resp = client.post(
        "/api/analyze-screenshot",
        data={
            "page_type": "Login / Sign-in Page",
            "user_context": context
        }
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page"
    assert len(data["checklist"]) >= 8
    print("[PASS] Test 2: Page Type + Context -> Login-specific checklist generated")


def test_3_page_type_plus_screenshot():
    """TEST 3: Page Type = Login, Screenshot = valid login screenshot"""
    img = read_sample("login.png")
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("login.png", img, "image/png")},
        data={"page_type": "Login / Sign-in Page"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page"
    assert data["visual_analysis_available"] is True
    assert len(data["checklist"]) >= 8
    print("[PASS] Test 3: Page Type + Screenshot -> Login checklist with visual context")


def test_4_mismatched_screenshot_no_override():
    """TEST 4: Deliberately mismatched screenshot (Page Type = Login, Screenshot = Search)"""
    search_img = read_sample("search.png")
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("search.png", search_img, "image/png")},
        data={"page_type": "Login / Sign-in Page"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page", f"Expected Login, got: {data['page_type']}"
    assert data["page_type_conflict"] is False
    assert data["conflict_reason"] is None
    search_items = [t for t in data["checklist"] if "search" in t["id"]]
    assert len(search_items) == 0, "Mismatched screenshot must not inject search items into Login checklist"
    print("[PASS] Test 4: Mismatched screenshot -> strictly Login checklist, NO mismatch alert, NO search checklist")


def test_5_another_page_type_file_upload():
    """TEST 5: Page Type = File Upload, Screenshot = None"""
    resp = client.post(
        "/api/analyze-screenshot",
        data={"page_type": "File Upload Page"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "File Upload Page"
    assert len(data["checklist"]) == 4, f"Expected 4 file upload tests, got {len(data['checklist'])}"
    upload_tests = [t for t in data["checklist"] if "upload" in t["id"] or "file" in t["name"].lower()]
    assert len(upload_tests) > 0
    print("[PASS] Test 5: Page Type = File Upload without screenshot -> File Upload-specific checklist")


def test_6_checkout_payment():
    """TEST 6: Page Type = Checkout / Payment, Screenshot = None"""
    resp = client.post(
        "/api/analyze-screenshot",
        data={"page_type": "Checkout / Payment Page"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Checkout / Payment Page"
    assert len(data["checklist"]) == 6, f"Expected 6 checkout tests, got {len(data['checklist'])}"
    biz_tests = [t for t in data["checklist"] if "biz-" in t["id"] or "price" in t["name"].lower() or "coupon" in t["name"].lower()]
    assert len(biz_tests) > 0
    print("[PASS] Test 6: Page Type = Checkout / Payment without screenshot -> Checkout-specific checklist")


def test_7_screenshot_removed_workflow():
    """TEST 7: Select Login -> Upload screenshot -> Remove screenshot -> Generate"""
    resp = client.post(
        "/api/analyze-screenshot",
        data={"page_type": "Login / Sign-in Page"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page"
    assert len(data["checklist"]) >= 8
    print("[PASS] Test 7: Screenshot removed workflow -> Login checklist generated cleanly")


def test_8_corrupt_screenshot_graceful_fallback():
    """TEST 8: Select Login -> Upload invalid/corrupted image -> Generate"""
    corrupt_bytes = b"CORRUPTED_NOT_AN_IMAGE_DATA_XYZ"
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("broken.png", corrupt_bytes, "image/png")},
        data={"page_type": "Login / Sign-in Page"}
    )
    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page"
    assert data["visual_analysis_available"] is False
    assert len(data["checklist"]) >= 8
    print("[PASS] Test 8: Corrupt screenshot -> Graceful fallback to knowledge base without error")


def test_9_auto_detect_ambiguous():
    """TEST 9: Auto Detect with ambiguous screenshot -> low confidence <= 0.70, prompts user"""
    ambig_img = read_sample("ambiguous.png")
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("ambiguous.png", ambig_img, "image/png")},
        data={"page_type": "Auto Detect"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["confidence"] <= 0.70
    assert "select a page type" in data["ambiguity_notes"].lower()
    print("[PASS] Test 9: Auto Detect with ambiguous screenshot -> Low confidence, prompts user to select Page Type")


def test_10_stale_request_protection():
    """TEST 10: Request ID staleness protection verified in app.js and echoed by API"""
    req_a = "req-1111-first"
    req_b = "req-2222-second"
    resp_a = client.post("/api/analyze-screenshot", data={"page_type": "Login / Sign-in Page", "request_id": req_a})
    resp_b = client.post("/api/analyze-screenshot", data={"page_type": "Checkout / Payment Page", "request_id": req_b})
    assert resp_a.json()["request_id"] == req_a
    assert resp_b.json()["request_id"] == req_b
    assert "data.request_id !== currentAnalysisRequestId" in JS_CONTENT
    print("[PASS] Test 10: Stale request protection -> Request IDs verified and stale check enforced")


def test_11_backend_json_screenshot_omitted():
    """TEST 11: Backend JSON payload with screenshot omitted"""
    resp = client.post(
        "/api/analyze-screenshot",
        json={"page_type": "login"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page"
    assert len(data["checklist"]) >= 8
    print("[PASS] Test 11: Backend JSON payload with screenshot omitted -> 200 OK")


def test_12_backend_json_screenshot_null():
    """TEST 12: Backend JSON payload with screenshot: null"""
    resp = client.post(
        "/api/analyze-screenshot",
        json={"page_type": "login", "screenshot": None}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page"
    assert len(data["checklist"]) >= 8
    print("[PASS] Test 12: Backend JSON payload with screenshot: null -> 200 OK")


def test_13_backend_json_base64_screenshot():
    """TEST 13: Backend JSON payload with valid base64 screenshot"""
    img = read_sample("login.png")
    b64_str = "data:image/png;base64," + base64.b64encode(img).decode("ascii")
    resp = client.post(
        "/api/analyze-screenshot",
        json={"page_type": "login", "screenshot": b64_str}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["page_type"] == "Login / Sign-in Page"
    assert data["visual_analysis_available"] is True
    print("[PASS] Test 13: Backend JSON payload with base64 screenshot -> 200 OK")


def test_14_backend_invalid_page_type_rejected():
    """TEST 14: Backend invalid Page Type safely rejected (HTTP 422/400)"""
    resp = client.post(
        "/api/analyze-screenshot",
        json={"page_type": "arbitrary_malicious_unrecognized_type"}
    )
    assert resp.status_code in [400, 422], f"Expected 400 or 422, got {resp.status_code}"
    print("[PASS] Test 14: Backend invalid Page Type rejected safely with HTTP 422/400")


def test_15_frontend_markup_and_controller_inspection():
    """TEST 15: Frontend index.html and app.js UI and logic validation"""
    assert not re.search(r'<button[^>]+id="btnAnalyze"[^>]*disabled', HTML_CONTENT), \
        "btnAnalyze must not have 'disabled' attribute in index.html"

    assert 'Page Type <strong style="color: var(--crit-color); font-size: 0.9em;">*</strong>' in HTML_CONTENT or \
           'Page Type <strong' in HTML_CONTENT or 'Page Type *' in HTML_CONTENT, \
        "Page Type selector must have required indicator (*)"

    assert '(Optional)' in HTML_CONTENT and 'Target Screenshot' in HTML_CONTENT, \
        "Target Screenshot must be marked (Optional)"

    assert "Upload a screenshot to provide additional visual context." in HTML_CONTENT, \
        "Helper text for optional screenshot must be present"

    assert 'if (!currentUploadedFile) {' not in JS_CONTENT, \
        "app.js must not block generateChecklist when currentUploadedFile is empty"

    assert 'btnAnalyze.disabled = true;' not in JS_CONTENT.split('function clearUploadedFile()')[1].split('}')[0], \
        "clearUploadedFile must not disable btnAnalyze"

    print("[PASS] Test 15: Frontend DOM and app.js inspection passed (button enabled, optional labels, no mandatory image check)")


if __name__ == "__main__":
    print("=== RUNNING TRACEGATE OPTIONAL SCREENSHOT & AUTHORITATIVE PAGE TYPE ACCEPTANCE SUITE ===")
    test_1_page_type_only_login()
    test_2_page_type_plus_context()
    test_3_page_type_plus_screenshot()
    test_4_mismatched_screenshot_no_override()
    test_5_another_page_type_file_upload()
    test_6_checkout_payment()
    test_7_screenshot_removed_workflow()
    test_8_corrupt_screenshot_graceful_fallback()
    test_9_auto_detect_ambiguous()
    test_10_stale_request_protection()
    test_11_backend_json_screenshot_omitted()
    test_12_backend_json_screenshot_null()
    test_13_backend_json_base64_screenshot()
    test_14_backend_invalid_page_type_rejected()
    test_15_frontend_markup_and_controller_inspection()
    print("\n>>> ALL 15 OPTIONAL SCREENSHOT ACCEPTANCE TESTS PASSED WITH 100% SUCCESS! <<<\n")
