"""
Comprehensive Verification Suite for Tracegate Final Implementation
- Visual Priority & Contradiction Resolution (Classifier Precedence)
- Controlled Knowledge Base Finding Templates & Auto-Structuring
- Microsoft Word (.docx) Report Generation via python-docx & Download
- Real SQLite-backed User Authentication, Registration & Session Invalidation
"""

import sys
from pathlib import Path

PROJECT_DIR = Path(r"C:\Users\Harsh\Desktop\vapt-checklist-generator")
sys.path.insert(0, str(PROJECT_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend.database import init_db

client = TestClient(app)

def run_tests():
    print("=== TRACEGATE FINAL COMPREHENSIVE VERIFICATION SUITE ===")
    init_db()

    # -------------------------------------------------------------
    # 1. VISUAL PRIORITY & CONTRADICTION RESOLUTION
    # -------------------------------------------------------------
    print("\n[FEATURE 1] Visual Priority & Contradiction Resolution...")
    sample_path = PROJECT_DIR / "samples" / "forgot_password.png"
    assert sample_path.exists(), "Sample forgot_password.png must exist"

    with open(sample_path, "rb") as f:
        img_bytes = f.read()

    # Intentionally provide a contradictory user hint: "Login / Sign-in"
    res = client.post(
        "/api/analyze-screenshot",
        files={"image": ("forgot_password.png", img_bytes, "image/png")},
        data={"page_type": "Login / Sign-in", "prompt": "Auditing user authentication"}
    )
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    data = res.json()

    # Must prioritize visual classifier
    assert "Forgot Password" in data["page_type"], f"Expected Forgot Password page_type, got {data['page_type']}"
    assert data["page_type_conflict"] is True, f"Expected page_type_conflict=True, got {data.get('page_type_conflict')}"
    assert "conflict_reason" in data and len(data["conflict_reason"]) > 10, "Expected non-empty conflict_reason"
    assert data["selected_page_type"] == "Login / Sign-in"

    # Verify checklist contains password reset items, not generic login items
    test_names = [item["name"].lower() for item in data["checklist"]]
    has_reset_test = any("password reset" in n or "token" in n or "enumeration" in n for n in test_names)
    assert has_reset_test, f"Checklist should contain password reset items: {test_names}"
    print(f"  [OK] Contradiction detected & resolved correctly:")
    print(f"       Detected: '{data['page_type']}' (Confidence: {data['confidence'] * 100:.0f}%)")
    print(f"       Conflict: {data['page_type_conflict']}")
    print(f"       Reason:   {data['conflict_reason']}")
    print(f"       Items:    {len(data['checklist'])} tests generated")

    # -------------------------------------------------------------
    # 2. CONTROLLED KNOWLEDGE BASE & FINDING TEMPLATES
    # -------------------------------------------------------------
    print("\n[FEATURE 2] Controlled Knowledge Base & Finding Templates...")
    # Get first checklist item from the analysis
    sample_item = data["checklist"][0]
    item_id = sample_item["id"]

    template_res = client.get(f"/api/checklist/{item_id}/finding-template")
    assert template_res.status_code == 200, f"Expected 200, got {template_res.status_code}"
    tmpl = template_res.json()
    assert "cwe" in tmpl and tmpl["cwe"].startswith("CWE-"), f"Expected valid CWE, got {tmpl.get('cwe')}"
    assert "cvss_score" in tmpl and tmpl["cvss_score"] > 0, f"Expected positive CVSS, got {tmpl.get('cvss_score')}"
    assert len(tmpl.get("description", "")) > 10, "Expected observation description"
    assert len(tmpl.get("reproduction_steps", "")) > 10, "Expected reproduction steps"
    assert len(tmpl.get("poc_text", "")) > 5, "Expected monospaced PoC snippet"
    assert len(tmpl.get("remediation", "")) > 10, "Expected remediation guidance"
    assert len(tmpl.get("mitigation", "")) > 10, "Expected mitigation"
    print(f"  [OK] Knowledge Base template retrieved for '{sample_item['name']}':")
    print(f"       CWE:          {tmpl['cwe']}")
    print(f"       CVSS:         {tmpl['cvss_score']}")
    print(f"       Observation:  {tmpl['description'][:60]}...")
    print(f"       Remediation:  {tmpl['remediation'][:60]}...")

    # -------------------------------------------------------------
    # 3. STRUCTURED FINDING PERSISTENCE
    # -------------------------------------------------------------
    print("\n[FEATURE 3] Structured Finding Persistence & Auto-Enrichment...")
    finding_res = client.post(
        f"/api/checklist/{item_id}/finding",
        json={
            "finding_name": "Verified " + sample_item["name"],
            "priority": "CRITICAL",
            "cwe": tmpl["cwe"],
            "cvss_score": tmpl["cvss_score"],
            "status": "Open",
            "description": tmpl["description"],
            "impact": tmpl.get("impact", "High confidentiality impact"),
            "reproduction_steps": tmpl["reproduction_steps"],
            "poc_text": tmpl["poc_text"],
            "remediation": tmpl["remediation"],
            "mitigation": tmpl["mitigation"]
        }
    )
    assert finding_res.status_code == 201, f"Expected 201, got {finding_res.status_code}: {finding_res.text}"
    saved_finding = finding_res.json()
    assert saved_finding["cwe"] == tmpl["cwe"]
    assert saved_finding["cvss_score"] == tmpl["cvss_score"]
    assert saved_finding["status"] == "Open"
    assert saved_finding["priority"] == "CRITICAL"
    print(f"  [OK] Finding saved with ID: {saved_finding['id']}")

    # -------------------------------------------------------------
    # 4. PROFESSIONAL MICROSOFT WORD (.DOCX) REPORT GENERATION
    # -------------------------------------------------------------
    print("\n[FEATURE 4] Professional Microsoft Word (.docx) Report Generation...")
    proj_id = "proj-ecommerce-001"
    report_res = client.post(
        f"/api/projects/{proj_id}/reports",
        json={"version": "v1.0", "author_name": "Lead Pentester Alex"}
    )
    assert report_res.status_code == 201, f"Expected 201, got {report_res.status_code}: {report_res.text}"
    report_info = report_res.json()
    assert report_info["version"] == "v1.0"
    assert report_info["author_name"] == "Lead Pentester Alex"
    assert report_info["filename"].endswith(".docx")
    report_id = report_info["id"]

    # Verify report file exists and has valid DOCX magic bytes (PK)
    file_path = Path(report_info["file_path"])
    assert file_path.exists(), f"DOCX report file does not exist at {file_path}"
    with open(file_path, "rb") as f:
        magic = f.read(4)
    assert magic == b"PK\x03\x04", f"Expected ZIP/DOCX magic bytes PK\x03\x04, got {magic}"
    file_size_kb = file_path.stat().st_size / 1024
    print(f"  [OK] Generated valid DOCX file ({file_size_kb:.1f} KB) at {file_path.name}")

    # Verify Download Endpoint
    download_res = client.get(f"/api/projects/{proj_id}/reports/{report_id}/download")
    assert download_res.status_code == 200
    assert "application/vnd.openxmlformats-officedocument.wordprocessingml.document" in download_res.headers.get("content-type", "")
    assert len(download_res.content) == file_path.stat().st_size
    print("  [OK] Report download endpoint verified with correct MIME type.")

    # Verify Reports List Endpoint
    list_res = client.get(f"/api/projects/{proj_id}/reports")
    assert list_res.status_code == 200
    reports_list = list_res.json()
    assert any(r["id"] == report_id for r in reports_list)
    print(f"  [OK] Report listed in project history: {len(reports_list)} reports recorded.")

    # -------------------------------------------------------------
    # 5. REAL SQLITE USER AUTHENTICATION & SESSIONS
    # -------------------------------------------------------------
    print("\n[FEATURE 5] Real SQLite User Authentication & Sessions...")
    
    # 5a. Login with pre-seeded learner account
    login_res = client.post(
        "/api/auth/login",
        json={"username_or_email": "learner@tracegate.lab", "password": "Password123!"}
    )
    assert login_res.status_code == 200, f"Pre-seeded learner login failed: {login_res.text}"
    token_data = login_res.json()
    learner_token = token_data["access_token"]
    assert token_data["user"]["email"] == "learner@tracegate.lab"
    print("  [OK] Pre-seeded learner login successful.")

    # 5b. Validate incorrect credentials
    bad_login = client.post(
        "/api/auth/login",
        json={"username_or_email": "learner@tracegate.lab", "password": "WrongPassword999!"}
    )
    assert bad_login.status_code == 401, f"Expected 401 for wrong password, got {bad_login.status_code}"
    assert "Invalid email/username or password." in bad_login.json()["detail"]
    print("  [OK] Invalid password correctly rejected with 401 error message.")

    # 5c. Register a new user
    import time
    test_user_email = f"tester_{int(time.time())}@securitylab.test"
    register_res = client.post(
        "/api/auth/register",
        json={
            "email": test_user_email,
            "username": f"tester_{int(time.time())}",
            "password": "StrongPassword2026!",
            "full_name": "Automated Test Auditor",
            "role": "AppSec Specialist"
        }
    )
    assert register_res.status_code == 201, f"Registration failed: {register_res.text}"
    reg_data = register_res.json()
    reg_token = reg_data["access_token"]
    assert reg_data["user"]["email"] == test_user_email
    print(f"  [OK] Registered new user: {test_user_email}")

    # 5d. Check /api/auth/me with bearer token
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {reg_token}"})
    assert me_res.status_code == 200
    me_user = me_res.json()
    assert me_user["email"] == test_user_email
    assert me_user["full_name"] == "Automated Test Auditor"
    print("  [OK] Session verified via /api/auth/me.")

    # 5e. Logout & terminate session
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {reg_token}"})
    assert logout_res.status_code == 200

    # 5f. Verify invalidated session returns 401
    me_after_logout = client.get("/api/auth/me", headers={"Authorization": f"Bearer {reg_token}"})
    assert me_after_logout.status_code == 401
    print("  [OK] Logout invalidated session token; /api/auth/me correctly returns 401.")

    print("\n=== ALL 5 CORE FEATURES TESTED AND 100% VERIFIED! ===")

if __name__ == "__main__":
    run_tests()
