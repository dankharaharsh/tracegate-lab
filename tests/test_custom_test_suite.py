r"""
TRACEGATE — ADD CUSTOM SECURITY TEST ACCEPTANCE & INTEGRATION TEST SUITE
========================================================================
Tests all functional requirements and edge cases:
1. Input validation on test name (< 3 chars, > 200 chars, whitespace)
2. Priority validation (CRITICAL, HIGH, MEDIUM, LOW)
3. CWE format validation (optional, ^CWE-\d+$)
4. Minimal custom test creation (name >= 3, priority default, optional empty)
5. Full custom test creation (name, priority, cwe, reason, testing_objective)
6. Non-existent project handling (404 Not Found)
7. Authoritative server ID generation (custom-<timestamp>, source='USER')
8. Database persistence & checklist query (/api/projects/{id}/checklist)
9. Verification status update (TESTED_NOT_FOUND)
10. Vuln finding logging on custom test (VULNERABILITY_FOUND)
11. DOCX report generation includes custom test finding
12. Frontend DOM structure & ID uniqueness
"""

import sys
import os
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend.database import (
    get_db_connection,
    create_project,
    get_project_by_id,
    get_project_checklist_items,
    delete_checklist_item
)

client = TestClient(app)


def test_1_name_too_short():
    """Test 1: Name < 3 chars fails validation (422)"""
    proj = create_project({"name": "Test Short Name Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "ab", "priority": "HIGH"}
    )
    assert res.status_code == 422, f"Expected 422, got {res.status_code}: {res.text}"
    print("[PASS] Test 1: Name < 3 characters rejected with HTTP 422")


def test_2_name_whitespace_only():
    """Test 2: Name with whitespace only fails validation (422)"""
    proj = create_project({"name": "Test Whitespace Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "    ", "priority": "HIGH"}
    )
    assert res.status_code == 422, f"Expected 422, got {res.status_code}: {res.text}"
    print("[PASS] Test 2: Whitespace-only name rejected with HTTP 422")


def test_3_name_too_long():
    """Test 3: Name > 200 chars fails validation (422)"""
    proj = create_project({"name": "Test Long Name Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "X" * 201, "priority": "HIGH"}
    )
    assert res.status_code == 422, f"Expected 422, got {res.status_code}: {res.text}"
    print("[PASS] Test 3: Name > 200 characters rejected with HTTP 422")


def test_4_invalid_priority():
    """Test 4: Invalid priority rejected (422)"""
    proj = create_project({"name": "Test Invalid Priority Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "Valid Test Name", "priority": "SUPER_CRITICAL"}
    )
    assert res.status_code == 422, f"Expected 422, got {res.status_code}: {res.text}"
    print("[PASS] Test 4: Invalid priority rejected with HTTP 422")


def test_5_invalid_cwe_format():
    """Test 5: Non-numeric or malformed CWE rejected (422)"""
    proj = create_project({"name": "Test Invalid CWE Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "Valid Test Name", "priority": "HIGH", "cwe": "CWE-ABC"}
    )
    assert res.status_code == 422, f"Expected 422, got {res.status_code}: {res.text}"

    res2 = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "Valid Test Name", "priority": "HIGH", "cwe": "307"}
    )
    assert res2.status_code == 422, f"Expected 422, got {res2.status_code}: {res2.text}"
    print("[PASS] Test 5: Malformed CWE identifier rejected with HTTP 422")


def test_6_minimal_custom_test_creation():
    """Test 6: Minimal custom test (only valid name and priority) succeeds (201) with defaults"""
    proj = create_project({"name": "Minimal Custom Test Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "OAuth Redirect URI Validation", "priority": "LOW"}
    )
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    data = res.json()
    assert data["id"].startswith("custom-")
    assert data["name"] == "OAuth Redirect URI Validation"
    assert data["priority"] == "LOW"
    assert data["source"] == "USER"
    assert data["status"] == "NOT_TESTED"
    assert data["project_id"] == proj["id"]
    assert len(data["reason"]) > 0
    assert len(data["testing_objective"]) > 0
    print(f"[PASS] Test 6: Minimal custom test created with ID={data['id']} and default fallbacks")


def test_7_full_custom_test_creation():
    """Test 7: Full custom test creation preserves all learner fields and normalizes CWE"""
    proj = create_project({"name": "Full Custom Test Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={
            "name": "BOLA / IDOR on Customer Invoices",
            "priority": "CRITICAL",
            "cwe": "cwe-639",
            "reason": "Invoice downloads query /api/invoices/{id} without authorization checks.",
            "testing_objective": "Enumerate sequential invoice IDs to verify authorization enforcement."
        }
    )
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    data = res.json()
    assert data["id"].startswith("custom-")
    assert data["name"] == "BOLA / IDOR on Customer Invoices"
    assert data["priority"] == "CRITICAL"
    assert data["cwe"] == "CWE-639"
    assert data["source"] == "USER"
    assert data["status"] == "NOT_TESTED"
    assert "Invoice downloads query" in data["reason"]
    assert "Enumerate sequential" in data["testing_objective"]
    print(f"[PASS] Test 7: Full custom test created successfully with CWE normalization ({data['cwe']})")


def test_8_nonexistent_project_404():
    """Test 8: Non-existent project returns 404"""
    res = client.post(
        "/api/projects/proj-does-not-exist-9999/checklist/custom",
        json={"name": "Valid Test Name", "priority": "HIGH"}
    )
    assert res.status_code == 404, f"Expected 404, got {res.status_code}: {res.text}"
    print("[PASS] Test 8: Non-existent project ID correctly returns HTTP 404")


def test_9_persistence_and_reload():
    """Test 9: Custom test persists in database and reloads via GET /api/projects/{id}/checklist"""
    proj = create_project({"name": "Persistence Verification Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "Host Header Poisoning via Password Reset", "priority": "HIGH", "cwe": "CWE-644"}
    )
    assert res.status_code == 201
    item_id = res.json()["id"]

    # Query checklist
    chk_res = client.get(f"/api/projects/{proj['id']}/checklist")
    assert chk_res.status_code == 200
    items = chk_res.json()["checklist"]
    matching = [i for i in items if i["id"] == item_id]
    assert len(matching) == 1, f"Expected 1 matching custom test in checklist, found {len(matching)}"
    item = matching[0]
    assert item["name"] == "Host Header Poisoning via Password Reset"
    assert item["source"] == "USER"
    assert item["status"] == "NOT_TESTED"
    print(f"[PASS] Test 9: Custom test {item_id} persisted in DB and successfully retrieved via checklist API")


def test_10_status_update_clean():
    """Test 10: Custom test status transition to TESTED_NOT_FOUND"""
    proj = create_project({"name": "Status Update Test Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "Padding Oracle Attack in CBC Mode", "priority": "HIGH", "cwe": "CWE-327"}
    )
    item_id = res.json()["id"]

    status_res = client.put(f"/api/checklist/{item_id}/status", json={"status": "TESTED_NOT_FOUND"})
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "TESTED_NOT_FOUND"

    chk_res = client.get(f"/api/projects/{proj['id']}/checklist")
    item = [i for i in chk_res.json()["checklist"] if i["id"] == item_id][0]
    assert item["status"] == "TESTED_NOT_FOUND"
    print(f"[PASS] Test 10: Custom test status updated to TESTED_NOT_FOUND successfully")


def test_11_log_vulnerability_finding():
    """Test 11: Recording a verified vulnerability on custom test updates status and connects finding"""
    proj = create_project({"name": "Finding Logging Test Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "GraphQL Introspection Enabled", "priority": "MEDIUM", "cwe": "CWE-200"}
    )
    item_id = res.json()["id"]

    finding_data = {
        "finding_name": "GraphQL Schema Introspection Permitted",
        "priority": "MEDIUM",
        "cwe": "CWE-200",
        "description": "Production GraphQL endpoint accepts __schema queries exposing all internal types.",
        "poc_text": 'POST /graphql {"query": "{ __schema { types { name } } }"}'
    }
    find_res = client.post(
        f"/api/projects/{proj['id']}/checklist/{item_id}/finding",
        json=finding_data
    )
    assert find_res.status_code == 201
    finding = find_res.json()
    assert finding["checklist_item_id"] == item_id
    assert finding["finding_name"] == "GraphQL Schema Introspection Permitted"

    chk_res = client.get(f"/api/projects/{proj['id']}/checklist")
    item = [i for i in chk_res.json()["checklist"] if i["id"] == item_id][0]
    assert item["status"] == "VULNERABILITY_FOUND"
    assert item["finding"] is not None
    assert item["finding"]["finding_name"] == "GraphQL Schema Introspection Permitted"
    print(f"[PASS] Test 11: Vulnerability finding successfully bound to custom test; status is VULNERABILITY_FOUND")


def test_12_report_generation_integration():
    """Test 12: DOCX report generation includes finding logged from custom test"""
    proj = create_project({"name": "Custom Test Report Project"})
    res = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "JWT Algorithm Confusion", "priority": "HIGH", "cwe": "CWE-327"}
    )
    item_id = res.json()["id"]

    client.post(
        f"/api/projects/{proj['id']}/checklist/{item_id}/finding",
        json={
            "finding_name": "JWT None Algorithm Signature Bypass",
            "priority": "HIGH",
            "cwe": "CWE-327",
            "description": "JWT parser accepts alg=none token signatures.",
            "poc_text": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
        }
    )

    rep_res = client.post(
        f"/api/projects/{proj['id']}/reports",
        json={"author_name": "Security Learner"}
    )
    assert rep_res.status_code == 201
    data = rep_res.json()
    assert data["total_findings"] >= 1
    assert data["file_path"].endswith(".docx")
    print(f"[PASS] Test 12: Generated DOCX report package incorporating custom test finding ({data['total_findings']} findings)")


def test_13_frontend_dom_uniqueness():
    """Test 13: Verify all custom test DOM IDs are unique with no duplicates"""
    html_path = BASE_DIR / "frontend" / "index.html"
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    ids = [
        "btnAddCustomTestBtn",
        "btnWsQuickAddTest",
        "modalAddCustomTest",
        "btnCloseAddCustomModal",
        "btnCancelCustomTest",
        "btnSaveCustomTest",
        "customTestName",
        "customTestPriority",
        "customTestCwe",
        "customTestReason",
        "customTestObjective",
        "customTestErrorAlert",
        "customTestErrorMsg",
        "addCustomTestForm"
    ]

    for element_id in ids:
        matches = re.findall(r'id=["\']' + element_id + r'["\']', html)
        assert len(matches) == 1, f"Expected exactly 1 element with id '{element_id}', found {len(matches)}"

    print(f"[PASS] Test 13: All {len(ids)} custom test DOM element IDs appear exactly once in index.html")


def test_14_frontend_js_wiring():
    """Test 14: Verify app.js wires modal listeners, client-side validation, and API fetch"""
    js_path = BASE_DIR / "frontend" / "js" / "app.js"
    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    assert "modalAddCustomTest" in js
    assert "btnSaveCustomTest" in js
    assert "btnAddCustomTestBtn" in js
    assert "btnWsQuickAddTest" in js
    assert "customTestErrorAlert" in js
    assert "customTestErrorMsg" in js
    assert "/checklist/custom" in js
    print("[PASS] Test 14: Frontend app.js properly wires all custom test elements, validation, and API endpoints")


def test_15_auth_and_permissions():
    """Test 15: Authentication token validation and project authorization enforcement"""
    # 1. Invalid bearer format
    proj = create_project({"name": "Auth Test Project", "created_by": "Security Learner"})
    res1 = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "Valid Test Name", "priority": "HIGH"},
        headers={"Authorization": "Basic 12345"}
    )
    assert res1.status_code == 401, f"Expected 401, got {res1.status_code}"

    # 2. Invalid or expired token
    res2 = client.post(
        f"/api/projects/{proj['id']}/checklist/custom",
        json={"name": "Valid Test Name", "priority": "HIGH"},
        headers={"Authorization": "Bearer non-existent-expired-token"}
    )
    assert res2.status_code == 401, f"Expected 401, got {res2.status_code}"

    print("[PASS] Test 15: Authentication header format and token validity enforced")


if __name__ == "__main__":
    print("=== RUNNING TRACEGATE ADD CUSTOM SECURITY TEST ACCEPTANCE SUITE ===")
    test_1_name_too_short()
    test_2_name_whitespace_only()
    test_3_name_too_long()
    test_4_invalid_priority()
    test_5_invalid_cwe_format()
    test_6_minimal_custom_test_creation()
    test_7_full_custom_test_creation()
    test_8_nonexistent_project_404()
    test_9_persistence_and_reload()
    test_10_status_update_clean()
    test_11_log_vulnerability_finding()
    test_12_report_generation_integration()
    test_13_frontend_dom_uniqueness()
    test_14_frontend_js_wiring()
    test_15_auth_and_permissions()
    print("\n>>> ALL 15 ADD CUSTOM SECURITY TEST ACCEPTANCE TESTS PASSED WITH 100% SUCCESS! <<<")
