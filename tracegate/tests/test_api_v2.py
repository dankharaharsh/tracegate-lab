import io
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_DIR = Path(r"C:\Users\Harsh\Desktop\vapt-checklist-generator")
sys.path.insert(0, str(PROJECT_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend.database import init_db

client = TestClient(app)

def run_tests():
    print("=== STARTING TRACEGATE END-TO-END REST API TESTS ===")
    
    # 1. Projects API
    print("\n[TEST 1] GET /api/projects...")
    res = client.get("/api/projects")
    assert res.status_code == 200
    res_data = res.json()
    projects = res_data if isinstance(res_data, list) else res_data.get("projects", [])
    assert isinstance(projects, list)
    assert len(projects) >= 3, f"Expected at least 3 seeded starter projects, found {len(projects)}"
    print(f"  [OK] Found {len(projects)} projects: {[p['id'] for p in projects[:3]]}")

    # 2. Project Creation
    print("\n[TEST 2] POST /api/projects...")
    new_proj_payload = {
        "name": "Automated VAPT Test Lab Project",
        "target_url": "https://vulnerable-shop.test.local",
        "environment": "Vulnerable Lab / CTF",
        "description": "Assessment for OWASP Juice Shop test environment.",
        "notes": "Admin test account provided: admin@juice-sh.op / admin123"
    }
    res = client.post("/api/projects", json=new_proj_payload)
    assert res.status_code == 201
    created_proj = res.json()
    assert created_proj["name"] == new_proj_payload["name"]
    proj_id = created_proj["id"]
    print(f"  [OK] Created project with ID: {proj_id}")

    # 3. Project Detail & Update
    print("\n[TEST 3] GET and PUT /api/projects/{id}...")
    res = client.get(f"/api/projects/{proj_id}")
    assert res.status_code == 200
    assert res.json()["id"] == proj_id

    res = client.put(f"/api/projects/{proj_id}", json={"status": "IN_PROGRESS", "notes": "Scope updated."})
    assert res.status_code == 200
    assert res.json()["notes"] == "Scope updated."
    print("  [OK] Project details and status update verified.")

    # 4. Analyze Screenshot linked to Project
    print("\n[TEST 4] POST /api/analyze-screenshot with project_id...")
    sample_path = PROJECT_DIR / "samples" / "profile.png"
    assert sample_path.exists()
    with open(sample_path, "rb") as f:
        img_bytes = f.read()

    res = client.post(
        "/api/analyze-screenshot",
        files={"image": ("profile.png", img_bytes, "image/png")},
        data={"project_id": proj_id, "page_type": "Account / Profile"}
    )
    assert res.status_code == 200
    analysis = res.json()
    assert "Account / Profile" in analysis["page_type"]
    assert len(analysis["checklist"]) > 0
    print(f"  [OK] Screenshot analyzed & linked to project: {len(analysis['checklist'])} tests generated.")

    # 5. Fetch Saved Checklist
    print("\n[TEST 5] GET /api/projects/{id}/checklist...")
    res = client.get(f"/api/projects/{proj_id}/checklist")
    assert res.status_code == 200
    chk_data = res.json()
    assert "checklist" in chk_data
    items = chk_data["checklist"]
    assert len(items) > 0
    test_item = items[0]
    item_id = test_item["id"]
    print(f"  [OK] Retrieved checklist from database: item '{test_item['name']}' ({item_id})")

    # 6. Status Update: TESTED_NOT_FOUND
    print("\n[TEST 6] PUT /api/checklist/{id}/status (TESTED_NOT_FOUND)...")
    res = client.put(f"/api/checklist/{item_id}/status", json={"status": "TESTED_NOT_FOUND"})
    assert res.status_code == 200
    assert res.json()["status"] == "TESTED_NOT_FOUND"
    print("  [OK] Status updated to TESTED_NOT_FOUND.")

    # 7. Record Finding on Second Item
    print("\n[TEST 7] POST /api/checklist/{id}/finding...")
    assert len(items) > 1
    target_item = items[1]
    finding_payload = {
        "finding_name": "Insecure Direct Object Reference on User Profile",
        "priority": "HIGH",
        "description": "User profile ID can be modified in the request parameter to access other users' sensitive PII.",
        "testing_notes": "1. Intercept GET /api/user/101\n2. Change ID to 102\n3. Full profile of user 102 returned without auth check.",
        "poc_text": "GET /api/user/102 HTTP/1.1\nHost: vulnerable-shop.test.local\nCookie: session=user101_sess\n\nHTTP/1.1 200 OK\n{\"id\": 102, \"email\": \"victim@test.local\", \"ssn\": \"***-**-1234\"}",
        "evidence_filename": "idor_proof.png"
    }
    res = client.post(f"/api/checklist/{target_item['id']}/finding", json=finding_payload)
    assert res.status_code == 201
    created_finding = res.json()
    assert created_finding["finding_name"] == finding_payload["finding_name"]
    finding_id = created_finding["id"]
    print(f"  [OK] Finding saved: ID={finding_id}")

    # Verify checklist item status was updated to VULNERABILITY_FOUND
    res = client.get(f"/api/projects/{proj_id}/checklist")
    updated_items = res.json()["checklist"]
    updated_target = next(i for i in updated_items if i["id"] == target_item["id"])
    assert updated_target["status"] == "VULNERABILITY_FOUND"
    print("  [OK] Checklist item status automatically updated to VULNERABILITY_FOUND.")

    # 8. Fetch Findings for Project
    print("\n[TEST 8] GET /api/projects/{id}/findings...")
    res = client.get(f"/api/projects/{proj_id}/findings")
    assert res.status_code == 200
    res_data = res.json()
    findings = res_data if isinstance(res_data, list) else res_data.get("findings", [])
    assert len(findings) == 1
    assert findings[0]["id"] == finding_id
    print(f"  [OK] Found 1 recorded finding for project: '{findings[0]['finding_name']}'")

    # 9. Add Custom Checklist Test
    print("\n[TEST 9] POST /api/projects/{id}/checklist/custom...")
    custom_payload = {
        "name": "Custom Business Logic Bypass Test",
        "priority": "CRITICAL",
        "cwe": "CWE-840",
        "reason": "Verify that multi-step wizard cannot be skipped by direct step URL navigation.",
        "testing_objective": "Attempt to access step 3 (final confirmation) without completing step 1 or step 2."
    }
    res = client.post(f"/api/projects/{proj_id}/checklist/custom", json=custom_payload)
    assert res.status_code == 201
    custom_item = res.json()
    assert custom_item["name"] == custom_payload["name"]
    assert custom_item["source"] == "USER"
    custom_id = custom_item["id"]
    print(f"  [OK] Custom test created with source='USER', ID={custom_id}")

    # 10. Edit Checklist Item
    print("\n[TEST 10] PUT /api/checklist/{id}...")
    edit_payload = {
        "name": "Custom Business Logic Bypass (Modified by Senior Assessor)",
        "priority": "HIGH",
        "cwe": "CWE-840",
        "reason": "Updated reason to reflect multi-tenant scoping.",
        "testing_objective": "Test with standard user and admin user roles."
    }
    res = client.put(f"/api/checklist/{custom_id}", json=edit_payload)
    assert res.status_code == 200
    edited_item = res.json()
    assert edited_item["name"] == edit_payload["name"]
    assert edited_item["source"] == "USER_MODIFIED"
    print("  [OK] Checklist item updated with source='USER_MODIFIED'.")

    # 11. Delete Finding
    print("\n[TEST 11] DELETE /api/findings/{id}...")
    res = client.delete(f"/api/findings/{finding_id}")
    assert res.status_code == 200
    res = client.get(f"/api/projects/{proj_id}/findings")
    rem_findings = res.json() if isinstance(res.json(), list) else res.json().get("findings", [])
    assert len(rem_findings) == 0
    print("  [OK] Finding deleted successfully.")

    # 12. Delete Project
    print("\n[TEST 12] DELETE /api/projects/{id}...")
    res = client.delete(f"/api/projects/{proj_id}")
    assert res.status_code == 200
    res = client.get(f"/api/projects/{proj_id}")
    assert res.status_code == 404
    print("  [OK] Project and cascaded data deleted successfully.")

    print("\nALL END-TO-END REST API TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
