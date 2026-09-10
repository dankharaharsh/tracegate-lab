import io
import os
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend.schemas import VaptAnalysisResponse, PriorityEnum

client = TestClient(app)

PRIORITY_ORDER = {
    PriorityEnum.CRITICAL: 0,
    PriorityEnum.HIGH: 1,
    PriorityEnum.MEDIUM: 2,
    PriorityEnum.LOW: 3,
}

def test_health_endpoint():
    print("\n[TEST 1] Testing /api/health...")
    response = client.get("/api/health")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert data["status"] == "healthy"
    assert "provider" in data
    print(f"  [OK] Health check passed (Provider: {data['provider']}, Mode: {data['mode']})")

def test_samples_endpoint():
    print("\n[TEST 2] Testing /api/samples...")
    response = client.get("/api/samples")
    assert response.status_code == 200
    data = response.json()
    assert "samples" in data
    assert len(data["samples"]) == 11
    sample_ids = [s["id"] for s in data["samples"]]
    expected_ids = [
        "login", "registration", "forgot_password", "profile",
        "settings", "dashboard", "search", "file_upload",
        "checkout", "admin_panel", "ambiguous"
    ]
    for eid in expected_ids:
        assert eid in sample_ids, f"Missing sample: {eid}"
    print(f"  [OK] Found all 11 sample scenarios: {sample_ids}")

def test_all_sample_screenshots():
    print("\n[TEST 3] Testing all 10 categories + ambiguous scenario...")
    samples_dir = BASE_DIR / "samples"
    scenarios = [
        ("login.png", "Login / Sign-in Page"),
        ("registration.png", "Sign-up / Registration Page"),
        ("forgot_password.png", "Forgot Password / Password Reset Page"),
        ("profile.png", "Account / Profile Page"),
        ("settings.png", "Settings / Security Settings Page"),
        ("dashboard.png", "Home / Dashboard Page"),
        ("search.png", "Search / Search Results Page"),
        ("file_upload.png", "File Upload Page"),
        ("checkout.png", "Checkout / Payment Page"),
        ("admin_panel.png", "Admin Dashboard / Admin Panel"),
        ("ambiguous.png", "Unknown / Ambiguous")
    ]

    scenario_checklists = {}

    for filename, expected_page_type in scenarios:
        filepath = samples_dir / filename
        assert filepath.exists(), f"Sample file {filepath} must exist"

        with open(filepath, "rb") as f:
            file_bytes = f.read()

        response = client.post(
            "/api/analyze-screenshot",
            files={"image": (filename, file_bytes, "image/png")},
            data={"prompt": f"Verify tests for {expected_page_type}"}
        )

        assert response.status_code == 200, f"Failed for {filename}: {response.text}"
        data = response.json()

        validated = VaptAnalysisResponse(**data)
        assert validated.confidence >= 0.0 and validated.confidence <= 1.0
        assert len(validated.detected_elements) > 0
        assert len(validated.checklist) >= 2
        assert validated.page_type == expected_page_type, f"Expected '{expected_page_type}', got '{validated.page_type}'"

        if filename == "ambiguous.png":
            assert validated.ambiguity_notes is not None, "Ambiguous screenshot must have ambiguity_notes"
            assert validated.confidence < 0.5, "Ambiguous screenshot must have low confidence"

        # Verify priority ordering
        priorities = [item.priority for item in validated.checklist]
        weights = [PRIORITY_ORDER[p] for p in priorities]
        assert weights == sorted(weights), f"Checklist items must be sorted CRITICAL -> LOW for {filename}"

        # Verify items have id, source, status
        for item in validated.checklist:
            assert len(item.id) > 0
            assert item.source in ["AI", "USER", "USER_MODIFIED"]
            assert item.status in ["NOT_TESTED", "TESTED_NOT_FOUND", "VULNERABILITY_FOUND"]
            if item.cwe:
                assert item.cwe.startswith("CWE-"), f"Invalid CWE format '{item.cwe}' in {item.name}"
            assert len(item.testing_objective) > 10
            assert len(item.reason) > 10

        scenario_checklists[filename] = [i.name for i in validated.checklist]
        print(f"  [OK] {filename:<20} -> Page: '{validated.page_type}' | {len(validated.checklist)} items")

    # Verify that the 10 main checklists are distinct from each other
    main_filenames = [s[0] for s in scenarios if s[0] != "ambiguous.png"]
    for i in range(len(main_filenames)):
        for j in range(i + 1, len(main_filenames)):
            names_i = set(scenario_checklists[main_filenames[i]])
            names_j = set(scenario_checklists[main_filenames[j]])
            overlap = names_i.intersection(names_j)
            assert len(overlap) < len(names_i), f"Scenarios {main_filenames[i]} and {main_filenames[j]} should not have identical checklists!"

    print("  [OK] All 10 categories produced distinct, context-aware VAPT checklists.")

def test_error_handling():
    print("\n[TEST 4] Testing Error Handling...")

    resp = client.post("/api/analyze-screenshot")
    assert resp.status_code in [400, 422]
    print("  [OK] Missing image rejected with 400/422")

    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("malicious.exe", b"MZtest", "application/x-msdownload")}
    )
    assert resp.status_code == 400
    assert "Unsupported file format" in resp.json()["detail"]
    print("  [OK] Unsupported file type rejected with 400")

    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("empty.png", b"", "image/png")}
    )
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()
    print("  [OK] Empty file rejected with 400")

    huge_bytes = b"0" * (10 * 1024 * 1024 + 1024)
    resp = client.post(
        "/api/analyze-screenshot",
        files={"image": ("huge.png", huge_bytes, "image/png")}
    )
    assert resp.status_code == 413
    assert "exceeds maximum permitted size" in resp.json()["detail"].lower()
    print("  [OK] Oversized file rejected with 413")

if __name__ == "__main__":
    print("=== STARTING COMPREHENSIVE VAPT CHECKLIST TESTS ===")
    test_health_endpoint()
    test_samples_endpoint()
    test_all_sample_screenshots()
    test_error_handling()
    print("\nALL TESTS PASSED SUCCESSFULLY!")
