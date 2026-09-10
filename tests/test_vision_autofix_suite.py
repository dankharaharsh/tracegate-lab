"""
Tracegate Comprehensive Verification Suite:
Vision Analysis Pipeline, Project Deletion Cascades & Complete AI AutoFix Integration.
"""

import os
import io
import json
import time
import shutil
import hashlib
import unittest
from pathlib import Path
from PIL import Image

from fastapi.testclient import TestClient

# Ensure workspace root in sys.path
WORKSPACE_DIR = Path(__file__).resolve().parent.parent
import sys
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

from backend.app import app
from backend.database import (
    get_db_connection,
    create_project as db_create_project,
    get_project_by_id,
    delete_project as db_delete_project,
    save_finding,
    get_project_findings_list,
    get_finding_by_id,
    save_report_record as save_report,
    get_project_reports,
)
from backend.github_service import (
    analyze_finding_code,
    apply_finding_fix,
    create_finding_pull_request,
    get_github_status,
    save_github_token,
)
from backend.analyzer import preprocess_image, extract_visible_security_signals
from backend.report_generator import generate_docx_report


class TestVisionAutofixSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.samples_dir = WORKSPACE_DIR / "samples"
        cls.reports_dir = WORKSPACE_DIR / "data" / "reports"
        cls.reports_dir.mkdir(parents=True, exist_ok=True)

        # Helper dummy image generator
        cls.test_png_bytes = cls._create_dummy_image(200, 200, "blue")
        cls.small_png_bytes = cls._create_dummy_image(50, 50, "red")

    @classmethod
    def _create_dummy_image(cls, w: int, h: int, color: str) -> bytes:
        img = Image.new("RGB", (w, h), color=color)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    def setUp(self):
        self.created_project_ids = []

    def tearDown(self):
        for pid in self.created_project_ids:
            try:
                db_delete_project(pid)
            except Exception:
                pass

    # =========================================================================
    # PART 1: VISION / SCREENSHOT ANALYSIS TESTS (Tests 1 - 10)
    # =========================================================================

    def test_01_login_screenshot_functionality_detected(self):
        """Correct Login screenshot -> Login functionality detected."""
        img_path = self.samples_dir / "login.png"
        img_bytes = img_path.read_bytes() if img_path.exists() else self.test_png_bytes

        res = self.client.post(
            "/api/analyze-screenshot",
            data={"page_type": "Auto Detect"},
            files={"image": ("login.png", img_bytes, "image/png")}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["page_type"], "Login / Sign-in Page")
        self.assertGreaterEqual(len(data["detected_elements"]), 3)
        self.assertTrue(any("login" in item.lower() or "auth" in item.lower() or "credential" in item.lower() for item in data["detected_elements"]))

    def test_02_account_screenshot_functionality_detected(self):
        """Correct Account screenshot -> Account functionality detected."""
        img_path = self.samples_dir / "profile.png"
        img_bytes = img_path.read_bytes() if img_path.exists() else self.test_png_bytes

        res = self.client.post(
            "/api/analyze-screenshot",
            data={"page_type": "Auto Detect"},
            files={"image": ("profile.png", img_bytes, "image/png")}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["page_type"], "Account / Profile Page")
        self.assertGreaterEqual(len(data["checklist"]), 5)

    def test_03_search_screenshot_functionality_detected(self):
        """Correct Search screenshot -> Search functionality detected."""
        img_path = self.samples_dir / "search.png"
        img_bytes = img_path.read_bytes() if img_path.exists() else self.test_png_bytes

        res = self.client.post(
            "/api/analyze-screenshot",
            data={"page_type": "Auto Detect"},
            files={"image": ("search.png", img_bytes, "image/png")}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["page_type"], "Search / Search Results Page")
        self.assertTrue(any("search" in item["name"].lower() or "injection" in item["name"].lower() for item in data["checklist"]))

    def test_04_new_screenshot_fresh_image_hash(self):
        """New screenshot invalidates old analysis with unique image_hash."""
        img1 = self._create_dummy_image(150, 150, "green")
        img2 = self._create_dummy_image(150, 150, "yellow")

        res1 = self.client.post(
            "/api/analyze-screenshot",
            data={"page_type": "Login / Sign-in Page"},
            files={"image": ("img1.png", img1, "image/png")}
        )
        res2 = self.client.post(
            "/api/analyze-screenshot",
            data={"page_type": "Login / Sign-in Page"},
            files={"image": ("img2.png", img2, "image/png")}
        )
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res2.status_code, 200)
        hash1 = res1.json().get("image_hash")
        hash2 = res2.json().get("image_hash")
        self.assertIsNotNone(hash1)
        self.assertIsNotNone(hash2)
        self.assertNotEqual(hash1, hash2)

    def test_05_corrupt_screenshot_graceful_fallback(self):
        """Corrupt screenshot falls back gracefully without 500 error."""
        corrupt_bytes = b"NOT_A_VALID_IMAGE_BYTES_XYZ123"
        res = self.client.post(
            "/api/analyze-screenshot",
            data={"page_type": "Forgot Password / Password Reset Page"},
            files={"image": ("broken.png", corrupt_bytes, "image/png")}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["page_type"], "Forgot Password / Password Reset Page")
        self.assertGreaterEqual(len(data["checklist"]), 6)
        self.assertEqual(data.get("image_quality"), "UNREADABLE")

    def test_06_selected_page_type_authoritative_no_override(self):
        """Selected Page Type is strictly authoritative and NEVER overridden by screenshot."""
        search_img = (self.samples_dir / "search.png").read_bytes()
        res = self.client.post(
            "/api/analyze-screenshot",
            data={"page_type": "Login / Sign-in Page"},
            files={"image": ("search.png", search_img, "image/png")}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["page_type"], "Login / Sign-in Page")
        self.assertFalse(data.get("page_type_conflict", False))

    def test_07_additional_context_does_not_override_page_type(self):
        """Additional Context textbox refines checklist but NEVER overrides selected Page Type."""
        login_img = (self.samples_dir / "login.png").read_bytes()
        res = self.client.post(
            "/api/analyze-screenshot",
            data={
                "page_type": "Login / Sign-in Page",
                "additional_context": "The user is searching for medical records in an admin portal."
            },
            files={"image": ("login.png", login_img, "image/png")}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["page_type"], "Login / Sign-in Page")

    def test_08_ambiguous_image_fallback_prompts_user(self):
        """Auto Detect on ambiguous/unclear image returns confidence <= 0.70 and prompts user to select page type."""
        amb_path = self.samples_dir / "ambiguous.png"
        amb_bytes = amb_path.read_bytes() if amb_path.exists() else self._create_dummy_image(30, 30, "gray")

        res = self.client.post(
            "/api/analyze-screenshot",
            data={"page_type": "Auto Detect"},
            files={"image": ("ambiguous.png", amb_bytes, "image/png")}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["page_type"], "Unknown / Ambiguous")
        self.assertLessEqual(data["confidence"], 0.70)
        self.assertIsNotNone(data.get("ambiguity_notes"))

    def test_09_image_dimensions_and_quality_assessment(self):
        """Image dimensions and quality metrics (GOOD vs LIMITED) are extracted."""
        good_prep = preprocess_image(self.test_png_bytes, "image/png")
        self.assertTrue(good_prep["valid"])
        self.assertEqual(good_prep["quality"], "GOOD")
        self.assertEqual(good_prep["dimensions"]["width"], 200)
        self.assertEqual(good_prep["dimensions"]["height"], 200)

        small_prep = preprocess_image(self.small_png_bytes, "image/png")
        self.assertTrue(small_prep["valid"])
        self.assertEqual(small_prep["quality"], "LIMITED")
        self.assertEqual(small_prep["dimensions"]["width"], 50)
        self.assertEqual(small_prep["dimensions"]["height"], 50)

    def test_10_visible_security_signals_extraction(self):
        """Security-relevant visible features (e.g. CAPTCHA, 2FA, OTP) are extracted into visible_security_signals."""
        signals = extract_visible_security_signals(
            scenario="forgot_password",
            detected_elements=["Username Input", "CAPTCHA Widget", "OTP verification input"],
            prompt="Assess OTP bypass"
        )
        self.assertTrue(any("CAPTCHA" in s for s in signals))
        self.assertTrue(any("OTP" in s or "Two-factor" in s for s in signals))

    # =========================================================================
    # PART 2: PROJECT DELETE FEATURE TESTS (Tests 11 - 16)
    # =========================================================================

    def test_11_project_deletion_cascades_and_removes_from_db(self):
        """Deleting a project removes it and cascades removal of findings & checklists."""
        proj = db_create_project({"name": "Del-Test-1", "target_url": "https://del1.test"})
        pid = proj["id"]

        save_finding({
            "project_id": pid,
            "finding_name": "Test Vuln to Delete",
            "priority": "HIGH"
        })
        self.assertEqual(len(get_project_findings_list(pid)), 1)

        res = self.client.delete(f"/api/projects/{pid}")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"deleted": True, "project_id": pid})

        self.assertIsNone(get_project_by_id(pid))
        self.assertEqual(len(get_project_findings_list(pid)), 0)

    def test_12_project_deletion_cleans_up_physical_docx_reports(self):
        """Deleting a project unlinks/deletes physical .docx files from data/reports/."""
        proj = db_create_project({"name": "Del-Report-Test", "target_url": "https://delrep.test"})
        pid = proj["id"]

        dummy_docx = self.reports_dir / f"{pid}_v1_0_assessment_report.docx"
        dummy_docx.write_bytes(b"PK\x03\x04DummyDOCXContent")
        self.assertTrue(dummy_docx.exists())

        save_report({
            "project_id": pid,
            "version": "v1.0",
            "report_title": "Assessment Report",
            "file_path": str(dummy_docx),
            "total_findings": 0,
            "selected_finding_ids": []
        })

        res = self.client.delete(f"/api/projects/{pid}")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(dummy_docx.exists())

    def test_13_other_projects_remain_unaffected_after_deletion(self):
        """Deleting project A leaves project B completely intact."""
        proj_a = db_create_project({"name": "Project A", "target_url": "https://a.test"})
        proj_b = db_create_project({"name": "Project B", "target_url": "https://b.test"})
        self.created_project_ids.append(proj_b["id"])

        res = self.client.delete(f"/api/projects/{proj_a['id']}")
        self.assertEqual(res.status_code, 200)

        found_b = get_project_by_id(proj_b["id"])
        self.assertIsNotNone(found_b)
        self.assertEqual(found_b["name"], "Project B")

    def test_14_delete_non_existent_project_returns_404(self):
        """Attempting to delete non-existent project returns HTTP 404."""
        res = self.client.delete("/api/projects/proj-non-existent-999999")
        self.assertEqual(res.status_code, 404)

    def test_15_frontend_danger_zone_and_delete_modal_markup_present(self):
        """Verify #btnDeleteProject and #modalDeleteProject requiring 'DELETE' exist in frontend/index.html."""
        index_html = (WORKSPACE_DIR / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="btnDeleteProject"', index_html)
        self.assertIn('id="modalDeleteProject"', index_html)
        self.assertIn('id="txtDeleteProjectConfirm"', index_html)
        self.assertIn('id="btnConfirmDeleteProject"', index_html)
        self.assertIn('Type DELETE to confirm', index_html)

    def test_16_frontend_delete_controller_logic_wired(self):
        """Verify frontend/js/app.js enforces 'DELETE' string check before calling DELETE /api/projects/{id}."""
        app_js = (WORKSPACE_DIR / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn('btnDeleteProject', app_js)
        self.assertIn('txtDeleteProjectConfirm', app_js)
        self.assertIn('btnConfirmDeleteProject', app_js)
        self.assertIn('val === "DELETE"', app_js)
        self.assertIn('/api/projects/', app_js)
        self.assertIn('method: "DELETE"', app_js)

    # =========================================================================
    # PART 3: AI AUTOFIX & GITHUB INTEGRATION TESTS (Tests 17 - 28)
    # =========================================================================

    def test_17_github_status_and_masking(self):
        """GitHub status endpoint safely returns username and masked token (never raw token)."""
        save_github_token("usr-learner-001", "ghp_secureSampleToken9876543210ZYX", "learner-analyst")
        status = get_github_status("usr-learner-001")
        self.assertTrue(status.connected)
        self.assertEqual(status.username, "learner-analyst")
        self.assertIn("ghp_...", status.token_preview)
        self.assertNotIn("secureSampleToken", status.token_preview)

    def test_18_finding_code_analysis_generates_diff_and_changes(self):
        """Finding + source file produces unified diff and discrete changes list."""
        finding = {
            "id": "find-idor-001",
            "vuln_id": "VULN-001",
            "finding_name": "Insecure Direct Object Reference on User Profile",
            "cwe": "CWE-639",
            "priority": "HIGH"
        }
        res = analyze_finding_code(
            user_id="usr-learner-001",
            repo="tracegate-lab/ecommerce-platform",
            branch="main",
            finding=finding,
            file_path="server/controllers/userController.js"
        )
        self.assertTrue(res.is_relevant_file)
        self.assertIn("server/controllers/userController.js", res.file_path)
        self.assertIsNotNone(res.diff_unified)
        self.assertIn("+", res.diff_unified)
        self.assertIn("-", res.diff_unified)
        self.assertGreaterEqual(len(res.changes), 2)
        self.assertIsNotNone(res.security_impact)
        self.assertIsNotNone(res.testing_recommendation)
        self.assertIsNotNone(res.file_sha)

    def test_19_irrelevant_source_file_rejected_without_fake_patch(self):
        """Irrelevant source file (.css, .png, docs) returns is_relevant_file=False with explanation."""
        finding = {
            "id": "find-sqli-002",
            "vuln_id": "VULN-002",
            "finding_name": "SQL Injection in Search Query",
            "cwe": "CWE-89",
            "priority": "CRITICAL"
        }
        res = analyze_finding_code(
            user_id="usr-learner-001",
            repo="tracegate-lab/ecommerce-platform",
            branch="main",
            finding=finding,
            file_path="assets/logo.png"
        )
        self.assertFalse(res.is_relevant_file)
        self.assertEqual(res.diff_unified, "")
        self.assertIn("irrelevant", res.reason.lower())
        self.assertEqual(len(res.changes), 0)

    def test_20_irrelevant_documentation_file_rejected(self):
        """Irrelevant markdown/docs file returns is_relevant_file=False."""
        finding = {
            "id": "find-xss-003",
            "vuln_id": "VULN-003",
            "finding_name": "Stored Cross-Site Scripting",
            "cwe": "CWE-79",
            "priority": "HIGH"
        }
        res = analyze_finding_code(
            user_id="usr-learner-001",
            repo="tracegate-lab/ecommerce-platform",
            branch="main",
            finding=finding,
            file_path="docs/architecture_overview.md"
        )
        self.assertFalse(res.is_relevant_file)
        self.assertIn("non-executable", res.reason.lower())

    def test_21_apply_fix_creates_dedicated_branch_never_overwrites_main(self):
        """Applying fix creates branch 'tracegate/fix/{vuln_id}', never overwriting main."""
        finding = {
            "id": "find-idor-001",
            "vuln_id": "VULN-001",
            "finding_name": "IDOR on Profile",
            "cwe": "CWE-639"
        }
        fix_res = apply_finding_fix(
            user_id="usr-learner-001",
            repo="tracegate-lab/ecommerce-platform",
            target_branch="main",
            finding=finding,
            file_path="server/controllers/userController.js",
            diff_or_fixed_code="// secured code"
        )
        self.assertTrue(fix_res.success)
        self.assertEqual(fix_res.branch_name, "tracegate/fix/VULN-001")
        self.assertNotEqual(fix_res.branch_name, "main")
        self.assertIsNotNone(fix_res.commit_sha)

    def test_22_stale_source_file_sha_raises_conflict_409(self):
        """Stale or mismatched source file SHA is rejected with HTTP 409 Conflict."""
        res = self.client.post(
            "/api/github/apply-fix",
            json={
                "finding_id": "VULN-001",
                "repository": "tracegate-lab/ecommerce-platform",
                "file_path": "server/controllers/userController.js",
                "file_sha": "stale_sha",
                "diff_or_fixed_code": "// secured code"
            }
        )
        self.assertEqual(res.status_code, 409)
        self.assertIn("changed since this fix was generated", res.json()["detail"])

    def test_23_pull_request_creation_with_security_metadata(self):
        """Pull Request is created with structured title and security description."""
        finding = {
            "id": "find-csrf-004",
            "vuln_id": "VULN-004",
            "finding_name": "Cross-Site Request Forgery",
            "cwe": "CWE-352"
        }
        pr_res = create_finding_pull_request(
            user_id="usr-learner-001",
            repo="tracegate-lab/ecommerce-platform",
            fix_branch="tracegate/fix/VULN-004",
            base_branch="main",
            title="fix(security): remediate CSRF on password update",
            body="Remediates CWE-352 by introducing SameSite cookies and CSRF synchronization token.",
            finding=finding
        )
        self.assertTrue(pr_res.success)
        self.assertGreaterEqual(pr_res.pr_number, 100)
        self.assertIn("github.com", pr_res.pr_url)
        self.assertIn("CSRF", pr_res.title)

    def test_24_apply_fix_persists_ai_fix_to_database(self):
        """Applying a fix persists commit, branch, and fix_status to finding record in database."""
        proj = db_create_project({"name": "Fix-Persist-Proj", "target_url": "https://fix.test"})
        pid = proj["id"]
        self.created_project_ids.append(pid)

        f = save_finding({
            "project_id": pid,
            "vuln_id": "VULN-101",
            "finding_name": "Direct Object Reference",
            "priority": "HIGH",
            "cwe": "CWE-639"
        })
        fid = f["id"]

        res = self.client.post(
            "/api/github/apply-fix",
            json={
                "finding_id": fid,
                "repository": "tracegate-lab/ecommerce-platform",
                "file_path": "server/controllers/userController.js",
                "diff_or_fixed_code": "// secured code"
            }
        )
        self.assertEqual(res.status_code, 200)

        updated = get_finding_by_id(fid)
        self.assertEqual(updated["fix_status"], "Fix Applied")
        self.assertEqual(updated["github_branch"], "tracegate/fix/VULN-101")
        self.assertIsNotNone(updated["github_commit"])

    def test_25_create_pr_persists_pr_url_to_database(self):
        """Creating a PR persists pr_url and transitions fix_status to 'PR Created'."""
        proj = db_create_project({"name": "PR-Persist-Proj", "target_url": "https://pr.test"})
        pid = proj["id"]
        self.created_project_ids.append(pid)

        f = save_finding({
            "project_id": pid,
            "vuln_id": "VULN-202",
            "finding_name": "SQL Injection",
            "priority": "CRITICAL",
            "cwe": "CWE-89"
        })
        fid = f["id"]

        res = self.client.post(
            "/api/github/create-pr",
            json={
                "finding_id": fid,
                "repo": "tracegate-lab/ecommerce-platform",
                "fix_branch": "tracegate/fix/VULN-202",
                "base_branch": "main"
            }
        )
        self.assertEqual(res.status_code, 200)
        updated = get_finding_by_id(fid)
        self.assertEqual(updated["fix_status"], "PR Created")
        self.assertIn("github.com", updated["github_pr"])

    def test_26_docx_report_includes_ai_autofix_section(self):
        """DOCX Report Section 6 includes AI AutoFix details when a fix was applied."""
        proj = db_create_project({"name": "DOCX-AutoFix-Proj", "target_url": "https://docx-af.test"})
        pid = proj["id"]
        self.created_project_ids.append(pid)

        f = save_finding({
            "project_id": pid,
            "vuln_id": "VULN-001",
            "finding_name": "Insecure Direct Object Reference",
            "priority": "HIGH",
            "cwe": "CWE-639",
            "fix_status": "Fix Applied",
            "github_branch": "tracegate/fix/VULN-001",
            "github_commit": "a1b2c3d4e5",
            "github_pr": "https://github.com/tracegate-lab/ecommerce-platform/pull/101"
        })

        proj_full = get_project_by_id(pid)
        rep_file_path = generate_docx_report(
            project=proj_full,
            version="v1.0",
            selected_finding_ids=[f["id"]]
        )
        out_path = Path(rep_file_path)
        self.assertTrue(out_path.exists())

        from docx import Document
        doc = Document(str(out_path))
        doc_text = " ".join(p.text for p in doc.paragraphs)
        self.assertIn("AI AutoFix Remediation Tracking", doc_text)
        self.assertIn("tracegate/fix/VULN-001", doc_text)
        self.assertIn("a1b2c3d4e5", doc_text)

        try:
            os.remove(out_path)
        except Exception:
            pass

    def test_27_frontend_retesting_checklist_markup(self):
        """Verify interactive retesting checklist (#chkRetestFinding) exists in frontend."""
        index_html = (WORKSPACE_DIR / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="chkRetestFinding"', index_html)
        self.assertIn('id="retestSuccessBadge"', index_html)
        self.assertIn('Fix Applied &rarr; Retested &rarr; Resolved', index_html)

    def test_28_frontend_retesting_controller_wiring(self):
        """Verify frontend/js/app.js handles chkRetestFinding event and transitions finding to Resolved."""
        app_js = (WORKSPACE_DIR / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn('chkRetestFinding', app_js)
        self.assertIn('retestSuccessBadge', app_js)
        self.assertIn('f.fix_status = "Resolved"', app_js)


if __name__ == "__main__":
    unittest.main(verbosity=2)
