"""
Tests for Repository Vulnerability Scanner & All-Code Multi-Vulnerability Batch Remediation.
Verifies:
1. scan_repository_vulnerabilities SAST engine detects all CWE patterns across repository.
2. generate_cumulative_repository_fix iteratively patches all vulnerable locations across files.
3. POST /api/ai-fix/scan-repository endpoint scans and auto-registers findings in project.
4. POST /api/ai-fix/batch-patch endpoint generates multi-file diff and valid code.
5. POST /api/ai-fix/apply endpoint commits multi-file cumulative patches to dedicated branch.
6. POST /api/ai-fix/create-pr endpoint creates PR and updates all remediated findings.
"""

import unittest
import re
from fastapi.testclient import TestClient
from backend.app import app
from backend.database import init_db, create_project, get_project_findings_list, get_db_connection, save_user_github_config
from backend.github_service import get_repository_tree, get_file_contents
from backend.ai_autofix import scan_repository_vulnerabilities, generate_cumulative_repository_fix, validate_syntax


class TestRepoScannerBatchPatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.repo = "dankharaharsh/vulnerable-code"
        cls.branch = "main"

    def setUp(self):
        # Set mock sandbox github configuration for test isolation
        save_user_github_config("usr-learner-001", "ghp_secureSampleToken9876543210ZYX", "mock", "learner-analyst")

        # Create a fresh test project
        self.project = create_project({
            "name": "Test Vulnerability Scanner Project",
            "target_url": "https://test.app",
            "description": "Test project for repo scanning and batch patching"
        })
        self.project_id = self.project["id"]

    def tearDown(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM findings WHERE project_id = ?", (self.project_id,))
        cursor.execute("DELETE FROM projects WHERE id = ?", (self.project_id,))
        conn.commit()
        conn.close()

    def test_01_scanner_detects_all_vulnerabilities_on_real_repo(self):
        """Test: scan_repository_vulnerabilities detects all 9 vulnerabilities on dankharaharsh/vulnerable-code."""
        tree = get_repository_tree("anon", self.repo, self.branch)
        items = tree.get("tree", [])

        def fetch_cb(p: str) -> str:
            res = get_file_contents("anon", self.repo, self.branch, p)
            return res.get("content", "")

        scan_result = scan_repository_vulnerabilities(self.repo, self.branch, items, fetch_cb)
        self.assertTrue(scan_result["success"])
        self.assertGreaterEqual(scan_result["vulnerabilities_detected_count"], 8)

        cwes = [f["cwe"] for f in scan_result["findings"]]
        self.assertIn("CWE-89", cwes)    # SQL Injection
        self.assertIn("CWE-288", cwes)   # 2FA Bypass
        self.assertIn("CWE-204", cwes)   # Username Enumeration
        self.assertIn("CWE-639", cwes)   # IDOR
        self.assertIn("CWE-434", cwes)   # File Upload
        self.assertIn("CWE-79", cwes)    # Stored XSS
        self.assertIn("CWE-22", cwes)    # Path Traversal
        self.assertIn("CWE-524", cwes)   # Autocomplete

        # Verify line numbers are captured accurately
        for f in scan_result["findings"]:
            self.assertIsNotNone(f.get("line_number"))
            self.assertGreater(f["line_number"], 0)
            self.assertGreater(len(f.get("vulnerable_snippet", "")), 0)

    def test_02_cumulative_fix_patches_all_files_with_valid_syntax(self):
        """Test: generate_cumulative_repository_fix patches app.py and template files cleanly."""
        tree = get_repository_tree("anon", self.repo, self.branch)
        items = tree.get("tree", [])

        def fetch_cb(p: str) -> str:
            res = get_file_contents("anon", self.repo, self.branch, p)
            return res.get("content", "")

        scan_result = scan_repository_vulnerabilities(self.repo, self.branch, items, fetch_cb)
        findings = scan_result["findings"]

        fix_res = generate_cumulative_repository_fix(findings, self.repo, self.branch, fetch_cb)
        self.assertTrue(fix_res["success"])
        self.assertEqual(fix_res["patch_status"], "PATCH_VALIDATED")

        # Verify all modified files have diffs and valid syntax
        files_map = {f["path"]: f for f in fix_res["files"]}
        self.assertIn("app.py", files_map)
        self.assertIn("templates/login.html", files_map)
        self.assertIn("templates/uploads.html", files_map)

        app_patch = files_map["app.py"]
        self.assertEqual(app_patch["validation"]["syntax"], "PASSED")
        self.assertIn(".resolve()", app_patch["after_code"])
        self.assertIn("Path(", app_patch["after_code"])
        self.assertIn("clean_svg", app_patch["after_code"])
        self.assertIn("uuid", app_patch["after_code"].lower())

        login_patch = files_map["templates/login.html"]
        self.assertIn('autocomplete="off"', login_patch["after_code"])

        uploads_patch = files_map["templates/uploads.html"]
        clean_uploads = re.sub(r'<!--[\s\S]*?-->', '', uploads_patch["after_code"])
        self.assertNotIn('| safe', clean_uploads)
        self.assertNotIn('|safe', clean_uploads)

    def test_03_scan_repository_api_endpoint(self):
        """Test: POST /api/ai-fix/scan-repository populates findings in project database."""
        resp = self.client.post("/api/ai-fix/scan-repository", json={
            "repo": self.repo,
            "branch": self.branch,
            "project_id": self.project_id,
            "auto_register": True
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["vulnerabilities_detected_count"], 8)

        # Verify registered in project findings
        db_findings = get_project_findings_list(self.project_id)
        self.assertGreaterEqual(len(db_findings), 8)
        db_cwes = [f["cwe"] for f in db_findings]
        self.assertIn("CWE-89", db_cwes)
        self.assertIn("CWE-22", db_cwes)

    def test_04_batch_patch_api_endpoint(self):
        """Test: POST /api/ai-fix/batch-patch generates cumulative multi-file patch."""
        # First scan to populate
        self.client.post("/api/ai-fix/scan-repository", json={
            "repo": self.repo,
            "branch": self.branch,
            "project_id": self.project_id,
            "auto_register": True
        })

        resp = self.client.post("/api/ai-fix/batch-patch", json={
            "repo": self.repo,
            "branch": self.branch,
            "project_id": self.project_id
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["patch_status"], "PATCH_VALIDATED")
        self.assertGreaterEqual(len(data["files"]), 3)
        self.assertGreater(len(data["diff_unified"]), 0)

    def test_05_apply_and_create_pr_for_batch_fix(self):
        """Test: POST /api/ai-fix/apply and POST /api/ai-fix/create-pr handles batch remediation."""
        # 1. Run batch patch
        patch_resp = self.client.post("/api/ai-fix/batch-patch", json={
            "repo": self.repo,
            "branch": self.branch,
            "project_id": self.project_id
        })
        patch_data = patch_resp.json()

        # 2. Apply fix with multi-file list
        apply_resp = self.client.post("/api/ai-fix/apply", json={
            "finding_id": "__ALL_FINDINGS__",
            "project_id": self.project_id,
            "repo": self.repo,
            "target_branch": self.branch,
            "fix_branch": "tracegate/fix/cumulative-test-patch",
            "files": patch_data["files"]
        })
        self.assertEqual(apply_resp.status_code, 200)
        apply_data = apply_resp.json()
        self.assertTrue(apply_data["success"])
        self.assertEqual(apply_data["validation_status"], "PASSED")

        # 3. Create PR for batch
        pr_resp = self.client.post("/api/ai-fix/create-pr", json={
            "finding_id": "__ALL_FINDINGS__",
            "repo": self.repo,
            "fix_branch": apply_data["branch_name"],
            "base_branch": self.branch
        })
        self.assertEqual(pr_resp.status_code, 200)
        pr_data = pr_resp.json()
        self.assertTrue(pr_data["success"])
        self.assertIn("pull", pr_data["pr_url"].lower())


if __name__ == "__main__":
    unittest.main()
