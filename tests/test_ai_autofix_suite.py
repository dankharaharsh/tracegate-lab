import os
import sys
import json
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import (
    init_db,
    create_project,
    delete_project,
    save_finding,
    get_project_findings_list,
    get_ai_fix_for_finding,
    get_ai_fix_by_id,
    list_ai_fixes_for_project,
    record_finding_retest,
)
from backend.github_service import (
    get_github_status,
    save_github_token,
    disconnect_github,
    list_github_repositories,
    list_repository_branches,
    get_repository_tree,
    get_file_contents,
    create_fix_branch,
    commit_file_change,
    create_finding_pull_request,
    get_pull_request_status,
    merge_pull_request,
)
from backend.ai_autofix import (
    discover_vulnerable_source_file,
    is_file_relevant,
    check_precommit_safety,
    generate_secure_fix,
    generate_retest_checklist,
    generate_remediation_review_report,
)

class TestAIAutoFixSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

        # Create a test project for autofix
        res = cls.client.post("/api/projects", json={
            "name": "AutoFix Enterprise Security Test",
            "description": "Integration testing project for Tracegate AI AutoFix",
            "target_url": "https://staging.targetcorp.local"
        })
        assert res.status_code in (200, 201), f"Project creation failed: {res.text}"
        cls.project_id = res.json()["id"]

        # Create a confirmed SQLi finding directly using save_finding
        sqli_data = save_finding(cls.project_id, None, {
            "finding_name": "SQL Injection in Product Catalog Search",
            "title": "SQL Injection in Product Catalog Search",
            "severity": "CRITICAL",
            "priority": "CRITICAL",
            "category": "INJECTION",
            "description": "Raw string concatenation in SQL query allows arbitrary data exfiltration.",
            "impact": "Complete database compromise and credential dump.",
            "remediation": "Use parameterized queries or prepared statements.",
            "affected_component": "backend/services/catalogService.py",
            "component": "backend/services/catalogService.py",
            "cwe": "CWE-89",
            "cwe_id": "CWE-89",
            "owasp_id": "A03:2021-Injection",
            "poc": "curl -k 'https://staging.targetcorp.local/api/catalog/search?query=test%27%20OR%201=1--'",
            "poc_text": "curl -k 'https://staging.targetcorp.local/api/catalog/search?query=test%27%20OR%201=1--'",
            "is_confirmed": True,
            "status": "CONFIRMED"
        })
        cls.sqli_finding_id = sqli_data["id"]

        # Create an IDOR finding
        idor_data = save_finding(cls.project_id, None, {
            "finding_name": "Insecure Direct Object Reference (IDOR) on User Profiles",
            "title": "Insecure Direct Object Reference (IDOR) on User Profiles",
            "severity": "HIGH",
            "priority": "HIGH",
            "category": "BROKEN_ACCESS_CONTROL",
            "description": "Any authenticated user can view another user profile by modifying id parameter.",
            "impact": "Confidential user profile data leak.",
            "remediation": "Enforce session ownership validation.",
            "affected_component": "server/controllers/userController.js",
            "component": "server/controllers/userController.js",
            "cwe": "CWE-639",
            "cwe_id": "CWE-639",
            "owasp_id": "A01:2021-Broken Access Control",
            "poc": "GET /api/v1/users/42/profile HTTP/1.1 with User B session",
            "poc_text": "GET /api/v1/users/42/profile HTTP/1.1 with User B session",
            "is_confirmed": True,
            "status": "CONFIRMED"
        })
        cls.idor_finding_id = idor_data["id"]

    @classmethod
    def tearDownClass(cls):
        # Cleanup
        try:
            delete_project(cls.project_id)
        except Exception:
            pass

    # ---------------------------------------------------------
    # TEST 1: GitHub Connection & Server-Side Security
    # ---------------------------------------------------------
    def test_01_github_connection_and_token_masking(self):
        # Disconnect first to ensure clean state
        res = self.client.post("/api/github/disconnect")
        self.assertEqual(res.status_code, 200)

        status_res = self.client.get("/api/github/status")
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.json()
        self.assertFalse(status_data["connected"])

        # Connect with sandbox mock mode
        conn_res = self.client.post("/api/github/connect", json={
            "token": "ghp_TracegateTestTokenSandbox1234567890",
            "username": "tracegate-sec-bot"
        })
        self.assertEqual(conn_res.status_code, 200)
        conn_data = conn_res.json()
        self.assertTrue(conn_data["connected"])
        # Ensure raw token is NEVER returned in response
        self.assertNotIn("ghp_TracegateTestTokenSandbox1234567890", json.dumps(conn_data))
        self.assertTrue(conn_data["token_preview"] is not None)

        # Verify status endpoint returns masked token
        st = self.client.get("/api/github/status").json()
        self.assertTrue(st["connected"])
        self.assertEqual(st["username"], "tracegate-sec-bot")

    # ---------------------------------------------------------
    # TEST 2: Repository and Branch Navigation
    # ---------------------------------------------------------
    def test_02_repositories_and_branches(self):
        # Repositories list
        repos_res = self.client.get("/api/github/repositories")
        self.assertEqual(repos_res.status_code, 200)
        repos = repos_res.json()
        self.assertGreaterEqual(len(repos), 1)
        repo_names = [r["full_name"] for r in repos]
        self.assertIn("tracegate-lab/ecommerce-platform", repo_names)

        # Branches list for ecommerce-platform
        branches_res = self.client.get("/api/github/branches?repository=tracegate-lab/ecommerce-platform")
        self.assertEqual(branches_res.status_code, 200)
        branches = branches_res.json()["branches"]
        self.assertIn("main", branches)
        self.assertIn("develop", branches)

        # File Tree for ecommerce-platform
        tree_res = self.client.get("/api/github/tree?repository=tracegate-lab/ecommerce-platform&branch=main")
        self.assertEqual(tree_res.status_code, 200)
        tree = tree_res.json()["tree"]
        paths = [t["path"] for t in tree]
        self.assertIn("backend/services/catalogService.py", paths)
        self.assertIn("server/controllers/userController.js", paths)

        # File content reading
        file_res = self.client.get("/api/github/file?repository=tracegate-lab/ecommerce-platform&branch=main&path=backend/services/catalogService.py")
        self.assertEqual(file_res.status_code, 200)
        file_data = file_res.json()
        self.assertEqual(file_data["path"], "backend/services/catalogService.py")
        self.assertIn("SELECT id, title, price, stock FROM products", file_data["content"])
        self.assertTrue(len(file_data["sha"]) > 0)

    # ---------------------------------------------------------
    # TEST 3: Guardrails - File Relevance & Precommit Safety
    # ---------------------------------------------------------
    def test_03_relevance_and_safety_checks(self):
        # Non-executable files must be rejected by relevance check
        is_rel_png, _ = is_file_relevant("assets/logo.png", {})
        self.assertFalse(is_rel_png)
        is_rel_lock, _ = is_file_relevant("package-lock.json", {})
        self.assertFalse(is_rel_lock)
        is_rel_md, _ = is_file_relevant("docs/ARCHITECTURE.md", {})
        self.assertFalse(is_rel_md)
        is_rel_css, _ = is_file_relevant("static/style.css", {})
        self.assertFalse(is_rel_css)

        # Executable code files must pass relevance check
        is_rel_py, _ = is_file_relevant("backend/services/catalogService.py", {})
        self.assertTrue(is_rel_py)
        is_rel_js, _ = is_file_relevant("server/controllers/auth.js", {})
        self.assertTrue(is_rel_js)
        is_rel_go, _ = is_file_relevant("cmd/main.go", {})
        self.assertTrue(is_rel_go)

        # Precommit safety check flags workflows and dependency manifests
        safe_code = check_precommit_safety("backend/services/catalogService.py", "print('hello')")
        self.assertFalse(safe_code["is_dependency_file"])
        self.assertFalse(safe_code["is_workflow_file"])
        self.assertEqual(len(safe_code["warnings"]), 0)

        dep_check = check_precommit_safety("package.json", '{"dependencies": {}}')
        self.assertTrue(dep_check["is_dependency_file"])
        self.assertGreater(len(dep_check["warnings"]), 0)

        workflow_check = check_precommit_safety(".github/workflows/deploy.yml", "name: Deploy")
        self.assertTrue(workflow_check["is_workflow_file"])
        self.assertGreater(len(workflow_check["warnings"]), 0)

    # ---------------------------------------------------------
    # TEST 4: Vulnerable File Discovery
    # ---------------------------------------------------------
    def test_04_discover_file_for_finding(self):
        res = self.client.post("/api/ai-fix/discover-file", json={
            "finding_id": self.sqli_finding_id,
            "repository": "tracegate-lab/ecommerce-platform",
            "branch": "main"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["file_path"], "backend/services/catalogService.py")
        self.assertGreaterEqual(data["confidence"], 0.70)
        self.assertIn("def search_catalog_items", data["preview_snippet"])

    # ---------------------------------------------------------
    # TEST 5: AI Code Analysis & Unified Diff Generation (SQLi)
    # ---------------------------------------------------------
    def test_05_ai_code_analysis_sqli(self):
        # Fetch file sha and content
        file_res = self.client.get("/api/github/file?repository=tracegate-lab/ecommerce-platform&branch=main&path=backend/services/catalogService.py")
        file_info = file_res.json()

        res = self.client.post("/api/ai-fix/analyze", json={
            "project_id": self.project_id,
            "finding_id": self.sqli_finding_id,
            "repository": "tracegate-lab/ecommerce-platform",
            "branch": "main",
            "file_path": "backend/services/catalogService.py",
            "file_sha": file_info["sha"],
            "constraints": "Strict parameterized queries only."
        })
        self.assertEqual(res.status_code, 200)
        analysis = res.json()

        # Check required fields
        self.assertIn("explanation", analysis)
        self.assertIn("security_impact", analysis)
        self.assertIn("diff_unified", analysis)
        self.assertIn("proposed_code", analysis)
        self.assertIn("changes", analysis)
        self.assertIn("preserved_logic", analysis)
        self.assertIn("potential_side_effects", analysis)
        self.assertIn("retest_checklist", analysis)

        # Diff format check
        self.assertTrue(analysis["diff_unified"].startswith("--- a/backend/services/catalogService.py"))
        self.assertIn("+++ b/backend/services/catalogService.py", analysis["diff_unified"])
        self.assertIn("@@", analysis["diff_unified"])

        # Check that proposed code replaces vulnerable string concatenation
        self.assertNotIn("f\"SELECT id, title, price, stock FROM products WHERE category_id = {category_id}", analysis["proposed_code"])
        self.assertIn(":category_id", analysis["proposed_code"])

        # Retest checklist check
        self.assertGreaterEqual(len(analysis["retest_checklist"]), 2)

    # ---------------------------------------------------------
    # TEST 6: Developer Revision Loop
    # ---------------------------------------------------------
    def test_06_developer_revision_loop(self):
        file_res = self.client.get("/api/github/file?repository=tracegate-lab/ecommerce-platform&branch=main&path=backend/services/catalogService.py")
        file_info = file_res.json()

        # First analyze
        a_res = self.client.post("/api/ai-fix/analyze", json={
            "project_id": self.project_id,
            "finding_id": self.sqli_finding_id,
            "repository": "tracegate-lab/ecommerce-platform",
            "branch": "main",
            "file_path": "backend/services/catalogService.py",
            "file_sha": file_info["sha"]
        })
        self.assertEqual(a_res.status_code, 200)
        first_patch = a_res.json()["proposed_code"]

        # Request revision
        rev_res = self.client.post("/api/ai-fix/revise", json={
            "project_id": self.project_id,
            "finding_id": self.sqli_finding_id,
            "repository": "tracegate-lab/ecommerce-platform",
            "branch": "main",
            "file_path": "backend/services/catalogService.py",
            "current_proposed_code": first_patch,
            "developer_instructions": "Add typecast to integer before parameterization",
            "revision_count": 1
        })
        self.assertEqual(rev_res.status_code, 200)
        rev_data = rev_res.json()
        self.assertIn("int", rev_data["proposed_code"])
        self.assertIn("diff_unified", rev_data)

    # ---------------------------------------------------------
    # TEST 7: Pre-Write Safety & SHA Conflict Handling (409)
    # ---------------------------------------------------------
    def test_07_sha_conflict_detection(self):
        # Attempt to apply a patch with an outdated or incorrect file SHA
        apply_res = self.client.post("/api/ai-fix/apply", json={
            "project_id": self.project_id,
            "finding_id": self.sqli_finding_id,
            "repository": "tracegate-lab/ecommerce-platform",
            "base_branch": "main",
            "file_path": "backend/services/catalogService.py",
            "file_sha": "stale_sha_mismatch_123456",
            "proposed_code": "# safe code",
            "commit_message": "fix: parameterized query",
            "diff_unified": "dummy diff",
            "explanation": "Security patch",
            "security_impact": "Prevents injection"
        })
        # Must return HTTP 409 Conflict
        self.assertEqual(apply_res.status_code, 409)
        self.assertIn("SOURCE_CHANGED", apply_res.json()["detail"])

    # ---------------------------------------------------------
    # TEST 8: Branch Isolation Enforcement
    # ---------------------------------------------------------
    def test_08_branch_isolation_enforcement(self):
        # Service level directly prevents committing to main / master
        with self.assertRaises(ValueError) as ctx:
            commit_file_change(
                user_id="usr-learner-001",
                repository="tracegate-lab/ecommerce-platform",
                branch="main", # Direct write to main prohibited!
                file_path="backend/services/catalogService.py",
                content="# safe code",
                commit_message="Direct commit attempt",
                expected_sha="any_sha"
            )
        self.assertIn("protected", str(ctx.exception).lower())

    # ---------------------------------------------------------
    # TEST 9: Dedicated Branch Creation & Commit Apply Flow
    # ---------------------------------------------------------
    def test_09_apply_fix_creates_branch_and_commits(self):
        file_res = self.client.get("/api/github/file?repository=tracegate-lab/ecommerce-platform&branch=main&path=backend/services/catalogService.py")
        file_info = file_res.json()

        analysis_res = self.client.post("/api/ai-fix/analyze", json={
            "project_id": self.project_id,
            "finding_id": self.sqli_finding_id,
            "repository": "tracegate-lab/ecommerce-platform",
            "branch": "main",
            "file_path": "backend/services/catalogService.py",
            "file_sha": file_info["sha"]
        })
        analysis = analysis_res.json()

        # Apply patch to create fix branch
        apply_res = self.client.post("/api/ai-fix/apply", json={
            "project_id": self.project_id,
            "finding_id": self.sqli_finding_id,
            "repository": "tracegate-lab/ecommerce-platform",
            "base_branch": "main",
            "file_path": "backend/services/catalogService.py",
            "file_sha": file_info["sha"],
            "proposed_code": analysis["proposed_code"],
            "commit_message": "fix(security): sanitize user lookup query [Tracegate CWE-89]",
            "diff_unified": analysis["diff_unified"],
            "explanation": analysis["explanation"],
            "security_impact": analysis["security_impact"]
        })
        self.assertEqual(apply_res.status_code, 200)
        apply_data = apply_res.json()
        self.assertTrue(apply_data["success"])
        self.assertTrue(apply_data["branch_name"].startswith("tracegate/fix/"))
        self.assertIsNotNone(apply_data["commit_sha"])

        # Check database record
        db_fix = get_ai_fix_for_finding(self.sqli_finding_id)
        self.assertIsNotNone(db_fix)
        self.assertEqual(db_fix["fix_branch"], apply_data["branch_name"])

    # ---------------------------------------------------------
    # TEST 10: Pull Request Creation & Review Tracking
    # ---------------------------------------------------------
    def test_10_pull_request_creation_and_status(self):
        db_fix = get_ai_fix_for_finding(self.sqli_finding_id)
        self.assertIsNotNone(db_fix)

        pr_res = self.client.post("/api/ai-fix/create-pr", json={
            "project_id": self.project_id,
            "finding_id": self.sqli_finding_id,
            "repository": "tracegate-lab/ecommerce-platform",
            "base_branch": "main",
            "fix_branch": db_fix["fix_branch"],
            "title": "fix(sec): Parameterize SQL queries for User Profile [Tracegate CWE-89]",
            "body": "Detailed security advisory for CWE-89."
        })
        self.assertEqual(pr_res.status_code, 200)
        pr_data = pr_res.json()
        self.assertIn("pr_number", pr_data)
        self.assertGreaterEqual(pr_data["pr_number"], 1)
        self.assertIn("https://github.com/", pr_data["pr_url"])

        # Check PR status endpoint
        st_res = self.client.get(f"/api/ai-fix/pr/tracegate-lab/ecommerce-platform/{pr_data['pr_number']}/status")
        self.assertEqual(st_res.status_code, 200)
        self.assertEqual(st_res.json()["status"], "Open")

    # ---------------------------------------------------------
    # TEST 11: PR Merge Flow & Retest Decoupling
    # ---------------------------------------------------------
    def test_11_pr_merge_does_not_resolve_finding(self):
        db_fix = get_ai_fix_for_finding(self.sqli_finding_id)
        pr_number = db_fix["pr_number"]

        # Merge the PR
        merge_res = self.client.post("/api/ai-fix/pr/merge", json={
            "repository": "tracegate-lab/ecommerce-platform",
            "pr_number": pr_number,
            "commit_title": "Merge Tracegate security fix branch",
            "finding_id": self.sqli_finding_id
        })
        self.assertEqual(merge_res.status_code, 200)
        m_data = merge_res.json()
        self.assertTrue(m_data["merged"])
        self.assertEqual(m_data["status"], "MERGED")

        # Verify Finding is NOT yet RESOLVED in database
        findings = get_project_findings_list(self.project_id)
        sqli_finding = next(f for f in findings if f["id"] == self.sqli_finding_id)
        self.assertNotEqual(sqli_finding["fix_status"], "RESOLVED", "Merging code must NOT mark finding resolved without human retest!")
        self.assertEqual(sqli_finding["fix_status"], "Code Merged (Retest Required)")

    # ---------------------------------------------------------
    # TEST 12: Human Retest Verification (FAIL -> REOPENED)
    # ---------------------------------------------------------
    def test_12_retest_fail_reopens_finding(self):
        retest_fail_res = self.client.post(f"/api/ai-fix/{self.sqli_finding_id}/retest", json={
            "result": "FAIL",
            "notes": "Retest with payload id=1%20UNION%20SELECT still leaked table structure.",
            "checklist_items": [
                {"step": "Verify endpoint blocks raw quotes", "completed": True},
                {"step": "Verify union query returns empty error", "completed": False}
            ]
        })
        self.assertEqual(retest_fail_res.status_code, 200)
        fail_data = retest_fail_res.json()
        self.assertEqual(fail_data["retest_status"], "FAILED")
        self.assertEqual(fail_data["status"], "REOPENED")

        # Verify in database
        findings = get_project_findings_list(self.project_id)
        sqli_finding = next(f for f in findings if f["id"] == self.sqli_finding_id)
        self.assertEqual(sqli_finding["status"], "REOPENED")
        self.assertEqual(sqli_finding["fix_status"], "RETEST_FAILED")

    # ---------------------------------------------------------
    # TEST 13: Human Retest Verification (PASS -> RESOLVED)
    # ---------------------------------------------------------
    def test_13_retest_pass_resolves_finding(self):
        retest_pass_res = self.client.post(f"/api/ai-fix/{self.sqli_finding_id}/retest", json={
            "result": "PASS",
            "notes": "Verified endpoint with 12 SQL injection fuzz payloads. All return 400 Bad Request or empty profile. No database error leaked.",
            "checklist_items": [
                {"step": "Verify endpoint blocks raw quotes", "completed": True},
                {"step": "Verify union query returns empty error", "completed": True}
            ]
        })
        self.assertEqual(retest_pass_res.status_code, 200)
        pass_data = retest_pass_res.json()
        self.assertEqual(pass_data["retest_status"], "PASSED")
        self.assertEqual(pass_data["status"], "RESOLVED")

        # Verify in database
        findings = get_project_findings_list(self.project_id)
        sqli_finding = next(f for f in findings if f["id"] == self.sqli_finding_id)
        self.assertEqual(sqli_finding["status"], "RESOLVED")
        self.assertEqual(sqli_finding["fix_status"], "RESOLVED")

    # ---------------------------------------------------------
    # TEST 14: Remediation Review Report Generation
    # ---------------------------------------------------------
    def test_14_remediation_review_report(self):
        report_res = self.client.get(f"/api/ai-fix/{self.sqli_finding_id}/report")
        self.assertEqual(report_res.status_code, 200)
        report_data = report_res.json()
        self.assertIn("report_markdown", report_data)
        md = report_data["report_markdown"]
        self.assertIn("Tracegate AI Security Remediation Review Report", md)
        self.assertIn("SQL Injection", md)
        self.assertIn("CWE-89", md)
        self.assertIn("RESOLVED", md)
        self.assertIn("Retest Verification", md)

    # ---------------------------------------------------------
    # TEST 15: GitHub Token Permission 403 Diagnostics & Sandbox Fallback
    # ---------------------------------------------------------
    def test_15_github_token_permission_403_handling(self):
        # Configure a mock user with live mode and a Fine-Grained token
        from backend.database import save_user_github_config
        save_user_github_config("usr-learner-001", "github_pat_11ABC_test_token_with_readonly", "live", "octocat")

        # Mock _github_api_request to simulate GitHub 403 on branch creation
        with patch("backend.github_service._github_api_request") as mock_req:
            def side_effect(token, endpoint, method="GET", data=None, timeout=8):
                if "/git/ref/heads/main" in endpoint:
                    return 200, {"object": {"sha": "abcdef1234567890"}}, {}
                if "/git/refs" in endpoint and method == "POST":
                    # GitHub 403 Forbidden when PAT lacks write permissions
                    return 403, {"message": "Resource not accessible by personal access token", "documentation_url": "https://docs.github.com/rest/git/refs#create-a-reference"}, {}
                if "/pulls" in endpoint and method == "POST":
                    return 403, {"message": "Resource not accessible by personal access token"}, {}
                return 200, {}, {}

            mock_req.side_effect = side_effect

            # 1. Test Apply Fix with 403
            apply_res = self.client.post("/api/ai-fix/apply", json={
                "project_id": self.project_id,
                "finding_id": self.sqli_finding_id,
                "repository": "octocat/custom-live-repo",
                "base_branch": "main",
                "file_path": "backend/services/catalogService.py",
                "file_sha": "valid_sha_123456",
                "proposed_code": "# fixed code",
                "commit_message": "fix: security patch"
            })
            self.assertEqual(apply_res.status_code, 403)
            err_data = apply_res.json()["detail"]
            self.assertEqual(err_data["error"], "GITHUB_PERMISSION_DENIED")
            self.assertEqual(err_data["token_type"], "fine-grained")
            self.assertIn("octocat/custom-live-repo", err_data["message"])
            self.assertIn("Contents", err_data["message"])
            self.assertIn("Read and write", err_data["message"])

            # 2. Test Create PR with 403
            pr_res = self.client.post("/api/ai-fix/create-pr", json={
                "finding_id": self.sqli_finding_id,
                "repository": "octocat/custom-live-repo",
                "fix_branch": "tracegate/fix/VULN-001",
                "base_branch": "main"
            })
            self.assertEqual(pr_res.status_code, 403)
            pr_err = pr_res.json()["detail"]
            self.assertEqual(pr_err["error"], "GITHUB_PERMISSION_DENIED")

        # Re-set user github config back to sandbox mock
        save_user_github_config("usr-learner-001", None, "mock", "tracegate-learner")

if __name__ == "__main__":
    unittest.main()
