import os
import json
import unittest
from unittest.mock import patch, MagicMock
import urllib.error
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import (
    init_db,
    create_project,
    delete_project,
    save_finding,
    get_finding_by_id,
    get_ai_fix_for_finding,
    save_user_github_config,
    get_db_connection,
)
from backend.github_service import (
    create_finding_pull_request,
    get_pull_request_status,
    merge_pull_request,
)

class MockHTTPResponse:
    def __init__(self, data: dict, status_code: int = 200):
        self.data = json.dumps(data).encode("utf-8")
        self.status = status_code
        self.code = status_code

    def read(self):
        return self.data

    def getheaders(self):
        return [("content-type", "application/json")]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class TestPRLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

        save_user_github_config(
            user_id="default_user",
            token="ghp_test_token_abcdef1234567890",
            username="testdeveloper",
            mode="live"
        )

        res = cls.client.post("/api/projects", json={
            "name": "PR Lifecycle Security Audit",
            "description": "Integration testing for Tracegate PR and Merge workflow",
            "target_url": "https://pr-test.local"
        })
        assert res.status_code in (200, 201)
        cls.project_id = res.json()["id"]

    def setUp(self):
        for uid in ["default_user", "usr-learner-001"]:
            save_user_github_config(
                user_id=uid,
                token="ghp_test_token_abcdef1234567890",
                username="testdeveloper",
                mode="live"
            )

        self.finding = save_finding(self.project_id, None, {
            "finding_name": "SQL Injection in User Authentication",
            "vuln_id": "VULN-PR-001",
            "priority": "HIGH",
            "cwe": "CWE-89",
            "affected_component": "api/v1/login.py",
            "observation": "Tester observed raw query formatting without parameterized variables.",
            "description": "Unsanitized user input concatenated into database query.",
            "remediation": "Use parameterized prepared statements.",
            "fix_status": "Fix Applied"
        })
        self.finding_id = self.finding["id"]

    @classmethod
    def tearDownClass(cls):
        delete_project(cls.project_id)
        for uid in ["default_user", "usr-learner-001"]:
            save_user_github_config(user_id=uid, token=None, mode="mock", username=None)

    @patch("backend.github_service.urllib.request.urlopen")
    def test_01_create_pr_uses_real_github_url_and_verifies(self, mock_urlopen):
        """Verify PR creation uses GitHub's verified html_url and does not use mock #101 formulas."""
        repo = "testdeveloper/sql-vulnerable-code"
        fix_branch = "tracegate/fix/VULN-PR-001"
        real_pr_number = 77
        real_pr_url = f"https://github.com/{repo}/pull/{real_pr_number}"

        def side_effect(req, *args, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if f"/branches/{fix_branch}" in url:
                return MockHTTPResponse({"name": fix_branch, "commit": {"sha": "sha_fix_123"}})
            elif "/pulls?" in url or url.endswith("/pulls"):
                if req.get_method() == "GET":
                    # Check for existing PR: none found
                    return MockHTTPResponse([])
                elif req.get_method() == "POST":
                    # PR creation POST
                    return MockHTTPResponse({
                        "number": real_pr_number,
                        "html_url": real_pr_url,
                        "head": {"ref": fix_branch, "sha": "sha_fix_123"},
                        "base": {"ref": "main", "sha": "sha_base_000"},
                        "state": "open",
                        "title": "fix(security): remediate VULN-PR-001",
                        "body": "Remediation PR"
                    }, 201)
            elif f"/pulls/{real_pr_number}" in url:
                # PR verification GET
                return MockHTTPResponse({
                    "number": real_pr_number,
                    "html_url": real_pr_url,
                    "head": {"ref": fix_branch, "sha": "sha_fix_123"},
                    "base": {"ref": "main", "sha": "sha_base_000"},
                    "state": "open"
                }, 200)
            return MockHTTPResponse({})

        mock_urlopen.side_effect = side_effect

        res = create_finding_pull_request(
            user_id="default_user",
            repo=repo,
            fix_branch=fix_branch,
            base_branch="main",
            title="fix(security): remediate VULN-PR-001",
            body="Tracegate Security Patch",
            finding=self.finding
        )

        self.assertEqual(res.pr_number, real_pr_number)
        self.assertEqual(res.pr_url, real_pr_url)
        self.assertNotIn("101", str(res.pr_number))
        self.assertNotIn("/issues/", res.pr_url)
        self.assertEqual(res.head_branch, fix_branch)
        self.assertEqual(res.base_branch, "main")

    @patch("backend.github_service.urllib.request.urlopen")
    def test_02_create_pr_idempotent_reuses_existing_open_pr(self, mock_urlopen):
        """Verify that when a PR already exists for the fix branch, it reuses the open PR instead of failing with 422."""
        repo = "testdeveloper/sql-vulnerable-code"
        fix_branch = "tracegate/fix/VULN-PR-001"
        existing_pr_number = 33
        existing_pr_url = f"https://github.com/{repo}/pull/{existing_pr_number}"

        def side_effect(req, *args, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if f"/branches/{fix_branch}" in url:
                return MockHTTPResponse({"name": fix_branch, "commit": {"sha": "sha_fix_123"}})
            elif "/pulls?" in url:
                # Existing open PR query returns existing PR
                return MockHTTPResponse([{
                    "number": existing_pr_number,
                    "html_url": existing_pr_url,
                    "head": {"ref": fix_branch, "sha": "sha_fix_123"},
                    "base": {"ref": "main", "sha": "sha_base_000"},
                    "state": "open",
                    "title": "fix(security): existing PR"
                }])
            return MockHTTPResponse({})

        mock_urlopen.side_effect = side_effect

        res = create_finding_pull_request(
            user_id="default_user",
            repo=repo,
            fix_branch=fix_branch,
            base_branch="main",
            title="fix(security): retry PR",
            body="Retry PR",
            finding=self.finding
        )

        self.assertEqual(res.pr_number, existing_pr_number)
        self.assertEqual(res.pr_url, existing_pr_url)

    @patch("backend.github_service.urllib.request.urlopen")
    def test_03_get_pull_request_status_and_reviews(self, mock_urlopen):
        """Verify PR status retrieval includes real state, mergeable check, and aggregated reviews."""
        repo = "testdeveloper/sql-vulnerable-code"
        pr_number = 42

        def side_effect(req, *args, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if f"/pulls/{pr_number}/reviews" in url:
                return MockHTTPResponse([
                    {"state": "APPROVED", "submitted_at": "2026-09-08T18:00:00Z", "user": {"login": "senior-secops"}}
                ])
            elif f"/pulls/{pr_number}" in url:
                return MockHTTPResponse({
                    "number": pr_number,
                    "html_url": f"https://github.com/{repo}/pull/{pr_number}",
                    "state": "open",
                    "merged": False,
                    "mergeable": True,
                    "mergeable_state": "clean",
                    "head": {"ref": "fix/branch", "sha": "sha_head"},
                    "base": {"ref": "main", "sha": "sha_base"}
                })
            return MockHTTPResponse({})

        mock_urlopen.side_effect = side_effect

        status = get_pull_request_status("default_user", repo, pr_number)
        self.assertEqual(status["pr_number"], pr_number)
        self.assertEqual(status["state"], "open")
        self.assertFalse(status["merged"])
        self.assertTrue(status["mergeable"])
        self.assertEqual(status["review_status"], "APPROVED")
        self.assertEqual(len(status["reviews"]), 1)

    @patch("backend.github_service.urllib.request.urlopen")
    def test_04_merge_pull_request_and_verify_lifecycle_state(self, mock_urlopen):
        """Verify merge execution succeeds, verifies on GitHub, and NEVER marks finding as RESOLVED directly."""
        repo = "testdeveloper/sql-vulnerable-code"
        pr_number = 42
        merge_commit = "merge_commit_sha_9999"

        call_count = {"merge_put": 0}

        def side_effect(req, *args, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            method = req.get_method() if hasattr(req, "get_method") else "GET"

            if f"/pulls/{pr_number}/merge" in url and method == "PUT":
                call_count["merge_put"] += 1
                return MockHTTPResponse({"sha": merge_commit, "merged": True, "message": "Pull Request successfully merged"})
            elif f"/pulls/{pr_number}" in url:
                # Pre-merge check (merged=False) or post-merge verification (merged=True)
                merged = call_count["merge_put"] > 0
                return MockHTTPResponse({
                    "number": pr_number,
                    "html_url": f"https://github.com/{repo}/pull/{pr_number}",
                    "state": "closed" if merged else "open",
                    "merged": merged,
                    "merged_at": "2026-09-08 19:15:00" if merged else None,
                    "merge_commit_sha": merge_commit if merged else None,
                    "mergeable": True,
                    "mergeable_state": "clean"
                })
            return MockHTTPResponse({})

        mock_urlopen.side_effect = side_effect

        # Call FastAPI endpoint
        res = self.client.post("/api/ai-fix/pr/merge", json={
            "finding_id": self.finding_id,
            "repo": repo,
            "pr_number": pr_number
        })

        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertTrue(data["merged"])
        self.assertEqual(data["merge_commit_sha"], merge_commit)

        # Verify finding lifecycle: MUST be 'Code Merged (Retest Required)', NEVER 'RESOLVED'
        updated_finding = get_finding_by_id(self.finding_id)
        self.assertEqual(updated_finding["fix_status"], "Code Merged (Retest Required)")
        self.assertNotEqual(updated_finding.get("status"), "RESOLVED")

    def test_05_retest_verification_transitions_to_resolved(self):
        """Verify that human tester retest verification PASS is required to mark finding as RESOLVED."""
        res = self.client.post(f"/api/ai-fix/{self.finding_id}/retest", json={
            "finding_id": self.finding_id,
            "result": "PASS",
            "notes": "Verified login with SQL payload ' OR 1=1 --. Returned 401 Unauthorized as expected."
        })

        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn(data["result"], ["PASS", "PASSED"])
        self.assertEqual(data["status"], "RESOLVED")
        self.assertEqual(data["retest_status"], "PASSED")

        updated_finding = get_finding_by_id(self.finding_id)
        self.assertEqual(updated_finding["status"], "RESOLVED")

    def test_06_sha_conflict_blocks_commit(self):
        """Verify that applying fix when source file SHA is stale returns 409 SOURCE_CHANGED conflict."""
        res = self.client.post("/api/ai-fix/apply", json={
            "finding_id": self.finding_id,
            "repo": "tracegate-lab/ecommerce-platform",
            "target_branch": "main",
            "fix_branch": "tracegate/fix/VULN-PR-001",
            "file_path": "api/v1/login.py",
            "file_sha": "stale_sha",
            "diff_or_fixed_code": "# fixed code"
        })
        self.assertEqual(res.status_code, 409)
        self.assertIn("SOURCE_CHANGED", str(res.json()))

    def test_07_reject_proposal_records_audit_event(self):
        """Verify that developer rejecting a fix proposal marks status REJECTED and preserves audit event without GitHub writes."""
        res = self.client.post("/api/ai-fix/reject", json={
            "finding_id": self.finding_id,
            "repo": "testdeveloper/sql-vulnerable-code",
            "branch": "main",
            "reason": "Security architect requested stored procedure approach instead of parameterized query."
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "REJECTED")

        # Check finding status in database
        updated_finding = get_finding_by_id(self.finding_id)
        self.assertEqual(updated_finding["fix_status"], "Fix Rejected")

        # Check latest ai_fix record
        latest_fix = get_ai_fix_for_finding(self.finding_id)
        self.assertIsNotNone(latest_fix)
        self.assertEqual(latest_fix["status"], "REJECTED")
        self.assertIn("stored procedure", latest_fix["explanation"])

    def test_08_revision_preserves_immutable_proposal_history(self):
        """Verify requesting revision creates a new proposal record with incremented count and updates previous proposal."""
        # 1. Analyze code to generate initial proposal (rev 0)
        res_analyze = self.client.post("/api/ai-fix/analyze", json={
            "finding_id": self.finding_id,
            "repo": "testdeveloper/sql-vulnerable-code",
            "branch": "main",
            "file_path": "api/v1/login.py",
            "code_snippet": "query = f'SELECT * FROM users WHERE user={user}'"
        })
        self.assertEqual(res_analyze.status_code, 200)

        initial_fix = get_ai_fix_for_finding(self.finding_id)
        self.assertIsNotNone(initial_fix)
        self.assertEqual(initial_fix["status"], "FIX_PROPOSED")
        self.assertEqual(initial_fix["revision_count"], 0)
        initial_fix_id = initial_fix["id"]

        # 2. Revise fix proposal (rev 1)
        res_revise = self.client.post("/api/ai-fix/revise", json={
            "finding_id": self.finding_id,
            "repo": "testdeveloper/sql-vulnerable-code",
            "branch": "main",
            "file_path": "api/v1/login.py",
            "developer_instructions": "Ensure strict type checking and custom exception handling"
        })
        self.assertEqual(res_revise.status_code, 200)
        self.assertEqual(res_revise.json()["revision_count"], 1)

        # 3. Check DB records
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, status, revision_count FROM ai_fixes WHERE finding_id = ? ORDER BY created_at ASC", (self.finding_id,))
        records = [dict(r) for r in cursor.fetchall()]
        conn.close()

        # We should see the initial record marked REVISION_REQUESTED and new record as FIX_PROPOSED (rev 1)
        rev_req = [r for r in records if r["id"] == initial_fix_id]
        self.assertEqual(len(rev_req), 1)
        self.assertEqual(rev_req[0]["status"], "REVISION_REQUESTED")

        latest_fix = get_ai_fix_for_finding(self.finding_id)
        self.assertEqual(latest_fix["revision_count"], 1)
        self.assertEqual(latest_fix["status"], "FIX_PROPOSED")

