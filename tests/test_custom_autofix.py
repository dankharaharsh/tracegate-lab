import os
import sys
import unittest
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import init_db, create_project, save_finding
from backend.ai_autofix import generate_secure_fix, remediate_custom_source_code
from backend.github_service import get_file_contents, commit_file_change, create_fix_branch, create_finding_pull_request

class TestCustomRemediationSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

        # Create test project
        res = cls.client.post("/api/projects", json={
            "name": "Custom Repo & Code Remediation Test",
            "description": "Testing custom repository and surgical code remediation",
            "target_url": "https://test.local"
        })
        assert res.status_code in (200, 201)
        cls.project_id = res.json()["id"]

        cls.finding = save_finding(cls.project_id, None, {
            "finding_name": "SQL Injection in User Authentication",
            "cwe": "CWE-89",
            "cwe_id": "CWE-89",
            "severity": "CRITICAL",
            "priority": "P1",
            "affected_component": "sqlinjection.py",
            "affected_endpoint": "/api/v1/auth/login",
            "status": "CONFIRMED",
            "poc_text": "' OR '1'='1"
        })

    def test_01_surgical_remediation_of_sqlinjection_py(self):
        user_code = (
            "import sqlite3\n\n"
            "def get_user_by_username(username: str, password_hash: str):\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    cursor = conn.cursor()\n"
            "    # Vulnerable SQL query using string formatting\n"
            "    query = f\"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password_hash}'\"\n"
            "    cursor.execute(query)\n"
            "    user = cursor.fetchone()\n"
            "    conn.close()\n"
            "    return user\n"
        )

        fix_result = generate_secure_fix(
            finding=self.finding,
            repo="my-org/custom-target-repo",
            branch="main",
            file_path="sqlinjection.py",
            source_code=user_code
        )

        proposed = fix_result["after_code"]

        # Verify surrounding code is preserved
        self.assertIn("def get_user_by_username(username: str, password_hash: str):", proposed)
        self.assertIn("conn = sqlite3.connect('app.db')", proposed)
        self.assertIn("user = cursor.fetchone()", proposed)
        self.assertIn("return user", proposed)

        # Verify query was parameterized
        self.assertIn("SELECT id, username, role FROM users WHERE username = :username AND password = :password_hash", proposed)
        self.assertIn('cursor.execute(query, {"username": username, "password_hash": password_hash})', proposed)

        # Verify diff is clean and minimal
        diff = fix_result["diff_unified"]
        self.assertIn("-    query = f", diff)
        self.assertIn("+    query = \"SELECT id, username, role FROM users WHERE username = :username AND password = :password_hash\"", diff)

    def test_02_custom_repo_transmitted_in_analyze(self):
        custom_repo = "developer-xyz/secure-app"
        res = self.client.post("/api/ai-fix/analyze", json={
            "repo": custom_repo,
            "branch": "main",
            "finding_id": self.finding["id"],
            "file_path": "sqlinjection.py"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["repo"], custom_repo)
        self.assertIn(":username", data["after_code"])

    def test_03_custom_repo_preserved_in_apply(self):
        custom_repo = "developer-xyz/secure-app"
        fixed_code = "def secure(): pass"
        res = self.client.post("/api/ai-fix/apply", json={
            "repo": custom_repo,
            "target_branch": "main",
            "finding_id": self.finding["id"],
            "file_path": "sqlinjection.py",
            "diff_or_fixed_code": fixed_code,
            "commit_message": "fix(security): sanitize user query"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("tracegate/fix/", data["branch_name"])

    def test_04_custom_repo_preserved_in_create_pr(self):
        custom_repo = "developer-xyz/secure-app"
        res = self.client.post("/api/ai-fix/create-pr", json={
            "repo": custom_repo,
            "fix_branch": "tracegate/fix/VULN-001",
            "base_branch": "main",
            "finding_id": self.finding["id"],
            "title": "fix(security): resolve SQL injection in sqlinjection.py",
            "body": "Remediation PR"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("github.com/developer-xyz/secure-app/pull/", data["pr_url"])

if __name__ == "__main__":
    unittest.main()
