import os
import sys
import unittest
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import init_db, save_finding
from backend.github_service import MOCK_REPO_FILES, get_file_contents
from backend.ai_autofix import (
    is_comment_or_whitespace_only,
    validate_syntax,
    validate_patch_exact_diff,
    generate_secure_fix,
    analyze_root_cause,
    generate_semantic_patch,
)

class TestRealRemediationEngine(unittest.TestCase):
    """
    Authoritative test suite verifying Tracegate's real code remediation engine:
    - Zero tolerance for comment-only, whitespace-only, or dummy patches.
    - Verified semantic AST-valid modifications across all 8 security vulnerability types.
    - Proper rejection of invalid syntax or unaddressed security properties.
    """

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def test_01_comment_only_patch_rejected(self):
        """Zero tolerance: patches that only add comments must be rejected."""
        orig = (
            "def login(user, password):\n"
            "    query = f\"SELECT * FROM users WHERE u='{user}' AND p='{password}'\"\n"
            "    return db.execute(query)\n"
        )
        # Bug case reported by user: comment added at top or inline
        comment_patch_1 = (
            "# Remediated: Defensive security controls applied for VULN-001 (CWE-287)\n"
            + orig
        )
        comment_patch_2 = (
            "def login(user, password):\n"
            "    # Fixed SQL injection vulnerability\n"
            "    query = f\"SELECT * FROM users WHERE u='{user}' AND p='{password}'\"\n"
            "    return db.execute(query)\n"
        )
        comment_patch_3 = (
            "def login(user, password):\n"
            "    query = f\"SELECT * FROM users WHERE u='{user}' AND p='{password}'\" # security controls applied\n"
            "    return db.execute(query)\n"
        )

        self.assertTrue(is_comment_or_whitespace_only(orig, comment_patch_1, "login.py"))
        self.assertTrue(is_comment_or_whitespace_only(orig, comment_patch_2, "login.py"))
        self.assertTrue(is_comment_or_whitespace_only(orig, comment_patch_3, "login.py"))

        # Verify exact diff validator rejects comment-only patches
        finding = {
            "vuln_id": "VULN-001",
            "cwe": "CWE-89",
            "finding_name": "SQL Injection"
        }
        root_cause = {"security_property_missing": "Missing parameter binding"}
        is_valid1, reason1, score1 = validate_patch_exact_diff(orig, comment_patch_1, finding, root_cause, file_path="login.py")
        self.assertFalse(is_valid1)
        self.assertIn("does not modify the vulnerable logic", reason1)

        is_valid2, reason2, score2 = validate_patch_exact_diff(orig, comment_patch_2, finding, root_cause, file_path="login.py")
        self.assertFalse(is_valid2)

    def test_02_whitespace_only_patch_rejected(self):
        """Patches that only alter indentation or trailing whitespace must be rejected."""
        orig = "def auth(x):\n    return x == 'secret'\n"
        ws_patch = "def auth(x):\n\n    return x == 'secret'  \n"
        self.assertTrue(is_comment_or_whitespace_only(orig, ws_patch, "auth.py"))

        finding = {"vuln_id": "VULN-001", "cwe": "CWE-287"}
        root_cause = {"security_property_missing": "Property"}
        is_valid, reason, score = validate_patch_exact_diff(orig, ws_patch, finding, root_cause, file_path="auth.py")
        self.assertFalse(is_valid)

    def test_03_syntax_validation(self):
        """Invalid syntax in Python AST or unbalanced JS delimiters must fail validation."""
        valid_py = "def add(a, b):\n    return a + b\n"
        invalid_py = "def add(a, b)\n    return a + b\n"  # missing colon
        ok_py, _ = validate_syntax(valid_py, "test.py")
        self.assertTrue(ok_py)
        bad_py, _ = validate_syntax(invalid_py, "test.py")
        self.assertFalse(bad_py)

        valid_js = "function test() { if (true) { return 1; } }"
        invalid_js = "function test() { if (true) { return 1; }"  # unbalanced brace
        ok_js, _ = validate_syntax(valid_js, "test.js")
        self.assertTrue(ok_js)
        bad_js, _ = validate_syntax(invalid_js, "test.js")
        self.assertFalse(bad_js)

    def test_04_remediation_vuln_001_sqli(self):
        """VULN-001: SQL Injection (CWE-287 / CWE-89) must replace f-string with parameterized query."""
        src = MOCK_REPO_FILES["tracegate-lab/ecommerce-platform"]["sqlinjection.py"]
        finding = {
            "vuln_id": "VULN-001",
            "cwe": "CWE-287",
            "finding_name": "SQL Injection Authentication Bypass in get_user_by_username",
            "affected_component": "sqlinjection.py"
        }
        res = generate_secure_fix(finding, "tracegate-lab/ecommerce-platform", "main", "sqlinjection.py", src)
        self.assertTrue(res["success"], f"VULN-001 failed: {res.get('reason')}")
        self.assertIn(":username", res["after_code"])
        self.assertNotIn("f\"SELECT id, username, role FROM users WHERE username = '{username}'", res["after_code"])
        self.assertEqual(res["validation"]["syntax"], "PASSED")
        self.assertEqual(res["validation"]["tests"], "PASSED")
        self.assertEqual(res["validation"]["security_regression"], "PASSED")

    def test_05_remediation_vuln_002_caching_autocomplete(self):
        """VULN-002: Form Autocomplete (CWE-524) must set autocomplete='off'."""
        src = MOCK_REPO_FILES["tracegate-lab/ecommerce-platform"]["templates/login.html"]
        finding = {
            "vuln_id": "VULN-002",
            "cwe": "CWE-524",
            "finding_name": "Credential Caching and Form Autocomplete Enabled on Login",
            "affected_component": "templates/login.html"
        }
        res = generate_secure_fix(finding, "tracegate-lab/ecommerce-platform", "main", "templates/login.html", src)
        self.assertTrue(res["success"], f"VULN-002 failed: {res.get('reason')}")
        self.assertIn('autocomplete="off"', res["after_code"])
        self.assertNotIn('autocomplete="on"', res["after_code"])
        self.assertEqual(res["validation"]["syntax"], "PASSED")

    def test_06_remediation_vuln_003_2fa_bypass(self):
        """VULN-003: 2FA Bypass (CWE-288) must gate full session until 2FA token verified."""
        src = MOCK_REPO_FILES["tracegate-lab/ecommerce-platform"]["backend/controllers/authController.py"]
        finding = {
            "vuln_id": "VULN-003",
            "cwe": "CWE-288",
            "finding_name": "Two-Factor Authentication (2FA) Bypass in Login Workflow",
            "affected_component": "backend/controllers/authController.py"
        }
        res = generate_secure_fix(finding, "tracegate-lab/ecommerce-platform", "main", "backend/controllers/authController.py", src)
        self.assertTrue(res["success"], f"VULN-003 failed: {res.get('reason')}")
        self.assertIn("pending_2fa_user_id", res["after_code"])
        self.assertEqual(res["validation"]["syntax"], "PASSED")

    def test_07_remediation_vuln_004_username_enumeration(self):
        """VULN-004: Username Enumeration (CWE-204) must provide generic authentication failure."""
        src = MOCK_REPO_FILES["tracegate-lab/ecommerce-platform"]["backend/controllers/authController.py"]
        finding = {
            "vuln_id": "VULN-004",
            "cwe": "CWE-204",
            "finding_name": "Username Enumeration via Differentiated Authentication Responses",
            "affected_component": "backend/controllers/authController.py"
        }
        res = generate_secure_fix(finding, "tracegate-lab/ecommerce-platform", "main", "backend/controllers/authController.py", src)
        self.assertTrue(res["success"], f"VULN-004 failed: {res.get('reason')}")
        self.assertIn("Invalid username or password", res["after_code"])
        self.assertNotIn("User not found", res["after_code"])
        self.assertEqual(res["validation"]["syntax"], "PASSED")

    def test_08_remediation_vuln_005_svg_xss(self):
        """VULN-005: Stored XSS via SVG (CWE-79) must strip scripts and enforce CSP header."""
        src = MOCK_REPO_FILES["tracegate-lab/ecommerce-platform"]["backend/controllers/svgController.py"]
        finding = {
            "vuln_id": "VULN-005",
            "cwe": "CWE-79",
            "finding_name": "Stored XSS via Malicious SVG Image Upload",
            "affected_component": "backend/controllers/svgController.py"
        }
        res = generate_secure_fix(finding, "tracegate-lab/ecommerce-platform", "main", "backend/controllers/svgController.py", src)
        self.assertTrue(res["success"], f"VULN-005 failed: {res.get('reason')}")
        self.assertIn("Content-Security-Policy", res["after_code"])
        self.assertIn("clean_svg", res["after_code"])
        self.assertEqual(res["validation"]["syntax"], "PASSED")

    def test_09_remediation_vuln_006_path_traversal(self):
        """VULN-006: Path Traversal (CWE-22) must resolve paths and verify directory containment."""
        src = MOCK_REPO_FILES["tracegate-lab/ecommerce-platform"]["backend/controllers/uploadController.py"]
        finding = {
            "vuln_id": "VULN-006",
            "cwe": "CWE-22",
            "finding_name": "Path Traversal & Destination Storage Directory Escapes",
            "affected_component": "backend/controllers/uploadController.py"
        }
        res = generate_secure_fix(finding, "tracegate-lab/ecommerce-platform", "main", "backend/controllers/uploadController.py", src)
        self.assertTrue(res["success"], f"VULN-006 failed: {res.get('reason')}")
        self.assertIn("candidate.parents", res["after_code"])
        self.assertEqual(res["validation"]["syntax"], "PASSED")

    def test_10_remediation_vuln_007_file_upload(self):
        """VULN-007: Unrestricted File Upload (CWE-434) must check ALLOWED_EXTENSIONS and use UUID."""
        src = MOCK_REPO_FILES["tracegate-lab/ecommerce-platform"]["backend/controllers/uploadController.py"]
        finding = {
            "vuln_id": "VULN-007",
            "cwe": "CWE-434",
            "finding_name": "Arbitrary File Upload via Unrestricted Extension Validation",
            "affected_component": "backend/controllers/uploadController.py"
        }
        res = generate_secure_fix(finding, "tracegate-lab/ecommerce-platform", "main", "backend/controllers/uploadController.py", src)
        self.assertTrue(res["success"], f"VULN-007 failed: {res.get('reason')}")
        self.assertIn("ALLOWED_EXTENSIONS", res["after_code"])
        self.assertIn("uuid", res["after_code"])
        self.assertEqual(res["validation"]["syntax"], "PASSED")

    def test_11_remediation_vuln_008_idor(self):
        """VULN-008: IDOR (CWE-639) must verify authenticated user session ownership."""
        src = MOCK_REPO_FILES["tracegate-lab/ecommerce-platform"]["server/controllers/userController.js"]
        finding = {
            "vuln_id": "VULN-008",
            "cwe": "CWE-639",
            "finding_name": "Insecure Direct Object References (IDOR) on Profile Update",
            "affected_component": "server/controllers/userController.js"
        }
        res = generate_secure_fix(finding, "tracegate-lab/ecommerce-platform", "main", "server/controllers/userController.js", src)
        self.assertTrue(res["success"], f"VULN-008 failed: {res.get('reason')}")
        self.assertIn("req.user.id !== targetUserId", res["after_code"])
        self.assertEqual(res["validation"]["syntax"], "PASSED")

    def test_12_apply_endpoint_rejects_comment_only_patch(self):
        """API /api/ai-fix/apply must reject comment-only patches with HTTP 400."""
        orig_file = get_file_contents("test-usr", "tracegate-lab/ecommerce-platform", "main", "sqlinjection.py")
        orig_content = orig_file["content"]

        comment_patch = "# Remediated: Applied controls for VULN-001\n" + orig_content

        res = self.client.post("/api/ai-fix/apply", json={
            "finding_id": "VULN-001",
            "file_path": "sqlinjection.py",
            "proposed_code": comment_patch,
            "repo": "tracegate-lab/ecommerce-platform",
            "base_branch": "main"
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("does not modify the vulnerable logic", res.json()["detail"])

if __name__ == "__main__":
    unittest.main()
