import difflib
import os
import sys
import unittest
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import (
    init_db,
    save_finding,
    save_source_discovery,
    get_source_discovery,
    update_source_discovery_selection
)
from backend.github_service import MOCK_REPO_FILES, get_file_contents, apply_finding_fix
from backend.ai_autofix import (
    discover_repository_sources,
    generate_secure_fix,
    generate_multi_file_secure_fix,
    is_comment_or_whitespace_only,
    validate_syntax,
    tokenize_name,
    classify_source_layer,
    detect_source_language
)
from backend.schemas import DiscoveredSourceItem

class TestPhase1Phase2Suite(unittest.TestCase):
    """
    Comprehensive test suite verifying:
    - Phase 1 Completion: Multi-file source selection, deterministic route/param-first discovery,
      relegation of presentation templates for server-side flaws, NO_MATCH handling, and SQLite persistence.
    - Phase 2: Real multi-file patch generation, real Before baseline code, real After derived code,
      programmatic unified diff, rejection of placeholder/comment patches, and patch status validation.
    """

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.repo = "tracegate-lab/ecommerce-platform"
        cls.branch = "main"

    def test_01_2fa_source_discovery_selects_auth_controller_and_penalizes_template(self):
        """Test Part L 60: 2FA bypass selects backend controller with HIGH confidence,
        penalizes templates/2fa.html to candidate list with LOW confidence."""
        finding = {
            "id": "FIND-2FA-001",
            "finding_name": "2FA Authentication Bypass",
            "title": "2FA Authentication Bypass",
            "affected_endpoint": "/api/v1/auth/2fa",
            "endpoint": "/api/v1/auth/2fa",
            "affected_component": "AuthController",
            "cwe": "CWE-287",
            "description": "Two-factor authentication can be bypassed by manipulating the OTP verification parameter."
        }

        result = discover_repository_sources(finding, self.repo, self.branch)
        self.assertIn(result["discovery_status"], ["HIGH_CONFIDENCE_MATCH", "MATCH_FOUND", "COMPLETED"])

        selected_paths = [s["path"] for s in result["selected_sources"]]
        candidate_paths = [c["path"] for c in result["candidate_sources"]]

        # authController.py MUST be selected with HIGH confidence
        self.assertIn("backend/controllers/authController.py", selected_paths)
        auth_source = next(s for s in result["selected_sources"] if s["path"] == "backend/controllers/authController.py")
        self.assertEqual(auth_source["confidence"], "HIGH")
        self.assertGreaterEqual(auth_source["relevance_score"], 70)
        self.assertEqual(auth_source["layer"].lower(), "controller")

        # templates/2fa.html MUST NOT be in selected_sources (never auto-selected for server-side flaws)
        self.assertNotIn("templates/2fa.html", selected_paths)
        # It must be relegated to candidates with LOW confidence and template reason
        if "templates/2fa.html" in candidate_paths:
            template_cand = next(c for c in result["candidate_sources"] if c["path"] == "templates/2fa.html")
            self.assertEqual(template_cand["confidence"], "LOW")
            self.assertLess(template_cand["relevance_score"], 50)
            self.assertTrue(any("template" in r.lower() for r in template_cand["reasons"]))

    def test_02_idor_source_discovery_selects_profile_controller(self):
        """Test Part L 61: IDOR finding discovers actual access logic in profileController.py."""
        finding = {
            "id": "FIND-IDOR-002",
            "finding_name": "Insecure Direct Object Reference in User Profile",
            "affected_endpoint": "/api/v1/user/profile/{id}",
            "parameter": "user_id",
            "affected_component": "ProfileController",
            "cwe": "CWE-639",
            "description": "User ID parameter can be modified to access other users' profile records."
        }

        result = discover_repository_sources(finding, self.repo, self.branch)
        selected_paths = [s["path"] for s in result["selected_sources"]]
        self.assertIn("backend/controllers/profileController.py", selected_paths)

        profile_source = next(s for s in result["selected_sources"] if s["path"] == "backend/controllers/profileController.py")
        self.assertEqual(profile_source["layer"].lower(), "controller")
        self.assertIn(profile_source["confidence"], ["HIGH", "MEDIUM"])

    def test_03_file_upload_source_discovery_selects_upload_controller(self):
        """Test Part L 62: Unrestricted file upload finding discovers uploadController.py."""
        finding = {
            "id": "FIND-UPL-003",
            "finding_name": "Unrestricted File Upload Leading to RCE",
            "affected_endpoint": "/api/v1/upload/avatar",
            "parameter": "avatar",
            "affected_component": "UploadController",
            "cwe": "CWE-434",
            "description": "Arbitrary file extensions can be uploaded without MIME-type or extension validation."
        }

        result = discover_repository_sources(finding, self.repo, self.branch)
        selected_paths = [s["path"] for s in result["selected_sources"]]
        self.assertIn("backend/controllers/uploadController.py", selected_paths)

    def test_04_stored_xss_source_discovery_selects_svg_controller(self):
        """Test Part L 63: Stored XSS in SVG finding discovers svgController.py."""
        finding = {
            "id": "FIND-XSS-004",
            "finding_name": "Stored Cross-Site Scripting via Profile SVG Avatar",
            "affected_endpoint": "/api/v1/avatar/svg",
            "parameter": "svg_data",
            "affected_component": "SvgController",
            "cwe": "CWE-79",
            "description": "Uploaded SVG avatars allow execution of inline JavaScript in victim browsers."
        }

        result = discover_repository_sources(finding, self.repo, self.branch)
        selected_paths = [s["path"] for s in result["selected_sources"]]
        self.assertIn("backend/controllers/svgController.py", selected_paths)

    def test_05_unknown_finding_returns_no_match(self):
        """Test Part L 72: Finding unrelated to repo produces NO_MATCH without false random selections."""
        finding = {
            "id": "FIND-UNKNOWN-005",
            "finding_name": "Quantum Entanglement Vulnerability in Blockchain Subsystem",
            "affected_endpoint": "/blockchain/quantum/hash",
            "parameter": "qubit_spin",
            "cwe": "CWE-999",
            "description": "Zero knowledge qubit entanglement error in decentralized ledger."
        }

        result = discover_repository_sources(finding, self.repo, self.branch)
        self.assertEqual(result["discovery_status"], "NO_MATCH")
        self.assertEqual(len(result["selected_sources"]), 0)

    def test_06_manual_multi_file_selection_toggle_and_persistence(self):
        """Test Part L 65: Multiple files can be selected, saved, individual files removed,
        persisted across API calls, and selection mode becomes USER_MODIFIED."""
        finding_id = "FIND-MANUAL-006"
        initial_paths = [
            "backend/controllers/authController.py",
            "backend/controllers/profileController.py",
            "backend/controllers/uploadController.py"
        ]

        # 1. Save 3 files via API
        resp = self.client.post("/api/ai-fix/selected-sources", json={
            "finding_id": finding_id,
            "repo": self.repo,
            "selected_paths": initial_paths,
            "manual_additions": [],
            "manual_removals": []
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["selection_mode"], "USER_MODIFIED")
        self.assertEqual(len(data["selected_sources"]), 3)

        # 2. Retrieve via GET API and verify all 3 persist
        get_resp = self.client.get(f"/api/ai-fix/selected-sources?finding_id={finding_id}&repo={self.repo}")
        self.assertEqual(get_resp.status_code, 200)
        get_data = get_resp.json()
        saved_paths = [s["path"] for s in get_data["selected_sources"]]
        self.assertEqual(saved_paths, initial_paths)

        # 3. Remove 1 file ("uploadController.py") and verify 2 persist
        reduced_paths = [
            "backend/controllers/authController.py",
            "backend/controllers/profileController.py"
        ]
        resp_del = self.client.post("/api/ai-fix/selected-sources", json={
            "finding_id": finding_id,
            "repo": self.repo,
            "selected_paths": reduced_paths,
            "manual_additions": [],
            "manual_removals": ["backend/controllers/uploadController.py"]
        })
        self.assertEqual(resp_del.status_code, 200)
        data_del = resp_del.json()
        self.assertEqual(len(data_del["selected_sources"]), 2)
        self.assertEqual([s["path"] for s in data_del["selected_sources"]], reduced_paths)

    def test_07_multi_file_patch_generation_produces_real_before_after_diff(self):
        """Test Part L 64, 66, 67, 68: Multi-file patch produces real Before from GitHub,
        derived After, and exact programmatic diff for each file."""
        finding = {
            "id": "FIND-MULTI-007",
            "finding_name": "Missing Server-Side Session Validation and 2FA Control",
            "affected_endpoint": "/api/v1/auth/2fa",
            "affected_component": "AuthController",
            "cwe": "CWE-287",
            "description": "Multi-layer flaw requiring server-side session checks and rate-limiting."
        }
        selected_files = [
            "backend/controllers/authController.py",
            "backend/controllers/userController.js"
        ]

        result = generate_multi_file_secure_fix(
            finding=finding,
            repo=self.repo,
            branch=self.branch,
            selected_files=selected_files,
            developer_instructions="Ensure robust validation."
        )

        self.assertEqual(result["patch_status"], "PATCH_VALIDATED")
        self.assertGreaterEqual(len(result["files"]), 1)

        # Check the primary patched file item
        patch_item = result["files"][0]
        self.assertTrue(patch_item["path"] in selected_files)
        self.assertTrue(len(patch_item["before_code"]) > 0)
        self.assertTrue(len(patch_item["after_code"]) > 0)
        self.assertNotEqual(patch_item["before_code"], patch_item["after_code"])
        self.assertTrue(len(patch_item["diff_unified"]) > 0)

        # Exact Programmatic Diff Verification: difflib.unified_diff(before, after) == diff_unified
        expected_diff_lines = list(difflib.unified_diff(
            patch_item["before_code"].splitlines(keepends=True),
            patch_item["after_code"].splitlines(keepends=True),
            fromfile=f"a/{patch_item['path']}",
            tofile=f"b/{patch_item['path']}"
        ))
        expected_diff = "".join(expected_diff_lines).strip()
        self.assertEqual(patch_item["diff_unified"].strip(), expected_diff)

    def test_08_comment_only_patch_rejected(self):
        """Test Part L 70: Patches that only add comments are strictly rejected as PATCH_REJECTED."""
        orig_code = (
            "def verify_token(token):\n"
            "    return True\n"
        )
        cosmetic_patch = (
            "# security fix applied\n"
            "def verify_token(token):\n"
            "    return True\n"
        )
        is_comment = is_comment_or_whitespace_only(orig_code, cosmetic_patch, "auth.py")
        self.assertTrue(is_comment, "Cosmetic comment patch must be detected as comment-only")

    def test_09_placeholder_patch_rejected(self):
        """Test Part L 70: Patches with dummy placeholder `# security fix applied` or pass are rejected."""
        orig_code = "def authenticate():\n    return False\n"
        placeholder_patch = "def authenticate():\n    # security fix applied\n    pass\n    return False\n"
        is_dummy = is_comment_or_whitespace_only(orig_code, placeholder_patch, "auth.py")
        self.assertTrue(is_dummy, "Dummy placeholder patch must be rejected")

    def test_10_syntax_error_patch_rejected(self):
        """Test Part L 69: Patches introducing invalid syntax fail validation."""
        bad_syntax_code = "def check_perms():\n    if user.is_admin(\n"
        is_valid, err = validate_syntax(bad_syntax_code, "controller.py")
        self.assertFalse(is_valid)
        self.assertIsNotNone(err)

    def test_11_source_changed_conflict_detection(self):
        """Test Part L 71: When file_sha indicates a stale or conflicting baseline,
        apply_finding_fix rejects with 409 conflict and SOURCE_CHANGED."""
        finding = {
            "id": "FIND-STALE-011",
            "finding_name": "SQL Injection",
            "affected_component": "AuthController"
        }
        with self.assertRaises(ValueError) as ctx:
            apply_finding_fix(
                user_id="test_user",
                repo=self.repo,
                target_branch="main",
                finding=finding,
                file_path="backend/controllers/authController.py",
                diff_or_fixed_code="# Real fix\ndef secure(): pass",
                file_sha="stale_mismatch_sha_conflict_999"
            )
        self.assertIn("SOURCE_CHANGED", str(ctx.exception))

    def test_12_project_and_finding_isolation(self):
        """Test Part L 73 & 74: Separate findings retain strictly isolated source selections."""
        finding_a = "FIND-ISO-A"
        finding_b = "FIND-ISO-B"

        paths_a = ["backend/controllers/authController.py"]
        paths_b = ["backend/controllers/profileController.py"]

        save_source_discovery(
            finding_id=finding_a,
            repo=self.repo,
            branch="main",
            discovery_status="HIGH_CONFIDENCE_MATCH",
            selection_mode="USER_MODIFIED",
            selected_sources=[DiscoveredSourceItem(path=p, layer="Controller", language="python", relevance_score=90, confidence="HIGH") for p in paths_a],
            candidate_sources=[],
            summary="A isolated"
        )

        save_source_discovery(
            finding_id=finding_b,
            repo=self.repo,
            branch="main",
            discovery_status="HIGH_CONFIDENCE_MATCH",
            selection_mode="USER_MODIFIED",
            selected_sources=[DiscoveredSourceItem(path=p, layer="Controller", language="python", relevance_score=90, confidence="HIGH") for p in paths_b],
            candidate_sources=[],
            summary="B isolated"
        )

        rec_a = get_source_discovery(finding_a, self.repo)
        rec_b = get_source_discovery(finding_b, self.repo)

        self.assertEqual([s["path"] for s in rec_a["selected_sources"]], paths_a)
        self.assertEqual([s["path"] for s in rec_b["selected_sources"]], paths_b)
        self.assertNotEqual(rec_a["selected_sources"], rec_b["selected_sources"])

    def test_13_zero_manual_file_selection_autofix_vuln_009(self):
        """Test: User provides only repo, branch, and VULN-009 finding (zero manual files).
        Tracegate automatically locates svgController.py, fetches real source,
        generates real patch, and validates as PATCH_VALIDATED."""
        from backend.github_service import analyze_finding_code

        finding = {
            "id": "VULN-009",
            "vuln_id": "VULN-009",
            "finding_name": "Stored XSS via Malicious SVG Image Upload",
            "title": "Stored XSS via Malicious SVG Image Upload",
            "cwe": "CWE-79",
            "observation": "Uploaded SVG avatars allow execution of inline JavaScript in victim browsers."
        }

        # Call analyze_finding_code with zero manual files
        result = analyze_finding_code(
            user_id="test_user",
            repo=self.repo,
            branch=self.branch,
            finding=finding,
            file_path=None,
            selected_files=[]
        )

        self.assertTrue(result.success, f"Analysis failed: {result.reason}")
        self.assertEqual(result.patch_status, "PATCH_VALIDATED")
        self.assertEqual(result.file_path, "backend/controllers/svgController.py")
        self.assertGreater(len(result.diff_unified or ""), 0)
        self.assertIn("Content-Security-Policy", result.after_code or "")
        self.assertIn("clean_svg", result.after_code or "")
        self.assertGreaterEqual(len(result.selected_sources), 1)
        self.assertEqual(result.selected_sources[0].path, "backend/controllers/svgController.py")

    def test_14_discover_sources_api_with_finding_context(self):
        """Test: Discover sources API returns real candidates for VULN-009 without crashing."""
        resp = self.client.post("/api/ai-fix/discover-sources", json={
            "finding_id": "VULN-009",
            "repo": self.repo,
            "branch": self.branch,
            "finding_name": "Stored XSS via Malicious SVG Image Upload",
            "title": "Stored XSS via Malicious SVG Image Upload",
            "cwe": "CWE-79"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn(data["discovery_status"], ["COMPLETED", "HIGH_CONFIDENCE_MATCH"])
        selected_paths = [s["path"] for s in data["selected_sources"]]
        self.assertIn("backend/controllers/svgController.py", selected_paths)

    def test_15_unknown_finding_returns_no_relevant_source_found(self):
        """Test: Finding with no relevant code in repo returns NO_RELEVANT_SOURCE_FOUND cleanly."""
        from backend.github_service import analyze_finding_code

        finding = {
            "id": "VULN-UNKNOWN-999",
            "vuln_id": "VULN-UNKNOWN-999",
            "finding_name": "Nonexistent Quantum Glitch in Supercomputer Firmware",
            "title": "Nonexistent Quantum Glitch in Supercomputer Firmware",
            "cwe": "CWE-999"
        }

        result = analyze_finding_code(
            user_id="test_user",
            repo=self.repo,
            branch=self.branch,
            finding=finding,
            file_path=None,
            selected_files=[]
        )

        self.assertFalse(result.success)
        self.assertEqual(result.patch_status, "NO_RELEVANT_SOURCE_FOUND")
        self.assertIn("could not identify source code relevant", result.reason or "")

    def test_16_analyze_api_endpoint_zero_files_end_to_end(self):
        """Test: POST /api/ai-fix/analyze works end-to-end with selected_files=[] for VULN-009."""
        resp = self.client.post("/api/ai-fix/analyze", json={
            "finding_id": "VULN-009",
            "repo": self.repo,
            "branch": self.branch,
            "file_path": None,
            "selected_files": []
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["patch_status"], "PATCH_VALIDATED")
        self.assertEqual(data["file_path"], "backend/controllers/svgController.py")
        self.assertGreater(len(data["diff_unified"]), 0)
        self.assertGreaterEqual(len(data["selected_sources"]), 1)

    def test_17_wrong_template_files_triggers_automatic_discovery_recovery(self):
        """Test: User manually selects wrong template files (templates/profile.html, login.html, etc.).
        Tracegate detects these files contain no vulnerable logic, automatically discovers
        the real vulnerable controller (backend/controllers/svgController.py), and remediates with PATCH_VALIDATED."""
        from backend.github_service import analyze_finding_code

        finding = {
            "id": "VULN-009",
            "vuln_id": "VULN-009",
            "finding_name": "Stored XSS via Malicious SVG Image Upload",
            "title": "Stored XSS via Malicious SVG Image Upload",
            "cwe": "CWE-79",
            "observation": "Uploaded SVG avatars allow execution of inline JavaScript in victim browsers."
        }

        # Stale or mistaken template files selected by user
        wrong_files = [
            "templates/profile.html",
            "templates/login.html",
            "templates/profile_edit.html",
            "templates/dashboard.html"
        ]

        result = analyze_finding_code(
            user_id="test_user",
            repo=self.repo,
            branch=self.branch,
            finding=finding,
            selected_files=wrong_files
        )

        self.assertTrue(result.success, f"Analysis failed: {result.reason}")
        self.assertEqual(result.patch_status, "PATCH_VALIDATED")
        self.assertEqual(result.file_path, "backend/controllers/svgController.py")
        self.assertGreater(len(result.diff_unified or ""), 0)
        self.assertIn("Notice: The initially selected files did not contain vulnerable logic", result.explanation or "")
        selected_paths = [s.path for s in result.selected_sources]
        self.assertIn("backend/controllers/svgController.py", selected_paths)

    def test_18_single_wrong_file_triggers_automatic_discovery_recovery(self):
        """Test: User manually selects a single irrelevant template file (templates/profile.html).
        Tracegate automatically recovers and finds the real vulnerable controller."""
        from backend.github_service import analyze_finding_code

        finding = {
            "id": "VULN-009",
            "vuln_id": "VULN-009",
            "finding_name": "Stored XSS via Malicious SVG Image Upload",
            "title": "Stored XSS via Malicious SVG Image Upload",
            "cwe": "CWE-79",
            "observation": "Uploaded SVG avatars allow execution of inline JavaScript in victim browsers."
        }

        result = analyze_finding_code(
            user_id="test_user",
            repo=self.repo,
            branch=self.branch,
            finding=finding,
            file_path="templates/profile.html"
        )

        self.assertTrue(result.success, f"Analysis failed: {result.reason}")
        self.assertEqual(result.patch_status, "PATCH_VALIDATED")
        self.assertEqual(result.file_path, "backend/controllers/svgController.py")

    def test_19_end_to_end_api_recovers_from_stale_manual_files(self):
        """Test: POST /api/ai-fix/analyze with stale manual files recovers cleanly to PATCH_VALIDATED."""
        resp = self.client.post("/api/ai-fix/analyze", json={
            "finding_id": "VULN-009",
            "repo": self.repo,
            "branch": self.branch,
            "file_path": None,
            "selected_files": ["templates/profile.html", "templates/login.html"]
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["patch_status"], "PATCH_VALIDATED")
        self.assertEqual(data["file_path"], "backend/controllers/svgController.py")
        self.assertGreater(len(data["diff_unified"]), 0)

    def test_20_app_py_svg_stored_xss_auto_discovery_and_patch(self):
        """Test: Real repository pattern in app.py (uploads_gallery reading SVG without sanitization)
        is automatically discovered, patched with script/event handler stripping, and passes validation."""
        app_code = (
            "from flask import Flask, request, render_template\n"
            "import os\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/uploads')\n"
            "def uploads_gallery():\n"
            "    files = get_uploaded_files()\n"
            "    svg_files = []\n"
            "    for f in files:\n"
            "        is_svg = f['original_filename'].lower().endswith('.svg')\n"
            "        if is_svg:\n"
            "            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f['stored_filename'])\n"
            "            with open(file_path, 'r', encoding='utf-8') as svg_file:\n"
            "                f_dict['svg_content'] = svg_file.read()\n"
            "                svg_files.append(f_dict)\n"
            "    return render_template('uploads.html', svg_files=svg_files)\n"
        )
        finding = {
            "id": "VULN-009",
            "vuln_id": "VULN-009",
            "finding_name": "[VULN-009] Stored XSS via Malicious SVG Image Upload",
            "title": "Stored XSS via Malicious SVG Image Upload",
            "cwe": "CWE-79",
            "observation": "Uploaded SVG files are read from storage and rendered unsafely."
        }

        # 1. Discovery selects app.py and rejects tests / static assets
        tree = [
            {"path": "app.py", "type": "blob"},
            {"path": "reset_lab.py", "type": "blob"},
            {"path": "templates/upload.html", "type": "blob"},
            {"path": "static/js/app.js", "type": "blob"}
        ]
        disc = discover_repository_sources(finding, tree, lambda p: app_code if p == "app.py" else "")
        self.assertEqual(disc["discovery_status"], "COMPLETED")
        selected_paths = [s["path"] for s in disc["selected_sources"]]
        self.assertIn("app.py", selected_paths)
        self.assertNotIn("reset_lab.py", selected_paths)
        self.assertNotIn("static/js/app.js", selected_paths)

        # 2. Patch generation produces valid fix with exact diff
        fix = generate_secure_fix(finding, "dankharaharsh/vulnerable-code", "main", "app.py", app_code)
        self.assertTrue(fix["success"])
        self.assertEqual(fix["patch_status"], "PATCH_VALIDATED")
        self.assertIn("clean_svg", fix["after_code"])
        self.assertIn("import re", fix["after_code"])
        self.assertIn("Sanitized stored SVG content", fix["changes"][0])
        self.assertGreater(len(fix["diff_unified"]), 0)
        self.assertEqual(fix["validation"]["syntax"], "PASSED")
        self.assertEqual(fix["validation"]["security"], "PASSED")

if __name__ == "__main__":
    unittest.main()
