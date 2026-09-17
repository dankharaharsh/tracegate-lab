"""
Tracegate VAPT Assessment Completion Certificate Test Suite
Comprehensive testing for Section 69:
- Deterministic Eligibility Engine (zero-finding rejection, partial completion rejection, failed retest rejection, 100% completion acceptance)
- Post-Retest Automated Non-Blocking Trigger
- Persistent Record Creation & Idempotent Safety Guard
- Certificate Preview and Download Endpoints (DOCX / PDF)
- One-time Notice Dismissal Persistence
- Public Verification Endpoint (JSON & HTML) with Zero Data Leakage
"""

import unittest
import io
import os
import sys
import uuid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend import database as db
from backend import certificate_service

client = TestClient(app)

class TestVAPTCertificateSuite(unittest.TestCase):

    def setUp(self):
        # Create a unique project for each test
        self.proj_name = f"Cert Test Proj {uuid.uuid4().hex[:8]}"
        res = client.post("/api/projects", json={
            "name": self.proj_name,
            "target_url": "https://secure-target.local",
            "environment": "Web Application (Staging)",
            "description": "VAPT Certificate automated test project"
        })
        self.assertIn(res.status_code, [200, 201])
        self.proj_data = res.json()
        self.proj_id = self.proj_data["id"]

    def _create_finding(self, title, severity="HIGH", status="CONFIRMED", retest_status=None, poc=None):
        finding_id = f"f-{uuid.uuid4().hex[:8]}"
        conn = db.get_db_connection()
        cursor = conn.cursor()
        now = "2026-09-17 01:00:00"
        cursor.execute("""
        INSERT INTO findings (
            id, project_id, vuln_id, finding_name, severity_source,
            affected_url, affected_endpoint, affected_component, description, observation, testing_notes,
            poc_text, priority, cwe, cvss_score, status, fix_status, source,
            retest_status, retest_notes, recorded_at
        ) VALUES (?, ?, ?, ?, 'TEST', 'https://secure-target.local', '/api/test', 'app', ?, ?, ?, ?, ?, 'CWE-89', 8.5, ?, 'Fix Applied', 'MANUAL', ?, 'Retest notes', ?)
        """, (
            finding_id, self.proj_id, f"VULN-{uuid.uuid4().hex[:4]}", title,
            f"Description for {title}", f"Observation for {title}", "Notes",
            poc or "SELECT * FROM users WHERE 1=1",
            severity, status, retest_status or "PENDING", now
        ))
        conn.commit()
        conn.close()
        return finding_id

    def test_01_eligibility_zero_findings_rejected(self):
        """Zero-finding project must not be eligible for a remediation certificate."""
        eligibility = certificate_service.check_assessment_certificate_eligibility(self.proj_id)
        self.assertFalse(eligibility["eligible"])
        self.assertIn("no confirmed findings", eligibility["reason"].lower())
        self.assertEqual(eligibility["total_findings"], 0)

        # Status endpoint verification
        res = client.get(f"/api/projects/{self.proj_id}/certificate/status")
        self.assertEqual(res.status_code, 200)
        status_data = res.json()
        self.assertFalse(status_data["eligible"])
        self.assertIsNone(status_data["certificate"])

    def test_02_eligibility_partial_findings_rejected(self):
        """Project with unresolved/pending findings must be rejected with remaining breakdown."""
        f1 = self._create_finding("SQL Injection", severity="CRITICAL", status="RESOLVED", retest_status="PASSED")
        f2 = self._create_finding("XSS Stored", severity="MEDIUM", status="CONFIRMED", retest_status="PENDING")

        eligibility = certificate_service.check_assessment_certificate_eligibility(self.proj_id)
        self.assertFalse(eligibility["eligible"])
        self.assertEqual(eligibility["total_findings"], 2)
        self.assertEqual(eligibility["resolved_findings"], 1)
        self.assertEqual(eligibility["pending_retests"], 1)
        self.assertIn("1 in-scope finding(s) remain pending retest", eligibility["reason"])
        self.assertIn("Medium", eligibility["reason"])

    def test_03_eligibility_failed_retest_rejected(self):
        """Project with failed retest must be rejected."""
        f1 = self._create_finding("Command Injection", severity="HIGH", status="RESOLVED", retest_status="PASSED")
        f2 = self._create_finding("IDOR", severity="HIGH", status="OPEN", retest_status="FAILED")

        eligibility = certificate_service.check_assessment_certificate_eligibility(self.proj_id)
        self.assertFalse(eligibility["eligible"])
        self.assertEqual(eligibility["failed_retests"], 1)
        self.assertIn("remain unresolved or pending remediation", eligibility["reason"])

    def test_04_eligibility_and_generation_success(self):
        """100% resolved and passed findings generate a valid certificate."""
        f1 = self._create_finding("SQL Injection", severity="CRITICAL", status="RESOLVED", retest_status="PASSED")
        f2 = self._create_finding("CSRF", severity="MEDIUM", status="RESOLVED", retest_status="PASSED")

        eligibility = certificate_service.check_assessment_certificate_eligibility(self.proj_id)
        self.assertTrue(eligibility["eligible"])
        self.assertEqual(eligibility["total_findings"], 2)
        self.assertEqual(eligibility["resolved_findings"], 2)
        self.assertEqual(eligibility["pending_retests"], 0)

        # Generate certificate via endpoint
        gen_res = client.post(f"/api/projects/{self.proj_id}/certificate/generate")
        self.assertEqual(gen_res.status_code, 200)
        res_data = gen_res.json()
        self.assertTrue(res_data["success"])
        cert = res_data["certificate"]

        self.assertIn("TG-VAPT-", cert["certificate_id"])
        self.assertIn("TG-VERIFY-", cert["verification_id"])
        self.assertEqual(cert["status"], "VALID")
        self.assertEqual(cert["total_findings"], 2)
        self.assertEqual(cert["findings_passed"], 2)
        self.assertEqual(cert["findings_failed"], 0)
        self.assertEqual(cert["critical_count"], 1)
        self.assertEqual(cert["medium_count"], 1)
        self.assertEqual(cert["target_name"], self.proj_name)
        self.assertEqual(cert["notice_seen"], 0)

        # Verify idempotency: generating again returns the same certificate
        gen_res_2 = client.post(f"/api/projects/{self.proj_id}/certificate/generate")
        self.assertEqual(gen_res_2.status_code, 200)
        cert_2 = gen_res_2.json()["certificate"]
        self.assertEqual(cert["certificate_id"], cert_2["certificate_id"])
        self.assertEqual(cert["verification_id"], cert_2["verification_id"])

    def test_05_retest_endpoint_auto_triggers_certificate(self):
        """Executing the final PASS retest via the AI Fix retest endpoint auto-generates certificate."""
        f1 = self._create_finding("Broken Auth", severity="HIGH", status="RESOLVED", retest_status="PASSED")
        f2 = self._create_finding("Open Redirect", severity="LOW", status="CONFIRMED", retest_status="PENDING")

        # Retest f2 with result="PASS"
        retest_res = client.post(f"/api/ai-fix/{f2}/retest", json={
            "result": "PASS",
            "notes": "Verified patch in production"
        })
        self.assertEqual(retest_res.status_code, 200)
        retest_data = retest_res.json()
        self.assertEqual(retest_data["retest_status"], "PASSED")
        self.assertEqual(retest_data["status"], "RESOLVED")
        self.assertTrue(retest_data.get("certificate_eligible"))
        self.assertIsNotNone(retest_data.get("certificate"))
        cert = retest_data["certificate"]
        self.assertIn("TG-VAPT-", cert["certificate_id"])
        self.assertEqual(cert["total_findings"], 2)
        self.assertEqual(cert["findings_passed"], 2)

    def test_06_dismiss_notice_endpoint(self):
        """Dismiss notice updates notice_seen to 1."""
        f1 = self._create_finding("SSRF", severity="CRITICAL", status="RESOLVED", retest_status="PASSED")
        gen_res = client.post(f"/api/projects/{self.proj_id}/certificate/generate")
        cert = gen_res.json()["certificate"]
        cert_id = cert["certificate_id"]
        self.assertEqual(cert["notice_seen"], 0)

        # Dismiss notice
        dismiss_res = client.post(f"/api/certificates/{cert_id}/dismiss-notice")
        self.assertEqual(dismiss_res.status_code, 200)
        self.assertTrue(dismiss_res.json()["success"])

        # Fetch certificate again
        get_res = client.get(f"/api/certificates/{cert_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["notice_seen"], 1)

    def test_07_public_verification_endpoint_and_html(self):
        """Public verification endpoint and HTML route render valid attestation with zero sensitive data."""
        secret_poc = "SECRET_SUPER_ADMIN_PASSWORD_HASH_12345"
        f1 = self._create_finding("Super Secret Zero Day Bug", severity="CRITICAL", status="RESOLVED", retest_status="PASSED", poc=secret_poc)

        gen_res = client.post(f"/api/projects/{self.proj_id}/certificate/generate")
        cert = gen_res.json()["certificate"]
        cert_id = cert["certificate_id"]
        verify_id = cert["verification_id"]

        # 1. Test JSON verification endpoint
        verify_res = client.get(f"/api/certificates/{cert_id}/verify")
        self.assertEqual(verify_res.status_code, 200)
        verify_json = verify_res.json()
        self.assertEqual(verify_json["status"], "VALID")
        self.assertEqual(verify_json["certificate_id"], cert_id)
        self.assertEqual(verify_json["verification_id"], verify_id)
        self.assertEqual(verify_json["target_name"], self.proj_name)
        self.assertEqual(verify_json["target_url"], "https://secure-target.local")
        self.assertIn("remediation retesting", verify_json["attestation"].lower())

        # Crucial Security Check: Ensure NO vulnerability names or PoCs leak into public JSON
        verify_str = str(verify_json)
        self.assertNotIn("Super Secret Zero Day Bug", verify_str)
        self.assertNotIn(secret_poc, verify_str)

        # 2. Test HTML public route by Certificate ID
        html_res = client.get(f"/certificate/verify/{cert_id}")
        self.assertEqual(html_res.status_code, 200)
        self.assertIn("text/html", html_res.headers["content-type"])
        html_content = html_res.text
        self.assertIn(cert_id, html_content)
        self.assertIn(verify_id, html_content)
        self.assertIn("VAPT Assessment Completion Verification", html_content)
        self.assertIn("VALID", html_content)
        self.assertIn(self.proj_name, html_content)

        # Crucial Security Check: Ensure NO vulnerability names or PoCs leak into public HTML
        self.assertNotIn("Super Secret Zero Day Bug", html_content)
        self.assertNotIn(secret_poc, html_content)

        # 3. Test HTML public route by Verification ID
        html_res_vid = client.get(f"/certificate/verify/{verify_id}")
        self.assertEqual(html_res_vid.status_code, 200)
        self.assertIn(cert_id, html_res_vid.text)

        # 4. Test non-existent certificate
        not_found_res = client.get("/certificate/verify/TG-VAPT-9999-NONEXISTENT")
        self.assertEqual(not_found_res.status_code, 404)
        self.assertIn("NOT FOUND", not_found_res.text)

    def test_08_certificate_download_endpoint(self):
        """Certificate download endpoint serves valid DOCX / PDF file."""
        f1 = self._create_finding("Insecure Direct Object Reference", severity="HIGH", status="RESOLVED", retest_status="PASSED")
        gen_res = client.post(f"/api/projects/{self.proj_id}/certificate/generate")
        cert = gen_res.json()["certificate"]
        cert_id = cert["certificate_id"]

        # Download DOCX
        dl_docx = client.get(f"/api/certificates/{cert_id}/download?format=docx")
        self.assertEqual(dl_docx.status_code, 200)
        self.assertGreater(len(dl_docx.content), 1000)

        # Download PDF (or fallback if Word COM is not installed/configured)
        dl_pdf = client.get(f"/api/certificates/{cert_id}/download?format=pdf")
        self.assertEqual(dl_pdf.status_code, 200)
        self.assertGreater(len(dl_pdf.content), 1000)

    def test_09_project_certificates_list_endpoint(self):
        """Project certificates endpoint returns list of all generated certificates for project."""
        f1 = self._create_finding("CORS Misconfiguration", severity="LOW", status="RESOLVED", retest_status="PASSED")
        client.post(f"/api/projects/{self.proj_id}/certificate/generate")

        list_res = client.get(f"/api/projects/{self.proj_id}/certificates")
        self.assertEqual(list_res.status_code, 200)
        certs = list_res.json()
        self.assertIsInstance(certs, list)
        self.assertGreaterEqual(len(certs), 1)
        self.assertEqual(certs[0]["project_id"], self.proj_id)

if __name__ == "__main__":
    unittest.main()
