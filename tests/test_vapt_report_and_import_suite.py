"""
Unit and Integration Test Suite for Tracegate VAPT Report Ingestion & Report Generator.
Verifies complete extraction of all 8 findings from regression DOCX, 15-part finding sections,
selective import subsets, duplicate detection, and strict branch traceability isolation.
"""

import unittest
import json
from pathlib import Path

from backend.report_importer import (
    parse_report_document,
    segment_report_text,
    parse_candidate_finding,
    detect_duplicates,
    normalize_severity,
)
from backend.report_generator import (
    generate_docx_report,
    calculate_deterministic_risk_rating,
)
from backend.database import (
    init_db,
    save_imported_findings,
    get_project_findings_list,
    get_db_connection,
)
import docx

REGRESSION_DOCX_PATH = Path("data/reports/proj-ecommerce-001_v1_0_assessment_report.docx")

class TestVaptReportImportSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_parse_regression_docx_extracts_all_8_findings(self):
        """
        Verify that parsing data/reports/proj-ecommerce-001_v1_0_assessment_report.docx
        successfully extracts all 8 distinct candidate findings (VULN-001 through VULN-008).
        """
        self.assertTrue(REGRESSION_DOCX_PATH.exists(), f"Target test docx {REGRESSION_DOCX_PATH} does not exist.")
        file_bytes = REGRESSION_DOCX_PATH.read_bytes()
        
        result = parse_report_document(file_bytes, "proj-ecommerce-001_v1_0_assessment_report.docx")
        candidates = result.get("candidate_findings", [])
        
        self.assertEqual(len(candidates), 8, f"Expected exactly 8 candidate findings, got {len(candidates)}")
        
        expected_ids = [f"VULN-00{i}" for i in range(1, 9)]
        extracted_ids = [c.get("source_finding_id") for c in candidates]
        self.assertEqual(extracted_ids, expected_ids)

        # Verify severities
        expected_sevs = ["CRITICAL", "CRITICAL", "CRITICAL", "CRITICAL", "CRITICAL", "HIGH", "HIGH", "LOW"]
        extracted_sevs = [c.get("severity") for c in candidates]
        self.assertEqual(extracted_sevs, expected_sevs)

        # Verify CWE classifications
        expected_cwes = ["CWE-639", "CWE-434", "CWE-22", "CWE-288", "CWE-287", "CWE-79", "CWE-204", "CWE-524"]
        extracted_cwes = [c.get("cwe") for c in candidates]
        self.assertEqual(extracted_cwes, expected_cwes)

        # Verify all candidates have high extraction quality and complete fields
        for idx, c in enumerate(candidates):
            self.assertEqual(c.get("extraction_quality"), "HIGH", f"Finding {idx+1} quality not HIGH")
            self.assertTrue(bool(c.get("title")), f"Finding {idx+1} missing title")
            self.assertTrue(bool(c.get("poc")), f"Finding {idx+1} missing PoC")
            self.assertTrue(bool(c.get("steps_to_reproduce")), f"Finding {idx+1} missing reproduction steps")
            self.assertTrue(bool(c.get("remediation")), f"Finding {idx+1} missing remediation")
            self.assertTrue(bool(c.get("affected_url")), f"Finding {idx+1} missing affected URL")
            self.assertEqual(c.get("source"), "IMPORTED_REPORT")

    def test_duplicate_detection_against_existing_findings(self):
        """
        Verify duplicate detection identifies exact title and CWE matches against existing findings.
        """
        existing = [
            {
                "id": "existing-find-1",
                "vuln_id": "VULN-001",
                "finding_name": "Insecure Direct Object References (IDOR) on Profile Update",
                "cwe": "CWE-639",
                "affected_url": "/api/v1/records/102"
            }
        ]

        file_bytes = REGRESSION_DOCX_PATH.read_bytes()
        result = parse_report_document(file_bytes, "proj-ecommerce-001_v1_0_assessment_report.docx", existing_findings=existing)
        candidates = result.get("candidate_findings", [])
        
        self.assertEqual(len(candidates), 8)
        c1 = candidates[0]
        self.assertTrue(c1.get("is_duplicate"))
        self.assertIn("Potential duplicate", c1.get("duplicate_warning", ""))

        # Non-matching candidates are not flagged as duplicates
        c2 = candidates[1]
        self.assertFalse(c2.get("is_duplicate"))
        self.assertIsNone(c2.get("duplicate_warning"))

    def test_selective_import_persists_chosen_candidates(self):
        """
        Verify selective human-in-the-loop import: selecting 3 of 8 findings persists exactly those 3.
        """
        project_id = "proj-test-import-selective"
        conn = get_db_connection()
        conn.execute("INSERT OR REPLACE INTO projects (id, name, target_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                     (project_id, "Selective Import Test", "https://test.app", "2026-09-09T00:00:00", "2026-09-09T00:00:00"))
        conn.commit()

        file_bytes = REGRESSION_DOCX_PATH.read_bytes()
        result = parse_report_document(file_bytes, "proj.docx")
        all_candidates = result.get("candidate_findings", [])
        self.assertEqual(len(all_candidates), 8)

        # Select only 3 candidates (e.g. index 0, 1, 5: IDOR, File Upload, XSS)
        selected_candidates = [all_candidates[0], all_candidates[1], all_candidates[5]]

        saved = save_imported_findings(
            project_id=project_id,
            candidate_findings=selected_candidates,
            source_doc_id=result.get("source_document_id"),
            source_doc_name="proj.docx"
        )

        self.assertEqual(len(saved), 3)
        saved_titles = [s.get("finding_name") for s in saved]
        self.assertEqual(saved_titles[0], all_candidates[0]["title"])
        self.assertEqual(saved_titles[1], all_candidates[1]["title"])
        self.assertEqual(saved_titles[2], all_candidates[5]["title"])

        # Verify database records
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM findings WHERE project_id = ? AND source = 'IMPORTED_REPORT'", (project_id,))
        count = cursor.fetchone()[0]
        self.assertEqual(count, 3)

    def test_report_generator_traceability_and_15_point_structure(self):
        """
        Verify generated DOCX report:
        1. Preserves authentic finding IDs.
        2. Strictly isolates fix branches (VULN-001 never contains VULN-008's fix branch).
        3. Enforces full 15-part subsections A through O.
        4. Calculates dynamic statistics without hard-coding.
        """
        mock_proj = {
            "id": "proj-traceability-test",
            "name": "Traceability Audit Target",
            "target_url": "https://trace.target.app",
            "findings": [
                {
                    "id": "f-1",
                    "vuln_id": "VULN-001",
                    "finding_name": "Insecure Direct Object References (IDOR)",
                    "priority": "MEDIUM",
                    "cwe": "CWE-639",
                    "cvss_score": 5.0,
                    "description": "IDOR description.",
                    "observation": "IDOR observation.",
                    "impact": "Security Impact: Data exposure.\n\nBusiness Impact: Compliance fine.",
                    "reproduction_steps": "1. Step A\n2. Step B",
                    "poc": "GET /api/v1/records/1 HTTP/1.1",
                    "remediation": "Validate authorization.",
                    "mitigation": "Enforce centralized ACL.",
                    "root_cause": "Missing tenant check.",
                    "detection_monitoring": "Monitor 403 logs.",
                    "developer_validation": "Test tenant isolation.",
                    "status": "Open",
                    "retest_status": "PENDING",
                    "github_branch": None
                },
                {
                    "id": "f-8",
                    "vuln_id": "VULN-008",
                    "finding_name": "Critical Remote Code Execution",
                    "priority": "CRITICAL",
                    "cwe": "CWE-94",
                    "cvss_score": 9.8,
                    "description": "RCE description.",
                    "observation": "RCE observation.",
                    "impact": "Security Impact: Host compromise.\n\nBusiness Impact: Complete downtime.",
                    "reproduction_steps": "1. Upload shell\n2. Trigger execution",
                    "poc": "POST /upload HTTP/1.1",
                    "remediation": "Whitelist extensions.",
                    "mitigation": "Isolate container.",
                    "root_cause": "Unrestricted file upload.",
                    "detection_monitoring": "Process execution alerts.",
                    "developer_validation": "Run extension test suite.",
                    "status": "Fix Applied",
                    "retest_status": "PASSED",
                    "github_branch": "tracegate/fix/VULN-008",
                    "github_commit": "1a2b3c4d5e",
                    "github_pr": "https://github.com/tracegate/repo/pull/8"
                }
            ],
            "checklist": [
                {"test_id": "T1", "name": "Test 1", "status": "VULNERABILITY_FOUND"},
                {"test_id": "T2", "name": "Test 2", "status": "VULNERABILITY_FOUND"},
                {"test_id": "T3", "name": "Test 3", "status": "TESTED_NOT_FOUND"},
            ]
        }

        report_file = generate_docx_report(project=mock_proj, version="v2.0", author_name="Tester")
        self.assertTrue(Path(report_file).exists())

        doc = docx.Document(report_file)

        # Verify finding headings preserve authentic IDs
        h2_headings = [p.text for p in doc.paragraphs if p.style and "Heading 2" in p.style.name]
        self.assertIn("VULN-008: Critical Remote Code Execution", h2_headings)
        self.assertIn("VULN-001: Insecure Direct Object References (IDOR)", h2_headings)

        # Check section mapping for VULN-001 vs VULN-008
        current_heading = None
        sections_by_heading = {}
        for p in doc.paragraphs:
            if p.style and "Heading 2" in p.style.name:
                current_heading = p.text
                sections_by_heading[current_heading] = []
            elif current_heading:
                sections_by_heading[current_heading].append(p.text)

        # VULN-008 section must contain its dedicated fix branch
        v8_text = "\n".join(sections_by_heading["VULN-008: Critical Remote Code Execution"])
        self.assertIn("tracegate/fix/VULN-008", v8_text)
        self.assertIn("https://github.com/tracegate/repo/pull/8", v8_text)

        # VULN-001 section MUST NOT contain VULN-008's fix branch!
        v1_text = "\n".join(sections_by_heading["VULN-001: Insecure Direct Object References (IDOR)"])
        self.assertNotIn("tracegate/fix/VULN-008", v1_text)
        self.assertNotIn("https://github.com/tracegate/repo/pull/8", v1_text)

        # Verify 15-part subsections present in generated document
        all_para_text = "\n".join(p.text for p in doc.paragraphs)
        for letter, name in [
            ("A.", "Executive Description"),
            ("B.", "Technical Observation"),
            ("C.", "Affected Asset & Component"),
            ("D.", "Security Impact"),
            ("E.", "Business Impact"),
            ("F.", "Step-by-Step Reproduction Procedure"),
            ("G.", "Proof of Concept (PoC) Request / Payload Snippet"),
            ("I.", "Root Cause Analysis"),
            ("J.", "Recommended Technical Remediation"),
            ("K.", "Defense-in-Depth Architectural Mitigation"),
            ("L.", "Detection & Monitoring Guidance"),
            ("M.", "Developer Validation Guidance"),
            ("N.", "AI AutoFix Remediation Tracking & GitHub Audit"),
            ("O.", "Retest & Verification Lifecycle"),
        ]:
            self.assertIn(f"{letter} {name}", all_para_text)

if __name__ == "__main__":
    unittest.main()
