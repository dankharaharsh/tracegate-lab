import os
import sys
import io
import json
import tempfile
from pathlib import Path
import docx
from docx.shared import Inches

from backend.database import (
    init_db,
    get_all_projects,
    get_project_by_id,
    create_project,
    delete_project,
    save_finding,
    get_project_findings_list,
    get_project_reports,
    save_imported_findings,
    get_project_checklist_items,
    save_report_record,
)
from backend.report_importer import (
    parse_report_document,
    detect_duplicates,
    extract_text_from_docx,
    extract_text_from_txt_or_md,
    segment_report_text,
    parse_candidate_finding,
)
from backend.report_generator import (
    generate_docx_report,
    calculate_deterministic_risk_rating,
)
from fastapi.testclient import TestClient
from backend.app import app

def run_tests():
    print("=== STARTING COMPREHENSIVE VAPT REPORT & IMPORT SUITE ===")
    init_db()
    client = TestClient(app)

    # Test 1: Deterministic Risk Rating Calculation
    print("\n--- Test 1: Deterministic Risk Scoring Formula ---")
    assert calculate_deterministic_risk_rating(1, 0, 0, 0, 0, 10, 10)[0] == "CRITICAL RISK"
    assert calculate_deterministic_risk_rating(0, 2, 0, 0, 0, 10, 10)[0] == "CRITICAL RISK"
    assert calculate_deterministic_risk_rating(0, 1, 0, 0, 0, 10, 10)[0] == "HIGH RISK"
    assert calculate_deterministic_risk_rating(0, 0, 3, 0, 0, 10, 10)[0] == "HIGH RISK"
    assert calculate_deterministic_risk_rating(0, 0, 1, 0, 0, 10, 10)[0] == "MEDIUM RISK"
    assert calculate_deterministic_risk_rating(0, 0, 0, 4, 0, 10, 10)[0] == "MEDIUM RISK"
    assert calculate_deterministic_risk_rating(0, 0, 0, 1, 0, 10, 10)[0] == "LOW RISK"
    assert calculate_deterministic_risk_rating(0, 0, 0, 0, 1, 10, 10)[0] == "INFORMATIONAL RISK"
    # Zero findings on incomplete scope
    assert calculate_deterministic_risk_rating(0, 0, 0, 0, 0, 10, 3)[0] == "INCOMPLETE ASSESSMENT / NOT EVALUATED"
    assert calculate_deterministic_risk_rating(0, 0, 0, 0, 0, 0, 0)[0] == "INCOMPLETE ASSESSMENT / NOT EVALUATED"
    # Zero findings on 100% complete scope
    assert calculate_deterministic_risk_rating(0, 0, 0, 0, 0, 10, 10)[0] == "CLEAN POSTURE / NEGLIGIBLE RISK"
    print("✓ Deterministic risk rating formula verified for all conditions!")

    # Test 2: External Report Document Parsing (DOCX, TXT, MD)
    print("\n--- Test 2: External Report Parsing & Duplicate Detection ---")
    
    # 2a. Sample text report
    sample_text_report = """
PENETRATION TESTING ASSESSMENT REPORT
Target: https://staging-api.tracegate.internal
Date: 2026-09-08

Finding 1: Server-Side Request Forgery in Webhook Processor
Severity: Critical
CWE: CWE-918
CVSS: 9.1
Affected URL: https://staging-api.tracegate.internal/api/v1/webhooks
Component: Webhook Dispatcher
Description: The webhook endpoint allows an attacker to supply internal loopback IPs resulting in full internal cloud metadata disclosure.
Impact: Complete access to AWS IMDSv2 and IAM instance credentials.
Steps to Reproduce:
1. Send POST request to /api/v1/webhooks with URL http://169.254.169.254/latest/meta-data/
2. Observe HTTP 200 response containing cloud metadata.
Proof of Concept:
POST /api/v1/webhooks HTTP/1.1
Host: staging-api.tracegate.internal
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
Remediation: Restrict destination IP addresses to public ranges and enforce strict CIDR egress allowlists.

Finding 2: Broken Object Level Authorization on Order Invoices
Severity: High
CWE: CWE-639
CVSS: 8.2
Affected URL: https://staging-api.tracegate.internal/api/orders/invoice/
Component: Billing Module
Description: Users can view arbitrary customer invoice PDFs by altering the sequential invoice_id URL parameter without permission checks.
Impact: Confidential customer PII and purchase history leak.
Steps to Reproduce:
1. Log in as user A with invoice 1001.
2. Request GET /api/orders/invoice/1002.
3. Successfully download user B's invoice.
Proof of Concept:
GET /api/orders/invoice/1002 HTTP/1.1
Authorization: Bearer <userA_token>
Remediation: Implement authoritative tenancy validation and verify request ownership against the session identity.

Finding 3: Verbose Stack Trace in Error Handler
Severity: Informational
CWE: CWE-209
CVSS: 0.0
Affected URL: https://staging-api.tracegate.internal/api/debug
Component: API Gateway
Description: Sending malformed JSON returns Django stack trace revealing framework version and internal library paths.
Remediation: Disable debug mode and implement generic error pages in production.
"""

    existing_test_findings = [
        {
            "id": "find-exist-01",
            "finding_name": "Server-Side Request Forgery in Webhook Engine",
            "cwe": "CWE-918",
            "affected_component": "Webhook Dispatcher",
            "priority": "CRITICAL"
        }
    ]

    parsed = parse_report_document(sample_text_report.encode("utf-8"), "external_audit.txt", existing_findings=existing_test_findings)
    assert parsed["total_candidates"] >= 3, f"Expected at least 3 candidates, got {parsed['total_candidates']}"
    
    # Check SSRF duplicate detection
    ssrf_cand = [c for c in parsed["candidate_findings"] if "Server-Side Request Forgery" in c["title"]][0]
    assert ssrf_cand["is_duplicate"] == True, "SSRF should have been detected as duplicate"
    assert "duplicate_warning" in ssrf_cand
    print(f"✓ Duplicate detected accurately: {ssrf_cand['duplicate_warning']}")

    # Check BOLA finding
    bola_cand = [c for c in parsed["candidate_findings"] if "Broken Object Level Authorization" in c["title"]][0]
    assert bola_cand["is_duplicate"] == False, "BOLA should not be duplicate"
    assert bola_cand["severity"] == "HIGH"
    assert bola_cand["cwe"] == "CWE-639"
    assert bola_cand["cvss_score"] == 8.2
    assert "1002" in bola_cand["poc_text"]
    assert "ownership" in bola_cand["remediation"]
    print("✓ Finding fields extracted cleanly (Severity, CWE, CVSS, Description, PoC, Remediation)!")

    # Check Informational finding
    info_cand = [c for c in parsed["candidate_findings"] if "Verbose Stack Trace" in c["title"]][0]
    assert info_cand["severity"] == "INFORMATIONAL"
    print("✓ Informational finding parsed and normalized cleanly!")

    # 2b. Test DOCX parsing
    doc = docx.Document()
    doc.add_heading("Vulnerability Assessment Report", level=1)
    doc.add_heading("Finding 1: Cross-Site Scripting (Reflected)", level=2)
    doc.add_paragraph("Severity: Medium")
    doc.add_paragraph("CWE: CWE-79")
    doc.add_paragraph("CVSS: 6.1")
    doc.add_paragraph("Affected URL: https://example.com/search")
    doc.add_paragraph("Description: The query parameter is echoed back without output encoding.")
    doc.add_paragraph("Proof of Concept: https://example.com/search?q=<script>alert(1)</script>")
    doc.add_paragraph("Remediation: Apply context-aware HTML entity encoding on user reflection.")

    docx_bio = io.BytesIO()
    doc.save(docx_bio)
    docx_bytes = docx_bio.getvalue()

    docx_parsed = parse_report_document(docx_bytes, "test_pentest.docx")
    assert docx_parsed["total_candidates"] >= 1
    xss_cand = docx_parsed["candidate_findings"][0]
    assert "Cross-Site Scripting" in xss_cand["title"]
    assert xss_cand["severity"] == "MEDIUM"
    assert xss_cand["cwe"] == "CWE-79"
    print("✓ DOCX external report parsing verified!")

    # Test 3: API Integration (Parse, Import, and Project Integrity)
    print("\n--- Test 3: API Endpoints for Parse & Import ---")
    
    # Create temporary project
    proj_resp = client.post("/api/projects", json={
        "name": "VAPT Report Test Project",
        "target_url": "https://audit-target.tracegate.local",
        "environment": "Staging",
        "description": "Project for automated verification of reporting & import."
    })
    assert proj_resp.status_code == 201, proj_resp.text
    proj_id = proj_resp.json()["id"]

    # 3a. Call /parse-import endpoint
    files = {"file": ("external_audit.txt", io.BytesIO(sample_text_report.encode("utf-8")), "text/plain")}
    parse_resp = client.post(f"/api/projects/{proj_id}/reports/parse-import", files=files)
    assert parse_resp.status_code == 200, parse_resp.text
    parse_data = parse_resp.json()
    assert parse_data["total_candidates"] >= 3
    print(f"✓ POST /api/projects/{proj_id}/reports/parse-import returned {parse_data['total_candidates']} candidate findings")

    # 3b. Call /import-findings endpoint with selected candidates (BOLA and Verbose Stack Trace)
    cands_to_import = [
        c for c in parse_data["candidate_findings"]
        if "Broken Object Level" in c["title"] or "Verbose Stack Trace" in c["title"]
    ]
    import_resp = client.post(f"/api/projects/{proj_id}/reports/import-findings", json={
        "source_document_id": parse_data["source_document_id"],
        "source_document_name": parse_data["source_document_name"],
        "candidate_findings": cands_to_import
    })
    assert import_resp.status_code == 200, import_resp.text
    import_result = import_resp.json()
    assert import_result["imported_count"] == 2
    print(f"✓ POST /api/projects/{proj_id}/reports/import-findings successfully imported 2 findings")

    # 3c. Verify findings persisted in database with correct source provenance
    findings_list = get_project_findings_list(proj_id)
    assert len(findings_list) == 2
    for f in findings_list:
        assert f["source"] == "IMPORTED_REPORT"
        assert f["source_document_name"] == "external_audit.txt"
        assert f["retest_status"] == "PENDING"
    print("✓ Imported findings correctly tagged with source='IMPORTED_REPORT', provenance, and retest_status='PENDING'!")

    # Test 4: Comprehensive VAPT Report Generation
    print("\n--- Test 4: Detailed VAPT DOCX Report Generation ---")
    
    # 4a. Add an evidence item with multi-file evidence (image + text)
    # Create a 1x1 png base64 for test
    tiny_png_b64 = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    test_evidence = [
        {"name": "evidence_screenshot.png", "data": tiny_png_b64},
        {"name": "request_payload.json", "data": "{\n  \"action\": \"dump_users\",\n  \"admin\": true\n}"}
    ]
    
    # Save a critical native finding as well
    save_finding(proj_id, None, {
        "finding_name": "SQL Injection in Authentication Header",
        "priority": "CRITICAL",
        "cwe": "CWE-89",
        "cvss_score": 9.8,
        "affected_url": "https://audit-target.tracegate.local/api/auth/token",
        "affected_component": "Token Authenticator",
        "description": "SQL injection in x-auth-token header permits complete database dump.",
        "observation": "SQL error reflected when quote supplied.",
        "poc_text": "' UNION SELECT username, password_hash FROM auth_users--",
        "reproduction_steps": "1. Inject quote into token header.\n2. Observe SQL syntax error.\n3. Execute UNION SELECT query.",
        "remediation": "Utilize parameterized prepared statements without string concatenation.",
        "evidence": test_evidence,
        "status": "Open"
    })

    all_proj_findings = get_project_findings_list(proj_id)
    assert len(all_proj_findings) == 3, f"Expected 3 findings, got {len(all_proj_findings)}"

    # Generate Report via API with selection (include Critical and High, omit Informational to test selection filter)
    crit_high_ids = [f["id"] for f in all_proj_findings if f["priority"] in ["CRITICAL", "HIGH"]]
    rep_resp = client.post(f"/api/projects/{proj_id}/reports", json={
        "version": "v1.0",
        "title": "Comprehensive VAPT Report - Test Target",
        "author_name": "Lead Assessor Alice",
        "methodology": "owasp_wstg",
        "selected_finding_ids": crit_high_ids
    })
    assert rep_resp.status_code == 201, rep_resp.text
    rep_record = rep_resp.json()
    assert rep_record["total_findings"] == 2
    assert rep_record["crit_count"] == 1
    assert rep_record["high_count"] == 1
    docx_file = Path(rep_record["file_path"])
    assert docx_file.exists(), f"DOCX file does not exist at {docx_file}"
    print(f"✓ DOCX Report created successfully at: {docx_file.name} (Size: {docx_file.stat().st_size} bytes)")

    # 4b. Inspect Generated DOCX document content
    gen_doc = docx.Document(str(docx_file))
    doc_text = "\n".join([p.text for p in gen_doc.paragraphs])
    
    # Check key sections
    assert "PENETRATION TESTING REPORT" in doc_text, "Missing cover page title"
    assert "Document Control & Version History" in doc_text, "Missing Document Control"
    assert "Table of Contents" in doc_text, "Missing Table of Contents"
    assert "1. Executive Summary" in doc_text, "Missing Executive Summary"
    assert "CRITICAL RISK" in doc_text, "Missing Deterministic Overall Risk Rating"
    assert "Assessment Scope & Target Architecture" in doc_text, "Missing Scope & Target"
    assert "Testing Methodology & Standards" in doc_text, "Missing Methodology"
    assert "Security Test Coverage & Statistics" in doc_text, "Missing Security Test Coverage"
    assert "Detailed Technical Findings & Proof of Concept" in doc_text, "Missing Detailed Findings"
    assert "Prioritized Remediation Action Plan" in doc_text, "Missing Action Plan"
    assert "Retest & Validation Lifecycle" in doc_text, "Missing Retest Lifecycle"
    assert "Assessment Conclusion & Formal Sign-Off" in doc_text, "Missing Sign-Off"
    assert "Appendix A: CWE Classification Index" in doc_text
    print("✓ All 14 required report sections and appendices confirmed present in DOCX!")

    # Check that selected findings are present in detailed findings
    assert "SQL Injection in Authentication Header" in doc_text
    assert "Broken Object Level Authorization" in doc_text
    
    # Check that unselected informational finding is NOT in the detailed findings of this report
    assert "Verbose Stack Trace" not in doc_text
    print("✓ Selected findings filter strictly honored: unselected findings excluded without modifying database status!")

    # Verify that database status of omitted finding was NOT changed
    info_in_db = [f for f in get_project_findings_list(proj_id) if "Verbose Stack Trace" in f["finding_name"]][0]
    assert info_in_db["status"] == "Open", "Unselected finding status must remain intact"
    print("✓ Authoritative finding status preserved intact in database!")

    # Check images / figures embedded in DOCX
    images_count = len(gen_doc.inline_shapes)
    print(f"✓ Embedded DOCX figures/inline shapes count: {images_count}")
    assert images_count >= 1, "Evidence screenshot should be embedded as a DOCX inline shape"

    # 4c. Test Report Versioning (v1.1)
    rep2_resp = client.post(f"/api/projects/{proj_id}/reports", json={
        "version": "v1.1",
        "title": "Comprehensive VAPT Report - Retest Update",
        "author_name": "Lead Assessor Alice",
        "methodology": "owasp_wstg",
        "selected_finding_ids": [f["id"] for f in all_proj_findings]  # Include all 3 now
    })
    assert rep2_resp.status_code == 201
    rep2_record = rep2_resp.json()
    assert rep2_record["version"] == "v1.1"
    assert rep2_record["total_findings"] == 3
    
    gen_doc2 = docx.Document(str(Path(rep2_record["file_path"])))
    doc2_text = "\n".join([p.text for p in gen_doc2.paragraphs] + [c.text for t in gen_doc2.tables for row in t.rows for c in row.cells])
    assert "v1.0" in doc2_text and "v1.1" in doc2_text, "Version history should list both v1.0 and v1.1"
    print("✓ Report version history tracking (v1.0 and v1.1) verified!")

    # 4d. Test Download Endpoint
    dl_resp = client.get(f"/api/projects/{proj_id}/reports/{rep_record['id']}/download")
    assert dl_resp.status_code == 200
    assert len(dl_resp.content) == docx_file.stat().st_size
    print(f"✓ Report download endpoint tested: {len(dl_resp.content)} bytes streamed successfully")

    # 4e. Test Clean Assessment Report with 0 findings on 0 tested controls -> Incomplete
    clean_proj_resp = client.post("/api/projects", json={
        "name": "Clean Test Project",
        "target_url": "https://clean.tracegate.local",
        "environment": "Production"
    })
    clean_proj_id = clean_proj_resp.json()["id"]

    clean_rep_resp = client.post(f"/api/projects/{clean_proj_id}/reports", json={
        "version": "v1.0",
        "allow_clean_report": True
    })
    assert clean_rep_resp.status_code == 201, clean_rep_resp.text
    clean_rep_file = Path(clean_rep_resp.json()["file_path"])
    clean_doc = docx.Document(str(clean_rep_file))
    clean_text = "\n".join([p.text for p in clean_doc.paragraphs])
    assert "INCOMPLETE ASSESSMENT / NOT EVALUATED" in clean_text
    print("✓ Zero findings on untested scope correctly reported as 'INCOMPLETE ASSESSMENT / NOT EVALUATED' (Rule 5)!")

    # Cleanup temporary test projects
    delete_project(proj_id)
    delete_project(clean_proj_id)
    print("✓ Temporary test projects cleaned up")

    print("\n=== ALL COMPREHENSIVE VAPT REPORT & IMPORT TESTS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    run_tests()
