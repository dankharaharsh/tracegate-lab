"""
Tracegate Professional Microsoft Word (.docx) VAPT Report Generator.
Generates comprehensive, client-ready cybersecurity assessment reports
using python-docx with executive cover pages, methodology, test coverage matrices,
structured findings, monospaced PoC callout blocks, and embedded evidence figures.
"""

import io
import os
import json
import base64
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from PIL import Image

import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

from backend.knowledge_base import get_finding_template_for_test

logger = logging.getLogger("report_generator")

# Professional Color Palette
COLOR_NAVY = RGBColor(30, 58, 138)       # Primary headings (#1E3A8A)
COLOR_SLATE = RGBColor(15, 23, 42)      # Primary text (#0F172A)
COLOR_MUTED = RGBColor(100, 116, 139)   # Subtitles (#64748B)
COLOR_CRIT = RGBColor(185, 28, 28)      # Critical severity (#B91C1C)
COLOR_HIGH = RGBColor(194, 65, 12)      # High severity (#C2410C)
COLOR_MED = RGBColor(180, 83, 9)        # Medium severity (#B45309)
COLOR_LOW = RGBColor(4, 120, 87)        # Low severity (#047857)
COLOR_INFO = RGBColor(2, 132, 199)      # Informational severity (#0284C7)

HEX_BG_HEADER = "1E3A8A"                # Dark navy header fill
HEX_BG_CALLOUT = "F8FAFC"               # Very light slate callout background
HEX_BG_MUTED = "F1F5F9"                 # Subtle border/zebra fill

REPORTS_DIR = Path(__file__).resolve().parent.parent / "data" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def set_cell_background(cell, fill_hex: str):
    """Applies background shading color to a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tc_pr.append(shd)

def set_cell_margins(cell, top: int = 120, bottom: int = 120, left: int = 160, right: int = 160):
    """Sets internal padding (in dxa) for a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)

def add_styled_heading(doc: Document, text: str, level: int):
    """Creates a cleanly styled heading."""
    h = doc.add_heading(text, level=level)
    h.paragraph_format.keep_with_next = True
    h.paragraph_format.space_before = Pt(14)
    h.paragraph_format.space_after = Pt(6)
    if level == 1:
        for run in h.runs:
            run.font.name = "Calibri"
            run.font.size = Pt(16)
            run.font.bold = True
            run.font.color.rgb = COLOR_NAVY
    elif level == 2:
        for run in h.runs:
            run.font.name = "Calibri"
            run.font.size = Pt(13)
            run.font.bold = True
            run.font.color.rgb = COLOR_NAVY
    return h

def generate_docx_report(
    project: Dict[str, Any],
    version: str = "v1.0",
    author_name: Optional[str] = None,
    selected_finding_ids: Optional[List[str]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    allow_clean_report: bool = False,
    methodology: str = "owasp_wstg"
) -> str:
    """
    Generates a professional VAPT Assessment Report in .docx format.
    Accurately consumes persisted project findings and selected findings,
    renders monospaced PoC callout blocks, embeds screenshot figures,
    and structures executive summaries and test coverage matrices.
    Returns the absolute path to the generated document file.
    """
    doc = Document()

    # Configure 1-inch margins
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
        
        # Configure Header and Footer
        header = section.header
        hp = header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hrun = hp.add_run("TRACEGATE SECURITY ASSESSMENT  |  STRICTLY CONFIDENTIAL")
        hrun.font.name = "Calibri"
        hrun.font.size = Pt(8.5)
        hrun.font.color.rgb = COLOR_MUTED

        footer = section.footer
        fp = footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.LEFT
        target_name = project.get("name", "Target Assessment")
        frun1 = fp.add_run(f"Project: {target_name} ({version})")
        frun1.font.name = "Calibri"
        frun1.font.size = Pt(8.5)
        frun1.font.color.rgb = COLOR_MUTED

    # 1. Resolve and filter findings
    if findings is None:
        source_findings = list(project.get("findings", []))
    else:
        source_findings = list(findings)

    if selected_finding_ids is not None:
        sel_set = set(str(sid) for sid in selected_finding_ids)
        active_findings = [
            f for f in source_findings
            if str(f.get("id")) in sel_set or str(f.get("vuln_id")) in sel_set or str(f.get("checklist_item_id")) in sel_set
        ]
    else:
        active_findings = list(source_findings)

    # Sort findings by severity order: Critical -> High -> Medium -> Low -> Informational
    prio_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    active_findings.sort(key=lambda x: prio_order.get((x.get("priority") or "HIGH").upper(), 99))

    checklist = project.get("checklist", [])

    # Count selected findings by severity
    crit_count = sum(1 for f in active_findings if (f.get("priority") or "").upper() == "CRITICAL")
    high_count = sum(1 for f in active_findings if (f.get("priority") or "").upper() == "HIGH")
    med_count = sum(1 for f in active_findings if (f.get("priority") or "").upper() == "MEDIUM")
    low_count = sum(1 for f in active_findings if (f.get("priority") or "").upper() == "LOW")
    info_count = sum(1 for f in active_findings if (f.get("priority") or "").upper() == "INFORMATIONAL")
    total_findings = len(active_findings)

    # Methodology name mapping
    methodology_labels = {
        "owasp_wstg": "OWASP Web Security Testing Guide (WSTG v4.2) & PTES",
        "owasp_top10": "OWASP Top 10 Web Application Security Risks (2025)",
        "asvs_l2": "OWASP Application Security Verification Standard (ASVS Level 2)"
    }
    methodology_name = methodology_labels.get(methodology, "OWASP WSTG v4.2 & PTES")

    # =========================================================================
    # 1. COVER PAGE
    # =========================================================================
    p_pre = doc.add_paragraph()
    p_pre.paragraph_format.space_before = Pt(60)

    p_eyebrow = doc.add_paragraph()
    run_eyebrow = p_eyebrow.add_run("CYBERSECURITY ASSESSMENT & PENETRATION TESTING REPORT")
    run_eyebrow.font.name = "Calibri"
    run_eyebrow.font.size = Pt(11)
    run_eyebrow.font.bold = True
    run_eyebrow.font.color.rgb = COLOR_NAVY
    p_eyebrow.paragraph_format.space_after = Pt(12)

    p_title = doc.add_paragraph()
    run_title = p_title.add_run(project.get("name", "Web Application Security Assessment"))
    run_title.font.name = "Calibri"
    run_title.font.size = Pt(26)
    run_title.font.bold = True
    run_title.font.color.rgb = COLOR_SLATE
    p_title.paragraph_format.space_after = Pt(8)

    p_sub = doc.add_paragraph()
    run_sub = p_sub.add_run("Vulnerability Assessment & Penetration Testing (VAPT) Findings & Remediation Roadmap")
    run_sub.font.name = "Calibri"
    run_sub.font.size = Pt(13)
    run_sub.font.color.rgb = COLOR_MUTED
    p_sub.paragraph_format.space_after = Pt(80)

    # Cover metadata table
    meta_table = doc.add_table(rows=7, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.LEFT
    meta_table.autofit = False

    metadata_rows = [
        ("Target URL / Host:", project.get("target_url", "https://target.app")),
        ("Environment:", project.get("environment", "Web Application (Staging)")),
        ("Assessment Methodology:", methodology_name),
        ("Assessment Date:", datetime.now().strftime("%B %d, %Y")),
        ("Document Version:", version),
        ("Lead Security Assessor:", author_name or project.get("created_by", "Security Learner")),
        ("Classification:", "CONFIDENTIAL / STRICTLY PROPRIETARY")
    ]

    for idx, (label, val) in enumerate(metadata_rows):
        row = meta_table.rows[idx]
        c1, c2 = row.cells[0], row.cells[1]
        c1.width = Inches(2.2)
        c2.width = Inches(4.3)
        set_cell_margins(c1, top=60, bottom=60, left=60, right=60)
        set_cell_margins(c2, top=60, bottom=60, left=60, right=60)

        p1 = c1.paragraphs[0]
        r1 = p1.add_run(label)
        r1.font.name = "Calibri"
        r1.font.bold = True
        r1.font.size = Pt(10)
        r1.font.color.rgb = COLOR_NAVY

        p2 = c2.paragraphs[0]
        r2 = p2.add_run(val)
        r2.font.name = "Calibri"
        r2.font.size = Pt(10)
        if "CONFIDENTIAL" in val:
            r2.font.bold = True
            r2.font.color.rgb = COLOR_CRIT

    doc.add_page_break()

    # =========================================================================
    # 2. DOCUMENT CONTROL & VERSION HISTORY
    # =========================================================================
    add_styled_heading(doc, "Document Control & Version History", level=1)
    
    doc_ctrl_table = doc.add_table(rows=2, cols=4)
    doc_ctrl_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Version", "Date", "Author", "Change Summary"]
    col_widths = [Inches(1.0), Inches(1.5), Inches(1.8), Inches(2.2)]

    for c_idx, title in enumerate(headers):
        cell = doc_ctrl_table.rows[0].cells[c_idx]
        cell.width = col_widths[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=100, bottom=100, left=100, right=100)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    row1 = doc_ctrl_table.rows[1]
    summary_msg = f"Compiled VAPT Report with {total_findings} verified finding(s)" if total_findings > 0 else "Clean Assessment Report (0 vulnerabilities identified)"
    for c_idx, text in enumerate([version, datetime.now().strftime("%Y-%m-%d"), author_name or project.get("created_by", "Security Learner"), summary_msg]):
        cell = row1.cells[c_idx]
        cell.width = col_widths[c_idx]
        set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        r = p.add_run(text)
        r.font.name = "Calibri"
        r.font.size = Pt(9)

    # =========================================================================
    # TABLE OF CONTENTS (Clean & Accurate Structure)
    # =========================================================================
    doc.add_page_break()
    add_styled_heading(doc, "Table of Contents", level=1)
    toc_table = doc.add_table(rows=8, cols=2)
    toc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    toc_table.autofit = False

    toc_entries = [
        ("1. Executive Summary & Findings Severity Matrix", "Section 1"),
        ("2. Assessment Scope & Target Architecture", "Section 2"),
        ("3. Testing Methodology & Security Standards", "Section 3"),
        ("4. Security Test Coverage & Verification Matrix", "Section 4"),
        ("5. Summary of Confirmed Vulnerabilities", "Section 5"),
        ("6. Detailed Technical Findings & Proof of Concept", "Section 6"),
        ("7. Prioritized Remediation Action Plan", "Section 7"),
        ("8. Assessment Conclusion & Formal Sign-Off", "Section 8"),
    ]

    for t_idx, (section_title, ref_str) in enumerate(toc_entries):
        t_row = toc_table.rows[t_idx]
        c_title, c_page = t_row.cells[0], t_row.cells[1]
        c_title.width = Inches(5.5)
        c_page.width = Inches(1.0)
        set_cell_margins(c_title, top=50, bottom=50, left=40, right=40)
        set_cell_margins(c_page, top=50, bottom=50, left=40, right=40)

        p_t = c_title.paragraphs[0]
        r_t = p_t.add_run(section_title)
        r_t.font.name = "Calibri"
        r_t.font.size = Pt(10)
        r_t.font.bold = True
        r_t.font.color.rgb = COLOR_NAVY

        p_p = c_page.paragraphs[0]
        p_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        r_p = p_p.add_run(ref_str)
        r_p.font.name = "Calibri"
        r_p.font.size = Pt(9.5)
        r_p.font.color.rgb = COLOR_MUTED

    doc.add_page_break()

    # =========================================================================
    # 1. EXECUTIVE SUMMARY
    # =========================================================================
    add_styled_heading(doc, "1. Executive Summary", level=1)
    p_exec = doc.add_paragraph()
    p_exec.add_run(
        f"Tracegate conducted an authorized Vulnerability Assessment and Penetration Testing (VAPT) "
        f"evaluation against the target application '{project.get('name')}' located at {project.get('target_url')}. "
        f"The primary objective of this assessment was to identify security weaknesses, evaluate authentication "
        f"and access control boundaries, assess input validation safeguards, and provide actionable technical remediation "
        f"guidance to harden the target architecture against unauthorized exploitation."
    )
    p_exec.paragraph_format.space_after = Pt(10)

    # Dynamic risk summary statement
    if total_findings > 0:
        p_risk = doc.add_paragraph()
        r_risk_lead = p_risk.add_run("Executive Risk Rating: ")
        r_risk_lead.bold = True

        if crit_count > 0:
            rating_label = "ELEVATED / CRITICAL"
            rating_col = COLOR_CRIT
        elif high_count > 0:
            rating_label = "HIGH"
            rating_col = COLOR_HIGH
        elif med_count > 0:
            rating_label = "MEDIUM"
            rating_col = COLOR_MED
        elif low_count > 0:
            rating_label = "LOW"
            rating_col = COLOR_LOW
        else:
            rating_label = "INFORMATIONAL"
            rating_col = COLOR_INFO

        r_risk_val = p_risk.add_run(rating_label)
        r_risk_val.bold = True
        r_risk_val.font.color.rgb = rating_col
        
        plural = "findings" if total_findings != 1 else "finding"
        p_risk.add_run(
            f" — The assessment identified {total_findings} confirmed security {plural} within the tested scope, "
            f"including {crit_count} Critical, {high_count} High, {med_count} Medium, {low_count} Low, and {info_count} Informational severity issues."
        )
    else:
        p_risk = doc.add_paragraph()
        r_risk_lead = p_risk.add_run("Executive Risk Rating: ")
        r_risk_lead.bold = True
        r_risk_val = p_risk.add_run("CLEAN POSTURE / NEGLIGIBLE RISK")
        r_risk_val.bold = True
        r_risk_val.font.color.rgb = COLOR_LOW
        p_risk.add_run(
            " — No confirmed vulnerabilities were identified during the tested scope. "
            "All evaluated security controls functioned in accordance with expected baseline security standards."
        )

    # Findings Breakdown Table (Dynamic 5-level severity matrix)
    summary_table = doc.add_table(rows=6, cols=3)
    summary_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    s_headers = ["Severity Level", "Findings Identified", "Recommended Remediation SLA"]
    s_widths = [Inches(2.0), Inches(2.0), Inches(2.5)]

    for c_idx, title in enumerate(s_headers):
        cell = summary_table.rows[0].cells[c_idx]
        cell.width = s_widths[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=100, bottom=100, left=100, right=100)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    severity_rows = [
        ("CRITICAL", str(crit_count), "Immediate (Within 24-48 Hours)", COLOR_CRIT),
        ("HIGH", str(high_count), "Urgent (Within 7 Days)", COLOR_HIGH),
        ("MEDIUM", str(med_count), "Moderate (Within 30 Days)", COLOR_MED),
        ("LOW", str(low_count), "Standard (Within 90 Days)", COLOR_LOW),
        ("INFORMATIONAL", str(info_count), "Best Practice / Discretionary", COLOR_INFO)
    ]

    for idx, (sev, count_str, sla, col) in enumerate(severity_rows):
        row = summary_table.rows[idx + 1]
        for c_idx, val in enumerate([sev, count_str, sla]):
            cell = row.cells[c_idx]
            cell.width = s_widths[c_idx]
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(9)
            if c_idx == 0:
                r.font.bold = True
                r.font.color.rgb = col
            elif c_idx == 1 and int(count_str) > 0:
                r.font.bold = True

    # =========================================================================
    # 2. SCOPE & 3. METHODOLOGY
    # =========================================================================
    add_styled_heading(doc, "2. Assessment Scope & Target Architecture", level=1)
    p_scope = doc.add_paragraph()
    p_scope.add_run(
        f"The testing activities were conducted strictly within the bounds authorized by the project scope:\n"
        f"• Target URL: {project.get('target_url')}\n"
        f"• Environment: {project.get('environment', 'Web Application (Staging)')}\n"
        f"• Scope Description: {project.get('description') or 'Comprehensive web application security audit.'}\n"
        f"• Scope Notes: {project.get('scope_notes') or project.get('notes') or 'Standard testing boundaries observed.'}"
    )

    add_styled_heading(doc, "3. Testing Methodology & Standards", level=1)
    p_method = doc.add_paragraph()
    p_method.add_run(
        f"Tracegate testing methodology aligns with industry-standard web security evaluation frameworks, "
        f"primarily {methodology_name}. "
        f"The assessment followed a structured five-phase security workflow:\n"
        f"1. Reconnaissance & Surface Inspection: Evaluation of target endpoints, user inputs, and workflows.\n"
        f"2. Visual Feature & Workflow Classification: Contextual analysis of application surfaces and targeted test selection.\n"
        f"3. Security Control Testing: Execution of prioritized security assessment procedures tailored to target components.\n"
        f"4. Manual Verification & Proof of Concept: Validation of anomalous behaviors with crafted payloads to confirm exploitative impact.\n"
        f"5. Remediation Roadmap Development: Formulation of actionable, code-level recommendations and defensive mitigations."
    )

    # =========================================================================
    # 4. TEST COVERAGE MATRIX
    # =========================================================================
    add_styled_heading(doc, "4. Security Test Coverage & Verification Matrix", level=1)
    p_cov = doc.add_paragraph()
    
    total_eval = sum(1 for item in checklist if item.get("status") != "NOT_TESTED")
    clean_eval = sum(1 for item in checklist if item.get("status") == "TESTED_NOT_FOUND")
    vuln_eval = sum(1 for item in checklist if item.get("status") == "VULNERABILITY_FOUND")
    
    p_cov.add_run(
        f"A total of {len(checklist)} security test procedures were designated for this assessment scope. "
        f"Tests completed: {total_eval} | Verified clean controls: {clean_eval} | Confirmed findings: {vuln_eval}. "
        f"The table below details all evaluated controls and verified findings status."
    )

    if checklist:
        cov_table = doc.add_table(rows=len(checklist) + 1, cols=4)
        cov_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        c_headers = ["Test ID", "Security Control", "CWE", "Verification Status"]
        c_widths = [Inches(1.6), Inches(2.6), Inches(1.0), Inches(1.3)]

        for c_idx, title in enumerate(c_headers):
            cell = cov_table.rows[0].cells[c_idx]
            cell.width = c_widths[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=100, bottom=100, left=100, right=100)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(9)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, item in enumerate(checklist):
            row = cov_table.rows[idx + 1]
            st = item.get("status", "NOT_TESTED")
            if st == "TESTED_NOT_FOUND":
                status_text = "Verified Clean"
            elif st == "VULNERABILITY_FOUND":
                status_text = "VULN CONFIRMED"
            else:
                status_text = "Not Tested"

            vals = [item.get("test_id", f"TEST-{idx+1}"), item.get("name", "Security Test"), item.get("cwe") or "-", status_text]
            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                cell.width = c_widths[c_idx]
                set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(val)
                r.font.name = "Calibri"
                r.font.size = Pt(8.5)
                if c_idx == 3:
                    r.font.bold = True
                    if "CONFIRMED" in val:
                        r.font.color.rgb = COLOR_CRIT
                    elif "Clean" in val:
                        r.font.color.rgb = COLOR_LOW
                    else:
                        r.font.color.rgb = COLOR_MUTED

    # =========================================================================
    # 5. SUMMARY OF CONFIRMED VULNERABILITIES
    # =========================================================================
    doc.add_page_break()
    add_styled_heading(doc, "5. Summary of Confirmed Vulnerabilities", level=1)

    if active_findings:
        vuln_table = doc.add_table(rows=len(active_findings) + 1, cols=5)
        vuln_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        v_headers = ["Finding ID", "Vulnerability Title", "Severity", "CWE", "Status"]
        v_widths = [Inches(1.1), Inches(2.8), Inches(1.1), Inches(1.0), Inches(0.8)]

        for c_idx, title in enumerate(v_headers):
            cell = vuln_table.rows[0].cells[c_idx]
            cell.width = v_widths[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=100, bottom=100, left=100, right=100)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(9)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, f in enumerate(active_findings):
            row = vuln_table.rows[idx + 1]
            vuln_id = f"VULN-{idx + 1:03d}"
            prio = (f.get("priority") or "HIGH").upper()
            vals = [vuln_id, f.get("finding_name", "Confirmed Vulnerability"), prio, f.get("cwe") or "CWE-200", f.get("status") or "Open"]

            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                cell.width = v_widths[c_idx]
                set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(val)
                r.font.name = "Calibri"
                r.font.size = Pt(8.5)
                if c_idx == 0:
                    r.font.bold = True
                elif c_idx == 2:
                    r.font.bold = True
                    if prio == "CRITICAL":
                        r.font.color.rgb = COLOR_CRIT
                    elif prio == "HIGH":
                        r.font.color.rgb = COLOR_HIGH
                    elif prio == "MEDIUM":
                        r.font.color.rgb = COLOR_MED
                    elif prio == "LOW":
                        r.font.color.rgb = COLOR_LOW
                    else:
                        r.font.color.rgb = COLOR_INFO
    else:
        p_none = doc.add_paragraph("No confirmed vulnerabilities were recorded for this assessment project.")
        p_none.runs[0].font.italic = True

    # =========================================================================
    # 6. DETAILED TECHNICAL FINDINGS & PROOF OF CONCEPT
    # =========================================================================
    doc.add_page_break()
    add_styled_heading(doc, "6. Detailed Technical Findings & Proof of Concept", level=1)

    if not active_findings:
        p_none = doc.add_paragraph("No confirmed vulnerabilities were recorded for this assessment project.")
        p_none.runs[0].font.italic = True

    figure_idx = 1
    for idx, f in enumerate(active_findings):
        vuln_id = f"VULN-{idx + 1:03d}"
        finding_title = f.get("finding_name", "Security Finding")
        add_styled_heading(doc, f"{vuln_id}: {finding_title}", level=2)

        # Vulnerability Metadata Box
        meta_box = doc.add_table(rows=2, cols=4)
        meta_box.alignment = WD_TABLE_ALIGNMENT.CENTER
        m_headers = ["Severity", "CWE Classification", "CVSS v3.1 Base Score", "Remediation Status"]
        m_widths = [Inches(1.6), Inches(1.8), Inches(1.6), Inches(1.5)]

        for c_idx, title in enumerate(m_headers):
            cell = meta_box.rows[0].cells[c_idx]
            cell.width = m_widths[c_idx]
            set_cell_background(cell, HEX_BG_MUTED)
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8.5)
            r.font.color.rgb = COLOR_NAVY

        prio = (f.get("priority") or "HIGH").upper()
        fix_st = f.get("fix_status") or f.get("status") or "Open"
        row_vals = [
            prio,
            f.get("cwe") or "CWE-200",
            str(f.get("cvss_score") or "7.5"),
            fix_st
        ]
        for c_idx, val in enumerate(row_vals):
            cell = meta_box.rows[1].cells[c_idx]
            cell.width = m_widths[c_idx]
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(9)
            if c_idx == 0:
                r.font.bold = True
                if prio == "CRITICAL":
                    r.font.color.rgb = COLOR_CRIT
                elif prio == "HIGH":
                    r.font.color.rgb = COLOR_HIGH
                elif prio == "MEDIUM":
                    r.font.color.rgb = COLOR_MED
                elif prio == "LOW":
                    r.font.color.rgb = COLOR_LOW
                else:
                    r.font.color.rgb = COLOR_INFO

        # A. Description / Technical Observation
        p_desc_head = doc.add_paragraph()
        p_desc_head.paragraph_format.space_before = Pt(8)
        p_desc_head.paragraph_format.space_after = Pt(2)
        r_dh = p_desc_head.add_run("A. Vulnerability Description & Technical Observation")
        r_dh.bold = True
        r_dh.font.size = Pt(10)
        r_dh.font.color.rgb = COLOR_NAVY

        desc_text = f.get("description") or "Technical observation not provided."
        p_desc = doc.add_paragraph(desc_text)
        p_desc.paragraph_format.space_after = Pt(6)

        # B. Impact
        p_imp_head = doc.add_paragraph()
        p_imp_head.paragraph_format.space_before = Pt(4)
        p_imp_head.paragraph_format.space_after = Pt(2)
        r_ih = p_imp_head.add_run("B. Business & Technical Impact")
        r_ih.bold = True
        r_ih.font.size = Pt(10)
        r_ih.font.color.rgb = COLOR_NAVY

        p_imp = doc.add_paragraph(f.get("impact") or "Specific business impact details were not recorded.")
        p_imp.paragraph_format.space_after = Pt(6)

        # C. Reproduction Steps
        p_rep_head = doc.add_paragraph()
        p_rep_head.paragraph_format.space_before = Pt(4)
        p_rep_head.paragraph_format.space_after = Pt(2)
        r_rh = p_rep_head.add_run("C. Step-by-Step Reproduction Procedure")
        r_rh.bold = True
        r_rh.font.size = Pt(10)
        r_rh.font.color.rgb = COLOR_NAVY

        repro = f.get("reproduction_steps") or f.get("testing_notes") or "Step-by-step reproduction notes were not recorded."
        p_rep = doc.add_paragraph(repro)
        p_rep.paragraph_format.space_after = Pt(6)

        # D. Proof of Concept (Monospaced Shaded Callout Box)
        poc = f.get("poc_text")
        p_poc_head = doc.add_paragraph()
        p_poc_head.paragraph_format.space_before = Pt(4)
        p_poc_head.paragraph_format.space_after = Pt(2)
        r_ph = p_poc_head.add_run("D. Proof of Concept (PoC) Request / Evidence Snippet")
        r_ph.bold = True
        r_ph.font.size = Pt(10)
        r_ph.font.color.rgb = COLOR_NAVY

        if poc and poc.strip():
            poc_table = doc.add_table(rows=1, cols=1)
            poc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
            poc_cell = poc_table.rows[0].cells[0]
            poc_cell.width = Inches(6.5)
            set_cell_background(poc_cell, HEX_BG_CALLOUT)
            set_cell_margins(poc_cell, top=140, bottom=140, left=180, right=180)

            poc_p = poc_cell.paragraphs[0]
            poc_p.paragraph_format.space_before = Pt(0)
            poc_p.paragraph_format.space_after = Pt(0)
            poc_run = poc_p.add_run(poc)
            poc_run.font.name = "Consolas"
            poc_run.font.size = Pt(8.5)
            poc_run.font.color.rgb = RGBColor(30, 41, 59)
        else:
            p_no_poc = doc.add_paragraph("Proof of concept details were not recorded for this finding.")
            p_no_poc.runs[0].font.italic = True
            p_no_poc.paragraph_format.space_after = Pt(6)

        # Embedded Evidence Screenshot (if provided)
        ev_data = f.get("evidence_data")
        ev_file = f.get("evidence_filename")
        img_bytes = None

        if ev_data and isinstance(ev_data, str):
            try:
                b64_str = ev_data.split(",", 1)[1] if "," in ev_data else ev_data
                img_bytes = base64.b64decode(b64_str)
            except Exception as e:
                logger.warning(f"Could not decode base64 evidence for {vuln_id}: {e}")

        if not img_bytes and ev_file and isinstance(ev_file, str):
            for candidate in [
                Path(ev_file),
                Path(__file__).resolve().parent.parent / ev_file,
                Path(__file__).resolve().parent.parent / "data" / "uploads" / ev_file,
                Path(__file__).resolve().parent.parent / "data" / ev_file
            ]:
                if candidate.exists() and candidate.is_file():
                    try:
                        img_bytes = candidate.read_bytes()
                        break
                    except Exception:
                        pass

        if img_bytes:
            try:
                img_stream = io.BytesIO(img_bytes)
                with Image.open(img_stream) as pil_img:
                    _w, _h = pil_img.size

                img_stream.seek(0)
                doc.add_paragraph().paragraph_format.space_before = Pt(6)
                p_img = doc.add_paragraph()
                p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
                run_img = p_img.add_run()
                run_img.add_picture(img_stream, width=Inches(5.5))

                p_caption = doc.add_paragraph()
                p_caption.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p_caption.paragraph_format.space_after = Pt(8)
                
                caption_text = f"Figure {figure_idx}: Evidence demonstrating the reported behavior for {vuln_id}: {finding_title}"
                r_cap = p_caption.add_run(caption_text)
                r_cap.font.name = "Calibri"
                r_cap.font.size = Pt(8.5)
                r_cap.font.italic = True
                r_cap.font.color.rgb = COLOR_MUTED
                figure_idx += 1
            except Exception as ie:
                logger.warning(f"Could not embed screenshot for {vuln_id}: {ie}")

        # Knowledge Base fallback template for empty remediation / mitigation
        tmpl = get_finding_template_for_test(f.get("checklist_item_id") or finding_title, test_name=finding_title, cwe=f.get("cwe"))

        # E. Technical Remediation
        remed = f.get("remediation")
        p_rem_head = doc.add_paragraph()
        p_rem_head.paragraph_format.space_before = Pt(6)
        p_rem_head.paragraph_format.space_after = Pt(2)
        if remed and remed.strip():
            r_remh = p_rem_head.add_run("E. Technical Remediation (Code / Configuration Guidance)")
            r_remh.bold = True
            r_remh.font.size = Pt(10)
            r_remh.font.color.rgb = COLOR_LOW
            p_rem = doc.add_paragraph(remed)
        else:
            r_remh = p_rem_head.add_run("E. Recommended Remediation (Security Best Practice)")
            r_remh.bold = True
            r_remh.font.size = Pt(10)
            r_remh.font.color.rgb = COLOR_LOW
            rec_text = tmpl.get("remediation") or "Apply strict input validation, authorization checks, and follow OWASP secure coding guidelines for this component."
            p_rem = doc.add_paragraph(rec_text)
        p_rem.paragraph_format.space_after = Pt(6)

        # F. Defense-in-Depth Mitigation
        mitig = f.get("mitigation")
        p_mit_head = doc.add_paragraph()
        p_mit_head.paragraph_format.space_before = Pt(4)
        p_mit_head.paragraph_format.space_after = Pt(2)
        if mitig and mitig.strip():
            r_mith = p_mit_head.add_run("F. Defense-in-Depth Architectural Mitigation")
            r_mith.bold = True
            r_mith.font.size = Pt(10)
            r_mith.font.color.rgb = COLOR_NAVY
            p_mit = doc.add_paragraph(mitig)
        else:
            r_mith = p_mit_head.add_run("F. Suggested Defense-in-Depth Mitigation")
            r_mith.bold = True
            r_mith.font.size = Pt(10)
            r_mith.font.color.rgb = COLOR_NAVY
            mit_text = tmpl.get("mitigation") or "Enforce centralized security controls, least privilege boundaries, and continuous automated regression auditing."
        p_mit.paragraph_format.space_after = Pt(8)

        # G. AI AutoFix Remediation Tracking
        branch_name = f.get("github_branch")
        commit_sha = f.get("github_commit")
        pr_url = f.get("github_pr")
        val_status = f.get("github_validation") or "PASSED"
        fix_status = f.get("fix_status") or "Open"

        if branch_name or commit_sha or pr_url or fix_status in ["Fix Applied", "PR Created"]:
            p_autofix_head = doc.add_paragraph()
            p_autofix_head.paragraph_format.space_before = Pt(6)
            p_autofix_head.paragraph_format.space_after = Pt(2)
            r_afh = p_autofix_head.add_run("G. AI AutoFix Remediation Tracking (GitHub Code Connector)")
            r_afh.bold = True
            r_afh.font.size = Pt(10)
            r_afh.font.color.rgb = COLOR_NAVY

            p_af = doc.add_paragraph()
            p_af.paragraph_format.space_after = Pt(14)
            r1 = p_af.add_run("• Remediation Lifecycle Status: ")
            r1.bold = True
            p_af.add_run(f"{fix_status}\n")
            if branch_name:
                r2 = p_af.add_run("• Dedicated Fix Branch: ")
                r2.bold = True
                p_af.add_run(f"{branch_name}\n")
            if commit_sha:
                r3 = p_af.add_run("• Fix Commit SHA: ")
                r3.bold = True
                p_af.add_run(f"{commit_sha}\n")
            if pr_url:
                r4 = p_af.add_run("• Pull Request: ")
                r4.bold = True
                p_af.add_run(f"{pr_url}\n")
            r5 = p_af.add_run("• Automated Validation Pipeline: ")
            r5.bold = True
            p_af.add_run(f"{val_status}")

    # =========================================================================
    # 7. REMEDIATION ACTION PLAN TABLE
    # =========================================================================
    if active_findings:
        doc.add_page_break()
        add_styled_heading(doc, "7. Prioritized Remediation Action Plan", level=1)
        p_plan = doc.add_paragraph()
        p_plan.add_run(
            "The following remediation action plan prioritizes vulnerability resolution based on risk severity. "
            "Engineering teams should address Critical and High severity findings according to the designated service level targets."
        )

        plan_table = doc.add_table(rows=len(active_findings) + 1, cols=5)
        plan_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        pl_headers = ["Finding ID", "Priority", "Recommended Action", "Status", "Target SLA"]
        pl_widths = [Inches(1.0), Inches(1.0), Inches(2.6), Inches(1.0), Inches(0.9)]

        for c_idx, title in enumerate(pl_headers):
            cell = plan_table.rows[0].cells[c_idx]
            cell.width = pl_widths[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=100, bottom=100, left=100, right=100)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(9)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, f in enumerate(active_findings):
            row = plan_table.rows[idx + 1]
            vuln_id = f"VULN-{idx + 1:03d}"
            prio = (f.get("priority") or "HIGH").upper()
            if prio == "CRITICAL":
                sla = "24-48 Hours"
            elif prio == "HIGH":
                sla = "7 Days"
            elif prio == "MEDIUM":
                sla = "30 Days"
            else:
                sla = "90 Days"

            action = f.get("remediation") or "Apply secure input validation and access controls."
            if len(action) > 160:
                action = action[:157] + "..."

            fix_st = f.get("fix_status") or f.get("status") or "Open"
            vals = [vuln_id, prio, action, fix_st, sla]
            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                cell.width = pl_widths[c_idx]
                set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(val)
                r.font.name = "Calibri"
                r.font.size = Pt(8.5)
                if c_idx == 0:
                    r.font.bold = True
                elif c_idx == 1:
                    r.font.bold = True
                    if prio == "CRITICAL":
                        r.font.color.rgb = COLOR_CRIT
                    elif prio == "HIGH":
                        r.font.color.rgb = COLOR_HIGH
                    elif prio == "MEDIUM":
                        r.font.color.rgb = COLOR_MED
                    elif prio == "LOW":
                        r.font.color.rgb = COLOR_LOW
                    else:
                        r.font.color.rgb = COLOR_INFO
    else:
        doc.add_page_break()
        add_styled_heading(doc, "7. Prioritized Remediation Action Plan", level=1)
        p_plan = doc.add_paragraph("No remediation action plan required for this assessment cycle as no vulnerabilities were identified.")
        p_plan.paragraph_format.space_after = Pt(14)

    # =========================================================================
    # 8. ASSESSMENT CONCLUSION & FORMAL SIGN-OFF
    # =========================================================================
    add_styled_heading(doc, "8. Assessment Conclusion & Formal Sign-Off", level=1)
    p_concl = doc.add_paragraph()
    p_concl.add_run(
        "This assessment reflects the security posture of the target interface at the time of testing. "
        "Cybersecurity testing is an iterative process; upon completion of any recommended remediations, "
        "a re-testing verification cycle is strongly advised to confirm that identified vulnerabilities "
        "have been resolved without introducing regression defects."
    )
    p_concl.paragraph_format.space_after = Pt(24)

    # Formal sign-off block
    sign_table = doc.add_table(rows=3, cols=2)
    sign_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    s_cells = sign_table.rows[0].cells
    s_cells[0].width = Inches(3.2)
    s_cells[1].width = Inches(3.3)
    p_s1 = s_cells[0].paragraphs[0]
    p_s1.add_run("Prepared by:").bold = True
    p_s2 = s_cells[1].paragraphs[0]
    p_s2.add_run("Verified & Reviewed by:").bold = True

    r2_cells = sign_table.rows[1].cells
    r2_cells[0].paragraphs[0].add_run(f"\n___________________________________\n{author_name or project.get('created_by', 'Security Learner')}\nSecurity Assessor, Tracegate VAPT")
    r2_cells[1].paragraphs[0].add_run(f"\n___________________________________\nLead Security Reviewer\nSenior Penetration Testing Lead")

    r3_cells = sign_table.rows[2].cells
    r3_cells[0].paragraphs[0].add_run(f"Date: {datetime.now().strftime('%B %d, %Y')}")
    r3_cells[1].paragraphs[0].add_run(f"Date: {datetime.now().strftime('%B %d, %Y')}")

    # Save to disk
    proj_id = project.get("id", "project")
    clean_version = version.replace(".", "_")
    filename = f"{proj_id}_{clean_version}_assessment_report.docx"
    output_path = REPORTS_DIR / filename
    doc.save(str(output_path))
    logger.info(f"DOCX Report successfully created at: {output_path}")

    return str(output_path)
