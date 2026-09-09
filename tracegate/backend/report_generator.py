"""
Tracegate Professional Microsoft Word (.docx) VAPT Report Generator.
Generates comprehensive, client-ready, auditable cybersecurity assessment reports
using python-docx with executive cover pages, document control history, deterministic risk ratings,
severity matrices, test coverage statistics, detailed technical findings with monospaced PoC callouts
and multi-file evidence embedding (PNG/JPG/WEBP and text/JSON), prioritized remediation action plans,
retest validation sections, and formal sign-offs.
"""

import io
import os
import json
import base64
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
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
            run.font.size = Pt(15)
            run.font.bold = True
            run.font.color.rgb = COLOR_NAVY
    elif level == 2:
        for run in h.runs:
            run.font.name = "Calibri"
            run.font.size = Pt(12.5)
            run.font.bold = True
            run.font.color.rgb = COLOR_NAVY
    elif level == 3:
        for run in h.runs:
            run.font.name = "Calibri"
            run.font.size = Pt(11)
            run.font.bold = True
            run.font.color.rgb = COLOR_SLATE
    return h

def calculate_deterministic_risk_rating(
    crit_count: int,
    high_count: int,
    med_count: int,
    low_count: int,
    info_count: int,
    total_tests: int,
    tested_tests: int
) -> Tuple[str, RGBColor, str]:
    """
    Deterministic calculation for Tracegate Assessment Risk Rating.
    Guarantees consistent, documented risk classifications based on actual findings.
    """
    total_findings = crit_count + high_count + med_count + low_count + info_count

    if crit_count >= 1 or high_count >= 2:
        return "CRITICAL RISK", COLOR_CRIT, (
            "The target architecture possesses vulnerabilities with severe exploitability or full impact "
            "over sensitive assets, user accounts, or underlying systems. Urgent remediation is mandatory."
        )
    elif high_count >= 1 or med_count >= 3:
        return "HIGH RISK", COLOR_HIGH, (
            "The target environment contains high-impact flaws or multiple moderate weaknesses that could "
            "be chained to bypass security boundaries. Timely remediation should be prioritized."
        )
    elif med_count >= 1 or low_count >= 4:
        return "MEDIUM RISK", COLOR_MED, (
            "The assessment identified moderate risks or multiple baseline flaws requiring planned remediation "
            "within the standard engineering cycle."
        )
    elif low_count >= 1:
        return "LOW RISK", COLOR_LOW, (
            "Identified issues present minimal immediate exploitability or low technical impact. "
            "Remediation is recommended during routine maintenance."
        )
    elif info_count >= 1:
        return "INFORMATIONAL RISK", COLOR_INFO, (
            "Only informational observations or defense-in-depth enhancements were noted. "
            "No direct vulnerability exploitation vectors were confirmed."
        )
    elif total_tests > 0 and tested_tests >= total_tests and total_findings == 0:
        return "CLEAN POSTURE / NEGLIGIBLE RISK", COLOR_LOW, (
            "No confirmed vulnerabilities were identified across all evaluated security controls. "
            "All targeted controls operated in accordance with expected baseline security standards."
        )
    else:
        return "INCOMPLETE ASSESSMENT / NOT EVALUATED", COLOR_MUTED, (
            "No confirmed vulnerabilities were identified; however, planned security controls have not been "
            "fully evaluated. This posture must not be interpreted as certified security."
        )

def generate_docx_report(
    project: Dict[str, Any],
    version: str = "v1.0",
    author_name: Optional[str] = None,
    selected_finding_ids: Optional[List[str]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    allow_clean_report: bool = False,
    methodology: str = "owasp_wstg",
    historical_reports: Optional[List[Dict[str, Any]]] = None,
    checklist_items: Optional[List[Dict[str, Any]]] = None
) -> str:
    """
    Generates a professional VAPT Assessment Report in Microsoft Word (.docx) format.
    Consumes persisted project data, selected findings, test coverage records, and evidence files.
    Returns the absolute path to the generated document file.
    """
    doc = Document()

    # Configure 1-inch margins
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

        # Header and Footer
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
        frun1 = fp.add_run(f"Project: {target_name} ({version})  |  Classification: CONFIDENTIAL")
        frun1.font.name = "Calibri"
        frun1.font.size = Pt(8.5)
        frun1.font.color.rgb = COLOR_MUTED

    # 1. Resolve findings strictly from project records
    if findings is None:
        source_findings = list(project.get("findings", []))
    else:
        source_findings = list(findings)

    if selected_finding_ids is not None:
        sel_set = set(str(sid) for sid in selected_finding_ids)
        active_findings = [
            f for f in source_findings
            if str(f.get("id")) in sel_set or str(f.get("vuln_id")) in sel_set or str(f.get("checklist_item_id")) in sel_set or str(f.get("test_id")) in sel_set
        ]
    else:
        active_findings = list(source_findings)

    # Sort findings by severity: Critical -> High -> Medium -> Low -> Informational
    prio_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "INFO": 4}
    active_findings.sort(key=lambda x: prio_order.get((x.get("priority") or "HIGH").upper(), 99))

    # Re-index vuln IDs consistently for document presentation
    for idx, f in enumerate(active_findings):
        f["report_vuln_id"] = f"VULN-{idx + 1:03d}"

    # Counts by severity
    crit_count = sum(1 for f in active_findings if (f.get("priority") or "").upper() == "CRITICAL")
    high_count = sum(1 for f in active_findings if (f.get("priority") or "").upper() == "HIGH")
    med_count = sum(1 for f in active_findings if (f.get("priority") or "").upper() == "MEDIUM")
    low_count = sum(1 for f in active_findings if (f.get("priority") or "").upper() == "LOW")
    info_count = sum(1 for f in active_findings if (f.get("priority") or "").upper() in ["INFORMATIONAL", "INFO"])
    total_findings = len(active_findings)

    # Test coverage items
    raw_checklist = checklist_items if checklist_items is not None else project.get("checklist", [])
    total_tests = len(raw_checklist)
    tested_tests = sum(1 for item in raw_checklist if item.get("status") in ["TESTED_NOT_FOUND", "VULNERABILITY_FOUND"])
    untested_tests = total_tests - tested_tests
    clean_eval = sum(1 for item in raw_checklist if item.get("status") == "TESTED_NOT_FOUND")
    vuln_eval = sum(1 for item in raw_checklist if item.get("status") == "VULNERABILITY_FOUND")
    coverage_pct = round((tested_tests / total_tests) * 100, 1) if total_tests > 0 else 0.0

    # Risk Rating
    risk_label, risk_color, risk_desc = calculate_deterministic_risk_rating(
        crit_count, high_count, med_count, low_count, info_count, total_tests, tested_tests
    )

    # Methodology name mapping
    methodology_labels = {
        "owasp_wstg": "OWASP Web Security Testing Guide (WSTG v4.2) & PTES",
        "owasp_top10": "OWASP Top 10 Web Application Security Risks (2025)",
        "asvs_l2": "OWASP Application Security Verification Standard (ASVS Level 2)",
        "ptes": "Penetration Testing Execution Standard (PTES)"
    }
    methodology_name = methodology_labels.get(methodology, "OWASP WSTG v4.2 & PTES")

    # =========================================================================
    # 1. COVER PAGE
    # =========================================================================
    p_pre = doc.add_paragraph()
    p_pre.paragraph_format.space_before = Pt(50)

    p_eyebrow = doc.add_paragraph()
    run_eyebrow = p_eyebrow.add_run("TRACEGATE SECURITY ASSESSMENT")
    run_eyebrow.font.name = "Calibri"
    run_eyebrow.font.size = Pt(11)
    run_eyebrow.font.bold = True
    run_eyebrow.font.color.rgb = COLOR_NAVY
    p_eyebrow.paragraph_format.space_after = Pt(8)

    p_title = doc.add_paragraph()
    run_title = p_title.add_run("CYBERSECURITY ASSESSMENT & PENETRATION TESTING REPORT")
    run_title.font.name = "Calibri"
    run_title.font.size = Pt(22)
    run_title.font.bold = True
    run_title.font.color.rgb = COLOR_SLATE
    p_title.paragraph_format.space_after = Pt(8)

    p_sub = doc.add_paragraph()
    run_sub = p_sub.add_run(f"Target: {project.get('name', 'Target Web Application')}")
    run_sub.font.name = "Calibri"
    run_sub.font.size = Pt(14)
    run_sub.font.color.rgb = COLOR_MUTED
    p_sub.paragraph_format.space_after = Pt(60)

    # Cover metadata table
    meta_table = doc.add_table(rows=7, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.LEFT
    meta_table.autofit = False

    metadata_rows = [
        ("Project Name:", project.get("name", "Assessment Target")),
        ("Target URL / Host:", project.get("target_url") or "Not specified"),
        ("Environment:", project.get("environment") or "Web Application (Staging)"),
        ("Assessment Methodology:", methodology_name),
        ("Assessment Date:", datetime.now().strftime("%B %d, %Y")),
        ("Document Version:", version),
        ("Lead Security Assessor:", author_name or project.get("created_by", "Security Learner")),
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

    doc.add_page_break()

    # =========================================================================
    # 2. DOCUMENT CONTROL & VERSION HISTORY
    # =========================================================================
    add_styled_heading(doc, "Document Control & Version History", level=1)
    
    p_dc_intro = doc.add_paragraph(
        "This document is an authorized, confidential deliverable. Any modifications to this report "
        "must be registered in the version control history below."
    )
    p_dc_intro.paragraph_format.space_after = Pt(8)

    version_rows = []
    seen_versions = set()
    if historical_reports:
        for hr in historical_reports:
            v_num = hr.get("version", "v1.0")
            if v_num not in seen_versions:
                seen_versions.add(v_num)
                d_str = (hr.get("created_at") or "").split("T")[0] or datetime.now().strftime("%Y-%m-%d")
                auth = hr.get("created_by") or author_name or "Security Assessor"
                f_count = hr.get("total_findings", 0)
                summary = f"Audit Report package ({f_count} confirmed findings)" if f_count > 0 else "Clean Assessment Report"
                version_rows.append((v_num, d_str, auth, summary))

    if version not in seen_versions:
        curr_summary = f"Compiled assessment report with {total_findings} verified findings" if total_findings > 0 else "Evaluated security audit report"
        version_rows.append((version, datetime.now().strftime("%Y-%m-%d"), author_name or project.get("created_by", "Security Learner"), curr_summary))

    doc_ctrl_table = doc.add_table(rows=len(version_rows) + 1, cols=4)
    doc_ctrl_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Version", "Date", "Author", "Change Summary"]
    col_widths = [Inches(1.0), Inches(1.4), Inches(1.8), Inches(2.3)]

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

    for r_idx, (v_val, d_val, a_val, s_val) in enumerate(version_rows):
        row = doc_ctrl_table.rows[r_idx + 1]
        for c_idx, text in enumerate([v_val, d_val, a_val, s_val]):
            cell = row.cells[c_idx]
            cell.width = col_widths[c_idx]
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            if r_idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(text)
            r.font.name = "Calibri"
            r.font.size = Pt(9)
            if c_idx == 0:
                r.font.bold = True

    # =========================================================================
    # TABLE OF CONTENTS
    # =========================================================================
    doc.add_page_break()
    add_styled_heading(doc, "Table of Contents", level=1)
    
    toc_table = doc.add_table(rows=10, cols=2)
    toc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    toc_table.autofit = False

    toc_entries = [
        ("1. Executive Summary & Risk Rating", "Section 1"),
        ("2. Findings Severity Matrix & SLAs", "Section 2"),
        ("3. Assessment Scope & Target Architecture", "Section 3"),
        ("4. Testing Methodology & Security Standards", "Section 4"),
        ("5. Security Test Coverage & Statistics", "Section 5"),
        ("6. Summary of Confirmed Vulnerabilities", "Section 6"),
        ("7. Detailed Technical Findings & Proof of Concept", "Section 7"),
        ("8. Prioritized Remediation Action Plan", "Section 8"),
        ("9. Retest & Validation Lifecycle", "Section 9"),
        ("10. Conclusion, Sign-Off & Appendices", "Section 10"),
    ]

    for t_idx, (section_title, ref_str) in enumerate(toc_entries):
        t_row = toc_table.rows[t_idx]
        c_title, c_page = t_row.cells[0], t_row.cells[1]
        c_title.width = Inches(5.3)
        c_page.width = Inches(1.2)
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
    # 1. EXECUTIVE SUMMARY & RISK RATING
    # =========================================================================
    add_styled_heading(doc, "1. Executive Summary", level=1)
    
    p_exec = doc.add_paragraph()
    p_exec.add_run(
        f"Tracegate performed an authorized security assessment against '{project.get('name')}' "
        f"located at {project.get('target_url') or 'the designated target environment'}. "
        f"The primary objective was to identify security vulnerabilities, validate access boundaries, "
        f"evaluate input handling safeguards, and provide actionable technical guidance to harden "
        f"the system against potential compromise."
    )
    p_exec.paragraph_format.space_after = Pt(8)

    # Risk Rating Box
    p_risk_box = doc.add_paragraph()
    p_risk_box.paragraph_format.space_before = Pt(6)
    p_risk_box.paragraph_format.space_after = Pt(6)
    r_rb_lead = p_risk_box.add_run("Tracegate Assessment Risk Rating: ")
    r_rb_lead.bold = True
    r_rb_lead.font.size = Pt(11)
    r_rb_lead.font.color.rgb = COLOR_SLATE

    r_rb_val = p_risk_box.add_run(risk_label)
    r_rb_val.bold = True
    r_rb_val.font.size = Pt(11)
    r_rb_val.font.color.rgb = risk_color

    p_risk_desc = doc.add_paragraph(risk_desc)
    p_risk_desc.paragraph_format.space_after = Pt(8)

    if total_findings > 0:
        p_exec_stat = doc.add_paragraph(f"The assessment identified {total_findings} confirmed security finding{'s' if total_findings != 1 else ''} across evaluated scope.")
        p_exec_stat.paragraph_format.space_after = Pt(4)
    elif allow_clean_report:
        p_clean = doc.add_paragraph("Clean Assessment Report (0 vulnerabilities identified).")
        p_clean.paragraph_format.space_after = Pt(4)

    p_summary_stats = doc.add_paragraph()
    p_summary_stats.add_run("• Total Confirmed Findings in Report: " + str(total_findings) + "\n")
    p_summary_stats.add_run("• Critical Severity: " + str(crit_count) + "\n")
    p_summary_stats.add_run("• High Severity: " + str(high_count) + "\n")
    p_summary_stats.add_run("• Medium Severity: " + str(med_count) + "\n")
    p_summary_stats.add_run("• Low Severity: " + str(low_count) + "\n")
    p_summary_stats.add_run("• Informational: " + str(info_count))
    p_summary_stats.paragraph_format.space_after = Pt(12)

    # =========================================================================
    # 2. FINDINGS SEVERITY MATRIX
    # =========================================================================
    add_styled_heading(doc, "2. Findings Severity Matrix", level=1)
    p_mat_desc = doc.add_paragraph(
        "The following matrix summarizes confirmed findings across severity tiers, "
        "calculated percentages relative to total identified findings, and recommended service level targets."
    )
    p_mat_desc.paragraph_format.space_after = Pt(8)

    summary_table = doc.add_table(rows=6, cols=5)
    summary_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    s_headers = ["Severity Level", "Count", "Action", "Percentage", "Remediation SLA"]
    s_widths = [Inches(1.5), Inches(0.9), Inches(1.4), Inches(1.1), Inches(1.6)]

    for c_idx, title in enumerate(s_headers):
        cell = summary_table.rows[0].cells[c_idx]
        cell.width = s_widths[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=100, bottom=100, left=100, right=100)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(255, 255, 255)

    def calc_pct(c: int) -> str:
        if total_findings == 0:
            return "0.0%"
        return f"{(c / total_findings) * 100:.1f}%"

    severity_rows = [
        ("CRITICAL", str(crit_count), "Immediate", calc_pct(crit_count), "24-48 Hours", COLOR_CRIT),
        ("HIGH", str(high_count), "Urgent", calc_pct(high_count), "7 Days", COLOR_HIGH),
        ("MEDIUM", str(med_count), "Planned", calc_pct(med_count), "30 Days", COLOR_MED),
        ("LOW", str(low_count), "Advisory", calc_pct(low_count), "90 Days", COLOR_LOW),
        ("INFORMATIONAL", str(info_count), "Best Practice", calc_pct(info_count), "Discretionary", COLOR_INFO)
    ]

    for idx, (sev, count_str, prio_str, pct_str, sla, col) in enumerate(severity_rows):
        row = summary_table.rows[idx + 1]
        for c_idx, val in enumerate([sev, count_str, prio_str, pct_str, sla]):
            cell = row.cells[c_idx]
            cell.width = s_widths[c_idx]
            set_cell_margins(cell, top=80, bottom=80, left=80, right=80)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
                r.font.color.rgb = col
            elif c_idx == 1 and int(count_str) > 0:
                r.font.bold = True

    # =========================================================================
    # 3. ASSESSMENT SCOPE & TARGET ARCHITECTURE
    # =========================================================================
    doc.add_page_break()
    add_styled_heading(doc, "3. Assessment Scope & Target Architecture", level=1)
    
    p_scope = doc.add_paragraph()
    scope_text = (
        f"• Target Application Name: {project.get('name', 'Not specified')}\n"
        f"• Target URL / Host: {project.get('target_url') or 'Not specified'}\n"
        f"• Target Environment: {project.get('environment') or 'Web Application (Staging)'}\n"
        f"• Scope Summary: {project.get('description') or 'Comprehensive web application assessment.'}\n"
        f"• Scope Boundaries & Notes: {project.get('scope_notes') or project.get('notes') or 'Authorized testing procedures within designated endpoints.'}\n"
        f"• In-Scope Components: Web Application UI, REST API endpoints, user authentication flows, session handling.\n"
        f"• Out-of-Scope Components: Third-party payment gateways, external cloud infrastructure, Denial of Service (DoS/DDoS) attacks."
    )
    p_scope.add_run(scope_text)
    p_scope.paragraph_format.space_after = Pt(10)

    # =========================================================================
    # 4. METHODOLOGY & STANDARDS
    # =========================================================================
    add_styled_heading(doc, "4. Testing Methodology & Standards", level=1)
    p_method = doc.add_paragraph()
    method_text = (
        f"Testing activities were conducted in alignment with {methodology_name}. "
        f"The assessment executed an eight-stage security testing lifecycle:\n"
        f"1. Reconnaissance & Surface Inspection: Asset enumeration and input identification.\n"
        f"2. Functional Analysis & Visual Classification: Analysis of workflows and UI controls.\n"
        f"3. Security Test Selection: Prioritized selection of threat-relevant testing procedures.\n"
        f"4. Manual Verification: Hands-on probing of boundaries, session tokens, and business logic.\n"
        f"5. Proof-of-Concept Validation: Controlled exploitation to confirm business and technical impact.\n"
        f"6. Finding Documentation: Precise recording of steps, payloads, and evidence.\n"
        f"7. Remediation Guidance: Concrete code and architecture remediation recommendations.\n"
        f"8. Retesting & Verification: Validation of deployed security fixes to prevent regressions.\n\n"
        f"Note: Referencing security standards indicates methodological alignment and does not constitute third-party certification."
    )
    p_method.add_run(method_text)
    p_method.paragraph_format.space_after = Pt(10)

    # =========================================================================
    # 5. SECURITY TEST COVERAGE & STATISTICS
    # =========================================================================
    doc.add_page_break()
    add_styled_heading(doc, "5. Security Test Coverage & Statistics", level=1)
    
    p_cov_stat = doc.add_paragraph()
    cov_summary = (
        f"• Total Planned Security Controls: {total_tests}\n"
        f"• Controls Fully Evaluated: {tested_tests}\n"
        f"• Controls Not Tested: {untested_tests}\n"
        f"• Confirmed Vulnerabilities Identified: {vuln_eval}\n"
        f"• Verified Clean Controls (Pass): {clean_eval}\n"
        f"• Security Test Coverage: {coverage_pct}%\n"
        f"Verified clean controls: {clean_eval}\n"
        f"Controls not tested: {untested_tests}"
    )
    p_cov_stat.add_run(cov_summary)
    p_cov_stat.paragraph_format.space_after = Pt(8)

    if raw_checklist:
        cov_table = doc.add_table(rows=len(raw_checklist) + 1, cols=4)
        cov_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        c_headers = ["Test ID", "Security Procedure", "CWE", "Verification Status"]
        c_widths = [Inches(1.4), Inches(2.8), Inches(1.0), Inches(1.3)]

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

        for idx, item in enumerate(raw_checklist):
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
    # 6. SUMMARY OF CONFIRMED VULNERABILITIES
    # =========================================================================
    doc.add_page_break()
    add_styled_heading(doc, "6. Summary of Confirmed Vulnerabilities", level=1)

    if active_findings:
        vuln_table = doc.add_table(rows=len(active_findings) + 1, cols=6)
        vuln_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        v_headers = ["Finding ID", "Vulnerability Title", "Severity", "CWE", "Status", "Retest"]
        v_widths = [Inches(1.0), Inches(2.4), Inches(1.0), Inches(0.9), Inches(0.8), Inches(0.9)]

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
            vuln_id = f.get("report_vuln_id", f"VULN-{idx + 1:03d}")
            prio = (f.get("priority") or "HIGH").upper()
            retest_st = f.get("retest_status") or "PENDING"
            vals = [vuln_id, f.get("finding_name", "Confirmed Vulnerability"), prio, f.get("cwe") or "CWE-200", f.get("status") or "Open", retest_st]

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
        p_none = doc.add_paragraph("No confirmed vulnerabilities were selected or recorded for this report.")
        p_none.runs[0].font.italic = True

    # =========================================================================
    # 7. DETAILED TECHNICAL FINDINGS & PROOF OF CONCEPT
    # =========================================================================
    doc.add_page_break()
    add_styled_heading(doc, "7. Detailed Technical Findings & Proof of Concept", level=1)

    if not active_findings:
        p_none = doc.add_paragraph("No confirmed vulnerabilities were selected for detailed reporting.")
        p_none.runs[0].font.italic = True

    figure_idx = 1
    for idx, f in enumerate(active_findings):
        vuln_id = f.get("report_vuln_id", f"VULN-{idx + 1:03d}")
        finding_title = f.get("finding_name", "Security Finding")
        add_styled_heading(doc, f"{vuln_id}: {finding_title}", level=2)

        # Metadata Box
        meta_box = doc.add_table(rows=2, cols=5)
        meta_box.alignment = WD_TABLE_ALIGNMENT.CENTER
        m_headers = ["Severity", "CWE", "CVSS v3.1", "Remediation Status", "Source"]
        m_widths = [Inches(1.2), Inches(1.2), Inches(1.1), Inches(1.5), Inches(1.5)]

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
        src_label = "Imported Report" if f.get("source") == "IMPORTED_REPORT" else "Tracegate Checklist"
        row_vals = [
            prio,
            f.get("cwe") or "CWE-200",
            str(f.get("cvss_score") or "7.5"),
            fix_st,
            src_label
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

        desc_text = f.get("observation") or f.get("description") or "Technical observation not provided."
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

        impact_text = f.get("impact") or "Exploitation of this vulnerability may lead to unauthorized access, data compromise, or service disruption."
        p_imp = doc.add_paragraph(impact_text)
        p_imp.paragraph_format.space_after = Pt(6)

        # C. Reproduction Steps
        p_rep_head = doc.add_paragraph()
        p_rep_head.paragraph_format.space_before = Pt(4)
        p_rep_head.paragraph_format.space_after = Pt(2)
        r_rh = p_rep_head.add_run("C. Step-by-Step Reproduction Procedure")
        r_rh.bold = True
        r_rh.font.size = Pt(10)
        r_rh.font.color.rgb = COLOR_NAVY

        repro = f.get("reproduction_steps") or f.get("testing_notes") or "1. Access target application.\n2. Execute proof of concept payload.\n3. Validate anomalous response."
        p_rep = doc.add_paragraph(repro)
        p_rep.paragraph_format.space_after = Pt(6)

        # D. Proof of Concept (Monospaced Callout Box)
        poc = f.get("poc_text") or f.get("poc")
        p_poc_head = doc.add_paragraph()
        p_poc_head.paragraph_format.space_before = Pt(4)
        p_poc_head.paragraph_format.space_after = Pt(2)
        r_ph = p_poc_head.add_run("D. Proof of Concept (PoC) Request / Payload Snippet")
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
            poc_run = poc_p.add_run(poc.strip())
            poc_run.font.name = "Consolas"
            poc_run.font.size = Pt(8.5)
            poc_run.font.color.rgb = RGBColor(30, 41, 59)
        else:
            p_no_poc = doc.add_paragraph("Proof of concept payload was not recorded.")
            p_no_poc.runs[0].font.italic = True
            p_no_poc.paragraph_format.space_after = Pt(6)

        # E. Multi-File Evidence Embedding (Images & Monospaced Text/JSON)
        evidence_list = f.get("evidence") or []
        if not evidence_list and (f.get("evidence_filename") or f.get("evidence_data")):
            evidence_list = [{
                "name": f.get("evidence_filename") or "evidence.png",
                "data": f.get("evidence_data"),
                "type": "image/png"
            }]

        if evidence_list:
            p_ev_head = doc.add_paragraph()
            p_ev_head.paragraph_format.space_before = Pt(4)
            p_ev_head.paragraph_format.space_after = Pt(2)
            r_evh = p_ev_head.add_run("E. Attached Proof-of-Concept Evidence")
            r_evh.bold = True
            r_evh.font.size = Pt(10)
            r_evh.font.color.rgb = COLOR_NAVY

            for ev_item in evidence_list:
                ev_name = ev_item.get("name") or ev_item.get("filename") or "evidence"
                ev_data = ev_item.get("data")
                ev_path = ev_item.get("file_path")
                is_img = any(ev_name.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".webp"]) or (ev_item.get("type", "").startswith("image/"))

                if is_img:
                    img_bytes = None
                    if ev_data and isinstance(ev_data, str) and "base64," in ev_data:
                        try:
                            img_bytes = base64.b64decode(ev_data.split("base64,", 1)[1])
                        except Exception as e:
                            logger.warning(f"Could not decode base64 for {ev_name}: {e}")
                    elif ev_path and Path(ev_path).exists():
                        try:
                            img_bytes = Path(ev_path).read_bytes()
                        except Exception:
                            pass
                    elif ev_name:
                        for cand in [
                            Path(ev_name),
                            Path(__file__).resolve().parent.parent / ev_name,
                            Path(__file__).resolve().parent.parent / "data" / "evidence" / project.get("id", "") / ev_name,
                            Path(__file__).resolve().parent.parent / "data" / "uploads" / ev_name
                        ]:
                            if cand.exists() and cand.is_file():
                                try:
                                    img_bytes = cand.read_bytes()
                                    break
                                except Exception:
                                    pass

                    if img_bytes:
                        try:
                            img_stream = io.BytesIO(img_bytes)
                            with Image.open(img_stream) as pil_img:
                                _w, _h = pil_img.size
                            img_stream.seek(0)
                            p_img = doc.add_paragraph()
                            p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
                            p_img.paragraph_format.space_before = Pt(4)
                            r_img = p_img.add_run()
                            r_img.add_picture(img_stream, width=Inches(5.5))

                            p_caption = doc.add_paragraph()
                            p_caption.alignment = WD_ALIGN_PARAGRAPH.CENTER
                            p_caption.paragraph_format.space_after = Pt(6)
                            caption_text = f"Figure {figure_idx}: Evidence demonstrating the reported behavior ({vuln_id} - {ev_name})"
                            r_cap = p_caption.add_run(caption_text)
                            r_cap.font.name = "Calibri"
                            r_cap.font.size = Pt(8.5)
                            r_cap.font.italic = True
                            r_cap.font.color.rgb = COLOR_MUTED
                            figure_idx += 1
                        except Exception as ie:
                            logger.warning(f"Could not embed image {ev_name}: {ie}")
                    else:
                        p_ref = doc.add_paragraph(f"• Evidence File: {ev_name} (Preserved in project evidence storage)")
                        p_ref.runs[0].font.size = Pt(8.5)
                        p_ref.runs[0].font.italic = True
                else:
                    text_content = ""
                    if ev_data and isinstance(ev_data, str) and not ev_data.startswith("data:"):
                        text_content = ev_data
                    elif ev_path and Path(ev_path).exists():
                        try:
                            text_content = Path(ev_path).read_text(encoding="utf-8", errors="replace")
                        except Exception:
                            pass
                    elif ev_data and "base64," in str(ev_data):
                        try:
                            text_content = base64.b64decode(ev_data.split("base64,", 1)[1]).decode("utf-8", errors="replace")
                        except Exception:
                            pass

                    p_label = doc.add_paragraph(f"Evidence Snippet: {ev_name}")
                    p_label.runs[0].font.name = "Calibri"
                    p_label.runs[0].font.size = Pt(8.5)
                    p_label.runs[0].font.bold = True
                    p_label.paragraph_format.space_before = Pt(4)
                    p_label.paragraph_format.space_after = Pt(2)

                    ev_table = doc.add_table(rows=1, cols=1)
                    ev_table.alignment = WD_TABLE_ALIGNMENT.CENTER
                    ev_cell = ev_table.rows[0].cells[0]
                    ev_cell.width = Inches(6.5)
                    set_cell_background(ev_cell, HEX_BG_CALLOUT)
                    set_cell_margins(ev_cell, top=120, bottom=120, left=160, right=160)

                    ev_p = ev_cell.paragraphs[0]
                    ev_p.paragraph_format.space_before = Pt(0)
                    ev_p.paragraph_format.space_after = Pt(0)
                    display_text = text_content.strip() if text_content else f"Raw content of {ev_name} stored securely in assessment repository."
                    ev_run = ev_p.add_run(display_text[:2000])
                    ev_run.font.name = "Consolas"
                    ev_run.font.size = Pt(8.0)
                    ev_run.font.color.rgb = RGBColor(30, 41, 59)

        # Knowledge Base fallback template for empty remediation / mitigation
        tmpl = get_finding_template_for_test(f.get("checklist_item_id") or finding_title, test_name=finding_title, cwe=f.get("cwe"))

        # F. Technical Remediation
        remed = f.get("remediation")
        p_rem_head = doc.add_paragraph()
        p_rem_head.paragraph_format.space_before = Pt(6)
        p_rem_head.paragraph_format.space_after = Pt(2)
        r_remh = p_rem_head.add_run("F. Recommended Technical Remediation")
        r_remh.bold = True
        r_remh.font.size = Pt(10)
        r_remh.font.color.rgb = COLOR_LOW
        
        rem_text = remed if (remed and remed.strip()) else (tmpl.get("remediation") or "Implement strict input validation, parameterized queries, and defensive access controls.")
        p_rem = doc.add_paragraph(rem_text)
        p_rem.paragraph_format.space_after = Pt(6)

        # G. Defense-in-Depth Mitigation
        mitig = f.get("mitigation")
        p_mit_head = doc.add_paragraph()
        p_mit_head.paragraph_format.space_before = Pt(4)
        p_mit_head.paragraph_format.space_after = Pt(2)
        r_mith = p_mit_head.add_run("G. Defense-in-Depth Architectural Mitigation")
        r_mith.bold = True
        r_mith.font.size = Pt(10)
        r_mith.font.color.rgb = COLOR_NAVY

        mit_text = mitig if (mitig and mitig.strip()) else (tmpl.get("mitigation") or "Enforce principle of least privilege, strict output encoding, and centralized access verification.")
        p_mit = doc.add_paragraph(mit_text)
        p_mit.paragraph_format.space_after = Pt(8)

        # H. Lifecycle & Remediation Tracking
        p_life_head = doc.add_paragraph()
        p_life_head.paragraph_format.space_before = Pt(4)
        p_life_head.paragraph_format.space_after = Pt(2)
        r_lh = p_life_head.add_run("H. AI AutoFix Remediation Tracking & Retest Lifecycle")
        r_lh.bold = True
        r_lh.font.size = Pt(10)
        r_lh.font.color.rgb = COLOR_NAVY

        p_life = doc.add_paragraph()
        p_life.add_run(f"• Remediation Status: {f.get('fix_status') or f.get('status') or 'Open'}\n")
        p_life.add_run(f"• Retest Status: {f.get('retest_status') or 'PENDING'}\n")
        if f.get("github_branch"):
            p_life.add_run(f"• Dedicated Fix Branch: {f.get('github_branch')}\n")
        if f.get("github_commit"):
            p_life.add_run(f"• Remediation Commit SHA: {f.get('github_commit')}\n")
        if f.get("github_pr"):
            p_life.add_run(f"• Pull Request: {f.get('github_pr')}\n")
        p_life.paragraph_format.space_after = Pt(14)

    # =========================================================================
    # 8. PRIORITIZED REMEDIATION ACTION PLAN
    # =========================================================================
    if active_findings:
        doc.add_page_break()
        add_styled_heading(doc, "8. Prioritized Remediation Action Plan", level=1)
        p_plan = doc.add_paragraph(
            "Engineering and DevOps teams should remediate confirmed vulnerabilities according to the risk-prioritized "
            "schedule below. Critical and High severity findings must be scheduled for immediate resolution."
        )
        p_plan.paragraph_format.space_after = Pt(8)

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
            vuln_id = f.get("report_vuln_id", f"VULN-{idx + 1:03d}")
            prio = (f.get("priority") or "HIGH").upper()
            if prio == "CRITICAL":
                sla = "24-48 Hours"
            elif prio == "HIGH":
                sla = "7 Days"
            elif prio == "MEDIUM":
                sla = "30 Days"
            else:
                sla = "90 Days"

            action = f.get("remediation") or "Implement secure input validation and access controls."
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

    # =========================================================================
    # 9. RETEST & VALIDATION LIFECYCLE
    # =========================================================================
    doc.add_page_break()
    add_styled_heading(doc, "9. Retest & Validation Lifecycle", level=1)
    p_retest_intro = doc.add_paragraph(
        "Remediation validation is an essential phase of any security assessment. "
        "The following table records the verification state for all identified findings."
    )
    p_retest_intro.paragraph_format.space_after = Pt(8)

    if active_findings:
        rt_table = doc.add_table(rows=len(active_findings) + 1, cols=4)
        rt_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        rt_headers = ["Finding ID", "Vulnerability Title", "Remediation Status", "Retest Verification"]
        rt_widths = [Inches(1.2), Inches(2.6), Inches(1.3), Inches(1.4)]

        for c_idx, title in enumerate(rt_headers):
            cell = rt_table.rows[0].cells[c_idx]
            cell.width = rt_widths[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=100, bottom=100, left=100, right=100)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(9)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, f in enumerate(active_findings):
            row = rt_table.rows[idx + 1]
            vuln_id = f.get("report_vuln_id", f"VULN-{idx + 1:03d}")
            fix_st = f.get("fix_status") or f.get("status") or "Open"
            retest_val = f.get("retest_status") or "Pending"
            vals = [vuln_id, f.get("finding_name", "Finding"), fix_st, retest_val]

            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                cell.width = rt_widths[c_idx]
                set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(val)
                r.font.name = "Calibri"
                r.font.size = Pt(8.5)
                if c_idx == 0:
                    r.font.bold = True
                elif c_idx == 3:
                    r.font.bold = True
                    if "PASS" in val.upper():
                        r.font.color.rgb = COLOR_LOW
                    elif "FAIL" in val.upper():
                        r.font.color.rgb = COLOR_CRIT
                    else:
                        r.font.color.rgb = COLOR_MUTED

    # =========================================================================
    # 10. CONCLUSION & FORMAL SIGN-OFF
    # =========================================================================
    doc.add_page_break()
    add_styled_heading(doc, "10. Assessment Conclusion & Formal Sign-Off", level=1)
    p_concl = doc.add_paragraph()
    
    if total_findings > 0:
        p_concl.add_run(
            f"The cybersecurity assessment against '{project.get('name')}' identified {total_findings} "
            f"confirmed findings within the tested scope ({crit_count} Critical, {high_count} High, "
            f"{med_count} Medium, {low_count} Low, {info_count} Informational). "
            f"Remediation must be executed according to the recommended priority targets, followed by "
            f"a retest verification cycle to guarantee that vulnerability vectors have been eliminated."
        )
    elif total_tests > 0 and tested_tests >= total_tests:
        p_concl.add_run(
            f"The assessment evaluated {tested_tests} designated security controls with zero confirmed "
            f"vulnerabilities identified in the tested scope. Continued regression auditing and dependency "
            f"monitoring are recommended to sustain a clean security posture."
        )
    else:
        p_concl.add_run(
            f"No confirmed vulnerabilities were recorded in this report; however, the assessment was "
            f"not fully evaluated across all planned scope controls ({tested_tests} of {total_tests} tested). "
            f"Further testing is required before certifying security assurance."
        )
    p_concl.paragraph_format.space_after = Pt(20)

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

    # Appendices
    doc.add_page_break()
    add_styled_heading(doc, "Appendix A: CWE Classification Index", level=1)
    p_app_a = doc.add_paragraph()
    appendix_a_text = (
        "• CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')\n"
        "• CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')\n"
        "• CWE-639: Authorization Bypass Through User-Controlled Key ('Insecure Direct Object References')\n"
        "• CWE-287: Improper Authentication\n"
        "• CWE-352: Cross-Site Request Forgery (CSRF)\n"
        "• CWE-434: Unrestricted Upload of File with Dangerous Type\n"
        "• CWE-200: Exposure of Sensitive Information to an Unauthorized Actor\n"
        "• CWE-693: Protection Mechanism Failure"
    )
    p_app_a.add_run(appendix_a_text)

    add_styled_heading(doc, "Appendix B: Report Traceability & Audit Metadata", level=1)
    p_meta = doc.add_paragraph()
    meta_text = (
        f"• Project ID: {project.get('id', 'N/A')}\n"
        f"• Report Document Version: {version}\n"
        f"• Selected Finding IDs: {', '.join([f.get('id', '') for f in active_findings]) or 'None'}\n"
        f"• Assessment Methodology: {methodology_name}\n"
        f"• Generation Timestamp: {datetime.now().isoformat()}"
    )
    p_meta.add_run(meta_text)

    # Save to disk
    proj_id = project.get("id", "project")
    clean_version = version.replace(".", "_")
    filename = f"{proj_id}_{clean_version}_assessment_report.docx"
    output_path = REPORTS_DIR / filename
    doc.save(str(output_path))
    logger.info(f"DOCX Report successfully created at: {output_path}")

    return str(output_path)
