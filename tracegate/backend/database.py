import os
import sqlite3
import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger("vapt_db")

DB_DIR = Path(__file__).resolve().parent.parent / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "tracegate.db"

def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Projects table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target_url TEXT NOT NULL,
        description TEXT,
        scope_notes TEXT,
        environment TEXT DEFAULT 'Web Application (Staging)',
        status TEXT DEFAULT 'IN_PROGRESS',
        created_by TEXT DEFAULT 'Security Learner',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    # 2. Screenshots table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS screenshots (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        file_path TEXT,
        page_type TEXT,
        confidence REAL DEFAULT 0.0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    # 3. Checklists table (active analysis metadata per project)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS checklists (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        screenshot_id TEXT,
        page_type TEXT NOT NULL,
        confidence REAL DEFAULT 0.0,
        detected_elements_json TEXT,
        detected_functionalities_json TEXT,
        ambiguity_notes TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    # 4. Checklist items table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS checklist_items (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        checklist_id TEXT,
        test_id TEXT NOT NULL,
        name TEXT NOT NULL,
        priority TEXT NOT NULL,
        reason TEXT NOT NULL,
        testing_objective TEXT NOT NULL,
        cwe TEXT,
        source TEXT DEFAULT 'AI',
        status TEXT DEFAULT 'NOT_TESTED',
        sort_order INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    # 5. Findings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        checklist_item_id TEXT,
        finding_name TEXT NOT NULL,
        description TEXT,
        testing_notes TEXT,
        poc_text TEXT,
        evidence_filename TEXT,
        evidence_data TEXT,
        priority TEXT DEFAULT 'HIGH',
        cwe TEXT,
        cvss_score REAL DEFAULT 7.5,
        impact TEXT,
        reproduction_steps TEXT,
        remediation TEXT,
        mitigation TEXT,
        status TEXT DEFAULT 'Open',
        recorded_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    # Column migrations for existing findings table if columns missing
    cursor.execute("PRAGMA table_info(findings)")
    existing_finding_cols = [r["name"] for r in cursor.fetchall()]
    for col_name, col_def in [
        ("vuln_id", "TEXT"),
        ("severity_source", "TEXT DEFAULT 'AI'"),
        ("affected_url", "TEXT"),
        ("affected_endpoint", "TEXT"),
        ("affected_component", "TEXT"),
        ("cwe", "TEXT"),
        ("cvss_score", "REAL DEFAULT 7.5"),
        ("impact", "TEXT"),
        ("reproduction_steps", "TEXT"),
        ("remediation", "TEXT"),
        ("mitigation", "TEXT"),
        ("status", "TEXT DEFAULT 'Open'"),
        ("fix_status", "TEXT DEFAULT 'NOT_STARTED'"),
        ("github_repo", "TEXT"),
        ("github_branch", "TEXT"),
        ("github_commit", "TEXT"),
        ("github_pr", "TEXT"),
        ("github_validation", "TEXT"),
        ("ai_fix_json", "TEXT")
    ]:
        if col_name not in existing_finding_cols:
            cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}")

    # 5b. User GitHub configurations table (secure server-side storage)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_github_configs (
        user_id TEXT PRIMARY KEY,
        token TEXT,
        mode TEXT DEFAULT 'mock',
        username TEXT,
        updated_at TEXT NOT NULL
    )
    """)

    # 6. Reports table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        version TEXT NOT NULL,
        report_title TEXT NOT NULL,
        file_path TEXT NOT NULL,
        total_findings INTEGER DEFAULT 0,
        crit_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        med_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        info_count INTEGER DEFAULT 0,
        selected_finding_ids TEXT,
        created_by TEXT DEFAULT 'Security Learner',
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("PRAGMA table_info(reports)")
    existing_report_cols = [r["name"] for r in cursor.fetchall()]
    for col_name, col_def in [
        ("info_count", "INTEGER DEFAULT 0"),
        ("selected_finding_ids", "TEXT")
    ]:
        if col_name not in existing_report_cols:
            cursor.execute(f"ALTER TABLE reports ADD COLUMN {col_name} {col_def}")

    # 7. Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT DEFAULT 'Junior Pentester',
        created_at TEXT NOT NULL
    )
    """)

    # 8. Sessions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")

# =========================================================================
# PROJECT CRUD
# =========================================================================

def get_all_projects() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM projects ORDER BY updated_at DESC")
    rows = cursor.fetchall()
    projects = []
    for r in rows:
        p = dict(r)
        p["notes"] = p.get("scope_notes", "")
        # Fetch metrics
        metrics = get_project_metrics(p["id"], conn)
        p.update(metrics)
        projects.append(p)
    conn.close()
    return projects

def get_project_by_id(project_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    proj = dict(row)
    proj["notes"] = proj.get("scope_notes", "")
    proj.update(get_project_metrics(project_id, conn))
    
    # Also fetch active checklist items and findings
    proj["checklist"] = get_project_checklist_items(project_id, conn)
    proj["findings"] = get_project_findings_list(project_id, conn)
    conn.close()
    return proj

def create_project(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    proj_id = data.get("id") or f"proj-{int(datetime.now().timestamp()*1000)}"
    notes_val = data.get("scope_notes") or data.get("notes", "")
    cursor.execute("""
    INSERT INTO projects (id, name, target_url, description, scope_notes, environment, status, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        proj_id,
        data.get("name", "Untitled Project"),
        data.get("target_url", "https://target.app"),
        data.get("description", ""),
        notes_val,
        data.get("environment", "Web Application (Staging)"),
        data.get("status", "IN_PROGRESS"),
        data.get("created_by", "Security Learner"),
        data.get("created_at", now),
        now
    ))
    conn.commit()
    conn.close()
    return get_project_by_id(proj_id)

def update_project(project_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # If notes passed instead of scope_notes, normalize
    if "notes" in data and "scope_notes" not in data:
        data["scope_notes"] = data["notes"]
        
    fields = []
    vals = []
    for k in ["name", "target_url", "description", "scope_notes", "environment", "status"]:
        if k in data and data[k] is not None:
            fields.append(f"{k} = ?")
            vals.append(data[k])
    if fields:
        fields.append("updated_at = ?")
        vals.append(now)
        vals.append(project_id)
        cursor.execute(f"UPDATE projects SET {', '.join(fields)} WHERE id = ?", vals)
        conn.commit()
    conn.close()
    return get_project_by_id(project_id)

def delete_project(project_id: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Clean up physical report files (.docx) from disk
    try:
        cursor.execute("SELECT file_path FROM reports WHERE project_id = ?", (project_id,))
        for row in cursor.fetchall():
            fp = row["file_path"] if isinstance(row, sqlite3.Row) or isinstance(row, dict) else row[0]
            if fp and os.path.exists(fp):
                try:
                    os.remove(fp)
                    logger.info(f"Deleted physical report file on project deletion: {fp}")
                except Exception as fe:
                    logger.warning(f"Could not remove report file {fp}: {fe}")
    except Exception as e:
        logger.warning(f"Error querying reports for file cleanup: {e}")

    # 2. Clean up any attached evidence files on disk
    try:
        cursor.execute("SELECT evidence_filename FROM findings WHERE project_id = ?", (project_id,))
        for row in cursor.fetchall():
            ef = row["evidence_filename"] if isinstance(row, sqlite3.Row) or isinstance(row, dict) else row[0]
            if ef and os.path.exists(ef):
                try:
                    os.remove(ef)
                except Exception:
                    pass
    except Exception:
        pass

    # 3. Cascading delete from database
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def get_project_metrics(project_id: str, conn=None) -> Dict[str, Any]:
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM checklist_items WHERE project_id = ?", (project_id,))
    total_tests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM checklist_items WHERE project_id = ? AND status != 'NOT_TESTED'", (project_id,))
    completed_tests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM checklist_items WHERE project_id = ? AND status = 'VULNERABILITY_FOUND'", (project_id,))
    vulns_found = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM checklist_items WHERE project_id = ? AND status = 'TESTED_NOT_FOUND'", (project_id,))
    not_found = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM findings WHERE project_id = ?", (project_id,))
    total_findings = cursor.fetchone()[0]

    if close_conn:
        conn.close()

    remaining = max(0, total_tests - completed_tests)
    pct = round((completed_tests / total_tests * 100)) if total_tests > 0 else 0
    return {
        "total_tests": total_tests,
        "completed_tests": completed_tests,
        "vulns_found": vulns_found,
        "not_found": not_found,
        "remaining_tests": remaining,
        "progress_pct": pct,
        "total_findings": total_findings
    }

# =========================================================================
# CHECKLIST & ITEMS CRUD
# =========================================================================

def save_analysis_for_project(project_id: str, analysis_data: Dict[str, Any], filename: Optional[str] = None) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Record screenshot
    screenshot_id = f"shot-{int(datetime.now().timestamp()*1000)}"
    cursor.execute("""
    INSERT INTO screenshots (id, project_id, filename, page_type, confidence, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        screenshot_id,
        project_id,
        filename or "uploaded_screenshot.png",
        analysis_data.get("page_type", "Unknown / Ambiguous"),
        analysis_data.get("confidence", 0.0),
        now
    ))

    # 2. Record checklist container
    checklist_id = f"chk-{int(datetime.now().timestamp()*1000)}"
    cursor.execute("""
    INSERT INTO checklists (id, project_id, screenshot_id, page_type, confidence, detected_elements_json, detected_functionalities_json, ambiguity_notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        checklist_id,
        project_id,
        screenshot_id,
        analysis_data.get("page_type", "Unknown / Ambiguous"),
        analysis_data.get("confidence", 0.0),
        json.dumps(analysis_data.get("detected_elements", [])),
        json.dumps(analysis_data.get("detected_functionalities", []) or analysis_data.get("security_relevant_features", [])),
        analysis_data.get("ambiguity_notes"),
        now
    ))

    # 3. Replace or append checklist items
    # We clear prior items for this project to ensure freshness for the new screen
    cursor.execute("DELETE FROM checklist_items WHERE project_id = ?", (project_id,))

    items = analysis_data.get("checklist", [])
    for idx, item in enumerate(items):
        raw_id = item.get("id") or f"test-{idx}"
        item_id = f"{project_id}_{raw_id}"
        item["id"] = item_id
        cursor.execute("""
        INSERT INTO checklist_items (id, project_id, checklist_id, test_id, name, priority, reason, testing_objective, cwe, source, status, sort_order, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item_id,
            project_id,
            checklist_id,
            raw_id,
            item.get("name", "Security Test"),
            item.get("priority", "MEDIUM"),
            item.get("reason", ""),
            item.get("testing_objective", ""),
            item.get("cwe"),
            item.get("source", "AI"),
            item.get("status", "NOT_TESTED"),
            idx,
            now
        ))

    # Touch project updated_at
    cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    conn.close()

    return get_project_by_id(project_id)

def get_project_checklist_items(project_id: str, conn=None) -> List[Dict[str, Any]]:
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
    cursor = conn.cursor()
    cursor.execute("""
    SELECT ci.*, f.id as finding_id, f.finding_name, f.description as finding_desc, f.poc_text, f.evidence_filename, f.evidence_data
    FROM checklist_items ci
    LEFT JOIN findings f ON ci.id = f.checklist_item_id
    WHERE ci.project_id = ?
    ORDER BY ci.sort_order ASC, ci.created_at ASC
    """, (project_id,))
    rows = cursor.fetchall()
    items = []
    for r in rows:
        d = dict(r)
        if d.get("finding_id"):
            d["finding"] = {
                "id": d["finding_id"],
                "finding_name": d["finding_name"],
                "description": d["finding_desc"],
                "poc_text": d["poc_text"],
                "evidence_filename": d["evidence_filename"],
                "evidence_data": d["evidence_data"]
            }
        else:
            d["finding"] = None
        items.append(d)

    if close_conn:
        conn.close()
    return items

def update_checklist_item(item_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    fields = []
    vals = []
    for k in ["name", "priority", "reason", "testing_objective", "cwe"]:
        if k in data:
            fields.append(f"{k} = ?")
            vals.append(data[k])
    if fields:
        fields.append("source = 'USER_MODIFIED'")
        vals.append(item_id)
        cursor.execute(f"UPDATE checklist_items SET {', '.join(fields)} WHERE id = ?", vals)
        conn.commit()

    cursor.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_item_status(item_id: str, status: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE checklist_items SET status = ? WHERE id = ?", (status, item_id))
    # If set to TESTED_NOT_FOUND, remove any existing finding for this item
    if status == "TESTED_NOT_FOUND":
        cursor.execute("DELETE FROM findings WHERE checklist_item_id = ?", (item_id,))
    conn.commit()
    cursor.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def delete_checklist_item(item_id: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings WHERE checklist_item_id = ?", (item_id,))
    cursor.execute("DELETE FROM checklist_items WHERE id = ?", (item_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def add_custom_checklist_item(project_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    item_id = f"custom-{int(datetime.now().timestamp()*1000)}"
    name = (data.get("name") or "Custom Security Test").strip()
    priority = (data.get("priority") or "HIGH").strip().upper()
    reason = (data.get("reason") or "").strip() or "Learner-defined custom test procedure."
    testing_objective = (data.get("testing_objective") or "").strip() or "Verify security control enforcement and validate expected behavior."
    cwe = (data.get("cwe") or "").strip()

    cursor.execute("""
    INSERT INTO checklist_items (id, project_id, checklist_id, test_id, name, priority, reason, testing_objective, cwe, source, status, sort_order, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'USER', 'NOT_TESTED', 0, ?)
    """, (
        item_id,
        project_id,
        None,
        item_id,
        name,
        priority,
        reason,
        testing_objective,
        cwe,
        now
    ))
    cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    cursor.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,))
    row = cursor.fetchone()
    conn.close()
    res = dict(row) if row else {}
    res["finding"] = None
    return res

# =========================================================================
# FINDINGS CRUD
# =========================================================================

def save_finding(project_id: Any, item_id: Optional[str] = None, finding_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from backend.knowledge_base import get_finding_template_for_test

    if isinstance(project_id, dict):
        finding_data = project_id
        item_id = finding_data.get("checklist_item_id")
        project_id = finding_data.get("project_id")

    if finding_data is None:
        finding_data = {}

    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    finding_id = finding_data.get("id") or f"find-{int(datetime.now().timestamp()*1000)}"

    cursor.execute("SELECT COUNT(*) FROM findings WHERE project_id = ?", (project_id,))
    cnt = cursor.fetchone()[0]
    vuln_id = finding_data.get("vuln_id") or f"VULN-{cnt + 1:03d}"

    item_row = None
    if item_id:
        cursor.execute("UPDATE checklist_items SET status = 'VULNERABILITY_FOUND' WHERE id = ?", (item_id,))
        cursor.execute("DELETE FROM findings WHERE checklist_item_id = ?", (item_id,))
        cursor.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,))
        item_row = cursor.fetchone()

    # Automatic finding enrichment for any blank fields
    cwe_val = finding_data.get("cwe") or (item_row["cwe"] if item_row else None)
    name_val = finding_data.get("finding_name") or (item_row["name"] if item_row else "Confirmed Vulnerability")
    priority_val = finding_data.get("priority") or (item_row["priority"] if item_row else "HIGH")
    severity_source_val = finding_data.get("severity_source") or "AI"

    tmpl = get_finding_template_for_test(item_id or name_val, test_name=name_val, cwe=cwe_val)

    desc_val = finding_data.get("description") or tmpl.get("description", "")
    notes_val = finding_data.get("testing_notes") or tmpl.get("reproduction_steps", "")
    poc_val = finding_data.get("poc_text") or tmpl.get("poc_text", "")
    impact_val = finding_data.get("impact") or tmpl.get("impact", "")
    repro_val = finding_data.get("reproduction_steps") or tmpl.get("reproduction_steps", "")
    remed_val = finding_data.get("remediation") or tmpl.get("remediation", "")
    mitig_val = finding_data.get("mitigation") or tmpl.get("mitigation", "")
    cvss_val = finding_data.get("cvss_score") or tmpl.get("cvss_score", 7.5)
    status_val = finding_data.get("status") or "Open"
    fix_status_val = finding_data.get("fix_status") or "NOT_STARTED"

    cursor.execute("""
    INSERT INTO findings (
        id, project_id, checklist_item_id, vuln_id, finding_name, severity_source,
        affected_url, affected_endpoint, affected_component, description, testing_notes,
        poc_text, evidence_filename, evidence_data, priority, cwe, cvss_score,
        impact, reproduction_steps, remediation, mitigation, status, fix_status,
        github_repo, github_branch, github_commit, github_pr, github_validation, recorded_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding_id,
        project_id,
        item_id,
        vuln_id,
        name_val,
        severity_source_val,
        finding_data.get("affected_url"),
        finding_data.get("affected_endpoint"),
        finding_data.get("affected_component"),
        desc_val,
        notes_val,
        poc_val,
        finding_data.get("evidence_filename"),
        finding_data.get("evidence_data"),
        priority_val,
        cwe_val or tmpl.get("cwe", "CWE-200"),
        cvss_val,
        impact_val,
        repro_val,
        remed_val,
        mitig_val,
        status_val,
        fix_status_val,
        finding_data.get("github_repo"),
        finding_data.get("github_branch"),
        finding_data.get("github_commit"),
        finding_data.get("github_pr"),
        finding_data.get("github_validation"),
        now
    ))

    cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    conn.close()
    d = dict(row)
    d["github_fix"] = {
        "repository": d.get("github_repo"),
        "branch": d.get("github_branch"),
        "commit": d.get("github_commit"),
        "pull_request": d.get("github_pr"),
        "pr_url": d.get("github_pr"),
        "validation_status": d.get("github_validation")
    }
    d["ai_fix"] = d["github_fix"]
    return d

def get_project_findings_list(project_id: str, conn=None) -> List[Dict[str, Any]]:
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
    cursor = conn.cursor()
    cursor.execute("""
    SELECT f.*, ci.test_id as test_id, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe, ci.priority as item_priority
    FROM findings f
    LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
    WHERE f.project_id = ?
    ORDER BY f.recorded_at DESC
    """, (project_id,))
    rows = cursor.fetchall()
    findings = []
    for r in rows:
        d = dict(r)
        if not d.get("test_id"):
            d["test_id"] = d.get("checklist_item_id")
        if not d.get("cwe") and d.get("resolved_cwe"):
            d["cwe"] = d["resolved_cwe"]
        if not d.get("vuln_id"):
            d["vuln_id"] = f"VULN-{len(findings) + 1:03d}"
        d["github_fix"] = {
            "repository": d.get("github_repo"),
            "branch": d.get("github_branch"),
            "commit": d.get("github_commit"),
            "pull_request": d.get("github_pr"),
            "pr_url": d.get("github_pr"),
            "validation_status": d.get("github_validation")
        }
        d["ai_fix"] = d["github_fix"]
        findings.append(d)
    if close_conn:
        conn.close()
    return findings

def get_finding_by_id(finding_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT f.*, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe
    FROM findings f
    LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
    WHERE f.id = ? OR f.vuln_id = ?
    """, (finding_id, finding_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if not d.get("cwe") and d.get("resolved_cwe"):
        d["cwe"] = d["resolved_cwe"]
    d["github_fix"] = {
        "repository": d.get("github_repo"),
        "branch": d.get("github_branch"),
        "commit": d.get("github_commit"),
        "pull_request": d.get("github_pr"),
        "pr_url": d.get("github_pr"),
        "validation_status": d.get("github_validation")
    }
    d["ai_fix"] = d["github_fix"]
    return d

def update_finding_github_fix(
    finding_id: str,
    fix_status: str,
    repo: Optional[str] = None,
    branch: Optional[str] = None,
    commit: Optional[str] = None,
    pr: Optional[str] = None,
    validation: Optional[str] = None,
    commit_sha: Optional[str] = None,
    pr_url: Optional[str] = None,
    **kwargs
) -> Optional[Dict[str, Any]]:
    actual_commit = commit or commit_sha
    actual_pr = pr or pr_url
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE findings SET
        fix_status = COALESCE(?, fix_status),
        github_repo = COALESCE(?, github_repo),
        github_branch = COALESCE(?, github_branch),
        github_commit = COALESCE(?, github_commit),
        github_pr = COALESCE(?, github_pr),
        github_validation = COALESCE(?, github_validation)
    WHERE id = ? OR vuln_id = ?
    """, (fix_status, repo, branch, actual_commit, actual_pr, validation, finding_id, finding_id))
    conn.commit()
    conn.close()
    return get_finding_by_id(finding_id)

def update_finding_ai_fix(finding_id: str, ai_fix_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Update AI AutoFix metadata on finding."""
    status_val = ai_fix_data.get("status") or ai_fix_data.get("fix_status") or "Fix Applied"
    return update_finding_github_fix(
        finding_id=finding_id,
        fix_status=status_val,
        repo=ai_fix_data.get("repository") or ai_fix_data.get("repo"),
        branch=ai_fix_data.get("branch"),
        commit_sha=ai_fix_data.get("commit_sha") or ai_fix_data.get("commit"),
        pr_url=ai_fix_data.get("pr_url") or ai_fix_data.get("pull_request"),
        validation=ai_fix_data.get("validation_status") or ai_fix_data.get("validation")
    )

def save_user_github_config(user_id: str, token: Optional[str], mode: str = "mock", username: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO user_github_configs (user_id, token, mode, username, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
        token = COALESCE(excluded.token, user_github_configs.token),
        mode = excluded.mode,
        username = COALESCE(excluded.username, user_github_configs.username),
        updated_at = excluded.updated_at
    """, (user_id, token, mode, username, now))
    conn.commit()
    conn.close()

def get_user_github_config(user_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_github_configs WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def delete_finding(finding_id: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT checklist_item_id FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    if row and row["checklist_item_id"]:
        cursor.execute("UPDATE checklist_items SET status = 'NOT_TESTED' WHERE id = ?", (row["checklist_item_id"],))

    cursor.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

# =========================================================================
# SEEDING DEFAULT STARTER PROJECTS
# =========================================================================

def seed_default_projects_if_empty():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM projects")
    count = cursor.fetchone()[0]
    if count > 0:
        conn.close()
        return

    logger.info("Seeding initial starter projects into SQLite database...")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    starter_projects = [
        {
            "id": "proj-ecommerce-001",
            "name": "E-Commerce Gateway & Auth Audit",
            "target_url": "https://shop.tracegate.lab",
            "description": "Authorized penetration test assessing user registration, multi-factor authentication, and payment handling.",
            "scope_notes": "Scope includes checkout, account reset, and cart endpoints.",
            "environment": "Web Application (Staging)",
            "status": "IN_PROGRESS",
            "created_by": "Security Learner",
            "created_at": "2026-08-28 10:00:00",
            "updated_at": "2026-09-03 16:30:00"
        },
        {
            "id": "proj-health-002",
            "name": "Patient Records EHR API Audit",
            "target_url": "https://ehr-api.medlab.test",
            "description": "Compliance assessment for HIPAA/OWASP ASVS patient record search and attachment upload endpoints.",
            "scope_notes": "Test API tokens provided in lab environment.",
            "environment": "API & Microservices",
            "status": "COMPLETED",
            "created_by": "Security Learner",
            "created_at": "2026-08-15 09:00:00",
            "updated_at": "2026-08-30 18:00:00"
        },
        {
            "id": "proj-fintech-003",
            "name": "Cloud Banking Admin Panel Review",
            "target_url": "https://admin.fintech-vault.stage",
            "description": "Role-based access control (RBAC) and audit log tampering assessment for internal financial staff.",
            "scope_notes": "Admin credentials provided for testing least-privilege.",
            "environment": "Web Application (Production)",
            "status": "NEEDS_REVIEW",
            "created_by": "Security Learner",
            "created_at": "2026-09-01 11:30:00",
            "updated_at": "2026-09-04 08:45:00"
        }
    ]

    for p in starter_projects:
        cursor.execute("""
        INSERT INTO projects (id, name, target_url, description, scope_notes, environment, status, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (p["id"], p["name"], p["target_url"], p["description"], p["scope_notes"], p["environment"], p["status"], p["created_by"], p["created_at"], p["updated_at"]))

    # Seed starter finding for proj-ecommerce-001
    finding_id = "find-ecommerce-001"
    cursor.execute("""
    INSERT INTO findings (id, project_id, checklist_item_id, finding_name, description, testing_notes, poc_text, evidence_filename, priority, recorded_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding_id,
        "proj-ecommerce-001",
        None,
        "Broken Authentication on Password Reset",
        "Password reset tokens do not expire upon use and have insufficient entropy (4-digit numeric pin).",
        "Requested reset token via /forgot-password, intercepted response, brute forced 4-digit code within 200 requests.",
        'POST /api/v1/auth/reset HTTP/1.1\nHost: shop.tracegate.lab\nContent-Type: application/json\n\n{"token": "1042", "new_password": "pwnedPass!"} -> 200 OK',
        "reset_token_bruteforce.png",
        "CRITICAL",
        "2026-09-02 14:22:00"
    ))

    conn.commit()
    conn.close()
    seed_default_users_if_empty()
    logger.info("Default starter projects and users seeded successfully.")

# =========================================================================
# AUTHENTICATION & SESSIONS CRUD
# =========================================================================

import hashlib
import secrets

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${pw_hash}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, pw_hash = stored_hash.split("$", 1)
        expected = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        return secrets.compare_digest(expected, pw_hash)
    except Exception:
        return False

def register_user(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_id = f"user-{int(datetime.now().timestamp()*1000)}"
    pw_hash = hash_password(data["password"])

    cursor.execute("""
    INSERT INTO users (id, username, email, password_hash, full_name, role, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        data["username"].strip().lower(),
        data["email"].strip().lower(),
        pw_hash,
        data.get("full_name", "Security Learner"),
        data.get("role", "Junior Pentester"),
        now
    ))
    conn.commit()
    cursor.execute("SELECT id, username, email, full_name, role, created_at FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row)

def authenticate_user(username_or_email: str, password: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    clean_val = username_or_email.strip().lower()
    cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (clean_val, clean_val))
    user = cursor.fetchone()
    conn.close()
    if not user:
        return None
    if verify_password(password, user["password_hash"]):
        u = dict(user)
        u.pop("password_hash", None)
        return u
    return None

def create_session(user_id: str) -> str:
    from datetime import timedelta
    conn = get_db_connection()
    cursor = conn.cursor()
    token = secrets.token_hex(32)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    expires = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO sessions (token, user_id, created_at, expires_at)
    VALUES (?, ?, ?, ?)
    """, (token, user_id, now, expires))
    conn.commit()
    conn.close()
    return token

def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    SELECT u.id, u.username, u.email, u.full_name, u.role, u.created_at
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ? AND s.expires_at > ?
    """, (token, now))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def delete_session(token: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def seed_default_users_if_empty():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    if count > 0:
        conn.close()
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    default_users = [
        {
            "id": "user-learner-001",
            "username": "learner",
            "email": "learner@tracegate.lab",
            "password": "Password123!",
            "full_name": "Security Learner",
            "role": "Junior Pentester"
        },
        {
            "id": "user-admin-001",
            "username": "admin",
            "email": "admin@tracegate.lab",
            "password": "AdminPassword123!",
            "full_name": "Lead Security Assessor",
            "role": "Lead Auditor"
        }
    ]
    for u in default_users:
        cursor.execute("""
        INSERT INTO users (id, username, email, password_hash, full_name, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (u["id"], u["username"], u["email"], hash_password(u["password"]), u["full_name"], u["role"], now))
    conn.commit()
    conn.close()
    logger.info("Default user accounts seeded (learner & admin).")

# =========================================================================
# REPORTS CRUD
# =========================================================================

def save_report_record(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rep_id = data.get("id") or f"rep-{int(datetime.now().timestamp()*1000)}"
    sel_ids = data.get("selected_finding_ids")
    sel_ids_json = json.dumps(sel_ids) if isinstance(sel_ids, list) else (sel_ids or "[]")
    
    cursor.execute("""
    INSERT INTO reports (
        id, project_id, version, report_title, file_path,
        total_findings, crit_count, high_count, med_count, low_count, info_count,
        selected_finding_ids, created_by, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rep_id,
        data["project_id"],
        data.get("version", "v1.0"),
        data.get("report_title", "Penetration Testing Assessment Report"),
        data["file_path"],
        data.get("total_findings", 0),
        data.get("crit_count", 0),
        data.get("high_count", 0),
        data.get("med_count", 0),
        data.get("low_count", 0),
        data.get("info_count", 0),
        sel_ids_json,
        data.get("created_by", "Security Learner"),
        now
    ))
    conn.commit()
    cursor.execute("SELECT * FROM reports WHERE id = ?", (rep_id,))
    row = cursor.fetchone()
    conn.close()
    d = dict(row)
    d["download_url"] = f"/api/projects/{d['project_id']}/reports/{d['id']}/download"
    d["filename"] = Path(d["file_path"]).name if d.get("file_path") else f"{d['project_id']}_{d['version']}.docx"
    d["author_name"] = d.get("created_by", "Security Learner")
    d["findings_count"] = d.get("total_findings", 0)
    d["info_count"] = d.get("info_count", 0)
    if d.get("selected_finding_ids") and isinstance(d["selected_finding_ids"], str):
        try:
            d["selected_finding_ids"] = json.loads(d["selected_finding_ids"])
        except Exception:
            d["selected_finding_ids"] = []
    else:
        d["selected_finding_ids"] = d.get("selected_finding_ids") or []
    return d

def get_project_reports(project_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reports WHERE project_id = ? ORDER BY created_at DESC", (project_id,))
    rows = cursor.fetchall()
    reports = []
    for r in rows:
        d = dict(r)
        d["download_url"] = f"/api/projects/{d['project_id']}/reports/{d['id']}/download"
        d["filename"] = Path(d["file_path"]).name if d.get("file_path") else f"{d['project_id']}_{d['version']}.docx"
        d["author_name"] = d.get("created_by", "Security Learner")
        d["findings_count"] = d.get("total_findings", 0)
        d["info_count"] = d.get("info_count", 0)
        if d.get("selected_finding_ids") and isinstance(d["selected_finding_ids"], str):
            try:
                d["selected_finding_ids"] = json.loads(d["selected_finding_ids"])
            except Exception:
                d["selected_finding_ids"] = []
        else:
            d["selected_finding_ids"] = d.get("selected_finding_ids") or []
        reports.append(d)
    conn.close()
    return reports

def get_report_by_id(report_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["download_url"] = f"/api/projects/{d['project_id']}/reports/{d['id']}/download"
    d["filename"] = Path(d["file_path"]).name if d.get("file_path") else f"{d['project_id']}_{d['version']}.docx"
    d["author_name"] = d.get("created_by", "Security Learner")
    d["findings_count"] = d.get("total_findings", 0)
    d["info_count"] = d.get("info_count", 0)
    if d.get("selected_finding_ids") and isinstance(d["selected_finding_ids"], str):
        try:
            d["selected_finding_ids"] = json.loads(d["selected_finding_ids"])
        except Exception:
            d["selected_finding_ids"] = []
    else:
        d["selected_finding_ids"] = d.get("selected_finding_ids") or []
    return d

def get_next_report_version(project_id: str) -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM reports WHERE project_id = ?", (project_id,))
    count = cursor.fetchone()[0]
    conn.close()
    return f"v{count + 1}.0"
