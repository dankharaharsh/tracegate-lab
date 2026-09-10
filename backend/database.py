import os
import sqlite3
import json
import logging
import uuid
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
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
    conn.execute("PRAGMA busy_timeout = 30000")
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
        ("ai_fix_json", "TEXT"),
        ("observation", "TEXT"),
        ("evidence_json", "TEXT"),
        ("source", "TEXT DEFAULT 'CHECKLIST'"),
        ("source_document_id", "TEXT"),
        ("source_document_name", "TEXT"),
        ("retest_status", "TEXT DEFAULT 'PENDING'"),
        ("retest_notes", "TEXT")
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

    # 5c. AI Fixes & GitHub code remediation tracking table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ai_fixes (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        repository TEXT NOT NULL,
        base_branch TEXT NOT NULL DEFAULT 'main',
        fix_branch TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_sha TEXT,
        commit_sha TEXT,
        commit_message TEXT,
        pr_number INTEGER,
        pr_url TEXT,
        pr_status TEXT DEFAULT 'Open',
        diff_unified TEXT,
        original_code TEXT,
        proposed_code TEXT,
        changes_json TEXT,
        explanation TEXT,
        security_impact TEXT,
        testing_recommendation TEXT,
        retest_checklist_json TEXT,
        retest_status TEXT DEFAULT 'PENDING',
        retest_notes TEXT,
        retested_at TEXT,
        status TEXT DEFAULT 'PROPOSED',
        revision_count INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
    )
    """)

    # 5d. Source discovery & multi-file mapping tracking table
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='source_discovery_results'")
    tbl_row = cursor.fetchone()
    if tbl_row and "FOREIGN KEY" in tbl_row[0]:
        cursor.execute("DROP TABLE source_discovery_results")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS source_discovery_results (
        id TEXT PRIMARY KEY,
        project_id TEXT,
        finding_id TEXT NOT NULL,
        repository TEXT NOT NULL,
        branch TEXT NOT NULL DEFAULT 'main',
        source_commit_sha TEXT NOT NULL DEFAULT 'main',
        selected_sources_json TEXT NOT NULL,
        candidate_sources_json TEXT NOT NULL,
        selection_source TEXT DEFAULT 'AUTOMATIC',
        discovery_status TEXT DEFAULT 'COMPLETED',
        created_at TEXT NOT NULL,
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
        ("selected_finding_ids", "TEXT"),
        ("methodology", "TEXT DEFAULT 'owasp_wstg'"),
        ("metadata_json", "TEXT")
    ]:
        if col_name not in existing_report_cols:
            cursor.execute(f"ALTER TABLE reports ADD COLUMN {col_name} {col_def}")

    cursor.execute("PRAGMA table_info(ai_fixes)")
    existing_fix_cols = [r["name"] for r in cursor.fetchall()]
    for col_name, col_def in [
        ("merge_commit_sha", "TEXT"),
        ("merged_at", "TEXT"),
        ("review_status", "TEXT DEFAULT 'PENDING'")
    ]:
        if col_name not in existing_fix_cols:
            cursor.execute(f"ALTER TABLE ai_fixes ADD COLUMN {col_name} {col_def}")

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

    # 9. Password Resets table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_resets (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash)")

    # 10. Users table 2FA column migrations
    cursor.execute("PRAGMA table_info(users)")
    existing_user_cols = [r["name"] for r in cursor.fetchall()]
    for col_name, col_def in [
        ("two_factor_enabled", "INTEGER DEFAULT 0"),
        ("two_factor_secret_encrypted", "TEXT"),
        ("two_factor_enabled_at", "TEXT"),
        ("two_factor_last_verified_at", "TEXT")
    ]:
        if col_name not in existing_user_cols:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")

    # 11. Two-Factor Pending Enrollments table (unconfirmed setup secrets)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS two_factor_pending_enrollments (
        user_id TEXT PRIMARY KEY,
        secret_encrypted TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # 12. Two-Factor Recovery Codes table (SHA-256 hashed single-use recovery codes)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS two_factor_recovery_codes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_2fa_recovery_user ON two_factor_recovery_codes(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_2fa_recovery_hash ON two_factor_recovery_codes(user_id, code_hash)")

    # 13. Two-Factor Pending Logins table (temporary challenge tokens)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS two_factor_pending_logins (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        attempts INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_2fa_pending_logins_user ON two_factor_pending_logins(user_id)")

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
    SELECT ci.*, f.id as finding_id, f.finding_name, f.description as finding_desc, f.observation as finding_observation,
           f.poc_text, f.evidence_filename, f.evidence_data, f.evidence_json
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
            ev_list = []
            if d.get("evidence_json"):
                try:
                    ev_list = json.loads(d["evidence_json"])
                except Exception:
                    ev_list = []
            if not ev_list and (d.get("evidence_filename") or d.get("evidence_data")):
                ev_list = [{
                    "name": d.get("evidence_filename") or "evidence.png",
                    "data": d.get("evidence_data"),
                    "type": "image/png"
                }]
            d["finding"] = {
                "id": d["finding_id"],
                "finding_name": d["finding_name"],
                "observation": d.get("finding_observation") or d.get("finding_desc") or "",
                "description": d.get("finding_desc") or d.get("finding_observation") or "",
                "poc_text": d["poc_text"],
                "evidence_filename": d["evidence_filename"],
                "evidence_data": d["evidence_data"],
                "evidence": ev_list
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

    observation_val = (finding_data.get("observation") or "").strip()
    desc_input = (finding_data.get("description") or "").strip()
    desc_val = observation_val or desc_input or tmpl.get("description", "")
    notes_val = finding_data.get("testing_notes") or tmpl.get("reproduction_steps", "")
    poc_val = finding_data.get("poc_text") or tmpl.get("poc_text", "")
    impact_val = finding_data.get("impact") or tmpl.get("impact", "")
    repro_val = finding_data.get("reproduction_steps") or tmpl.get("reproduction_steps", "")
    remed_val = finding_data.get("remediation") or tmpl.get("remediation", "")
    mitig_val = finding_data.get("mitigation") or tmpl.get("mitigation", "")
    cvss_val = finding_data.get("cvss_score") or tmpl.get("cvss_score", 7.5)
    status_val = finding_data.get("status") or "Open"
    fix_status_val = finding_data.get("fix_status") or "NOT_STARTED"

    # Multi-file evidence handling & persistence
    evidence_items = finding_data.get("evidence") or []
    if not evidence_items and (finding_data.get("evidence_filename") or finding_data.get("evidence_data")):
        evidence_items = [{
            "name": finding_data.get("evidence_filename") or "evidence.png",
            "data": finding_data.get("evidence_data"),
            "type": "image/png"
        }]

    first_ef = None
    first_ed = None
    if evidence_items:
        first_ef = evidence_items[0].get("name") or evidence_items[0].get("filename")
        first_ed = evidence_items[0].get("data") or evidence_items[0].get("url")
    if not first_ef:
        first_ef = finding_data.get("evidence_filename")
    if not first_ed:
        first_ed = finding_data.get("evidence_data")

    evidence_json_str = json.dumps(evidence_items)

    source_val = finding_data.get("source") or "CHECKLIST"
    source_doc_id = finding_data.get("source_document_id")
    source_doc_name = finding_data.get("source_document_name")
    retest_status_val = finding_data.get("retest_status") or "PENDING"
    retest_notes_val = finding_data.get("retest_notes") or ""

    cursor.execute("""
    INSERT INTO findings (
        id, project_id, checklist_item_id, vuln_id, finding_name, severity_source,
        affected_url, affected_endpoint, affected_component, description, observation, testing_notes,
        poc_text, evidence_filename, evidence_data, evidence_json, priority, cwe, cvss_score,
        impact, reproduction_steps, remediation, mitigation, status, fix_status,
        github_repo, github_branch, github_commit, github_pr, github_validation,
        source, source_document_id, source_document_name, retest_status, retest_notes, recorded_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding_id,
        project_id,
        item_id,
        vuln_id,
        name_val,
        severity_source_val,
        finding_data.get("affected_url") or finding_data.get("target_url"),
        finding_data.get("affected_endpoint") or finding_data.get("endpoint") or finding_data.get("component"),
        finding_data.get("affected_component") or finding_data.get("component"),
        desc_val,
        observation_val or desc_val,
        notes_val,
        poc_val,
        first_ef,
        first_ed,
        evidence_json_str,
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
        source_val,
        source_doc_id,
        source_doc_name,
        retest_status_val,
        retest_notes_val,
        now
    ))

    cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    conn.close()
    d = dict(row)
    ev_list = []
    if d.get("evidence_json"):
        try:
            ev_list = json.loads(d["evidence_json"])
        except Exception:
            ev_list = []
    if not ev_list and (d.get("evidence_filename") or d.get("evidence_data")):
        ev_list = [{"name": d.get("evidence_filename") or "evidence.png", "data": d.get("evidence_data"), "type": "image/png"}]
    d["evidence"] = ev_list
    d["observation"] = d.get("observation") or d.get("description") or ""
    d["source"] = d.get("source") or "CHECKLIST"
    d["source_document_id"] = d.get("source_document_id")
    d["source_document_name"] = d.get("source_document_name")
    d["retest_status"] = d.get("retest_status") or "PENDING"
    d["retest_notes"] = d.get("retest_notes") or ""
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

def save_imported_findings(
    project_id: str,
    candidate_findings: List[Dict[str, Any]],
    source_doc_id: Optional[str] = None,
    source_doc_name: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Persist confirmed candidate findings from an external VAPT report into the project's authoritative findings.
    Assigns unique finding IDs, establishes traceable provenance, and updates project timestamps.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    cursor.execute("SELECT COUNT(*) FROM findings WHERE project_id = ?", (project_id,))
    existing_count = cursor.fetchone()[0]

    imported_records = []
    for idx, cand in enumerate(candidate_findings):
        fid = cand.get("id") or f"find-import-{int(datetime.now().timestamp() * 1000)}-{uuid.uuid4().hex[:6]}"
        vuln_id = f"VULN-{existing_count + idx + 1:03d}"
        name = (cand.get("title") or cand.get("finding_name") or "Imported Security Finding").strip()
        priority = (cand.get("severity") or cand.get("priority") or "HIGH").upper()
        if priority not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            priority = "MEDIUM"
        cwe = cand.get("cwe") or "CWE-200"
        cvss = cand.get("cvss_score") or (9.0 if priority == "CRITICAL" else 7.5 if priority == "HIGH" else 5.0 if priority == "MEDIUM" else 3.0 if priority == "LOW" else 0.0)
        desc = cand.get("description") or ""
        obs = cand.get("observation") or desc
        imp = cand.get("impact") or ""
        repro = cand.get("steps_to_reproduce") or cand.get("reproduction_steps") or cand.get("testing_notes") or ""
        poc = cand.get("poc") or cand.get("poc_text") or ""
        remed = cand.get("remediation") or ""
        mitig = cand.get("mitigation") or ""
        url = cand.get("affected_url") or ""
        comp = cand.get("affected_component") or ""
        status_val = cand.get("status") or "Open"
        
        evidence_list = cand.get("evidence") or []
        first_ef = None
        first_ed = None
        if evidence_list:
            first_ef = evidence_list[0].get("name") or evidence_list[0].get("filename")
            first_ed = evidence_list[0].get("data") or evidence_list[0].get("url")
        ev_json = json.dumps(evidence_list)

        cursor.execute("""
        INSERT INTO findings (
            id, project_id, checklist_item_id, vuln_id, finding_name, severity_source,
            affected_url, affected_endpoint, affected_component, description, observation, testing_notes,
            poc_text, evidence_filename, evidence_data, evidence_json, priority, cwe, cvss_score,
            impact, reproduction_steps, remediation, mitigation, status, fix_status,
            source, source_document_id, source_document_name, retest_status, retest_notes, recorded_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            fid, project_id, cand.get("checklist_item_id"), vuln_id, name, "IMPORTED",
            url, url, comp, desc, obs, repro,
            poc, first_ef, first_ed, ev_json, priority, cwe, cvss,
            imp, repro, remed, mitig, status_val, cand.get("fix_status") or "NOT_STARTED",
            "IMPORTED_REPORT", source_doc_id, source_doc_name, cand.get("retest_status") or "PENDING", cand.get("retest_notes") or "", now
        ))

        imported_records.append({
            "id": fid,
            "project_id": project_id,
            "vuln_id": vuln_id,
            "finding_name": name,
            "priority": priority,
            "cwe": cwe,
            "cvss_score": cvss,
            "affected_url": url,
            "affected_component": comp,
            "description": desc,
            "observation": obs,
            "impact": imp,
            "reproduction_steps": repro,
            "poc_text": poc,
            "remediation": remed,
            "mitigation": mitig,
            "evidence": evidence_list,
            "evidence_filename": first_ef,
            "evidence_data": first_ed,
            "status": status_val,
            "fix_status": "NOT_STARTED",
            "source": "IMPORTED_REPORT",
            "source_document_id": source_doc_id,
            "source_document_name": source_doc_name,
            "retest_status": "PENDING",
            "retest_notes": "",
            "recorded_at": now
        })

    cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    conn.close()
    return imported_records

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
        ev_list = []
        if d.get("evidence_json"):
            try:
                ev_list = json.loads(d["evidence_json"])
            except Exception:
                ev_list = []
        if not ev_list and (d.get("evidence_filename") or d.get("evidence_data")):
            ev_list = [{"name": d.get("evidence_filename") or "evidence.png", "data": d.get("evidence_data"), "type": "image/png"}]
        d["evidence"] = ev_list
        d["observation"] = d.get("observation") or d.get("description") or ""
        d["source"] = d.get("source") or "CHECKLIST"
        d["source_document_id"] = d.get("source_document_id")
        d["source_document_name"] = d.get("source_document_name")
        d["retest_status"] = d.get("retest_status") or "PENDING"
        d["retest_notes"] = d.get("retest_notes") or ""
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
    ev_list = []
    if d.get("evidence_json"):
        try:
            ev_list = json.loads(d["evidence_json"])
        except Exception:
            ev_list = []
    if not ev_list and (d.get("evidence_filename") or d.get("evidence_data")):
        ev_list = [{"name": d.get("evidence_filename") or "evidence.png", "data": d.get("evidence_data"), "type": "image/png"}]
    d["evidence"] = ev_list
    d["observation"] = d.get("observation") or d.get("description") or ""
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
        token = excluded.token,
        mode = excluded.mode,
        username = excluded.username,
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
# AI FIXES & REMEDIATION AUDIT CRUD
# =========================================================================

def _hydrate_ai_fix_row(row_dict: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(row_dict)
    if d.get("changes_json"):
        try:
            d["changes"] = json.loads(d["changes_json"])
        except Exception:
            d["changes"] = []
    else:
        d["changes"] = []

    if d.get("retest_checklist_json"):
        try:
            d["retest_checklist"] = json.loads(d["retest_checklist_json"])
        except Exception:
            d["retest_checklist"] = []
    else:
        d["retest_checklist"] = []
    return d

def save_ai_fix_record(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fix_id = data.get("id") or f"fix-{int(datetime.now().timestamp() * 1000)}-{uuid.uuid4().hex[:6]}"

    proj_id = data.get("project_id") or "proj-default"
    finding_id = data.get("finding_id") or "find-default"

    cursor.execute("SELECT id FROM projects WHERE id = ?", (proj_id,))
    if not cursor.fetchone():
        cursor.execute("INSERT OR IGNORE INTO projects (id, name, target_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", (proj_id, "Default Project", "https://localhost", now, now))
        conn.commit()

    cursor.execute("SELECT id FROM findings WHERE id = ?", (finding_id,))
    if not cursor.fetchone():
        cursor.execute("INSERT OR IGNORE INTO findings (id, project_id, finding_name, priority, cwe, status, fix_status, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (finding_id, proj_id, "Vulnerability Finding", "HIGH", "CWE-200", "Open", "NOT_STARTED", now))
        conn.commit()

    changes_raw = data.get("changes") or []
    changes_json = json.dumps(changes_raw) if isinstance(changes_raw, list) else (data.get("changes_json") or "[]")

    checklist_raw = data.get("retest_checklist") or []
    checklist_json = json.dumps(checklist_raw) if isinstance(checklist_raw, list) else (data.get("retest_checklist_json") or "[]")

    cursor.execute("""
    INSERT INTO ai_fixes (
        id, project_id, finding_id, repository, base_branch, fix_branch,
        file_path, file_sha, commit_sha, commit_message, pr_number, pr_url, pr_status,
        diff_unified, original_code, proposed_code, changes_json, explanation,
        security_impact, testing_recommendation, retest_checklist_json,
        retest_status, retest_notes, retested_at, status, revision_count,
        created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        fix_id,
        data["project_id"],
        data["finding_id"],
        data.get("repository") or data.get("repo") or "tracegate-lab/ecommerce-platform",
        data.get("base_branch") or "main",
        data.get("fix_branch") or f"tracegate/fix/{data['finding_id']}",
        data.get("file_path") or "",
        data.get("file_sha"),
        data.get("commit_sha"),
        data.get("commit_message"),
        data.get("pr_number"),
        data.get("pr_url"),
        data.get("pr_status") or "Open",
        data.get("diff_unified") or data.get("unified_diff") or "",
        data.get("original_code") or data.get("before_code") or "",
        data.get("proposed_code") or data.get("after_code") or "",
        changes_json,
        data.get("explanation") or "",
        data.get("security_impact") or "",
        data.get("testing_recommendation") or "",
        checklist_json,
        data.get("retest_status") or "PENDING",
        data.get("retest_notes") or "",
        data.get("retested_at"),
        data.get("status") or "PROPOSED",
        data.get("revision_count", 0),
        now,
        now
    ))
    conn.commit()
    cursor.execute("SELECT * FROM ai_fixes WHERE id = ?", (fix_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_ai_fix_row(dict(row))

def get_ai_fix_by_id(fix_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ai_fixes WHERE id = ?", (fix_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_ai_fix_row(dict(row))

def get_ai_fix_for_finding(finding_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ai_fixes WHERE finding_id = ? ORDER BY revision_count DESC, updated_at DESC, rowid DESC LIMIT 1", (finding_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_ai_fix_row(dict(row))

def get_ai_fix_by_pr_number(pr_number: int, repo: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if repo:
        cursor.execute("SELECT * FROM ai_fixes WHERE pr_number = ? AND repository = ? ORDER BY updated_at DESC, rowid DESC LIMIT 1", (pr_number, repo))
    else:
        cursor.execute("SELECT * FROM ai_fixes WHERE pr_number = ? ORDER BY updated_at DESC, rowid DESC LIMIT 1", (pr_number,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_ai_fix_row(dict(row))

def update_ai_fix_record(fix_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    changes_json = None
    if "changes" in data:
        changes_json = json.dumps(data["changes"]) if isinstance(data["changes"], list) else data["changes"]

    checklist_json = None
    if "retest_checklist" in data:
        checklist_json = json.dumps(data["retest_checklist"]) if isinstance(data["retest_checklist"], list) else data["retest_checklist"]

    cursor.execute("""
    UPDATE ai_fixes SET
        repository = COALESCE(?, repository),
        base_branch = COALESCE(?, base_branch),
        fix_branch = COALESCE(?, fix_branch),
        file_path = COALESCE(?, file_path),
        file_sha = COALESCE(?, file_sha),
        commit_sha = COALESCE(?, commit_sha),
        commit_message = COALESCE(?, commit_message),
        pr_number = COALESCE(?, pr_number),
        pr_url = COALESCE(?, pr_url),
        pr_status = COALESCE(?, pr_status),
        diff_unified = COALESCE(?, diff_unified),
        original_code = COALESCE(?, original_code),
        proposed_code = COALESCE(?, proposed_code),
        changes_json = COALESCE(?, changes_json),
        explanation = COALESCE(?, explanation),
        security_impact = COALESCE(?, security_impact),
        testing_recommendation = COALESCE(?, testing_recommendation),
        retest_checklist_json = COALESCE(?, retest_checklist_json),
        retest_status = COALESCE(?, retest_status),
        retest_notes = COALESCE(?, retest_notes),
        retested_at = COALESCE(?, retested_at),
        status = COALESCE(?, status),
        revision_count = COALESCE(?, revision_count),
        merge_commit_sha = COALESCE(?, merge_commit_sha),
        merged_at = COALESCE(?, merged_at),
        review_status = COALESCE(?, review_status),
        updated_at = ?
    WHERE id = ?
    """, (
        data.get("repository") or data.get("repo"),
        data.get("base_branch"),
        data.get("fix_branch"),
        data.get("file_path"),
        data.get("file_sha"),
        data.get("commit_sha"),
        data.get("commit_message"),
        data.get("pr_number"),
        data.get("pr_url"),
        data.get("pr_status"),
        data.get("diff_unified") or data.get("unified_diff"),
        data.get("original_code") or data.get("before_code"),
        data.get("proposed_code") or data.get("after_code"),
        changes_json,
        data.get("explanation"),
        data.get("security_impact"),
        data.get("testing_recommendation"),
        checklist_json,
        data.get("retest_status"),
        data.get("retest_notes"),
        data.get("retested_at"),
        data.get("status"),
        data.get("revision_count"),
        data.get("merge_commit_sha"),
        data.get("merged_at"),
        data.get("review_status"),
        now,
        fix_id
    ))
    conn.commit()
    cursor.execute("SELECT * FROM ai_fixes WHERE id = ?", (fix_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_ai_fix_row(dict(row))

def list_ai_fixes_for_project(project_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ai_fixes WHERE project_id = ? ORDER BY updated_at DESC", (project_id,))
    rows = cursor.fetchall()
    conn.close()
    return [_hydrate_ai_fix_row(dict(r)) for r in rows]

def record_finding_retest(
    finding_id: str,
    fix_id: Optional[str] = None,
    result: str = "PASS",
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Record tester retest verification.
    PASS -> finding.status = 'RESOLVED', retest_status = 'PASSED'.
    FAIL -> finding.status = 'REOPENED', retest_status = 'FAILED'.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    normalized_res = result.upper()
    is_pass = "PASS" in normalized_res

    target_finding_status = "RESOLVED" if is_pass else "REOPENED"
    target_fix_status = "RESOLVED" if is_pass else "RETEST_FAILED"
    retest_stat = "PASSED" if is_pass else "FAILED"

    # Update finding
    cursor.execute("""
    UPDATE findings SET
        status = ?,
        fix_status = ?,
        retest_status = ?,
        retest_notes = COALESCE(?, retest_notes)
    WHERE id = ? OR vuln_id = ?
    """, (target_finding_status, target_fix_status, retest_stat, notes or "", finding_id, finding_id))

    # Update ai_fixes record if present
    if fix_id:
        cursor.execute("""
        UPDATE ai_fixes SET
            retest_status = ?,
            retest_notes = COALESCE(?, retest_notes),
            retested_at = ?,
            status = ?,
            updated_at = ?
        WHERE id = ?
        """, (retest_stat, notes or "", now, target_finding_status, now, fix_id))
    else:
        cursor.execute("""
        UPDATE ai_fixes SET
            retest_status = ?,
            retest_notes = COALESCE(?, retest_notes),
            retested_at = ?,
            status = ?,
            updated_at = ?
        WHERE finding_id = ?
        """, (retest_stat, notes or "", now, target_finding_status, now, finding_id))

    # Find project_id to update project updated_at
    cursor.execute("SELECT project_id FROM findings WHERE id = ? OR vuln_id = ? LIMIT 1", (finding_id, finding_id))
    f_row = cursor.fetchone()
    if f_row:
        cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, f_row["project_id"]))

    conn.commit()
    conn.close()

    updated_finding = get_finding_by_id(finding_id)
    return {
        "finding_id": finding_id,
        "fix_id": fix_id,
        "result": retest_stat,
        "status": target_finding_status,
        "retest_status": retest_stat,
        "notes": notes or "",
        "updated_at": now,
        "finding": updated_finding
    }

# =========================================================================
# SOURCE DISCOVERY PERSISTENCE (PHASE 1)
# =========================================================================

def _hydrate_source_discovery_row(row_dict: Dict[str, Any]) -> Dict[str, Any]:
    if not row_dict:
        return {}
    d = dict(row_dict)
    for field in ("selected_sources_json", "candidate_sources_json"):
        val = d.get(field)
        key = "selected_sources" if field == "selected_sources_json" else "candidate_sources"
        if val and isinstance(val, str):
            try:
                d[key] = json.loads(val)
            except Exception:
                d[key] = []
        elif key not in d:
            d[key] = []
    return d

def save_source_discovery(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disc_id = data.get("id") or f"disc-{uuid.uuid4().hex[:12]}"
    project_id = data.get("project_id") or "proj-default"
    finding_id = data["finding_id"]
    repo = data.get("repository") or data.get("repo") or "tracegate-lab/ecommerce-platform"
    branch = data.get("branch") or "main"
    sha = data.get("source_commit_sha") or "main"
    sel_json = json.dumps(data.get("selected_sources", []))
    cand_json = json.dumps(data.get("candidate_sources", []))
    sel_src = data.get("selection_source", "AUTOMATIC")
    status = data.get("discovery_status", "COMPLETED")

    cursor.execute("""
    SELECT id FROM source_discovery_results 
    WHERE (finding_id = ? OR finding_id IN (SELECT vuln_id FROM findings WHERE id = ?))
      AND project_id = ?
    LIMIT 1
    """, (finding_id, finding_id, project_id))
    existing = cursor.fetchone()

    if existing:
        disc_id = existing["id"]
        cursor.execute("""
        UPDATE source_discovery_results SET
            repository = ?,
            branch = ?,
            source_commit_sha = ?,
            selected_sources_json = ?,
            candidate_sources_json = ?,
            selection_source = ?,
            discovery_status = ?,
            updated_at = ?
        WHERE id = ?
        """, (repo, branch, sha, sel_json, cand_json, sel_src, status, now, disc_id))
    else:
        cursor.execute("""
        INSERT INTO source_discovery_results (
            id, project_id, finding_id, repository, branch,
            source_commit_sha, selected_sources_json, candidate_sources_json,
            selection_source, discovery_status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (disc_id, project_id, finding_id, repo, branch, sha, sel_json, cand_json, sel_src, status, now, now))

    conn.commit()
    cursor.execute("SELECT * FROM source_discovery_results WHERE id = ?", (disc_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_source_discovery_row(dict(row))

def get_source_discovery(finding_id: str, project_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if project_id:
        cursor.execute("""
        SELECT * FROM source_discovery_results 
        WHERE (finding_id = ? OR finding_id IN (SELECT vuln_id FROM findings WHERE id = ?))
          AND project_id = ?
        ORDER BY updated_at DESC LIMIT 1
        """, (finding_id, finding_id, project_id))
    else:
        cursor.execute("""
        SELECT * FROM source_discovery_results 
        WHERE finding_id = ? OR finding_id IN (SELECT vuln_id FROM findings WHERE id = ?)
        ORDER BY updated_at DESC LIMIT 1
        """, (finding_id, finding_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_source_discovery_row(dict(row))

def update_source_discovery_selection(
    finding_id: str,
    selected_paths: List[str],
    project_id: Optional[str] = None,
    source_commit_sha: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    disc = get_source_discovery(finding_id, project_id)
    if not disc:
        # Create minimal record if none exists yet
        disc = save_source_discovery({
            "project_id": project_id or "proj-default",
            "finding_id": finding_id,
            "repository": "tracegate-lab/ecommerce-platform",
            "branch": "main",
            "source_commit_sha": source_commit_sha or "main",
            "selected_sources": [],
            "candidate_sources": [],
            "selection_source": "USER_MODIFIED"
        })

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    old_selected = disc.get("selected_sources", [])
    old_candidates = disc.get("candidate_sources", [])
    path_map = {item["path"]: item for item in (old_selected + old_candidates) if isinstance(item, dict) and "path" in item}

    new_selected = []
    for p in selected_paths:
        if p in path_map:
            item = dict(path_map[p])
            item["confidence"] = "HIGH"
            item["relevance_score"] = max(item.get("relevance_score", 0), 85)
            reasons = list(item.get("reasons", []))
            if "Manually selected by developer" not in reasons:
                reasons.append("Manually selected by developer")
            item["reasons"] = reasons
            new_selected.append(item)
        else:
            new_selected.append({
                "path": p,
                "layer": "source",
                "language": os.path.splitext(p)[1].lstrip(".") or "Unknown",
                "symbols": [],
                "relevance_score": 90,
                "confidence": "HIGH",
                "reasons": ["Manually selected by developer"]
            })

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE source_discovery_results SET
        selected_sources_json = ?,
        selection_source = 'USER_MODIFIED',
        source_commit_sha = COALESCE(?, source_commit_sha),
        updated_at = ?
    WHERE id = ?
    """, (json.dumps(new_selected), source_commit_sha, now, disc["id"]))
    conn.commit()
    cursor.execute("SELECT * FROM source_discovery_results WHERE id = ?", (disc["id"],))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_source_discovery_row(dict(row))

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
from datetime import timedelta

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    salt_bytes = bytes.fromhex(salt)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt_bytes, n=16384, r=8, p=1)
    return f"scrypt$16384$8$1${salt}${derived.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        if not stored_hash:
            return False
        if stored_hash.startswith("scrypt$"):
            parts = stored_hash.split("$")
            if len(parts) == 6:
                _, n_str, r_str, p_str, salt_hex, hash_hex = parts
                n = int(n_str)
                r = int(r_str)
                p = int(p_str)
                salt_bytes = bytes.fromhex(salt_hex)
                computed = hashlib.scrypt(password.encode("utf-8"), salt=salt_bytes, n=n, r=r, p=p).hex()
                return secrets.compare_digest(computed, hash_hex)
        # Legacy fallback: salt$sha256_hash
        if "$" in stored_hash:
            salt, pw_hash = stored_hash.split("$", 1)
            expected = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
            return secrets.compare_digest(expected, pw_hash)
        return False
    except Exception:
        return False

def is_legacy_hash(stored_hash: str) -> bool:
    return not stored_hash.startswith("scrypt$")

def register_user(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        clean_username = data["username"].strip().lower()
        clean_email = data["email"].strip().lower()

        # Explicit uniqueness pre-check to give clean feedback and prevent concurrency locks
        cursor.execute("SELECT id, username, email FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (clean_username, clean_email))
        existing = cursor.fetchone()
        if existing:
            if existing["username"].lower() == clean_username:
                raise ValueError("Username already taken. Please choose another username.")
            else:
                raise ValueError("Email already registered. Please sign in or use another email.")

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user_id = f"user-{int(datetime.now().timestamp()*1000)}"
        pw_hash = hash_password(data["password"])
        full_name = data.get("full_name") or data.get("name") or "Security Learner"
        role = data.get("role", "Junior Pentester")

        cursor.execute("""
        INSERT INTO users (id, username, email, password_hash, full_name, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            clean_username,
            clean_email,
            pw_hash,
            full_name,
            role,
            now
        ))
        conn.commit()
        cursor.execute("SELECT id, username, email, full_name, role, created_at FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        res = dict(row)
        res["name"] = res["full_name"]
        return res
    finally:
        conn.close()

def authenticate_user(username_or_email: str, password: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        clean_val = username_or_email.strip().lower()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (clean_val, clean_val))
        user = cursor.fetchone()
        if not user:
            return None
        
        stored_hash = user["password_hash"]
        if verify_password(password, stored_hash):
            # Auto-upgrade legacy sha256 to modern scrypt
            if is_legacy_hash(stored_hash):
                try:
                    new_hash = hash_password(password)
                    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
                    conn.commit()
                except Exception as ex:
                    logger.warning(f"Failed to auto-upgrade legacy hash for user {user['id']}: {ex}")
            
            u = dict(user)
            u.pop("password_hash", None)
            u.pop("two_factor_secret_encrypted", None)
            u["name"] = u.get("full_name", "")
            u["two_factor_enabled"] = bool(u.get("two_factor_enabled", 0))
            return u
        return None
    finally:
        conn.close()

def create_session(user_id: str) -> str:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        token = secrets.token_hex(32)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        expires = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
        INSERT INTO sessions (token, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """, (token, user_id, now, expires))
        conn.commit()
        return token
    finally:
        conn.close()

def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
        SELECT u.id, u.username, u.email, u.full_name, u.role, u.created_at,
               u.two_factor_enabled, u.two_factor_enabled_at, u.two_factor_last_verified_at
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ? AND s.expires_at > ?
        """, (token, now))
        row = cursor.fetchone()
        if row:
            d = dict(row)
            d["name"] = d.get("full_name", "")
            d["two_factor_enabled"] = bool(d.get("two_factor_enabled", 0))
            return d
        return None
    finally:
        conn.close()

def delete_session(token: str) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()

def delete_user_sessions(user_id: str) -> int:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        count = cursor.rowcount
        conn.commit()
        return count
    finally:
        conn.close()

def create_password_reset(email: str) -> Optional[Tuple[str, str]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        clean_email = email.strip().lower()
        cursor.execute("SELECT id, email FROM users WHERE LOWER(email) = ?", (clean_email,))
        user = cursor.fetchone()
        if not user:
            return None
        
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        now = datetime.now()
        expires = (now + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        reset_id = f"rst-{secrets.token_hex(8)}"

        cursor.execute("""
        INSERT INTO password_resets (id, user_id, token_hash, expires_at, used_at, created_at)
        VALUES (?, ?, ?, ?, NULL, ?)
        """, (reset_id, user["id"], token_hash, expires, now_str))
        conn.commit()
        return raw_token, user["email"]
    finally:
        conn.close()

def validate_reset_token(raw_token: str) -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("SELECT * FROM password_resets WHERE token_hash = ?", (token_hash,))
        record = cursor.fetchone()
        if not record:
            return {"valid": False, "reason": "Invalid or unknown password reset token."}
        if record["used_at"] is not None:
            return {"valid": False, "reason": "This password reset token has already been used."}
        if record["expires_at"] <= now_str:
            return {"valid": False, "reason": "This password reset token has expired. Please request a new one."}
        return {"valid": True, "record": dict(record)}
    finally:
        conn.close()

def complete_password_reset(raw_token: str, new_password: str) -> bool:
    validation = validate_reset_token(raw_token)
    if not validation["valid"]:
        raise ValueError(validation["reason"])
    
    record = validation["record"]
    user_id = record["user_id"]
    new_hash = hash_password(new_password)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        cursor.execute("UPDATE password_resets SET used_at = ? WHERE id = ?", (now_str, record["id"]))
        # Invalidate existing sessions for this user for security
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()
        return True
    finally:
        conn.close()

def seed_default_users_if_empty():
    init_db()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        if count > 0:
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
        logger.info("Default user accounts seeded (learner & admin).")
    finally:
        conn.close()

# =========================================================================
# TWO-FACTOR AUTHENTICATION (TOTP) CRUD
# =========================================================================

def get_user_by_id_raw(user_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_user_2fa_status(user_id: str) -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT two_factor_enabled, two_factor_enabled_at, two_factor_last_verified_at FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            return {"enabled": False, "enabled_at": None, "last_verified_at": None, "recovery_codes_remaining": 0}
        
        cursor.execute("SELECT COUNT(*) FROM two_factor_recovery_codes WHERE user_id = ? AND used_at IS NULL", (user_id,))
        rec_count = cursor.fetchone()[0]

        return {
            "enabled": bool(user_row["two_factor_enabled"]),
            "enabled_at": user_row["two_factor_enabled_at"],
            "last_verified_at": user_row["two_factor_last_verified_at"],
            "recovery_codes_remaining": rec_count
        }
    finally:
        conn.close()

def save_pending_2fa_enrollment(user_id: str, secret_encrypted: str, ttl_minutes: int = 15) -> str:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        expires_str = (now + timedelta(minutes=ttl_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT OR REPLACE INTO two_factor_pending_enrollments (user_id, secret_encrypted, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        """, (user_id, secret_encrypted, now_str, expires_str))
        conn.commit()
        return expires_str
    finally:
        conn.close()

def get_pending_2fa_enrollment(user_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            SELECT * FROM two_factor_pending_enrollments
            WHERE user_id = ? AND expires_at > ?
        """, (user_id, now_str))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def delete_pending_2fa_enrollment(user_id: str) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM two_factor_pending_enrollments WHERE user_id = ?", (user_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()

def enable_user_2fa(user_id: str, secret_encrypted: str, recovery_code_hashes: List[str]) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            UPDATE users
            SET two_factor_enabled = 1,
                two_factor_secret_encrypted = ?,
                two_factor_enabled_at = ?,
                two_factor_last_verified_at = ?
            WHERE id = ?
        """, (secret_encrypted, now_str, now_str, user_id))
        
        cursor.execute("DELETE FROM two_factor_pending_enrollments WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM two_factor_recovery_codes WHERE user_id = ?", (user_id,))
        
        for ch in recovery_code_hashes:
            rec_id = f"rc-{secrets.token_hex(8)}"
            cursor.execute("""
                INSERT INTO two_factor_recovery_codes (id, user_id, code_hash, used_at, created_at)
                VALUES (?, ?, ?, NULL, ?)
            """, (rec_id, user_id, ch, now_str))
        
        conn.commit()
        return True
    finally:
        conn.close()

def disable_user_2fa(user_id: str) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users
            SET two_factor_enabled = 0,
                two_factor_secret_encrypted = NULL,
                two_factor_enabled_at = NULL,
                two_factor_last_verified_at = NULL
            WHERE id = ?
        """, (user_id,))
        cursor.execute("DELETE FROM two_factor_pending_enrollments WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM two_factor_recovery_codes WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM two_factor_pending_logins WHERE user_id = ?", (user_id,))
        conn.commit()
        return True
    finally:
        conn.close()

def replace_recovery_codes(user_id: str, recovery_code_hashes: List[str]) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("DELETE FROM two_factor_recovery_codes WHERE user_id = ?", (user_id,))
        for ch in recovery_code_hashes:
            rec_id = f"rc-{secrets.token_hex(8)}"
            cursor.execute("""
                INSERT INTO two_factor_recovery_codes (id, user_id, code_hash, used_at, created_at)
                VALUES (?, ?, ?, NULL, ?)
            """, (rec_id, user_id, ch, now_str))
        conn.commit()
        return True
    finally:
        conn.close()

def create_pending_2fa_login(user_id: str, ttl_minutes: int = 5) -> str:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM two_factor_pending_logins WHERE user_id = ?", (user_id,))
        
        token = f"2fa_pend_{secrets.token_urlsafe(32)}"
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        expires_str = (now + timedelta(minutes=ttl_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute("""
            INSERT INTO two_factor_pending_logins (token, user_id, attempts, created_at, expires_at)
            VALUES (?, ?, 0, ?, ?)
        """, (token, user_id, now_str, expires_str))
        conn.commit()
        return token
    finally:
        conn.close()

def get_pending_2fa_login(token: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            SELECT * FROM two_factor_pending_logins
            WHERE token = ? AND expires_at > ?
        """, (token, now_str))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def increment_pending_2fa_attempts(token: str) -> int:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE two_factor_pending_logins SET attempts = attempts + 1 WHERE token = ?", (token,))
        cursor.execute("SELECT attempts FROM two_factor_pending_logins WHERE token = ?", (token,))
        row = cursor.fetchone()
        conn.commit()
        return row[0] if row else 999
    finally:
        conn.close()

def delete_pending_2fa_login(token: str) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM two_factor_pending_logins WHERE token = ?", (token,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()

def verify_and_consume_recovery_code(user_id: str, raw_code: str) -> bool:
    if not raw_code:
        return False
    from backend.totp_service import hash_recovery_code
    code_hash = hash_recovery_code(raw_code)
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id FROM two_factor_recovery_codes
            WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
            LIMIT 1
        """, (user_id, code_hash))
        row = cursor.fetchone()
        if not row:
            return False
        
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE two_factor_recovery_codes SET used_at = ? WHERE id = ?", (now_str, row["id"]))
        cursor.execute("UPDATE users SET two_factor_last_verified_at = ? WHERE id = ?", (now_str, user_id))
        conn.commit()
        return True
    finally:
        conn.close()

def update_user_2fa_verified_timestamp(user_id: str):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE users SET two_factor_last_verified_at = ? WHERE id = ?", (now_str, user_id))
        conn.commit()
    finally:
        conn.close()

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
        selected_finding_ids, created_by, methodology, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        data.get("methodology", "owasp_wstg"),
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

# =============================================================================
# SOURCE DISCOVERY & MULTI-FILE REPOSITORY PERSISTENCE
# =============================================================================

def _hydrate_source_discovery_row(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    for field in ["selected_sources", "candidate_sources"]:
        json_field = f"{field}_json"
        if json_field in d and isinstance(d[json_field], str):
            try:
                d[field] = json.loads(d[json_field])
            except Exception:
                d[field] = []
        else:
            d[field] = d.get(field) or []
    d["selection_mode"] = d.get("selection_source") or "AUTOMATIC"
    d["repo"] = d.get("repository") or ""
    return d

def save_source_discovery(data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
    if data is None:
        data = kwargs
    elif isinstance(data, dict) and kwargs:
        data = {**data, **kwargs}
    elif not isinstance(data, dict):
        data = kwargs

    conn = get_db_connection()
    cursor = conn.cursor()
    record_id = data.get("id") or str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    project_id = data.get("project_id", "")
    finding_id = data.get("finding_id", "")
    repository = data.get("repository") or data.get("repo") or ""
    branch = data.get("branch", "main")
    source_commit_sha = data.get("source_commit_sha", "main")

    selected_sources = data.get("selected_sources") or []
    candidate_sources = data.get("candidate_sources") or []
    selection_source = data.get("selection_mode") or data.get("selection_source", "AUTOMATIC")
    discovery_status = data.get("discovery_status", "COMPLETED")

    # Serialize items cleanly, converting Pydantic models to dict if needed
    clean_sel = [s.model_dump() if hasattr(s, "model_dump") else (s.dict() if hasattr(s, "dict") else s) for s in selected_sources]
    clean_cand = [c.model_dump() if hasattr(c, "model_dump") else (c.dict() if hasattr(c, "dict") else c) for c in candidate_sources]
    sel_json = json.dumps(clean_sel)
    cand_json = json.dumps(clean_cand)

    cursor.execute("SELECT id FROM source_discovery_results WHERE finding_id = ?", (finding_id,))
    existing = cursor.fetchone()
    if existing:
        record_id = existing["id"]
        cursor.execute("""
            UPDATE source_discovery_results
            SET project_id = ?, repository = ?, branch = ?, source_commit_sha = ?,
                selected_sources_json = ?, candidate_sources_json = ?,
                selection_source = ?, discovery_status = ?, updated_at = ?
            WHERE id = ?
        """, (project_id, repository, branch, source_commit_sha, sel_json, cand_json, selection_source, discovery_status, now, record_id))
    else:
        cursor.execute("""
            INSERT INTO source_discovery_results (
                id, project_id, finding_id, repository, branch, source_commit_sha,
                selected_sources_json, candidate_sources_json, selection_source,
                discovery_status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (record_id, project_id, finding_id, repository, branch, source_commit_sha, sel_json, cand_json, selection_source, discovery_status, now, now))
    conn.commit()
    cursor.execute("SELECT * FROM source_discovery_results WHERE id = ?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_source_discovery_row(row) if row else {}

def get_source_discovery(finding_id: str, project_id: Optional[str] = None, repo: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if repo:
        cursor.execute("SELECT * FROM source_discovery_results WHERE finding_id = ? AND repository = ?", (finding_id, repo))
    elif project_id:
        cursor.execute("SELECT * FROM source_discovery_results WHERE finding_id = ? AND (project_id = ? OR repository = ?)", (finding_id, project_id, project_id))
    else:
        cursor.execute("SELECT * FROM source_discovery_results WHERE finding_id = ?", (finding_id,))
    row = cursor.fetchone()
    if not row and (project_id or repo):
        cursor.execute("SELECT * FROM source_discovery_results WHERE finding_id = ?", (finding_id,))
        row = cursor.fetchone()
    conn.close()
    return _hydrate_source_discovery_row(row) if row else None

def update_source_discovery_selection(
    finding_id: str,
    selected_paths: List[str],
    project_id: Optional[str] = None,
    source_commit_sha: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    existing = get_source_discovery(finding_id, project_id)
    now = datetime.utcnow().isoformat()
    if not existing:
        new_record = {
            "finding_id": finding_id,
            "project_id": project_id or "",
            "repository": "",
            "branch": "main",
            "source_commit_sha": source_commit_sha or "main",
            "selected_sources": [{"path": p, "layer": "source", "language": "Unknown", "confidence": "MANUAL", "relevance_score": 100, "reasons": ["Manually selected by developer"]} for p in selected_paths],
            "candidate_sources": [],
            "selection_source": "USER_MODIFIED",
            "discovery_status": "COMPLETED"
        }
        return save_source_discovery(new_record)

    curr_selected = existing.get("selected_sources") or []
    curr_candidates = existing.get("candidate_sources") or []
    all_known_items = {item["path"]: item for item in (curr_selected + curr_candidates) if isinstance(item, dict) and "path" in item}

    new_selected = []
    for p in selected_paths:
        if p in all_known_items:
            new_selected.append(all_known_items[p])
        else:
            new_selected.append({
                "path": p,
                "layer": "source",
                "language": "Unknown",
                "confidence": "MANUAL",
                "relevance_score": 100,
                "reasons": ["Manually selected by developer"]
            })

    selected_paths_set = set(selected_paths)
    new_candidates = [item for item in (curr_selected + curr_candidates) if isinstance(item, dict) and item.get("path") not in selected_paths_set]

    existing["selected_sources"] = new_selected
    existing["candidate_sources"] = new_candidates
    existing["selection_source"] = "USER_MODIFIED"
    if source_commit_sha:
        existing["source_commit_sha"] = source_commit_sha
    return save_source_discovery(existing)

