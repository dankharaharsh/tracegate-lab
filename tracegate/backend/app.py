import os
import logging
import hashlib
import uuid
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, File, Form, UploadFile, HTTPException, status, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config import (
    ALLOWED_MIME_TYPES,
    MAX_FILE_SIZE_BYTES,
    get_active_provider,
)
from backend.schemas import (
    GitHubStatusResponse,
    GitHubConnectRequest,
    GitHubRepoItem,
    GitHubAnalyzeCodeRequest,
    GitHubCodeAnalysisResponse,
    GitHubApplyFixRequest,
    GitHubApplyFixResponse,
    GitHubCreatePRRequest,
    GitHubCreatePRResponse,
    VaptAnalysisResponse,
    ProjectCreate,
    ProjectUpdate,
    ChecklistItemUpdate,
    StatusUpdate,
    CustomChecklistItemCreate,
    FindingCreate,
    UserRegister,
    UserLogin,
    UserResponse,
    AuthTokenResponse,
    ReportCreate,
    ReportRecord,
)
from backend.analyzer import run_vapt_analysis
from backend.knowledge_base import get_finding_template_for_test
from backend.report_generator import generate_docx_report
from backend.github_service import (
    get_github_status,
    save_github_token,
    list_github_repositories,
    list_repository_branches,
    analyze_finding_code,
    apply_finding_fix,
    create_finding_pull_request,
)
from backend.database import (
    init_db,
    get_finding_by_id,
    update_finding_github_fix,
    save_user_github_config,
    get_user_github_config,
    seed_default_projects_if_empty,
    seed_default_users_if_empty,
    get_all_projects,
    get_project_by_id,
    create_project as db_create_project,
    update_project as db_update_project,
    delete_project as db_delete_project,
    save_analysis_for_project,
    get_project_checklist_items,
    update_checklist_item as db_update_checklist_item,
    update_item_status as db_update_item_status,
    delete_checklist_item as db_delete_checklist_item,
    add_custom_checklist_item as db_add_custom_checklist_item,
    save_finding as db_save_finding,
    get_project_findings_list,
    delete_finding as db_delete_finding,
    get_db_connection,
    register_user,
    authenticate_user,
    create_session,
    get_user_by_token,
    delete_session,
    save_report_record,
    get_project_reports,
    get_report_by_id,
    get_next_report_version,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vapt_api")

app = FastAPI(
    title="Tracegate VAPT Learning Platform API",
    description="Secure REST API for AI-assisted VAPT assessments, checklists, findings, and reporting",
    version="2.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
SAMPLES_DIR = BASE_DIR / "samples"

@app.on_event("startup")
def on_startup():
    init_db()
    seed_default_projects_if_empty()
    seed_default_users_if_empty()

@app.get("/api/health")
def health_check():
    provider = get_active_provider()
    return {
        "status": "healthy",
        "service": "AI-Powered VAPT Checklist Generator",
        "provider": provider,
        "mode": "live" if provider in ["gemini", "openai"] else "simulation"
    }

@app.get("/api/samples")
def get_samples():
    """Returns sample screenshot metadata for testing convenience."""
    samples = [
        {
            "id": "login",
            "name": "Login / Sign-in",
            "filename": "login.png",
            "url": "/samples/login.png",
            "description": "Standard authentication screen with username & password"
        },
        {
            "id": "registration",
            "name": "Sign-up / Registration",
            "filename": "registration.png",
            "url": "/samples/registration.png",
            "description": "Sign-up form with password strength and email fields"
        },
        {
            "id": "forgot_password",
            "name": "Forgot Password",
            "filename": "forgot_password.png",
            "url": "/samples/forgot_password.png",
            "description": "Account recovery and password reset initiation form"
        },
        {
            "id": "profile",
            "name": "Account / Profile",
            "filename": "profile.png",
            "url": "/samples/profile.png",
            "description": "User account management, avatar upload, and password change"
        },
        {
            "id": "settings",
            "name": "Security Settings",
            "filename": "settings.png",
            "url": "/samples/settings.png",
            "description": "Two-factor authentication, active sessions, and API tokens"
        },
        {
            "id": "dashboard",
            "name": "Home / Dashboard",
            "filename": "dashboard.png",
            "url": "/samples/dashboard.png",
            "description": "Analytics dashboard with search, metrics widgets, and activity feed"
        },
        {
            "id": "search",
            "name": "Search / Results",
            "filename": "search.png",
            "url": "/samples/search.png",
            "description": "Search input bar with faceted filters and sorting pagination"
        },
        {
            "id": "file_upload",
            "name": "File Upload",
            "filename": "file_upload.png",
            "url": "/samples/file_upload.png",
            "description": "Document and attachment upload portal with drag-and-drop"
        },
        {
            "id": "checkout",
            "name": "Checkout / Payment",
            "filename": "checkout.png",
            "url": "/samples/checkout.png",
            "description": "Order breakdown, discount voucher, billing, and credit card form"
        },
        {
            "id": "admin_panel",
            "name": "Admin Panel",
            "filename": "admin_panel.png",
            "url": "/samples/admin_panel.png",
            "description": "Administrative user tables, role assignments, and audit event logs"
        },
        {
            "id": "ambiguous",
            "name": "Unknown / Ambiguous",
            "filename": "ambiguous.png",
            "url": "/samples/ambiguous.png",
            "description": "Unidentifiable non-web diagram to test low confidence and guidance notes"
        }
    ]
    return {"samples": samples}

# =========================================================================
# 1. PROJECT MANAGEMENT ENDPOINTS (Section 45)
# =========================================================================

@app.get("/api/projects")
def list_projects():
    """Retrieve all assessment projects with metrics."""
    return {"projects": get_all_projects()}

@app.post("/api/projects", status_code=status.HTTP_201_CREATED)
def create_project_endpoint(project: ProjectCreate):
    """Create a new assessment project."""
    created = db_create_project(project.model_dump())
    return created

@app.get("/api/projects/{project_id}")
def get_project_endpoint(project_id: str):
    """Get single project workspace details, checklist items, and findings."""
    proj = get_project_by_id(project_id)
    if not proj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    return proj

@app.put("/api/projects/{project_id}")
def update_project_endpoint(project_id: str, data: ProjectUpdate):
    """Update project details."""
    updated = db_update_project(project_id, data.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    return updated

@app.delete("/api/projects/{project_id}")
def delete_project_endpoint(project_id: str):
    """Delete project and associated artifacts."""
    deleted = db_delete_project(project_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    return {"deleted": True, "project_id": project_id}

# =========================================================================
# 2. SCREENSHOT ENDPOINTS (Section 45)
# =========================================================================

@app.get("/api/projects/{project_id}/screenshots")
def get_project_screenshots(project_id: str):
    """List screenshots captured for a project."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM screenshots WHERE project_id = ? ORDER BY created_at DESC", (project_id,))
    rows = cursor.fetchall()
    conn.close()
    return {"screenshots": [dict(r) for r in rows]}

@app.post("/api/projects/{project_id}/screenshots", status_code=status.HTTP_201_CREATED)
async def upload_project_screenshot(
    project_id: str,
    image: UploadFile = File(...)
):
    """Upload and record a screenshot for a project without triggering immediate analysis."""
    proj = get_project_by_id(project_id)
    if not proj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    conn = get_db_connection()
    cursor = conn.cursor()
    shot_id = f"shot-{int(os.times().system*1000)}"
    cursor.execute("""
    INSERT INTO screenshots (id, project_id, filename, created_at)
    VALUES (?, ?, ?, datetime('now'))
    """, (shot_id, project_id, image.filename))
    conn.commit()
    conn.close()
    return {"id": shot_id, "project_id": project_id, "filename": image.filename}

# =========================================================================
# 3. SCREENSHOT ANALYSIS ENDPOINT (Core MVP Feature)
# =========================================================================

@app.post(
    "/api/analyze-screenshot",
    response_model=VaptAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze web application screenshot and generate contextual VAPT checklist"
)
async def analyze_screenshot(
    image: UploadFile = File(..., description="Uploaded screenshot image (PNG, JPG/JPEG, WEBP)"),
    page_type: Optional[str] = Form(None, description="Optional user-designated page type or 'Auto Detect'"),
    user_context: Optional[str] = Form(None, description="Optional user instructions/context for security focus"),
    prompt: Optional[str] = Form(None, description="Backward compatible alias for user_context"),
    project_id: Optional[str] = Form(None, description="Optional project ID to associate and persist analysis"),
    request_id: Optional[str] = Form(None, description="Client request ID for staleness tracking")
):
    # 1. Validation: Image file present
    if not image or not image.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No screenshot file was provided. Please upload an image."
        )

    # 2. Validation: MIME type
    content_type = (image.content_type or "").lower()
    if content_type not in ALLOWED_MIME_TYPES:
        ext = Path(image.filename).suffix.lower().lstrip(".")
        valid_exts = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp"}
        if ext in valid_exts:
            content_type = valid_exts[ext]
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file format '{content_type or ext}'. Supported formats: PNG, JPG/JPEG, WEBP."
            )

    # 3. Read content & validate size
    try:
        contents = await image.read()
    except Exception as e:
        logger.error(f"Failed to read image stream: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to read the uploaded image file. Please try again."
        )

    if len(contents) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded image file is empty."
        )

    if len(contents) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds maximum permitted size of {MAX_FILE_SIZE_BYTES // (1024 * 1024)}MB."
        )

    combined_context = (user_context or prompt or "").strip()

    # 4. Process with Vision AI & Controlled Knowledge Base
    logger.info(
        f"[API] Processing /api/analyze-screenshot: filename='{image.filename}', "
        f"MIME='{content_type}', size={len(contents)} bytes, page_type='{page_type or 'Auto Detect'}', "
        f"project_id='{project_id}'"
    )
    try:
        image_hash = hashlib.sha256(contents).hexdigest()[:16]
        req_id = request_id or str(uuid.uuid4())

        result = run_vapt_analysis(
            image_bytes=contents,
            mime_type=content_type,
            user_prompt=combined_context,
            filename=image.filename,
            selected_page_type=page_type
        )
        result.request_id = req_id
        result.image_hash = image_hash
        if not result.visible_functionality:
            result.visible_functionality = result.detected_functionalities or result.visible_signals
        if not result.visible_signals and result.detected_elements:
            result.visible_signals = [e.get("name") if isinstance(e, dict) else getattr(e, "name", str(e)) for e in result.detected_elements]

        logger.info(
            f"[API] Analysis successful: page_type='{result.page_type}', "
            f"confidence={result.confidence:.2f}, elements={len(result.detected_elements)}, "
            f"checklist_items={len(result.checklist)}, req_id={req_id}, hash={image_hash}"
        )

        # 5. Persist to Project if project_id is valid
        if project_id and project_id.strip():
            try:
                save_analysis_for_project(
                    project_id=project_id.strip(),
                    analysis_data=result.model_dump(),
                    filename=image.filename
                )
                logger.info(f"[API] Persisted analysis to project: {project_id}")
            except Exception as pe:
                logger.warning(f"[API] Could not persist to project {project_id}: {pe}")

        return result
    except ValueError as ve:
        logger.warning(f"[API] Validation or model error: {ve}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ve)
        )
    except Exception as exc:
        logger.error(f"Unexpected error during analysis: {exc}", exc_info=True)
        if page_type and page_type != "Auto Detect":
            try:
                from backend.analyzer import simulate_analysis
                logger.info(f"[API] Recovering with emergency knowledge base fallback for '{page_type}'")
                fallback_result = simulate_analysis(b"", user_prompt=combined_context, selected_page_type=page_type)
                fallback_result.request_id = req_id
                fallback_result.image_hash = image_hash
                return fallback_result
            except Exception as fe:
                logger.error(f"Emergency fallback failed: {fe}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while analyzing the screenshot. Please check the image and try again."
        )

# =========================================================================
# 4. CHECKLIST MANAGEMENT ENDPOINTS (Section 45)
# =========================================================================

@app.get("/api/projects/{project_id}/checklist")
def get_project_checklist(project_id: str):
    """Retrieve all checklist items for a project with status and findings."""
    items = get_project_checklist_items(project_id)
    return {"checklist": items}

@app.put("/api/checklist/{item_id}")
def update_checklist_item_endpoint(item_id: str, data: ChecklistItemUpdate):
    """Edit an existing checklist item (marks source as USER_MODIFIED)."""
    updated = db_update_checklist_item(item_id, data.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found.")
    return updated

@app.delete("/api/checklist/{item_id}")
def delete_checklist_item_endpoint(item_id: str):
    """Delete a checklist item from the project matrix."""
    deleted = db_delete_checklist_item(item_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found.")
    return {"deleted": True, "item_id": item_id}

@app.post("/api/projects/{project_id}/checklist/custom", status_code=status.HTTP_201_CREATED)
def add_custom_test_endpoint(project_id: str, data: CustomChecklistItemCreate):
    """Add a custom learner-defined security test to the active project checklist."""
    proj = get_project_by_id(project_id)
    if not proj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    created = db_add_custom_checklist_item(project_id, data.model_dump())
    return created

@app.put("/api/checklist/{item_id}/status")
def update_checklist_status_endpoint(item_id: str, data: StatusUpdate):
    """Update verification status: NOT_TESTED, TESTED_NOT_FOUND, or VULNERABILITY_FOUND."""
    valid_statuses = ["NOT_TESTED", "TESTED_NOT_FOUND", "VULNERABILITY_FOUND"]
    if data.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{data.status}'. Allowed values: {', '.join(valid_statuses)}"
        )
    updated = db_update_item_status(item_id, data.status)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found.")
    return updated

# =========================================================================
# 5. FINDINGS MANAGEMENT ENDPOINTS (Section 45)
# =========================================================================

@app.post("/api/projects/{project_id}/checklist/{item_id}/finding", status_code=status.HTTP_201_CREATED)
def record_project_finding_endpoint(
    project_id: str,
    item_id: str,
    finding: FindingCreate
):
    """Record a verified vulnerability finding explicitly bound to a project."""
    saved = db_save_finding(project_id, item_id, finding.model_dump())
    return saved

@app.post("/api/checklist/{item_id}/finding", status_code=status.HTTP_201_CREATED)
def record_finding_endpoint(
    item_id: str,
    finding: FindingCreate,
    project_id: Optional[str] = Query(None, description="Project ID")
):
    """Record a verified vulnerability finding with PoC and optional evidence screenshot."""
    resolved_project_id = project_id
    conn = get_db_connection()
    cursor = conn.cursor()

    if not resolved_project_id:
        cursor.execute("SELECT project_id FROM checklist_items WHERE id = ?", (item_id,))
        row = cursor.fetchone()
        if not row:
            cursor.execute("SELECT project_id FROM checklist_items WHERE test_id = ?", (item_id,))
            row = cursor.fetchone()
        if row:
            resolved_project_id = row["project_id"]

    if not resolved_project_id:
        cursor.execute("SELECT id FROM projects ORDER BY updated_at DESC LIMIT 1")
        proj_row = cursor.fetchone()
        if proj_row:
            resolved_project_id = proj_row["id"]
        else:
            resolved_project_id = "proj-ecommerce-001"
    conn.close()

    saved = db_save_finding(resolved_project_id, item_id, finding.model_dump())
    return saved

@app.get("/api/projects/{project_id}/findings")
def get_project_findings(project_id: str):
    """Retrieve all confirmed vulnerability findings with PoCs for a project."""
    findings = get_project_findings_list(project_id)
    return {"findings": findings}

@app.delete("/api/findings/{finding_id}")
def delete_finding_endpoint(finding_id: str):
    """Delete a recorded finding and reset corresponding checklist item to NOT_TESTED."""
    deleted = db_delete_finding(finding_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return {"deleted": True, "finding_id": finding_id}

@app.get("/api/checklist/{item_id}/finding-template")
def get_finding_template_endpoint(item_id: str):
    """Retrieve structured AI finding template for a checklist item to pre-fill confirmation form."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,))
    item = cursor.fetchone()
    if not item:
        cursor.execute("SELECT * FROM checklist_items WHERE test_id = ?", (item_id,))
        item = cursor.fetchone()
    conn.close()

    if item:
        tmpl = get_finding_template_for_test(
            test_id=item["test_id"],
            test_name=item["name"],
            cwe=item["cwe"]
        )
        tmpl["checklist_item_id"] = item["id"]
        tmpl["priority"] = item["priority"]
        return tmpl

    # Fallback to direct Knowledge Base lookup (for ad-hoc or in-memory analysis)
    tmpl = get_finding_template_for_test(
        test_id=item_id,
        test_name=item_id
    )
    tmpl["checklist_item_id"] = item_id
    return tmpl

# =========================================================================
# 6. AUTHENTICATION ENDPOINTS
# =========================================================================

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED, response_model=AuthTokenResponse)
def auth_register(data: UserRegister):
    """Register a new user account and generate an authenticated session token."""
    try:
        user = register_user(data.model_dump())
        token = create_session(user["id"])
        return {"access_token": token, "token": token, "token_type": "bearer", "user": user}
    except Exception as e:
        logger.warning(f"Registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already in use. Please choose another or sign in."
        )

@app.post("/api/auth/login", response_model=AuthTokenResponse)
def auth_login(data: UserLogin):
    """Validate credentials and return session token."""
    user = authenticate_user(data.username_or_email, data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email/username or password."
        )
    token = create_session(user["id"])
    return {"access_token": token, "token": token, "token_type": "bearer", "user": user}

@app.post("/api/auth/logout")
def auth_logout(authorization: Optional[str] = Header(None)):
    """Terminate active session."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        delete_session(token)
    return {"message": "Logged out successfully."}

@app.get("/api/auth/me", response_model=UserResponse)
def auth_me(authorization: Optional[str] = Header(None)):
    """Retrieve currently authenticated user profile."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid authentication token.")
    token = authorization.split(" ", 1)[1]
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid token.")
    return user

# =========================================================================
# 7. PROFESSIONAL DOCX REPORTING ENDPOINTS
# =========================================================================

@app.post("/api/projects/{project_id}/reports", status_code=status.HTTP_201_CREATED)
def create_project_report(project_id: str, report_in: Optional[ReportCreate] = None):
    """Generate professional Microsoft Word (.docx) assessment report using persisted project data and selected findings."""
    proj = get_project_by_id(project_id)
    if not proj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    version = (report_in.version if report_in and report_in.version else None) or get_next_report_version(project_id)
    title = (report_in.title if report_in and report_in.title else None) or f"VAPT Assessment Report — {proj.get('name')}"
    author = (report_in.author_name if report_in and report_in.author_name else (report_in.author if report_in and report_in.author else None)) or proj.get("created_by", "Security Learner")
    methodology = (report_in.methodology if report_in and report_in.methodology else "owasp_wstg")
    allow_clean = (report_in.allow_clean_report if report_in and report_in.allow_clean_report else False)

    all_findings = get_project_findings_list(project_id)

    # 1. Finding selection & security validation
    if report_in and report_in.selected_finding_ids is not None:
        valid_ids = set()
        for f in all_findings:
            if f.get("id"): valid_ids.add(str(f["id"]))
            if f.get("vuln_id"): valid_ids.add(str(f["vuln_id"]))
            if f.get("checklist_item_id"): valid_ids.add(str(f["checklist_item_id"]))
            if f.get("test_id"): valid_ids.add(str(f["test_id"]))

        # Cross-project security check
        for sid in report_in.selected_finding_ids:
            if str(sid) not in valid_ids:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid finding ID '{sid}': finding does not belong to this project."
                )

        selected_set = set(str(sid) for sid in report_in.selected_finding_ids)
        chosen_findings = [
            f for f in all_findings
            if str(f.get("id")) in selected_set or str(f.get("vuln_id")) in selected_set or str(f.get("checklist_item_id")) in selected_set or str(f.get("test_id")) in selected_set
        ]

        if len(report_in.selected_finding_ids) == 0:
            if allow_clean and len(all_findings) == 0:
                chosen_findings = []
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Select at least one confirmed finding to generate the vulnerability report."
                )
    else:
        if len(all_findings) == 0:
            if allow_clean:
                chosen_findings = []
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Select at least one confirmed finding to generate the vulnerability report."
                )
        else:
            chosen_findings = list(all_findings)

    # 2. Dynamic metrics calculation
    crit_count = sum(1 for f in chosen_findings if (f.get("priority") or "").upper() == "CRITICAL")
    high_count = sum(1 for f in chosen_findings if (f.get("priority") or "").upper() == "HIGH")
    med_count = sum(1 for f in chosen_findings if (f.get("priority") or "").upper() == "MEDIUM")
    low_count = sum(1 for f in chosen_findings if (f.get("priority") or "").upper() == "LOW")
    info_count = sum(1 for f in chosen_findings if (f.get("priority") or "").upper() == "INFORMATIONAL")
    total_findings = len(chosen_findings)

    # 3. Generate DOCX
    try:
        docx_path = generate_docx_report(
            proj,
            version=version,
            author_name=author,
            findings=chosen_findings,
            selected_finding_ids=report_in.selected_finding_ids if (report_in and report_in.selected_finding_ids is not None) else None,
            allow_clean_report=allow_clean,
            methodology=methodology
        )
    except Exception as e:
        logger.error(f"Failed to generate DOCX report: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to generate DOCX report: {e}")

    # 4. Save report record
    saved_finding_ids = [f["id"] for f in chosen_findings if f.get("id")]
    report_record = save_report_record({
        "project_id": project_id,
        "version": version,
        "report_title": title,
        "file_path": docx_path,
        "total_findings": total_findings,
        "crit_count": crit_count,
        "high_count": high_count,
        "med_count": med_count,
        "low_count": low_count,
        "info_count": info_count,
        "selected_finding_ids": saved_finding_ids,
        "created_by": author
    })

    return report_record

@app.get("/api/projects/{project_id}/reports", response_model=List[ReportRecord])
def list_project_reports(project_id: str):
    """List all generated report versions for a project."""
    reports = get_project_reports(project_id)
    return reports

@app.get("/api/projects/{project_id}/reports/{report_id}/download")
def download_project_report(project_id: str, report_id: str):
    """Download Microsoft Word (.docx) report file."""
    report = get_report_by_id(report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report record not found.")

    file_path = Path(report["file_path"])
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found on disk.")

    filename = file_path.name
    return FileResponse(
        path=str(file_path),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=filename
    )


# =========================================================================
# 8. GITHUB CODE CONNECTOR & AI FIX ENDPOINTS (Security Tool #3)
# =========================================================================

def _resolve_user_id(authorization: Optional[str] = Header(None)) -> str:
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        user = get_user_by_token(token)
        if user and user.get("id"):
            return user["id"]
    return "usr-learner-001"

@app.get("/api/github/status", response_model=GitHubStatusResponse)
def github_status_endpoint(authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    return get_github_status(user_id)

@app.post("/api/github/connect", response_model=GitHubStatusResponse)
def github_connect_endpoint(req: GitHubConnectRequest, authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    return save_github_token(user_id, req.token, req.username)

@app.get("/api/github/repositories", response_model=List[GitHubRepoItem])
def github_repositories_endpoint(authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    return list_github_repositories(user_id)

@app.get("/api/github/branches")
def github_branches_endpoint(repo: str = Query(..., description="Repository full name"), authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    branches = list_repository_branches(user_id, repo)
    return {"branches": branches}

@app.post("/api/github/analyze-code", response_model=GitHubCodeAnalysisResponse)
def github_analyze_code_endpoint(req: GitHubAnalyzeCodeRequest, authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    finding = get_finding_by_id(req.finding_id)
    if not finding:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE vuln_id = ? OR id = ? LIMIT 1", (req.finding_id, req.finding_id))
        row = cursor.fetchone()
        conn.close()
        if row:
            finding = dict(row)
        else:
            finding = {"id": req.finding_id, "vuln_id": req.finding_id, "finding_name": f"Finding {req.finding_id}"}
    return analyze_finding_code(user_id, req.repo, req.branch, finding)

@app.post("/api/github/apply-fix", response_model=GitHubApplyFixResponse)
def github_apply_fix_endpoint(req: GitHubApplyFixRequest, authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    finding = get_finding_by_id(req.finding_id)
    if not finding:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE vuln_id = ? OR id = ? LIMIT 1", (req.finding_id, req.finding_id))
        row = cursor.fetchone()
        conn.close()
        if row:
            finding = dict(row)
        else:
            finding = {"id": req.finding_id, "vuln_id": req.finding_id}
    res = apply_finding_fix(user_id, req.repo, req.target_branch, finding, req.file_path, req.diff_or_fixed_code)
    if finding.get("id"):
        update_finding_github_fix(
            finding_id=finding["id"],
            fix_status="Fix Applied",
            repo=req.repo,
            branch=res.branch_name,
            commit_sha=res.commit_sha,
            validation=res.validation_status
        )
    return res

@app.post("/api/github/create-pr", response_model=GitHubCreatePRResponse)
def github_create_pr_endpoint(req: GitHubCreatePRRequest, authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    finding = get_finding_by_id(req.finding_id)
    if not finding:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE vuln_id = ? OR id = ? LIMIT 1", (req.finding_id, req.finding_id))
        row = cursor.fetchone()
        conn.close()
        if row:
            finding = dict(row)
        else:
            finding = {"id": req.finding_id, "vuln_id": req.finding_id}
    res = create_finding_pull_request(user_id, req.repo, req.fix_branch, req.base_branch, req.title, req.body, finding)
    if finding.get("id"):
        update_finding_github_fix(
            finding_id=finding["id"],
            fix_status="PR Created",
            repo=req.repo,
            branch=req.fix_branch,
            pr_url=res.pr_url
        )
    return res

# =========================================================================
# STATIC ASSETS & SPA ROUTING
# =========================================================================

# Mount samples directory if it exists
if SAMPLES_DIR.exists():
    app.mount("/samples", StaticFiles(directory=str(SAMPLES_DIR)), name="samples")

# Mount static frontend files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
def serve_index():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "Tracegate VAPT Learning Platform API operational."}
