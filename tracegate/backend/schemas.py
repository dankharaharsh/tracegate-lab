from enum import Enum
from typing import List, Optional, Any
from pydantic import BaseModel, Field


class PriorityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingRecord(BaseModel):
    id: Optional[str] = Field(None, description="Unique identifier for the finding record")
    vuln_id: Optional[str] = Field(None, description="Sequential vulnerability identifier, e.g. VULN-001")
    finding_name: str = Field(..., description="Name or title of the confirmed vulnerability finding")
    severity_source: Optional[str] = Field("AI", description="Origin of severity rating: 'AI' or 'USER_OVERRIDE'")
    description: Optional[str] = Field(None, description="Observation or explanation of the security issue")
    affected_url: Optional[str] = Field(None, description="Target application URL affected")
    affected_endpoint: Optional[str] = Field(None, description="Vulnerable API or web endpoint")
    affected_component: Optional[str] = Field(None, description="Affected UI element, parameter, or module")
    testing_notes: Optional[str] = Field(None, description="Steps taken or notes on reproducing the issue")
    poc_text: Optional[str] = Field(None, description="Proof of concept payload, request/response snippet, or notes")
    evidence_filename: Optional[str] = Field(None, description="Optional uploaded evidence file name")
    evidence_data: Optional[str] = Field(None, description="Optional base64 data URI of uploaded evidence screenshot")
    priority: Optional[PriorityEnum] = Field(PriorityEnum.HIGH, description="Severity / Priority")
    cwe: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89")
    cvss_score: Optional[float] = Field(7.5, description="CVSS v3.1 base score, e.g. 8.5")
    impact: Optional[str] = Field(None, description="Technical and business impact of the vulnerability")
    reproduction_steps: Optional[str] = Field(None, description="Step-by-step reproduction instructions")
    remediation: Optional[str] = Field(None, description="Specific technical code or configuration remediation")
    mitigation: Optional[str] = Field(None, description="Defense-in-depth architectural mitigation")
    status: Optional[str] = Field("Open", description="Finding lifecycle status: Open, In Progress, Remediated")
    fix_status: Optional[str] = Field("NOT_STARTED", description="AI Fix status: NOT_STARTED, FIX_PROPOSED, FIX_APPLIED, PR_CREATED, MANUALLY_REMEDIATED")
    github_fix: Optional[dict] = Field(None, description="GitHub commit and Pull Request tracking metadata")
    recorded_at: Optional[str] = Field(None, description="Timestamp when finding was recorded")


class ChecklistItem(BaseModel):
    id: str = Field(..., description="Unique identifier for the checklist item")
    name: str = Field(..., description="Vulnerability or security test name")
    priority: PriorityEnum = Field(..., description="Test priority: CRITICAL, HIGH, MEDIUM, or LOW")
    reason: str = Field(..., description="Brief explanation of why this test is relevant to the visible functionality")
    testing_objective: str = Field(..., description="Specific objective of what the security learner/tester should assess")
    cwe: Optional[str] = Field(None, description="CWE identifier where reasonably applicable, e.g. CWE-287")
    source: str = Field("AI", description="Origin of item: 'AI', 'USER', or 'USER_MODIFIED'")
    status: str = Field("NOT_TESTED", description="Testing status: 'NOT_TESTED', 'TESTED_NOT_FOUND', or 'VULNERABILITY_FOUND'")
    finding: Optional[FindingRecord] = Field(None, description="Associated finding details if a vulnerability was confirmed")


class VaptAnalysisResponse(BaseModel):
    page_type: str = Field(..., description="Identified type of page/functionality out of the 10 supported categories or 'Unknown / Ambiguous'")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    detected_elements: List[str] = Field(default_factory=list, description="List of visible UI elements and user-controlled inputs identified")
    detected_functionalities: List[str] = Field(default_factory=list, description="List of discrete functionalities identified, e.g. Search, File Upload")
    security_relevant_features: List[str] = Field(default_factory=list, description="Security-relevant functionalities identified")
    visible_signals: List[str] = Field(default_factory=list, description="Visual signals extracted from screenshot justifying classification")
    visible_functionality: List[str] = Field(default_factory=list, description="Visible UI controls and functionalities extracted from screenshot")
    ambiguity_notes: Optional[str] = Field(None, description="Explanation or recommendation if the page is ambiguous or unknown")
    checklist: List[ChecklistItem] = Field(..., description="Prioritized list of potential VAPT security tests")
    selected_page_type: Optional[str] = Field(None, description="Page type hint selected by user, if any")
    page_type_conflict: bool = Field(False, description="Deprecated; always False in simplified architecture")
    conflict_reason: Optional[str] = Field(None, description="Deprecated; always None in simplified architecture")
    request_id: Optional[str] = Field(None, description="Echoed client request ID for stale response protection")
    image_hash: Optional[str] = Field(None, description="SHA256 image fingerprint")
    analysis_mode: Optional[str] = Field("AI", description="Analysis mode: 'AI' or 'KNOWLEDGE_BASE_FALLBACK'")
    success: bool = Field(True, description="Indicates whether checklist generation succeeded")
    visual_analysis_available: bool = Field(True, description="Whether visual analysis was available")


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, description="Project / Assessment Name")
    target_url: str = Field(..., min_length=1, description="Target Application URL")
    description: Optional[str] = Field("", description="Scope and description")
    scope_notes: Optional[str] = Field("", description="Optional testing notes or boundaries")
    notes: Optional[str] = Field(None, description="Alias for scope_notes")
    environment: Optional[str] = Field("Web Application (Staging)", description="Environment")
    created_by: Optional[str] = Field("Security Learner", description="Author")


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    target_url: Optional[str] = None
    description: Optional[str] = None
    scope_notes: Optional[str] = None
    notes: Optional[str] = None
    environment: Optional[str] = None
    status: Optional[str] = None


class ChecklistItemUpdate(BaseModel):
    name: Optional[str] = None
    priority: Optional[PriorityEnum] = None
    reason: Optional[str] = None
    testing_objective: Optional[str] = None
    cwe: Optional[str] = None


class StatusUpdate(BaseModel):
    status: str = Field(..., description="Status: NOT_TESTED, TESTED_NOT_FOUND, or VULNERABILITY_FOUND")


class CustomChecklistItemCreate(BaseModel):
    name: str = Field(..., min_length=1, description="Test Name")
    priority: PriorityEnum = Field(PriorityEnum.HIGH, description="Priority")
    reason: Optional[str] = Field("Learner-defined custom test procedure.", description="Why relevant")
    testing_objective: str = Field(..., min_length=5, description="Testing objective")
    cwe: Optional[str] = Field(None, description="CWE identifier")


class FindingCreate(BaseModel):
    finding_name: str = Field(..., min_length=1, description="Finding Name / Title")
    vuln_id: Optional[str] = Field(None, description="Sequential vulnerability identifier, e.g. VULN-001")
    severity_source: Optional[str] = Field("AI", description="Origin of severity rating: 'AI' or 'USER_OVERRIDE'")
    affected_url: Optional[str] = Field(None, description="Target application URL affected")
    affected_endpoint: Optional[str] = Field(None, description="Vulnerable API or web endpoint")
    affected_component: Optional[str] = Field(None, description="Affected UI element, parameter, or module")
    description: Optional[str] = Field("", description="Description / Observation")
    testing_notes: Optional[str] = Field("", description="Testing steps and reproduction notes")
    poc_text: Optional[str] = Field("", description="PoC payload or request/response details")
    evidence_filename: Optional[str] = Field(None, description="Filename of attached evidence")
    evidence_data: Optional[str] = Field(None, description="Base64 data URI of attached evidence screenshot")
    priority: Optional[PriorityEnum] = Field(PriorityEnum.HIGH, description="Severity / Priority")
    cwe: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89")
    cvss_score: Optional[float] = Field(None, description="CVSS v3.1 base score, e.g. 8.5")
    impact: Optional[str] = Field(None, description="Technical and business impact")
    reproduction_steps: Optional[str] = Field(None, description="Step-by-step reproduction instructions")
    remediation: Optional[str] = Field(None, description="Specific technical code or configuration remediation")
    mitigation: Optional[str] = Field(None, description="Defense-in-depth architectural mitigation")
    status: Optional[str] = Field("Open", description="Finding lifecycle status: Open, In Progress, Remediated")
    fix_status: Optional[str] = Field("NOT_STARTED", description="AI Fix status: NOT_STARTED, FIX_PROPOSED, FIX_APPLIED, PR_CREATED, MANUALLY_REMEDIATED")
    github_fix: Optional[dict] = Field(None, description="GitHub commit and Pull Request tracking metadata")


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, description="Username")
    email: str = Field(..., min_length=5, description="Email address")
    password: str = Field(..., min_length=6, description="Password")
    full_name: Optional[str] = Field("Security Learner", description="Full display name")


class UserLogin(BaseModel):
    username_or_email: str = Field(..., min_length=3, description="Username or email")
    password: str = Field(..., min_length=1, description="Password")


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    role: str
    created_at: str


class AuthTokenResponse(BaseModel):
    access_token: str
    token: Optional[str] = None
    token_type: str = "bearer"
    user: UserResponse


class ReportCreate(BaseModel):
    title: Optional[str] = Field("Penetration Testing Assessment Report", description="Report title")
    author: Optional[str] = Field(None, description="Assessor name")
    author_name: Optional[str] = Field(None, description="Assessor name alias")
    version: Optional[str] = Field(None, description="Report version, e.g. v1.0")
    selected_finding_ids: Optional[List[str]] = Field(None, description="Confirmed finding IDs selected for report")
    methodology: Optional[str] = Field("owasp_wstg", description="Assessment methodology")
    allow_clean_report: Optional[bool] = Field(False, description="Allow generating clean assessment report if 0 findings")


class ReportRecord(BaseModel):
    id: str
    project_id: str
    version: str
    report_title: str
    file_path: str
    filename: Optional[str] = None
    total_findings: int
    findings_count: Optional[int] = None
    crit_count: int
    high_count: int
    med_count: int
    low_count: int
    info_count: Optional[int] = 0
    selected_finding_ids: Optional[List[str]] = None
    created_by: str
    author_name: Optional[str] = None
    created_at: str
    download_url: str


# =============================================================================
# GITHUB AI FIX / CODE CONNECTOR SCHEMAS
# =============================================================================

class GitHubStatusResponse(BaseModel):
    configured: bool = True
    connected: bool = False
    username: Optional[str] = None
    rate_limit: Optional[int] = 5000
    rate_limit_remaining: Optional[int] = 4980
    mode: str = "mock"  # "live" or "mock"
    token_preview: Optional[str] = None
    scopes: List[str] = []


class GitHubConnectRequest(BaseModel):
    token: Optional[str] = Field(None, description="Personal Access Token (handled securely on server only)")
    username: Optional[str] = None
    mode: Optional[str] = Field("mock", description="Connection mode: 'mock' or 'live'")


class GitHubRepoItem(BaseModel):
    name: str
    full_name: str
    default_branch: str
    description: Optional[str] = None
    private: bool = False


class GitHubAnalyzeCodeRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    repository: Optional[str] = Field(None, description="Repository full name, e.g. owner/repo")
    repo: Optional[str] = Field(None, description="Repository full name alias")
    branch: str = Field("main", description="Target branch")
    file_path: Optional[str] = Field(None, description="Affected source file path")
    code_snippet: Optional[str] = Field(None, description="Optional user-provided vulnerable source code snippet")


class GitHubCodeAnalysisResponse(BaseModel):
    finding_id: str
    vuln_id: Optional[str] = None
    finding_title: Optional[str] = None
    cwe: Optional[str] = None
    repo: Optional[str] = None
    branch: Optional[str] = None
    file_path: str
    original_code: str
    proposed_code: str
    unified_diff: Optional[str] = None
    diff_unified: Optional[str] = None
    explanation: str
    testing_steps: Optional[str] = None
    safety_notes: Optional[str] = None


class GitHubApplyFixRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    repository: Optional[str] = Field(None, description="Repository full name")
    repo: Optional[str] = Field(None, description="Repository alias")
    base_branch: str = Field("main", description="Base branch to fork from")
    target_branch: Optional[str] = Field(None, description="Target branch")
    fix_branch: Optional[str] = Field(None, description="Fix branch name, defaults to tracegate/fix/{vuln_id}")
    file_path: str = Field(..., description="Source code file path")
    fixed_code: Optional[str] = Field(None, description="Remediated code content")
    diff_or_fixed_code: Optional[str] = Field(None, description="Remediated code or diff")
    commit_message: Optional[str] = Field(None, description="Custom commit message")


class GitHubApplyFixResponse(BaseModel):
    success: bool
    branch_name: Optional[str] = None
    fix_branch: Optional[str] = None
    commit_sha: str
    commit_message: str
    validation_status: str = "PASSED"
    validation_details: Any = None


class GitHubCreatePRRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    repository: Optional[str] = Field(None, description="Repository full name")
    repo: Optional[str] = Field(None, description="Repository alias")
    fix_branch: str = Field(..., description="Branch containing the fix")
    base_branch: str = Field("main", description="Target merge branch")
    title: Optional[str] = Field(None, description="PR Title")
    body: Optional[str] = Field(None, description="PR Description")


class GitHubCreatePRResponse(BaseModel):
    success: bool = True
    pr_number: int
    pr_url: str
    title: str
    body: Optional[str] = None
    status: str = "Open"

