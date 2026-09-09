"""
Tracegate External VAPT Report Parser and Ingestion Subsystem.
Parses external security assessment reports in PDF, DOCX, TXT, and Markdown formats,
segments text into candidate vulnerability records, extracts structured technical fields,
performs duplicate detection against existing project findings, and prepares candidates
for human-in-the-loop review and selective project import.
"""

import io
import re
import uuid
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import pypdf
import docx

logger = logging.getLogger("report_importer")

SUPPORTED_IMPORT_EXTENSIONS = {".pdf", ".docx", ".txt", ".md"}
MAX_IMPORT_FILE_SIZE = 20 * 1024 * 1024  # 20MB

CWE_COMMON_MAPPINGS = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "cross-site scripting": "CWE-79",
    "xss": "CWE-79",
    "idor": "CWE-639",
    "insecure direct object reference": "CWE-639",
    "broken object level authorization": "CWE-639",
    "bola": "CWE-639",
    "csrf": "CWE-352",
    "cross-site request forgery": "CWE-352",
    "ssrf": "CWE-918",
    "server-side request forgery": "CWE-918",
    "command injection": "CWE-78",
    "os command injection": "CWE-78",
    "rce": "CWE-94",
    "remote code execution": "CWE-94",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "file upload": "CWE-434",
    "unrestricted file upload": "CWE-434",
    "broken authentication": "CWE-287",
    "authentication bypass": "CWE-287",
    "brute force": "CWE-307",
    "rate limit": "CWE-307",
    "security header": "CWE-693",
    "missing security header": "CWE-693",
    "information disclosure": "CWE-200",
    "sensitive data exposure": "CWE-200",
    "cors": "CWE-942",
    "open redirect": "CWE-601",
    "jwt": "CWE-345",
    "price manipulation": "CWE-390",
    "parameter tampering": "CWE-472"
}

def extract_text_from_pdf(file_bytes: bytes) -> str:
    """Extract textual content page-by-page from an uploaded PDF file."""
    try:
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        pages_text = []
        for i, page in enumerate(reader.pages):
            txt = page.extract_text() or ""
            if txt.strip():
                pages_text.append(f"--- Page {i + 1} ---\n" + txt)
        return "\n\n".join(pages_text)
    except Exception as e:
        logger.error(f"Failed to extract text from PDF: {e}")
        raise ValueError(f"Could not parse PDF document: {e}")

def extract_text_from_docx(file_bytes: bytes) -> str:
    """Extract textual content including headings, paragraphs, and tables from an uploaded Word DOCX."""
    try:
        doc = docx.Document(io.BytesIO(file_bytes))
        sections = []
        for p in doc.paragraphs:
            if p.text.strip():
                if p.style and "Heading" in p.style.name:
                    sections.append(f"## {p.text.strip()}")
                else:
                    sections.append(p.text.strip())
        
        for t in doc.tables:
            table_lines = []
            for row in t.rows:
                row_cells = [cell.text.strip().replace('\n', ' ') for cell in row.cells]
                table_lines.append(" | ".join(row_cells))
            if table_lines:
                sections.append("\n" + "\n".join(table_lines) + "\n")
                
        return "\n\n".join(sections)
    except Exception as e:
        logger.error(f"Failed to extract text from DOCX: {e}")
        raise ValueError(f"Could not parse DOCX document: {e}")

def extract_text_from_txt_or_md(file_bytes: bytes) -> str:
    """Extract text from plaintext or markdown file with multi-encoding fallback."""
    for enc in ["utf-8", "utf-8-sig", "latin-1", "cp1252"]:
        try:
            return file_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return file_bytes.decode("utf-8", errors="replace")

def normalize_severity(raw_sev: str) -> str:
    """Normalize arbitrary severity strings to Tracegate's 5 standard severities."""
    s = (raw_sev or "").strip().upper()
    if any(k in s for k in ["CRIT", "VERY HIGH", "P1"]):
        return "CRITICAL"
    elif any(k in s for k in ["HIGH", "P2", "IMPORTANT"]):
        return "HIGH"
    elif any(k in s for k in ["MED", "MODERATE", "P3"]):
        return "MEDIUM"
    elif any(k in s for k in ["LOW", "P4", "MINOR"]):
        return "LOW"
    elif any(k in s for k in ["INFO", "BEST PRACTICE", "NOTE", "P5"]):
        return "INFORMATIONAL"
    return "MEDIUM"

def segment_report_text(full_text: str) -> List[str]:
    """
    Segment document text into discrete potential vulnerability blocks based on
    heading structures, numbered finding markers, and vulnerability section headers.
    """
    pattern = r'(?i)(?:^|\n)(?=(?:#{1,3}\s+|\*{1,2}\s*)?(?:(?:finding|vulnerability|issue|defect|item)\s*#?\s*\d+[:\s\-]|\d+\.\s+(?:critical|high|medium|low|informational|[a-z0-9\s\-]+(?:vulnerability|injection|flaw|issue|bypass|disclosure|idor|xss|sqli))|vulnerability\s+name[:\s]|finding\s+title[:\s]|\[(?:critical|high|medium|low|info)\]))'
    
    parts = re.split(pattern, full_text, flags=re.MULTILINE)
    cleaned_chunks = []
    
    for chunk in parts:
        c = chunk.strip()
        if len(c) < 30:
            continue
        if any(w in c.lower() for w in ["vulnerability", "finding", "issue", "cwe-", "severity", "risk", "impact", "remediation", "poc", "injection", "bypass", "idor", "xss"]):
            cleaned_chunks.append(c)
            
    if not cleaned_chunks and len(full_text.strip()) > 50:
        md_chunks = re.split(r'\n\s*#{1,3}\s+', full_text)
        for mc in md_chunks:
            mc = mc.strip()
            if len(mc) > 40 and any(w in mc.lower() for w in ["vulnerability", "finding", "issue", "cwe", "severity", "poc", "remediation", "impact"]):
                cleaned_chunks.append(mc)
                
    if not cleaned_chunks and len(full_text.strip()) > 30:
        cleaned_chunks.append(full_text.strip())
        
    return cleaned_chunks

def parse_candidate_finding(chunk: str, chunk_index: int = 1) -> Optional[Dict[str, Any]]:
    """
    Parse a segmented text chunk into a structured candidate finding dictionary.
    Extracts title, severity, CWE, CVSS, description, impact, steps, PoC, remediation, and component.
    """
    lines = [line.strip() for line in chunk.splitlines() if line.strip()]
    if not lines:
        return None

    first_line = lines[0]
    title = re.sub(r'^[#*\s\-]+', '', first_line)
    title = re.sub(r'(?i)^(?:finding|vulnerability|issue)\s*#?\s*\d+[:\s\-]*', '', title).strip()
    title = re.sub(r'^\d+\.\s*', '', title).strip()
    title = re.sub(r'(?i)\[(critical|high|medium|low|info)\]\s*', '', title).strip()
    if not title or len(title) < 3:
        title = f"Security Finding #{chunk_index}"

    # 1. Severity extraction
    severity = "MEDIUM"
    sev_match = re.search(r'(?i)\b(?:severity|priority|risk\s*rating|risk\s*level|severity\s*level)\b\s*[:=\-]?\s*([A-Za-z]+)', chunk)
    if sev_match:
        severity = normalize_severity(sev_match.group(1))
    else:
        tag_match = re.search(r'(?i)\[(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\]', chunk)
        if tag_match:
            severity = normalize_severity(tag_match.group(1))
        elif "critical" in chunk.lower()[:300]:
            severity = "CRITICAL"
        elif "high" in chunk.lower()[:300]:
            severity = "HIGH"
        elif "low" in chunk.lower()[:300]:
            severity = "LOW"
        elif "informational" in chunk.lower()[:300] or "info" in chunk.lower()[:300]:
            severity = "INFORMATIONAL"

    # 2. CWE extraction
    cwe = None
    cwe_match = re.search(r'(?i)\b(CWE-\d+)\b', chunk)
    if cwe_match:
        cwe = cwe_match.group(1).upper()
    else:
        lower_chunk = chunk.lower()
        for kw, mapped_cwe in CWE_COMMON_MAPPINGS.items():
            if kw in lower_chunk or kw in title.lower():
                cwe = mapped_cwe
                break
    if not cwe:
        cwe = "CWE-200"

    # 3. CVSS score
    cvss = None
    cvss_match = re.search(r'(?i)CVSS(?:\s*v[23](?:\.[01])?)?(?:\s*Base)?(?:\s*Score)?[:\s]+(\d+(?:\.\d+)?)', chunk)
    if cvss_match:
        try:
            cvss = float(cvss_match.group(1))
        except ValueError:
            cvss = None
    if cvss is None:
        cvss = 9.0 if severity == "CRITICAL" else 7.5 if severity == "HIGH" else 5.0 if severity == "MEDIUM" else 3.0 if severity == "LOW" else 0.0

    # 4. Extract section bodies using regex helpers
    def extract_section_text(keywords: List[str]) -> str:
        kw_pattern = '|'.join(keywords)
        pattern = r'(?i)(?:^|\n)(?:[#*]{1,4}\s*)?(?:' + kw_pattern + r')[:\s\-]*(.*?)(?=\n(?:[#*]{1,4}\s*)?(?:severity|cwe|cvss|impact|reproduction|steps|proof|poc|remediation|mitigation|affected|solution|reference)|$)'
        m = re.search(pattern, chunk, flags=re.DOTALL)
        if m and m.group(1):
            text = (m.group(1) or "").strip()
            text = re.sub(r'^[\-:\s]+', '', text)
            return text
        return ""

    description = extract_section_text(["description", "overview", "summary", "details", "vulnerability description"])
    impact = extract_section_text(["impact", "business impact", "technical impact", "consequences"])
    steps = extract_section_text(["steps to reproduce", "reproduction steps", "reproduction procedure", "testing steps", "reproduction"])
    poc = extract_section_text(["proof of concept", "poc", "payload", "reproduction payload", "http request", "exploit"])
    remediation = extract_section_text(["remediation", "recommendation", "suggested fix", "solution", "mitigation guidance"])
    mitigation = extract_section_text(["mitigation", "defense-in-depth", "architectural mitigation"])
    
    # 5. Affected URL / Component
    url = ""
    url_match = re.search(r'(?i)(?:affected\s*(?:url|path|endpoint)|target\s*url|url)[:\s]+([https?://\S+|/\S+]+)', chunk)
    if url_match:
        url = url_match.group(1).strip()
    else:
        path_match = re.search(r'(/(?:api|v1|v2|auth|users|account|admin|profile|checkout|search|upload|login)[a-zA-Z0-9_/\-\.]*)', chunk)
        if path_match:
            url = path_match.group(1).strip()

    component = ""
    comp_match = re.search(r'(?i)(?:affected\s*component|component|module|service)[:\s]+([A-Za-z0-9_\-\s/]+)', chunk)
    if comp_match:
        component = comp_match.group(1).strip().splitlines()[0]
    if not component:
        if url:
            component = url.split("?")[0]
        else:
            component = "Web Application Surface"

    if not description:
        non_header_lines = [l for l in lines[1:] if not re.match(r'(?i)^(severity|cwe|cvss|component|url|date|status)[:\s]', l)]
        if non_header_lines:
            description = " ".join(non_header_lines[:4])
        else:
            description = f"{title} observed in target scope."

    if not poc:
        code_block_match = re.search(r'```(?:[a-zA-Z]*\n)?(.*?)```', chunk, flags=re.DOTALL)
        if code_block_match:
            poc = code_block_match.group(1).strip()

    # Discard preamble/header blocks that lack any explicit finding attributes
    has_explicit_sev = bool(sev_match or tag_match)
    has_explicit_cwe = bool(cwe_match)
    has_explicit_cvss = bool(cvss_match)
    has_explicit_poc = bool(poc)
    has_explicit_remed = bool(remediation)
    if not (has_explicit_sev or has_explicit_cwe or has_explicit_cvss or has_explicit_poc or has_explicit_remed):
        return None

    quality = "HIGH"
    if not poc and not steps:
        quality = "MEDIUM"
    if not impact and not remediation:
        quality = "LOW" if quality == "MEDIUM" else "MEDIUM"

    cand_id = f"cand-{uuid.uuid4().hex[:8]}"
    
    return {
        "id": cand_id,
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "cvss_score": cvss,
        "description": description,
        "impact": impact or f"Exploitation of {title} compromises application confidentiality, integrity, or availability.",
        "affected_url": url or "/api",
        "affected_component": component,
        "steps_to_reproduce": steps or "1. Access vulnerable endpoint.\n2. Supply test payload.\n3. Observe anomalous behavior.",
        "poc": poc or f"GET {url or '/api/vulnerable'} HTTP/1.1\nHost: target.app\nUser-Agent: Tracegate-Audit",
        "poc_text": poc or f"GET {url or '/api/vulnerable'} HTTP/1.1\nHost: target.app\nUser-Agent: Tracegate-Audit",
        "remediation": remediation or f"Enforce input validation, parameterized queries, and strict access controls for {title}.",
        "mitigation": mitigation or "Apply defense-in-depth architectural controls and continuous security regression monitoring.",
        "evidence": [],
        "extraction_quality": quality,
        "is_duplicate": False,
        "duplicate_match": None
    }

def detect_duplicates(candidate_findings: List[Dict[str, Any]], existing_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify potential duplicate findings by comparing candidates against
    existing project findings using title tokens, CWE classification, and URL/component matches.
    """
    for cand in candidate_findings:
        cand_title = (cand.get("title") or "").lower().strip()
        cand_cwe = (cand.get("cwe") or "").upper().strip()
        cand_url = (cand.get("affected_url") or "").lower().strip()
        cand_comp = (cand.get("affected_component") or "").lower().strip()
        cand_tokens = set(re.findall(r'\w+', cand_title))

        is_dup = False
        match_info = None

        for ex in existing_findings:
            ex_title = (ex.get("finding_name") or ex.get("title") or "").lower().strip()
            ex_cwe = (ex.get("cwe") or "").upper().strip()
            ex_url = (ex.get("affected_url") or "").lower().strip()
            ex_comp = (ex.get("affected_component") or "").lower().strip()
            ex_tokens = set(re.findall(r'\w+', ex_title))

            if cand_title == ex_title:
                is_dup = True
                match_info = {"id": ex["id"], "vuln_id": ex.get("vuln_id"), "title": ex.get("finding_name", ex_title), "reason": "Exact Title Match"}
                break

            if cand_tokens and ex_tokens:
                overlap = len(cand_tokens & ex_tokens) / max(len(cand_tokens | ex_tokens), 1)
                if overlap > 0.65:
                    is_dup = True
                    match_info = {"id": ex["id"], "vuln_id": ex.get("vuln_id"), "title": ex.get("finding_name", ex_title), "reason": "High Title Similarity"}
                    break

            if cand_cwe and ex_cwe and cand_cwe == ex_cwe and cand_cwe != "CWE-200":
                if (cand_url and ex_url and cand_url == ex_url) or (cand_comp and ex_comp and cand_comp == ex_comp and cand_comp != "Web Application Surface"):
                    is_dup = True
                    match_info = {"id": ex["id"], "vuln_id": ex.get("vuln_id"), "title": ex.get("finding_name", ex_title), "reason": "Matching CWE & Component"}
                    break

        cand["is_duplicate"] = is_dup
        cand["duplicate_match"] = match_info
        if is_dup and match_info:
            cand["duplicate_warning"] = f"Potential duplicate of existing finding: {match_info.get('title')} ({match_info.get('reason')})"
            cand["duplicate_of_id"] = match_info.get("id")
        else:
            cand["duplicate_warning"] = None
            cand["duplicate_of_id"] = None

    return candidate_findings

def parse_report_document(
    file_bytes: bytes,
    filename: str,
    existing_findings: Optional[List[Dict[str, Any]]] = None
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Main entry point for external VAPT report parsing.
    Validates format, extracts text, segments into candidate findings,
    and runs duplicate detection against the project's existing findings.
    Returns (raw_extracted_text, candidate_findings_list).
    """
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED_IMPORT_EXTENSIONS:
        raise ValueError(f"Unsupported file extension '{ext}'. Supported formats: PDF, DOCX, TXT, MD.")

    if len(file_bytes) > MAX_IMPORT_FILE_SIZE:
        raise ValueError(f"Uploaded report file exceeds maximum permitted size of {MAX_IMPORT_FILE_SIZE // (1024 * 1024)}MB.")

    if ext == ".pdf":
        full_text = extract_text_from_pdf(file_bytes)
    elif ext == ".docx":
        full_text = extract_text_from_docx(file_bytes)
    else:
        full_text = extract_text_from_txt_or_md(file_bytes)

    if not full_text or not full_text.strip():
        raise ValueError("The uploaded report file contains no readable text or is empty.")

    chunks = segment_report_text(full_text)
    candidate_findings = []
    
    for idx, chunk in enumerate(chunks):
        parsed = parse_candidate_finding(chunk, chunk_index=idx + 1)
        if parsed:
            candidate_findings.append(parsed)

    if existing_findings:
        candidate_findings = detect_duplicates(candidate_findings, existing_findings)

    logger.info(f"Parsed report '{filename}': extracted {len(candidate_findings)} candidate findings from {len(chunks)} text chunks.")
    doc_id = f"doc-{uuid.uuid4().hex[:8]}"
    return {
        "source_document_id": doc_id,
        "source_document_name": filename,
        "total_candidates": len(candidate_findings),
        "candidate_findings": candidate_findings,
        "full_text": full_text,
        "summary": {
            "critical": sum(1 for c in candidate_findings if (c.get("severity") or "").upper() == "CRITICAL"),
            "high": sum(1 for c in candidate_findings if (c.get("severity") or "").upper() == "HIGH"),
            "medium": sum(1 for c in candidate_findings if (c.get("severity") or "").upper() == "MEDIUM"),
            "low": sum(1 for c in candidate_findings if (c.get("severity") or "").upper() == "LOW"),
            "informational": sum(1 for c in candidate_findings if (c.get("severity") or "").upper() in ["INFORMATIONAL", "INFO"]),
            "duplicates": sum(1 for c in candidate_findings if c.get("is_duplicate")),
        }
    }
