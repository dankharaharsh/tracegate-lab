/**
 * Tracegate — Premium Cybersecurity Learning & VAPT Platform
 * Frontend SPA Controller, Routing, State Management & Real API Integration
 */

document.addEventListener("DOMContentLoaded", () => {
    // ==========================================================================
    // 1. GLOBAL STATE & CONSTANTS
    // ==========================================================================
    const DEFAULT_USER = {
        name: "Security Learner",
        email: "learner@tracegate.lab",
        role: "Junior Pentester / Security Learner",
        methodology: "owasp_top10"
    };

    const STARTER_PROJECTS = [
        {
            id: "proj-ecommerce-001",
            name: "E-Commerce Gateway & Auth Audit",
            target_url: "https://shop.tracegate.lab",
            environment: "Web Application (Staging)",
            description: "Authorized penetration test assessing user registration, multi-factor authentication, and payment handling.",
            notes: "Scope includes checkout, account reset, and cart endpoints.",
            status: "IN_PROGRESS",
            created_at: "2026-08-28",
            updated_at: "2026-09-03",
            checklist_data: null,
            findings: [
                {
                    id: "find-1",
                    finding_name: "Broken Authentication on Password Reset",
                    test_id: "test-auth-1",
                    priority: "CRITICAL",
                    description: "Password reset tokens do not expire upon use and have insufficient entropy (4-digit numeric pin).",
                    testing_notes: "Requested reset token via /forgot-password, intercepted response, brute forced 4-digit code within 200 requests.",
                    poc_text: "POST /api/v1/auth/reset HTTP/1.1\nHost: shop.tracegate.lab\nContent-Type: application/json\n\n{\"token\": \"1042\", \"new_password\": \"pwnedPass!\"} -> 200 OK",
                    evidence_filename: "reset_token_bruteforce.png",
                    evidence_data: null,
                    recorded_at: "2026-09-02 14:22"
                }
            ]
        },
        {
            id: "proj-health-002",
            name: "Patient Records EHR API Audit",
            target_url: "https://ehr-api.medlab.test",
            environment: "API & Microservices",
            description: "Compliance assessment for HIPAA/OWASP ASVS patient record search and attachment upload endpoints.",
            notes: "Test API tokens provided in lab environment.",
            status: "COMPLETED",
            created_at: "2026-08-15",
            updated_at: "2026-08-30",
            checklist_data: null,
            findings: []
        },
        {
            id: "proj-fintech-003",
            name: "Cloud Banking Admin Panel Review",
            target_url: "https://admin.fintech-vault.stage",
            environment: "Web Application (Production)",
            description: "Role-based access control (RBAC) and audit log tampering assessment for internal financial staff.",
            notes: "Admin credentials provided for testing least-privilege.",
            status: "NEEDS_REVIEW",
            created_at: "2026-09-01",
            updated_at: "2026-09-04",
            checklist_data: null,
            findings: []
        }
    ];

    const PRIORITY_ORDER = {
        CRITICAL: 0,
        HIGH: 1,
        MEDIUM: 2,
        LOW: 3
    };

    let currentUser = null;
    let projects = [];
    let activeProjectId = null;

    // Ephemeral Inspection & Checklist Architecture State (Section 17)
    let selectedPageType = "Auto Detect";
    let currentUploadedFile = null;
    let uploadedImage = null;
    let currentImageHash = null;
    let additionalContext = "";

    let analysisStatus = "IDLE"; // IDLE, RUNNING, SUCCESS, ERROR
    let analysisResult = null;

    let checklistStatus = "IDLE"; // IDLE, GENERATING, CURRENT, NEEDS_REGENERATION
    let checklist = [];

    let currentAnalysisRequestId = null;
    let currentAbortController = null;
    let lastAnalyzedPageType = null;
    let lastGeneratedPageType = null;

    let activeVerifyItem = null;
    let activeEditItem = null;
    let pendingEvidenceData = null;
    let pendingEvidenceFilename = null;

    // Filters & Sorting for Checklist
    let currentPriorityFilter = "ALL";
    let currentStatusFilter = "ALL";
    let currentSearchTerm = "";
    let currentSortMode = "priority_desc";

    // Filters for Findings View
    let currentFindingSeverityFilter = "ALL";
    let currentFindingSearchTerm = "";

    // ==========================================================================
    // 2. STATE INITIALIZATION & LOCALSTORAGE + REST API SYNC
    // ==========================================================================
    async function initState() {
        // Validate Session Token with backend
        const authToken = localStorage.getItem("tg_auth_token");
        const savedUser = localStorage.getItem("tg_user");

        if (authToken) {
            try {
                const meRes = await fetch("/api/auth/me", {
                    headers: { "Authorization": `Bearer ${authToken}` }
                });
                if (meRes.ok) {
                    currentUser = await meRes.json();
                    localStorage.setItem("tg_user", JSON.stringify(currentUser));
                } else {
                    localStorage.removeItem("tg_auth_token");
                    currentUser = null;
                }
            } catch (e) {
                if (savedUser) {
                    try { currentUser = JSON.parse(savedUser); } catch(err) { currentUser = DEFAULT_USER; }
                }
            }
        } else if (savedUser) {
            try { currentUser = JSON.parse(savedUser); } catch(e) { currentUser = null; }
        } else {
            currentUser = DEFAULT_USER;
            localStorage.setItem("tg_user", JSON.stringify(currentUser));
        }

        // Load Projects from LocalStorage cache first
        const savedProjects = localStorage.getItem("tg_projects");
        if (savedProjects) {
            try {
                projects = JSON.parse(savedProjects);
                if (!Array.isArray(projects) || projects.length === 0) {
                    projects = [...STARTER_PROJECTS];
                }
            } catch (e) {
                projects = [...STARTER_PROJECTS];
            }
        } else {
            projects = [...STARTER_PROJECTS];
            saveProjects();
        }

        // Load Active Project ID
        activeProjectId = localStorage.getItem("tg_active_proj_id");
        if (!activeProjectId || !projects.some(p => p.id === activeProjectId)) {
            activeProjectId = projects[0]?.id || null;
            if (activeProjectId) localStorage.setItem("tg_active_proj_id", activeProjectId);
        }

        updateUserUI();
        updateProjectsDropdown();
        refreshDashboardStats();

        // Sync fresh data from backend REST API
        await syncProjectsFromBackend();
    }

    async function syncProjectsFromBackend() {
        try {
            const res = await fetch("/api/projects");
            if (res.ok) {
                const resData = await res.json();
                const backendProjects = Array.isArray(resData) ? resData : (resData.projects || []);
                if (Array.isArray(backendProjects) && backendProjects.length > 0) {
                    // Merge backend projects preserving local memory where appropriate
                    projects = backendProjects.map(bp => {
                        const existing = projects.find(p => p.id === bp.id);
                        return {
                            ...bp,
                            checklist_data: existing?.checklist_data || null,
                            findings: existing?.findings || []
                        };
                    });
                    saveProjects();
                    updateProjectsDropdown();
                    refreshDashboardStats();
                }
            }
        } catch (e) {
            console.warn("[TRACEGATE] Offline or failed to sync /api/projects:", e);
        }

        // Pre-fetch details for active project
        if (activeProjectId) {
            await loadProjectDetails(activeProjectId);
        }
    }

    async function loadProjectDetails(projId) {
        const proj = projects.find(p => p.id === projId);
        if (!proj) return;

        try {
            // 1. Fetch checklist from backend
            const chkRes = await fetch(`/api/projects/${projId}/checklist`);
            if (chkRes.ok) {
                const chkData = await chkRes.json();
                if (chkData && chkData.checklist && chkData.checklist.length > 0) {
                    proj.checklist_data = chkData;
                }
            }

            // 2. Fetch findings from backend
            const findRes = await fetch(`/api/projects/${projId}/findings`);
            if (findRes.ok) {
                const rawFindings = await findRes.json();
                const findingsData = Array.isArray(rawFindings) ? rawFindings : (rawFindings.findings || []);
                if (Array.isArray(findingsData)) {
                    proj.findings = findingsData;
                    // Connect findings to matching checklist items
                    if (proj.checklist_data && proj.checklist_data.checklist) {
                        proj.checklist_data.checklist.forEach(item => {
                            const match = proj.findings.find(f => 
                                (f.test_id && (f.test_id === item.id || f.test_id === item.test_id)) ||
                                (f.checklist_item_id && (f.checklist_item_id === item.id || f.checklist_item_id === item.test_id))
                            );
                            if (match) {
                                item.finding = match;
                                item.status = "VULNERABILITY_FOUND";
                            }
                        });
                    }
                }
            }

            saveProjects();
            if (proj.id === activeProjectId) {
                renderActiveWorkspace();
                refreshDashboardStats();
            }
        } catch (err) {
            console.warn(`[TRACEGATE] Could not load details for project ${projId}:`, err);
        }
    }

    function saveProjects() {
        localStorage.setItem("tg_projects", JSON.stringify(projects));
    }

    function getActiveProject() {
        return projects.find(p => p.id === activeProjectId) || projects[0] || null;
    }

    async function setActiveProject(projId) {
        if (!projects.some(p => p.id === projId)) return;
        activeProjectId = projId;
        localStorage.setItem("tg_active_proj_id", projId);
        updateProjectsDropdown();
        renderActiveWorkspace();
        refreshDashboardStats();
        showToast(`Switched active project to "${getActiveProject().name}"`, "info");
        await loadProjectDetails(projId);
    }

    function updateUserUI() {
        const navItemLogin = document.getElementById("navItemLogin");
        const btnLogoutEl = document.getElementById("btnLogout");

        if (!currentUser) {
            if (navItemLogin) navItemLogin.style.display = "flex";
            if (btnLogoutEl) btnLogoutEl.style.display = "none";
            return;
        }

        if (navItemLogin) navItemLogin.style.display = "none";
        if (btnLogoutEl) btnLogoutEl.style.display = "flex";

        const initials = currentUser.name.split(" ").map(n => n[0]).join("").substring(0, 2).toUpperCase() || "SL";
        
        const avatarEl = document.getElementById("sidebarUserAvatar");
        if (avatarEl) avatarEl.textContent = initials;

        const nameEl = document.getElementById("sidebarUserName");
        if (nameEl) nameEl.textContent = currentUser.name;

        const roleEl = document.getElementById("sidebarUserRole");
        if (roleEl) roleEl.textContent = currentUser.role || "Junior Pentester";

        const dashNameEl = document.getElementById("dashGreetingName");
        if (dashNameEl) dashNameEl.textContent = currentUser.name;

        const profAvatar = document.getElementById("profileAvatarLarge");
        if (profAvatar) profAvatar.textContent = initials;

        const profName = document.getElementById("profileNameDisplay");
        if (profName) profName.textContent = currentUser.name;

        const profEmail = document.getElementById("profileEmailDisplay");
        if (profEmail) profEmail.textContent = `${currentUser.email} • ${currentUser.role || 'Junior Pentester'}`;

        const inpName = document.getElementById("profileInputName");
        if (inpName) inpName.value = currentUser.name;

        const inpEmail = document.getElementById("profileInputEmail");
        if (inpEmail) inpEmail.value = currentUser.email;

        const selMeth = document.getElementById("profileSelectMethodology");
        if (selMeth && currentUser.methodology) selMeth.value = currentUser.methodology;
    }

    function updateProjectsDropdown() {
        const select = document.getElementById("globalProjectSelect");
        if (!select) return;
        select.innerHTML = "";
        projects.forEach(p => {
            const opt = document.createElement("option");
            opt.value = p.id;
            opt.textContent = p.name;
            if (p.id === activeProjectId) opt.selected = true;
            select.appendChild(opt);
        });

        select.onchange = (e) => {
            setActiveProject(e.target.value);
        };
    }

    // ==========================================================================
    // 3. ROUTING & VIEW CONTROLLER
    // ==========================================================================
    const VIEWS = {
        "login": document.getElementById("view-login"),
        "dashboard": document.getElementById("view-dashboard"),
        "recent-projects": document.getElementById("view-recent-projects"),
        "about": document.getElementById("view-about"),
        "create-project": document.getElementById("view-create-project"),
        "existing-projects": document.getElementById("view-existing-projects"),
        "project-workspace": document.getElementById("view-project-workspace"),
        "autofix": document.getElementById("view-autofix"),
        "profile": document.getElementById("view-profile")
    };

    function navigateTo(hash) {
        let route = (hash || window.location.hash || "#dashboard").replace("#", "").trim();
        if (!route) route = "dashboard";

        // Route aliases & Security Tools mapping (maintaining active project context)
        if (route === "checklist-generator" || route === "tool-checklist") {
            route = "project-workspace";
            switchWorkspaceTab("checklist");
        } else if (route === "findings") {
            route = "project-workspace";
            switchWorkspaceTab("findings");
        } else if (route === "report-generation" || route === "tool-reports") {
            route = "project-workspace";
            switchWorkspaceTab("report");
        } else if (route === "autofix" || route === "tool-autofix") {
            route = "project-workspace";
            switchWorkspaceTab("autofix");
            renderWorkspaceAutoFix();
        }

        // Auth guard: if route is not login and user is logged out
        if (route !== "login" && !currentUser) {
            window.location.hash = "#login";
            return;
        }

        // Activate view
        Object.keys(VIEWS).forEach(k => {
            if (VIEWS[k]) {
                if (k === route) {
                    VIEWS[k].classList.add("active");
                } else {
                    VIEWS[k].classList.remove("active");
                }
            }
        });

        // Update sidebar nav highlighting
        document.querySelectorAll(".nav-item, .nav-child-item").forEach(item => {
            const itemRoute = item.getAttribute("data-route");
            if (itemRoute === route || (route === "project-workspace" && (itemRoute === "checklist-generator" || itemRoute === "findings" || itemRoute === "report-generation" || itemRoute === "autofix"))) {
                item.classList.add("active");
            } else {
                item.classList.remove("active");
            }
        });

        // Update Breadcrumbs
        const crumbCurrent = document.getElementById("crumbCurrentPage");
        if (crumbCurrent) {
            crumbCurrent.textContent = formatRouteName(route);
        }

        // View-specific renders
        if (route === "dashboard") {
            renderDashboard();
        } else if (route === "recent-projects") {
            renderRecentProjects();
        } else if (route === "existing-projects") {
            renderExistingProjects();
        } else if (route === "project-workspace") {
            renderActiveWorkspace();
        }

        // Scroll to top
        window.scrollTo(0, 0);

        // Close mobile sidebar if open
        const sidebar = document.getElementById("sidebar");
        if (sidebar) sidebar.classList.remove("mobile-open");
    }

    function formatRouteName(route) {
        const names = {
            "login": "Sign In",
            "dashboard": "Dashboard",
            "recent-projects": "Recent Projects",
            "about": "About Tracegate",
            "create-project": "Create New Project",
            "existing-projects": "Existing Projects",
            "project-workspace": "Project Workspace",
            "autofix": "AI AutoFix Connector Workbench",
            "profile": "Profile & Settings"
        };
        return names[route] || "Dashboard";
    }

    window.addEventListener("hashchange", () => {
        navigateTo(window.location.hash);
    });

    // Accordion handler
    const btnAccordion = document.getElementById("btnAccordionToggle");
    const projectsAccordion = document.getElementById("projectsAccordion");
    if (btnAccordion && projectsAccordion) {
        btnAccordion.addEventListener("click", () => {
            projectsAccordion.classList.toggle("open");
        });
    }

    // Mobile Hamburger
    const btnMobileToggle = document.getElementById("btnMobileToggle");
    const sidebar = document.getElementById("sidebar");
    if (btnMobileToggle && sidebar) {
        btnMobileToggle.addEventListener("click", () => {
            sidebar.classList.toggle("mobile-open");
        });
    }

    // Top New Project button
    const btnTopNavNewProject = document.getElementById("btnTopNavNewProject");
    if (btnTopNavNewProject) {
        btnTopNavNewProject.addEventListener("click", () => {
            window.location.hash = "#create-project";
        });
    }

    const btnDashQuickNewProject = document.getElementById("btnDashQuickNewProject");
    if (btnDashQuickNewProject) {
        btnDashQuickNewProject.addEventListener("click", () => {
            window.location.hash = "#create-project";
        });
    }

    // ==========================================================================
    // 4. AUTHENTICATION & LOGIN LOGIC (REAL SQLITE DB AUTH)
    // ==========================================================================
    const loginForm = document.getElementById("loginForm");
    const signupForm = document.getElementById("signupForm");
    const tabAuthSignIn = document.getElementById("tabAuthSignIn");
    const tabAuthSignUp = document.getElementById("tabAuthSignUp");
    const authHeaderTitle = document.getElementById("authHeaderTitle");
    const authAlertBox = document.getElementById("authAlertBox");
    const authAlertMessage = document.getElementById("authAlertMessage");

    const loginEmailInput = document.getElementById("loginEmailInput");
    const loginPasswordInput = document.getElementById("loginPasswordInput");
    const btnLoginSubmit = document.getElementById("btnLoginSubmit");
    const btnDemoQuickLogin = document.getElementById("btnDemoQuickLogin");
    const btnDemoQuickAdmin = document.getElementById("btnDemoQuickAdmin");
    const btnTogglePassword = document.getElementById("btnTogglePassword");
    const linkForgotPassword = document.getElementById("linkForgotPassword");
    const btnLogout = document.getElementById("btnLogout");

    const signupFullNameInput = document.getElementById("signupFullNameInput");
    const signupEmailInput = document.getElementById("signupEmailInput");
    const signupUsernameInput = document.getElementById("signupUsernameInput");
    const signupPasswordInput = document.getElementById("signupPasswordInput");
    const signupRoleSelect = document.getElementById("signupRoleSelect");
    const btnSignupSubmit = document.getElementById("btnSignupSubmit");

    // Tab Switching: Sign In vs Create Account
    if (tabAuthSignIn && tabAuthSignUp) {
        tabAuthSignIn.addEventListener("click", () => {
            tabAuthSignIn.classList.add("active");
            tabAuthSignUp.classList.remove("active");
            if (loginForm) loginForm.style.display = "flex";
            if (signupForm) signupForm.style.display = "none";
            if (authHeaderTitle) authHeaderTitle.textContent = "Sign in to Tracegate";
            hideAuthError();
        });

        tabAuthSignUp.addEventListener("click", () => {
            tabAuthSignUp.classList.add("active");
            tabAuthSignIn.classList.remove("active");
            if (loginForm) loginForm.style.display = "none";
            if (signupForm) signupForm.style.display = "flex";
            if (authHeaderTitle) authHeaderTitle.textContent = "Create Tracegate Account";
            hideAuthError();
        });
    }

    function showAuthError(msg) {
        if (authAlertBox && authAlertMessage) {
            authAlertMessage.textContent = msg;
            authAlertBox.style.display = "flex";
        }
        showToast(msg, "error");
    }

    function hideAuthError() {
        if (authAlertBox) authAlertBox.style.display = "none";
    }

    if (btnTogglePassword && loginPasswordInput) {
        btnTogglePassword.addEventListener("click", () => {
            const isPassword = loginPasswordInput.type === "password";
            loginPasswordInput.type = isPassword ? "text" : "password";
        });
    }

    if (linkForgotPassword) {
        linkForgotPassword.addEventListener("click", () => {
            openModal("modalForgotPassword");
        });
    }

    const btnForgotModalOk = document.getElementById("btnForgotModalOk");
    if (btnForgotModalOk) {
        btnForgotModalOk.addEventListener("click", () => {
            closeModal("modalForgotPassword");
        });
    }

    const btnCloseForgotModal = document.getElementById("btnCloseForgotModal");
    if (btnCloseForgotModal) {
        btnCloseForgotModal.addEventListener("click", () => {
            closeModal("modalForgotPassword");
        });
    }

    // Quick fill demo credentials
    if (btnDemoQuickLogin) {
        btnDemoQuickLogin.addEventListener("click", () => {
            if (loginEmailInput) loginEmailInput.value = "learner@tracegate.lab";
            if (loginPasswordInput) loginPasswordInput.value = "Password123!";
            hideAuthError();
            executeLogin();
        });
    }

    if (btnDemoQuickAdmin) {
        btnDemoQuickAdmin.addEventListener("click", () => {
            if (loginEmailInput) loginEmailInput.value = "admin@tracegate.lab";
            if (loginPasswordInput) loginPasswordInput.value = "AdminPassword123!";
            hideAuthError();
            executeLogin();
        });
    }

    if (btnLoginSubmit) {
        btnLoginSubmit.addEventListener("click", executeLogin);
    }

    if (loginPasswordInput) {
        loginPasswordInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") executeLogin();
        });
    }

    async function executeLogin() {
        const username_or_email = loginEmailInput ? loginEmailInput.value.trim() : "";
        const password = loginPasswordInput ? loginPasswordInput.value.trim() : "";

        if (!username_or_email || !password) {
            showAuthError("Please provide both email/username and password.");
            return;
        }

        const btnText = document.getElementById("loginBtnText");
        if (btnText) btnText.textContent = "Verifying Credentials...";
        if (btnLoginSubmit) btnLoginSubmit.disabled = true;
        hideAuthError();

        try {
            const res = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username_or_email, password })
            });

            if (!res.ok) {
                let errDetail = "Invalid email/username or password.";
                try {
                    const errData = await res.json();
                    if (errData.detail) errDetail = errData.detail;
                } catch (e) {}
                showAuthError(errDetail);
                if (btnText) btnText.textContent = "Sign In to Dashboard";
                if (btnLoginSubmit) btnLoginSubmit.disabled = false;
                return;
            }

            const data = await res.json();
            localStorage.setItem("tg_auth_token", data.access_token);
            currentUser = data.user;
            localStorage.setItem("tg_user", JSON.stringify(currentUser));

            updateUserUI();
            showToast(`Welcome back, ${currentUser.name}!`, "success");

            if (btnText) btnText.textContent = "Sign In to Dashboard";
            if (btnLoginSubmit) btnLoginSubmit.disabled = false;

            window.location.hash = "#dashboard";
        } catch (err) {
            showAuthError("Authentication service connection failed.");
            if (btnText) btnText.textContent = "Sign In to Dashboard";
            if (btnLoginSubmit) btnLoginSubmit.disabled = false;
        }
    }

    // Sign Up Execution
    if (btnSignupSubmit) {
        btnSignupSubmit.addEventListener("click", async () => {
            const full_name = signupFullNameInput?.value.trim();
            const email = signupEmailInput?.value.trim();
            const username = signupUsernameInput?.value.trim();
            const password = signupPasswordInput?.value.trim();
            const role = signupRoleSelect?.value || "Junior Pentester / Security Learner";

            if (!full_name || !email || !username || !password) {
                showAuthError("All fields marked * are required.");
                return;
            }

            if (password.length < 8) {
                showAuthError("Password must be at least 8 characters.");
                return;
            }

            const signupBtnText = document.getElementById("signupBtnText");
            if (signupBtnText) signupBtnText.textContent = "Creating Account...";
            btnSignupSubmit.disabled = true;
            hideAuthError();

            try {
                const res = await fetch("/api/auth/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, username, password, full_name, role })
                });

                if (!res.ok) {
                    let errDetail = "Failed to register account.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    showAuthError(errDetail);
                    if (signupBtnText) signupBtnText.textContent = "Create Account & Sign In";
                    btnSignupSubmit.disabled = false;
                    return;
                }

                const data = await res.json();
                localStorage.setItem("tg_auth_token", data.access_token);
                currentUser = data.user;
                localStorage.setItem("tg_user", JSON.stringify(currentUser));

                updateUserUI();
                showToast(`Account created! Welcome to Tracegate, ${currentUser.name}.`, "success");

                if (signupBtnText) signupBtnText.textContent = "Create Account & Sign In";
                btnSignupSubmit.disabled = false;

                window.location.hash = "#dashboard";
            } catch (err) {
                showAuthError("Registration service connection failed.");
                if (signupBtnText) signupBtnText.textContent = "Create Account & Sign In";
                btnSignupSubmit.disabled = false;
            }
        });
    }

    // Logout Handler
    if (btnLogout) {
        btnLogout.addEventListener("click", async () => {
            const token = localStorage.getItem("tg_auth_token");
            if (token) {
                try {
                    await fetch("/api/auth/logout", {
                        method: "POST",
                        headers: { "Authorization": `Bearer ${token}` }
                    });
                } catch (e) {}
            }
            localStorage.removeItem("tg_auth_token");
            localStorage.removeItem("tg_user");
            currentUser = null;
            showToast("You have been signed out.", "info");
            window.location.hash = "#login";
        });
    }

    // ==========================================================================
    // 5. DASHBOARD & RECENT PROJECTS LOGIC
    // ==========================================================================
    function calculateProjectMetrics(proj) {
        if (!proj.checklist_data || !proj.checklist_data.checklist) {
            const defaultTotal = 10;
            const completed = proj.status === "COMPLETED" ? 10 : (proj.status === "NEEDS_REVIEW" ? 6 : 4);
            const vulns = proj.findings ? proj.findings.length : 0;
            const clean = Math.max(0, completed - vulns);
            const remaining = defaultTotal - completed;
            const pct = Math.round((completed / defaultTotal) * 100);
            return { total: defaultTotal, completed, vulns, clean, remaining, pct };
        }

        const list = proj.checklist_data.checklist;
        const total = list.length;
        const clean = list.filter(i => i.status === "TESTED_NOT_FOUND").length;
        const vulns = list.filter(i => i.status === "VULNERABILITY_FOUND").length;
        const completed = clean + vulns;
        const remaining = total - completed;
        const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
        return { total, completed, vulns, clean, remaining, pct };
    }

    function refreshDashboardStats() {
        const totalProjects = projects.length;
        let totalCompletedTests = 0;
        let totalVulns = 0;
        let totalClean = 0;
        let checklistsCompleted = 0;

        projects.forEach(p => {
            const m = calculateProjectMetrics(p);
            totalCompletedTests += m.completed;
            totalVulns += (p.findings ? p.findings.length : m.vulns);
            totalClean += m.clean;
            if (m.pct === 100) checklistsCompleted++;
        });

        const statTotalProjectsEl = document.getElementById("statTotalProjects");
        if (statTotalProjectsEl) statTotalProjectsEl.textContent = totalProjects;

        const statTestsCompletedEl = document.getElementById("statTestsCompleted");
        if (statTestsCompletedEl) statTestsCompletedEl.textContent = totalCompletedTests;

        const statVulnsFoundEl = document.getElementById("statVulnsFound");
        if (statVulnsFoundEl) statVulnsFoundEl.textContent = totalVulns;

        const statVulnsNotFoundEl = document.getElementById("statVulnsNotFound");
        if (statVulnsNotFoundEl) statVulnsNotFoundEl.textContent = totalClean;

        const statChecklistsCompletedEl = document.getElementById("statChecklistsCompleted");
        if (statChecklistsCompletedEl) statChecklistsCompletedEl.textContent = checklistsCompleted;
    }

    function renderDashboard() {
        refreshDashboardStats();
        const listEl = document.getElementById("dashRecentProjectsList");
        if (!listEl) return;
        listEl.innerHTML = "";

        const recent = [...projects].slice(0, 4);
        recent.forEach(proj => {
            const m = calculateProjectMetrics(proj);
            const card = createProjectItemCard(proj, m);
            listEl.appendChild(card);
        });
    }

    function createProjectItemCard(proj, metrics) {
        const div = document.createElement("div");
        div.className = "project-item-card";

        const statusClass = proj.status === "COMPLETED" ? "badge-completed" : (proj.status === "NEEDS_REVIEW" ? "badge-needs-review" : "badge-in-progress");
        const statusText = proj.status === "COMPLETED" ? "Completed" : (proj.status === "NEEDS_REVIEW" ? "Needs Review" : "In Progress");

        div.innerHTML = `
            <div class="project-item-left">
                <div class="project-avatar">${escapeHtml(proj.name.substring(0, 2).toUpperCase())}</div>
                <div class="project-meta-info">
                    <span class="project-meta-title">${escapeHtml(proj.name)}</span>
                    <span class="project-meta-target">${escapeHtml(proj.target_url)}</span>
                </div>
            </div>

            <div class="project-item-center">
                <div class="project-progress-wrap">
                    <div class="project-progress-label">
                        <span>Checklist Progress</span>
                        <span>${metrics.pct}%</span>
                    </div>
                    <div class="project-progress-bar">
                        <div class="project-progress-fill" style="width: ${metrics.pct}%"></div>
                    </div>
                </div>
            </div>

            <div class="project-item-right">
                <span class="badge ${statusClass}">${statusText}</span>
                <span class="badge ${proj.findings && proj.findings.length > 0 ? 'badge-critical' : 'badge-low'}">
                    ${proj.findings ? proj.findings.length : 0} Vulns
                </span>
                <button type="button" class="btn btn-secondary btn-sm btn-open-project" data-proj-id="${proj.id}">
                    Open Project &rarr;
                </button>
            </div>
        `;

        div.querySelector(".btn-open-project").addEventListener("click", () => {
            setActiveProject(proj.id);
            window.location.hash = "#project-workspace";
        });

        return div;
    }

    function renderRecentProjects() {
        const listEl = document.getElementById("recentProjectsFullList");
        if (!listEl) return;
        listEl.innerHTML = "";

        const searchVal = (document.getElementById("recentProjectsSearchInput")?.value || "").toLowerCase().trim();
        const activeFilter = document.querySelector("[data-recent-status].active")?.getAttribute("data-recent-status") || "ALL";
        const sortVal = document.getElementById("recentProjectsSortSelect")?.value || "recent";

        let filtered = projects.filter(p => {
            const matchesSearch = p.name.toLowerCase().includes(searchVal) || p.target_url.toLowerCase().includes(searchVal);
            const matchesStatus = activeFilter === "ALL" || p.status === activeFilter;
            return matchesSearch && matchesStatus;
        });

        if (sortVal === "name") {
            filtered.sort((a, b) => a.name.localeCompare(b.name));
        } else if (sortVal === "progress") {
            filtered.sort((a, b) => calculateProjectMetrics(b).pct - calculateProjectMetrics(a).pct);
        } else {
            filtered.sort((a, b) => (b.updated_at || "").localeCompare(a.updated_at || ""));
        }

        if (filtered.length === 0) {
            listEl.innerHTML = `
                <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                    No projects found matching the criteria.
                </div>
            `;
            return;
        }

        filtered.forEach(p => {
            const m = calculateProjectMetrics(p);
            listEl.appendChild(createProjectItemCard(p, m));
        });
    }

    // Recent Projects Search & Filter Event Listeners
    const recentProjectsSearchInput = document.getElementById("recentProjectsSearchInput");
    if (recentProjectsSearchInput) {
        recentProjectsSearchInput.addEventListener("input", renderRecentProjects);
    }

    const recentProjectsSortSelect = document.getElementById("recentProjectsSortSelect");
    if (recentProjectsSortSelect) {
        recentProjectsSortSelect.addEventListener("change", renderRecentProjects);
    }

    document.querySelectorAll("[data-recent-status]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-recent-status]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            renderRecentProjects();
        });
    });

    function renderExistingProjects() {
        const listEl = document.getElementById("existingProjectsFullList");
        if (!listEl) return;
        listEl.innerHTML = "";

        const searchVal = (document.getElementById("existingProjectsSearchInput")?.value || "").toLowerCase().trim();
        const activeFilter = document.querySelector("[data-existing-status].active")?.getAttribute("data-existing-status") || "ALL";

        const filtered = projects.filter(p => {
            const matchesSearch = p.name.toLowerCase().includes(searchVal) || p.target_url.toLowerCase().includes(searchVal);
            const matchesStatus = activeFilter === "ALL" || p.status === activeFilter;
            return matchesSearch && matchesStatus;
        });

        if (filtered.length === 0) {
            listEl.innerHTML = `
                <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                    No projects found. Create your first security audit project!
                </div>
            `;
            return;
        }

        filtered.forEach(p => {
            const m = calculateProjectMetrics(p);
            listEl.appendChild(createProjectItemCard(p, m));
        });
    }

    const existingProjectsSearchInput = document.getElementById("existingProjectsSearchInput");
    if (existingProjectsSearchInput) {
        existingProjectsSearchInput.addEventListener("input", renderExistingProjects);
    }

    document.querySelectorAll("[data-existing-status]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-existing-status]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            renderExistingProjects();
        });
    });

    // Create New Project Form Submit
    const btnSubmitCreateProject = document.getElementById("btnSubmitCreateProject");
    if (btnSubmitCreateProject) {
        btnSubmitCreateProject.addEventListener("click", async () => {
            const name = document.getElementById("newProjName")?.value.trim();
            const target = document.getElementById("newProjTarget")?.value.trim();
            const env = document.getElementById("newProjEnv")?.value;
            const desc = document.getElementById("newProjDesc")?.value.trim();
            const notes = document.getElementById("newProjNotes")?.value.trim();

            if (!name || !target) {
                showToast("Project Name and Target Application URL are required.", "error");
                return;
            }

            let newProj = {
                id: "proj-" + Date.now(),
                name: name,
                target_url: target,
                environment: env,
                description: desc || "Authorized security testing assessment.",
                notes: notes || "",
                status: "IN_PROGRESS",
                created_at: new Date().toISOString().split("T")[0],
                updated_at: new Date().toISOString().split("T")[0],
                checklist_data: null,
                findings: []
            };

            // Call backend REST API
            try {
                const res = await fetch("/api/projects", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        name: newProj.name,
                        target_url: newProj.target_url,
                        environment: newProj.environment,
                        description: newProj.description,
                        notes: newProj.notes
                    })
                });
                if (res.ok) {
                    const created = await res.json();
                    newProj = { ...newProj, ...created, checklist_data: null, findings: [] };
                }
            } catch (err) {
                console.warn("[TRACEGATE] Project creation offline fallback:", err);
            }

            projects.unshift(newProj);
            saveProjects();
            await setActiveProject(newProj.id);

            // Clear form
            document.getElementById("newProjName").value = "";
            document.getElementById("newProjTarget").value = "";
            document.getElementById("newProjDesc").value = "";
            document.getElementById("newProjNotes").value = "";

            showToast(`Project "${newProj.name}" created!`, "success");
            window.location.hash = "#project-workspace";
        });
    }

    // ==========================================================================
    // 6. PROJECT WORKSPACE CONTROLLER
    // ==========================================================================
    window.switchWorkspaceTab = function(tabName) {
        document.querySelectorAll(".ws-tab-btn").forEach(b => {
            if (b.getAttribute("data-tab") === tabName) b.classList.add("active");
            else b.classList.remove("active");
        });

        document.querySelectorAll(".ws-tab-pane").forEach(pane => {
            if (pane.id === `pane-ws-${tabName}`) pane.classList.add("active");
            else pane.classList.remove("active");
        });

        if (tabName === "findings") renderWorkspaceFindings();
        if (tabName === "report") renderWorkspaceReport();
        if (tabName === "autofix") renderWorkspaceAutoFix();
    };

    document.querySelectorAll(".ws-tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const tab = btn.getAttribute("data-tab");
            switchWorkspaceTab(tab);
        });
    });

    function renderActiveWorkspace() {
        const proj = getActiveProject();
        if (!proj) return;

        const nameEl = document.getElementById("wsProjectName");
        if (nameEl) nameEl.textContent = proj.name;

        const targetEl = document.getElementById("wsProjectTargetUrl");
        if (targetEl) targetEl.textContent = proj.target_url;

        const statusEl = document.getElementById("wsProjectStatusBadge");
        if (statusEl) {
            statusEl.className = "badge " + (proj.status === "COMPLETED" ? "badge-completed" : (proj.status === "NEEDS_REVIEW" ? "badge-needs-review" : "badge-in-progress"));
            statusEl.textContent = proj.status === "COMPLETED" ? "Completed" : (proj.status === "NEEDS_REVIEW" ? "Needs Review" : "In Progress");
        }

        const descEl = document.getElementById("wsOverviewDescription");
        if (descEl) descEl.textContent = proj.description || "No description provided.";

        const notesEl = document.getElementById("wsOverviewNotes");
        if (notesEl) notesEl.textContent = proj.notes || "No scope notes recorded for this assessment.";

        const badgeCount = document.getElementById("wsFindingsBadgeCount");
        if (badgeCount) badgeCount.textContent = (proj.findings ? proj.findings.length : 0);

        // Checklist view render
        if (proj.checklist_data && proj.checklist_data.checklist) {
            document.getElementById("idleState").style.display = "none";
            document.getElementById("resultsContent").classList.add("active");
            renderPageAnalysis(proj.checklist_data);
            renderChecklistCards();
            updateChecklistProgressUI();
        } else {
            document.getElementById("idleState").style.display = "flex";
            document.getElementById("resultsContent").classList.remove("active");
        }
    }

    // Quick add test from workspace header
    const btnWsQuickAddTest = document.getElementById("btnWsQuickAddTest");
    if (btnWsQuickAddTest) {
        btnWsQuickAddTest.addEventListener("click", () => {
            openModal("modalAddCustomTest");
        });
    }

    // ==========================================================================
    // 7. CHECKLIST GENERATOR (CORE ENGINE & REAL API)
    // ==========================================================================
    const dropZone = document.getElementById("dropZone");
    const fileInput = document.getElementById("fileInput");
    const uploadEmptyState = document.getElementById("uploadEmptyState");
    const uploadPreviewState = document.getElementById("uploadPreviewState");
    const imagePreview = document.getElementById("imagePreview");
    const previewFileName = document.getElementById("previewFileName");
    const btnClearImage = document.getElementById("btnClearImage");
    const promptInput = document.getElementById("promptInput");
    const btnAnalyze = document.getElementById("btnAnalyze");
    const btnAnalyzeText = document.getElementById("btnAnalyzeText");
    const analysisStepperBox = document.getElementById("analysisStepperBox");
    const engineStatusDot = document.getElementById("engineStatusDot");
    const engineStatusText = document.getElementById("engineStatusText");

    // Check Backend Health
    async function checkBackendHealth() {
        try {
            const res = await fetch("/api/health");
            if (!res.ok) throw new Error("Health check non-200");
            const data = await res.json();
            if (data.mode === "live") {
                engineStatusDot.className = "status-indicator-dot online-live";
                engineStatusText.textContent = `AI Vision (${data.provider.toUpperCase()})`;
            } else {
                engineStatusDot.className = "status-indicator-dot online-sim";
                engineStatusText.textContent = "AI Vision Simulation (Ready)";
            }
        } catch (e) {
            engineStatusDot.className = "status-indicator-dot offline";
            engineStatusText.textContent = "Offline / Disconnected";
        }
    }
    checkBackendHealth();

    // 10 Sample Quick-Load Scenario Pills
    const samplePills = document.querySelectorAll(".sample-pill-btn");
    samplePills.forEach(pill => {
        pill.addEventListener("click", async () => {
            samplePills.forEach(p => p.classList.remove("active"));
            pill.classList.add("active");

            const sampleKey = pill.getAttribute("data-sample");
            const filename = `${sampleKey}.png`;
            showToast(`Loading scenario: ${pill.textContent.trim()}...`, "info");

            try {
                const res = await fetch(`/samples/${filename}`);
                if (!res.ok) throw new Error(`Could not load sample ${filename}`);
                const blob = await res.blob();
                const file = new File([blob], filename, { type: blob.type || "image/png" });
                setUploadedFile(file);
            } catch (err) {
                showToast(`Failed to load sample image: ${err.message}`, "error");
            }
        });
    });

    // Drag and drop handlers
    if (dropZone) {
        dropZone.addEventListener("click", (e) => {
            if (e.target !== btnClearImage) fileInput.click();
        });

        dropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropZone.classList.add("drag-over");
        });

        dropZone.addEventListener("dragleave", () => {
            dropZone.classList.remove("drag-over");
        });

        dropZone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropZone.classList.remove("drag-over");
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                validateAndSetFile(e.dataTransfer.files[0]);
            }
        });
    }

    if (fileInput) {
        fileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files[0]) {
                validateAndSetFile(e.target.files[0]);
            }
        });
    }

    if (btnClearImage) {
        btnClearImage.addEventListener("click", (e) => {
            e.stopPropagation();
            clearUploadedFile();
        });
    }

    function validateAndSetFile(file) {
        const allowed = ["image/png", "image/jpeg", "image/jpg", "image/webp"];
        if (!allowed.includes(file.type)) {
            showToast("Unsupported file format. Please upload a PNG, JPG, or WEBP screenshot.", "error");
            return;
        }

        if (file.size > 10 * 1024 * 1024) {
            showToast("File exceeds 10MB limit. Please upload a smaller image.", "error");
            return;
        }

        setUploadedFile(file);
    }

    function setUploadedFile(file) {
        currentUploadedFile = file;
        uploadedImage = file;
        analysisResult = null;
        analysisStatus = "IDLE";
        currentImageHash = null;
        checklistStatus = "IDLE";

        const staleBanner = document.getElementById("staleAnalysisBanner");
        if (staleBanner) staleBanner.style.display = "none";

        console.log(`[TRACEGATE UPLOAD] Selected file: "${file.name}", type: ${file.type || 'unknown'}, size: ${(file.size / 1024).toFixed(1)} KB`);
        const reader = new FileReader();
        reader.onload = (e) => {
            imagePreview.src = e.target.result;
            previewFileName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
            uploadEmptyState.style.display = "none";
            uploadPreviewState.classList.add("active");
            btnAnalyze.disabled = false;
        };
        reader.readAsDataURL(file);
    }

    function clearUploadedFile() {
        console.log("[TRACEGATE UPLOAD] Uploaded file state cleared.");
        currentUploadedFile = null;
        fileInput.value = "";
        imagePreview.src = "";
        uploadEmptyState.style.display = "flex";
        uploadPreviewState.classList.remove("active");
        btnAnalyze.disabled = true;
        samplePills.forEach(p => p.classList.remove("active"));
    }

    // ==========================================================================
    // 7. UNIFIED CHECKLIST GENERATOR (Sections 19, 20, 21, 22, 23)
    // ==========================================================================
    async function generateChecklist() {
        if (!currentUploadedFile) {
            showToast("Please select or upload a target screenshot.", "error");
            return;
        }

        const activeProj = getActiveProject();
        if (!activeProj) {
            showToast("Please select or create an assessment project first.", "error");
            return;
        }

        // Section 20: Read CURRENT input values at click time directly
        let pageTypeValue = document.getElementById("pageTypeSelect")?.value || "Auto Detect";
        if (pageTypeValue === "Other") {
            const otherCustom = document.getElementById("pageTypeOtherInput")?.value.trim();
            pageTypeValue = otherCustom || "Other";
        }
        selectedPageType = pageTypeValue;

        const userPrompt = (promptInput?.value || "").trim();
        additionalContext = userPrompt;

        // Section 22: Cancel any in-flight request before launching new generation
        if (currentAbortController) {
            try {
                currentAbortController.abort();
            } catch (e) {}
        }
        currentAbortController = new AbortController();

        // Section 21: Unique Request ID
        const reqId = "req-" + Date.now() + "-" + Math.random().toString(36).substring(2, 8);
        currentAnalysisRequestId = reqId;

        analysisStatus = "RUNNING";
        checklistStatus = "GENERATING";

        // Loading UI state
        if (btnAnalyze) {
            btnAnalyze.disabled = true;
            if (btnAnalyzeText) btnAnalyzeText.textContent = "Vision AI Processing...";
        }
        const regenBtn = document.getElementById("btnRegenerateChecklist");
        if (regenBtn) {
            regenBtn.disabled = true;
            regenBtn.textContent = "Processing...";
        }
        if (analysisStepperBox) analysisStepperBox.classList.add("active");

        const step1 = document.getElementById("loadingStep1");
        const step2 = document.getElementById("loadingStep2");
        const step3 = document.getElementById("loadingStep3");
        const step4 = document.getElementById("loadingStep4");

        if (step1) { step1.className = "step-item running"; step1.textContent = "● Image received"; }
        if (step2) { step2.className = "step-item pending"; step2.textContent = "○ Identifying visible functionality"; }
        if (step3) { step3.className = "step-item pending"; step3.textContent = "○ Building security checklist"; }
        if (step4) { step4.className = "step-item pending"; step4.textContent = "○ Prioritizing tests"; }

        setTimeout(() => {
            if (step1) { step1.className = "step-item done"; step1.textContent = "✓ Image received"; }
            if (step2) { step2.className = "step-item running"; step2.textContent = "● Identifying visible functionality"; }
        }, 300);

        setTimeout(() => {
            if (step2) { step2.className = "step-item done"; step2.textContent = "✓ Identifying visible functionality"; }
            if (step3) { step3.className = "step-item running"; step3.textContent = "● Building security checklist"; }
        }, 700);

        setTimeout(() => {
            if (step3) { step3.className = "step-item done"; step3.textContent = "✓ Building security checklist"; }
            if (step4) { step4.className = "step-item running"; step4.textContent = "● Prioritizing tests"; }
        }, 1100);

        const formData = new FormData();
        formData.append("image", currentUploadedFile);
        if (userPrompt) formData.append("prompt", userPrompt);
        formData.append("project_id", activeProj.id);
        formData.append("request_id", reqId);
        if (pageTypeValue && pageTypeValue !== "Auto Detect") {
            formData.append("page_type", pageTypeValue);
        }

        console.log(`[TRACEGATE API] Dispatching generateChecklist: req_id="${reqId}", file="${currentUploadedFile.name}", page_type="${pageTypeValue}"`);

        try {
            const response = await fetch("/api/analyze-screenshot", {
                method: "POST",
                body: formData,
                signal: currentAbortController.signal
            });

            if (!response.ok) {
                let errDetail = "Inspection failed.";
                try {
                    const errJson = await response.json();
                    errDetail = errJson.detail || errDetail;
                } catch (e) {}
                throw new Error(errDetail);
            }

            const data = await response.json();

            // Section 21 & 23: Ignore stale responses - latest request always wins!
            if (data.request_id && data.request_id !== currentAnalysisRequestId) {
                console.warn(`[TRACEGATE] Discarding stale response ${data.request_id} (active is ${currentAnalysisRequestId})`);
                return;
            }

            currentImageHash = data.image_hash || null;
            lastAnalyzedPageType = pageTypeValue;
            lastGeneratedPageType = pageTypeValue;
            analysisResult = data;
            checklist = data.checklist || [];
            analysisStatus = "SUCCESS";
            checklistStatus = "CURRENT";

            const staleBanner = document.getElementById("staleAnalysisBanner");
            if (staleBanner) staleBanner.style.display = "none";

            if (step4) {
                step4.className = "step-item done";
                step4.textContent = "✓ Prioritizing tests";
            }

            setTimeout(() => {
                if (analysisStepperBox) analysisStepperBox.classList.remove("active");
                if (btnAnalyze) {
                    btnAnalyze.disabled = false;
                    if (btnAnalyzeText) btnAnalyzeText.textContent = "Analyze & Generate Checklist";
                }
                if (regenBtn) {
                    regenBtn.disabled = false;
                    regenBtn.textContent = "Generate Checklist";
                }

                // Save to project
                activeProj.checklist_data = data;
                activeProj.updated_at = new Date().toISOString().split("T")[0];
                saveProjects();

                // Switch view states
                const idleEl = document.getElementById("idleState");
                const resEl = document.getElementById("resultsContent");
                if (idleEl) idleEl.style.display = "none";
                if (resEl) resEl.classList.add("active");

                renderPageAnalysis(data);
                renderChecklistCards();
                updateChecklistProgressUI();
                refreshDashboardStats();

                showToast("Security checklist generated successfully!", "success");
            }, 400);

        } catch (err) {
            // Section 22: Catch AbortError quietly, no error toast for aborted request
            if (err.name === "AbortError") {
                console.log(`[TRACEGATE] Superseded request "${reqId}" cancelled.`);
                return;
            }

            analysisStatus = "ERROR";
            checklistStatus = "IDLE";
            if (analysisStepperBox) analysisStepperBox.classList.remove("active");
            if (btnAnalyze) {
                btnAnalyze.disabled = false;
                if (btnAnalyzeText) btnAnalyzeText.textContent = "Analyze & Generate Checklist";
            }
            if (regenBtn) {
                regenBtn.disabled = false;
                regenBtn.textContent = "Generate Checklist";
            }
            showToast(`Analysis Error: ${err.message}`, "error");
        }
    }

    if (btnAnalyze) {
        btnAnalyze.addEventListener("click", generateChecklist);
    }

    function renderPageAnalysis(data) {
        const pageTypeEl = document.getElementById("detectedPageType");
        if (pageTypeEl) pageTypeEl.textContent = data.page_type || "Unknown Web Interface";

        const confValEl = document.getElementById("confidenceValue");
        const confBarEl = document.getElementById("confidenceBarFill");
        if (data.selected_page_type && data.selected_page_type !== "Auto Detect") {
            if (confValEl) confValEl.textContent = data.visual_analysis_available !== false ? "Visual Context Applied" : "Knowledge Base Active";
            if (confBarEl) confBarEl.style.width = data.visual_analysis_available !== false ? "100%" : "60%";
        } else {
            const pct = Math.round((data.confidence || 0) * 100);
            if (confValEl) confValEl.textContent = `${pct}%`;
            if (confBarEl) confBarEl.style.width = `${pct}%`;
        }

        // Section 4 & 36: Permanently hide conflict banner (mismatch warnings removed)
        const conflictBanner = document.getElementById("pageTypeConflictBanner");
        if (conflictBanner) conflictBanner.style.display = "none";

        // Ambiguity Warning Banner (only for truly ambiguous interfaces)
        const ambiguityBanner = document.getElementById("ambiguityBanner");
        const ambiguityText = document.getElementById("ambiguityText");
        if (ambiguityBanner) {
            if (data.page_type === "Unknown / Ambiguous" || (data.selected_page_type === "Auto Detect" && data.confidence < 0.5)) {
                ambiguityBanner.classList.add("active");
                if (ambiguityText) ambiguityText.textContent = data.ambiguity_notes || "The screenshot could not be uniquely categorized. Please select a specific Page Type from the dropdown.";
            } else {
                ambiguityBanner.classList.remove("active");
            }
        }

        // Visible Functionality
        const funcListEl = document.getElementById("detectedFunctionalitiesList");
        if (funcListEl) {
            funcListEl.innerHTML = "";
            const funcs = (data.visible_functionality && data.visible_functionality.length > 0)
                ? data.visible_functionality
                : (data.detected_functionalities && data.detected_functionalities.length > 0)
                    ? data.detected_functionalities
                    : ["Standard Authentication Surface", "Client Input Processing"];
            funcs.forEach(f => {
                const tag = document.createElement("span");
                tag.className = "surface-tag";
                tag.textContent = f;
                funcListEl.appendChild(tag);
            });
        }

        // Visible UI Elements
        const elemListEl = document.getElementById("detectedElementsList");
        if (elemListEl) {
            elemListEl.innerHTML = "";
            const elems = data.detected_elements || [];
            elems.forEach(e => {
                const tag = document.createElement("span");
                tag.className = "element-tag";
                tag.textContent = typeof e === "string" ? e : (e.name || JSON.stringify(e));
                elemListEl.appendChild(tag);
            });
        }
    }

    // ==========================================================================
    // 8. CHECKLIST COMPLETION WORKFLOW & FINDINGS LOGGING
    // ==========================================================================
    function renderChecklistCards() {
        const container = document.getElementById("checklistContainer");
        if (!container) return;
        container.innerHTML = "";

        const proj = getActiveProject();
        if (!proj || !proj.checklist_data || !proj.checklist_data.checklist) return;

        let items = [...proj.checklist_data.checklist];

        // 1. Filter by Search
        if (currentSearchTerm) {
            items = items.filter(i => 
                i.name.toLowerCase().includes(currentSearchTerm) ||
                (i.cwe && i.cwe.toLowerCase().includes(currentSearchTerm)) ||
                (i.testing_objective && i.testing_objective.toLowerCase().includes(currentSearchTerm)) ||
                (i.reason && i.reason.toLowerCase().includes(currentSearchTerm))
            );
        }

        // 2. Filter by Priority
        if (currentPriorityFilter !== "ALL") {
            items = items.filter(i => i.priority === currentPriorityFilter);
        }

        // 3. Filter by Status
        if (currentStatusFilter !== "ALL") {
            items = items.filter(i => i.status === currentStatusFilter);
        }

        // 4. Sort Items
        if (currentSortMode === "priority_desc") {
            items.sort((a, b) => (PRIORITY_ORDER[a.priority] ?? 99) - (PRIORITY_ORDER[b.priority] ?? 99));
        } else if (currentSortMode === "priority_asc") {
            items.sort((a, b) => (PRIORITY_ORDER[b.priority] ?? 99) - (PRIORITY_ORDER[a.priority] ?? 99));
        } else if (currentSortMode === "untested_first") {
            items.sort((a, b) => {
                if (a.status === "NOT_TESTED" && b.status !== "NOT_TESTED") return -1;
                if (a.status !== "NOT_TESTED" && b.status === "NOT_TESTED") return 1;
                return (PRIORITY_ORDER[a.priority] ?? 99) - (PRIORITY_ORDER[b.priority] ?? 99);
            });
        } else if (currentSortMode === "recently_completed") {
            items.sort((a, b) => {
                if (a.status !== "NOT_TESTED" && b.status === "NOT_TESTED") return -1;
                if (a.status === "NOT_TESTED" && b.status !== "NOT_TESTED") return 1;
                return (PRIORITY_ORDER[a.priority] ?? 99) - (PRIORITY_ORDER[b.priority] ?? 99);
            });
        }

        if (items.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 40px; background: var(--bg-surface); border: 1px dashed var(--border-subtle); border-radius: var(--radius-lg); color: var(--text-muted);">
                    No checklist items match the selected filter criteria.
                </div>
            `;
            return;
        }

        items.forEach(item => {
            container.appendChild(createChecklistItemCard(item, proj));
        });
    }

    function createChecklistItemCard(item, proj) {
        const card = document.createElement("div");
        const statusClass = item.status === "TESTED_NOT_FOUND" ? "status-clean" : (item.status === "VULNERABILITY_FOUND" ? "status-vuln" : "status-untested");
        card.className = `checklist-card ${statusClass}`;

        const priorityBadgeClass = `badge-${item.priority.toLowerCase()}`;
        const sourceLabel = item.source === "USER" ? "User Added" : (item.source === "USER_MODIFIED" ? "User Modified" : "AI Generated");
        const sourceClass = item.source === "USER" ? "source-user" : (item.source === "USER_MODIFIED" ? "source-modified" : "source-ai");

        // Status badge label
        let statusBadgeHtml = '<span class="status-indicator-badge untested">○ Not Tested</span>';
        let verifyBtnHtml = '<button type="button" class="btn-verify-action btn-verify-untested btn-open-verify">Verify / Complete</button>';

        if (item.status === "TESTED_NOT_FOUND") {
            statusBadgeHtml = '<span class="status-indicator-badge clean">✓ Tested — Not Found</span>';
            verifyBtnHtml = '<button type="button" class="btn-verify-action btn-verify-clean btn-open-verify">✓ Clean (Update)</button>';
        } else if (item.status === "VULNERABILITY_FOUND") {
            statusBadgeHtml = '<span class="status-indicator-badge vuln">⚠ Vulnerability Found</span>';
            verifyBtnHtml = '<button type="button" class="btn-verify-action btn-verify-vuln btn-open-verify">⚠ Vuln Found (Edit)</button>';
        }

        let findingPreviewHtml = "";
        if (item.status === "VULNERABILITY_FOUND" && item.finding) {
            findingPreviewHtml = `
                <div class="linked-finding-preview">
                    <span class="linked-finding-title">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                        Logged Finding: ${escapeHtml(item.finding.finding_name || item.name)}
                    </span>
                    <p class="linked-finding-snippet">${escapeHtml(item.finding.description || "Observation recorded.")}</p>
                </div>
            `;
        }

        card.innerHTML = `
            <div class="card-content-wrap">
                <div class="card-top-bar">
                    <div class="card-badges-row">
                        <span class="badge ${priorityBadgeClass}">${item.priority}</span>
                        ${item.cwe ? `<span class="cwe-pill">${escapeHtml(item.cwe)}</span>` : ""}
                        <span class="source-tag ${sourceClass}">${sourceLabel}</span>
                    </div>
                    <div class="card-item-title-row">
                        ${statusBadgeHtml}
                    </div>
                </div>

                <div class="test-name">${escapeHtml(item.name)}</div>

                <div class="card-details-grid">
                    <div class="detail-block">
                        <span class="detail-label">Why is this relevant?</span>
                        <p class="detail-text">${escapeHtml(item.reason)}</p>
                    </div>
                    <div class="detail-block">
                        <span class="detail-label">Testing Objective</span>
                        <p class="detail-text">${escapeHtml(item.testing_objective)}</p>
                    </div>
                </div>

                ${findingPreviewHtml}

                <div class="card-actions-bar">
                    <div class="left-actions">
                        ${verifyBtnHtml}
                    </div>
                    <div class="right-card-tools">
                        <button type="button" class="btn-icon-tool btn-edit-test" title="Edit Test Details">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>
                            </svg>
                        </button>
                        <button type="button" class="btn-icon-tool btn-delete btn-delete-test" title="Remove Test">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Event listener for Verify / Complete
        card.querySelector(".btn-open-verify").addEventListener("click", () => {
            activeVerifyItem = item;
            const titleEl = document.getElementById("verifyTestTitle");
            if (titleEl) titleEl.textContent = item.name;
            openModal("modalVerify");
        });

        // Event listener for Edit
        card.querySelector(".btn-edit-test").addEventListener("click", () => {
            activeEditItem = item;
            document.getElementById("editItemName").value = item.name;
            document.getElementById("editItemPriority").value = item.priority;
            document.getElementById("editItemCwe").value = item.cwe || "";
            document.getElementById("editItemReason").value = item.reason;
            document.getElementById("editItemObjective").value = item.testing_objective;
            openModal("modalEditItem");
        });

        // Event listener for Delete
        card.querySelector(".btn-delete-test").addEventListener("click", () => {
            if (confirm(`Remove test "${item.name}" from checklist?`)) {
                proj.checklist_data.checklist = proj.checklist_data.checklist.filter(i => i.id !== item.id);
                saveProjects();
                renderChecklistCards();
                updateChecklistProgressUI();
                refreshDashboardStats();
                showToast("Test removed from checklist", "info");
            }
        });

        return card;
    }

    // Modal Verify Actions
    const btnVerifyClean = document.getElementById("btnVerifyClean");
    const btnVerifyVuln = document.getElementById("btnVerifyVuln");
    const btnCloseVerifyModal = document.getElementById("btnCloseVerifyModal");

    if (btnCloseVerifyModal) {
        btnCloseVerifyModal.addEventListener("click", () => {
            closeModal("modalVerify");
        });
    }

    // Outcome 1: "Vulnerability Not Found" (Section 14)
    if (btnVerifyClean) {
        btnVerifyClean.addEventListener("click", async () => {
            if (!activeVerifyItem) return;
            const proj = getActiveProject();

            activeVerifyItem.status = "TESTED_NOT_FOUND";
            activeVerifyItem.finding = null;

            // Sync status with backend
            try {
                await fetch(`/api/checklist/${activeVerifyItem.id}/status`, {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ status: "TESTED_NOT_FOUND" })
                });
            } catch (err) {
                console.warn("[TRACEGATE] Status update API fallback:", err);
            }

            // Remove any previously recorded finding for this test if re-verifying
            if (proj.findings) {
                const oldFinding = proj.findings.find(f => f.test_id === activeVerifyItem.id);
                if (oldFinding) {
                    try {
                        await fetch(`/api/findings/${oldFinding.id}`, { method: "DELETE" });
                    } catch (e) {}
                    proj.findings = proj.findings.filter(f => f.test_id !== activeVerifyItem.id);
                }
            }
            proj.updated_at = new Date().toISOString().split("T")[0];
            saveProjects();

            closeModal("modalVerify");
            renderChecklistCards();
            updateChecklistProgressUI();
            refreshDashboardStats();
            showToast("✓ Tested — Marked clean with no vulnerability found", "success");
        });
    }

    // Outcome 2: "Vulnerability Found" (Section 15)
    if (btnVerifyVuln) {
        btnVerifyVuln.addEventListener("click", () => {
            if (!activeVerifyItem) return;
            closeModal("modalVerify");

            // Populate structured finding modal
            const nameInp = document.getElementById("findingNameInput");
            const sevInp = document.getElementById("findingSeverityInput");
            const cweInp = document.getElementById("findingCweInput");
            const cvssInp = document.getElementById("findingCvssInput");
            const statusInp = document.getElementById("findingStatusInput");
            const descInp = document.getElementById("findingDescInput");
            const impactInp = document.getElementById("findingImpactInput");
            const notesInp = document.getElementById("findingNotesInput");
            const pocInp = document.getElementById("findingPocInput");
            const remInp = document.getElementById("findingRemediationInput");
            const mitInp = document.getElementById("findingMitigationInput");

            const existingFinding = activeVerifyItem.finding;

            if (nameInp) nameInp.value = existingFinding?.finding_name || activeVerifyItem.name;
            if (sevInp) sevInp.value = existingFinding?.priority || activeVerifyItem.priority || "HIGH";
            if (cweInp) cweInp.value = existingFinding?.cwe || activeVerifyItem.cwe || "";
            if (cvssInp) cvssInp.value = existingFinding?.cvss_score || "";
            if (statusInp) statusInp.value = existingFinding?.status || "Open";
            if (descInp) descInp.value = existingFinding?.description || activeVerifyItem.reason || "";
            if (impactInp) impactInp.value = existingFinding?.impact || "";
            if (notesInp) notesInp.value = existingFinding?.reproduction_steps || existingFinding?.testing_notes || activeVerifyItem.testing_objective || "";
            if (pocInp) pocInp.value = existingFinding?.poc_text || "";
            if (remInp) remInp.value = existingFinding?.remediation || "";
            if (mitInp) mitInp.value = existingFinding?.mitigation || "";
            
            pendingEvidenceData = existingFinding?.evidence_data || null;
            pendingEvidenceFilename = existingFinding?.evidence_filename || null;
            updateEvidenceUI();

            openModal("modalFinding");
        });
    }

    // Modal Finding Actions
    const btnCloseFindingModal = document.getElementById("btnCloseFindingModal");
    const btnCancelFinding = document.getElementById("btnCancelFinding");
    const btnSaveFinding = document.getElementById("btnSaveFinding");
    const evidenceDropzone = document.getElementById("evidenceDropzone");
    const evidenceFileInput = document.getElementById("evidenceFileInput");
    const btnClearEvidence = document.getElementById("btnClearEvidence");

    if (btnCloseFindingModal) btnCloseFindingModal.addEventListener("click", () => closeModal("modalFinding"));
    if (btnCancelFinding) btnCancelFinding.addEventListener("click", () => closeModal("modalFinding"));

    if (evidenceDropzone && evidenceFileInput) {
        evidenceDropzone.addEventListener("click", (e) => {
            if (e.target !== btnClearEvidence) evidenceFileInput.click();
        });

        evidenceFileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files[0]) {
                const file = e.target.files[0];
                const reader = new FileReader();
                reader.onload = (ev) => {
                    pendingEvidenceData = ev.target.result;
                    pendingEvidenceFilename = file.name;
                    updateEvidenceUI();
                };
                reader.readAsDataURL(file);
            }
        });
    }

    if (btnClearEvidence) {
        btnClearEvidence.addEventListener("click", (e) => {
            e.stopPropagation();
            pendingEvidenceData = null;
            pendingEvidenceFilename = null;
            evidenceFileInput.value = "";
            updateEvidenceUI();
        });
    }

    function updateEvidenceUI() {
        const wrap = document.getElementById("evidencePreviewWrap");
        const empty = document.getElementById("evidenceEmptyLabel");
        const img = document.getElementById("evidencePreviewImg");
        const name = document.getElementById("evidenceFileName");

        if (pendingEvidenceData) {
            wrap.classList.add("active");
            empty.style.display = "none";
            img.src = pendingEvidenceData;
            name.textContent = pendingEvidenceFilename || "evidence.png";
        } else {
            wrap.classList.remove("active");
            empty.style.display = "block";
            img.src = "";
        }
    }

    // AI Auto-Structure Button
    const btnAiAutoStructure = document.getElementById("btnAiAutoStructure");
    if (btnAiAutoStructure) {
        btnAiAutoStructure.addEventListener("click", async () => {
            if (!activeVerifyItem) return;
            btnAiAutoStructure.disabled = true;
            btnAiAutoStructure.textContent = "Structuring...";
            try {
                const res = await fetch(`/api/checklist/${activeVerifyItem.id}/finding-template`);
                if (res.ok) {
                    const tmpl = await res.json();
                    if (tmpl.cwe && document.getElementById("findingCweInput")) {
                        document.getElementById("findingCweInput").value = tmpl.cwe;
                    }
                    if (tmpl.cvss_score != null && document.getElementById("findingCvssInput")) {
                        document.getElementById("findingCvssInput").value = tmpl.cvss_score;
                    }
                    if (tmpl.description && document.getElementById("findingDescInput")) {
                        document.getElementById("findingDescInput").value = tmpl.description;
                    }
                    if (tmpl.impact && document.getElementById("findingImpactInput")) {
                        document.getElementById("findingImpactInput").value = tmpl.impact;
                    }
                    if (tmpl.reproduction_steps && document.getElementById("findingNotesInput")) {
                        document.getElementById("findingNotesInput").value = tmpl.reproduction_steps;
                    }
                    if (tmpl.poc_text && document.getElementById("findingPocInput")) {
                        document.getElementById("findingPocInput").value = tmpl.poc_text;
                    }
                    if (tmpl.remediation && document.getElementById("findingRemediationInput")) {
                        document.getElementById("findingRemediationInput").value = tmpl.remediation;
                    }
                    if (tmpl.mitigation && document.getElementById("findingMitigationInput")) {
                        document.getElementById("findingMitigationInput").value = tmpl.mitigation;
                    }
                    showToast("✨ Finding auto-structured from controlled knowledge base!", "success");
                } else {
                    showToast("No specific template found; please complete fields manually.", "info");
                }
            } catch (e) {
                showToast("Failed to fetch finding template: " + e.message, "error");
            } finally {
                btnAiAutoStructure.disabled = false;
                btnAiAutoStructure.textContent = "✨ AI Auto-Structure";
            }
        });
    }

    if (btnSaveFinding) {
        btnSaveFinding.addEventListener("click", async () => {
            if (!activeVerifyItem) return;
            const proj = getActiveProject();

            const findingName = document.getElementById("findingNameInput")?.value.trim() || activeVerifyItem.name;
            const severity = document.getElementById("findingSeverityInput")?.value || activeVerifyItem.priority || "HIGH";
            const cwe = document.getElementById("findingCweInput")?.value.trim() || null;
            const cvss_val = parseFloat(document.getElementById("findingCvssInput")?.value);
            const cvss_score = !isNaN(cvss_val) ? cvss_val : null;
            const status = document.getElementById("findingStatusInput")?.value || "Open";
            const desc = document.getElementById("findingDescInput")?.value.trim() || "";
            const impact = document.getElementById("findingImpactInput")?.value.trim() || "";
            const notes = document.getElementById("findingNotesInput")?.value.trim() || "";
            const poc = document.getElementById("findingPocInput")?.value.trim() || "";
            const remediation = document.getElementById("findingRemediationInput")?.value.trim() || "";
            const mitigation = document.getElementById("findingMitigationInput")?.value.trim() || "";

            let findingObj = {
                id: "find-" + Date.now(),
                finding_name: findingName,
                test_id: activeVerifyItem.id,
                priority: severity,
                cwe: cwe,
                cvss_score: cvss_score,
                status: status,
                description: desc,
                impact: impact,
                reproduction_steps: notes,
                testing_notes: notes,
                poc_text: poc,
                remediation: remediation,
                mitigation: mitigation,
                evidence_filename: pendingEvidenceFilename,
                evidence_data: pendingEvidenceData,
                recorded_at: new Date().toISOString().replace("T", " ").substring(0, 16)
            };

            // Sync finding with backend REST API explicitly bound to active project
            try {
                const res = await fetch(`/api/checklist/${activeVerifyItem.id}/finding?project_id=${encodeURIComponent(proj.id)}`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        finding_name: findingName,
                        priority: severity,
                        cwe: cwe,
                        cvss_score: cvss_score,
                        status: status,
                        description: desc,
                        impact: impact,
                        reproduction_steps: notes,
                        testing_notes: notes,
                        poc_text: poc,
                        remediation: remediation,
                        mitigation: mitigation,
                        evidence_data: pendingEvidenceData,
                        evidence_filename: pendingEvidenceFilename
                    })
                });
                if (res.ok) {
                    const saved = await res.json();
                    findingObj = { ...findingObj, ...saved };
                }
            } catch (err) {
                console.warn("[TRACEGATE] Finding persist API fallback:", err);
            }

            activeVerifyItem.status = "VULNERABILITY_FOUND";
            activeVerifyItem.finding = findingObj;

            if (!proj.findings) proj.findings = [];
            // Remove previous finding for this test if existing
            proj.findings = proj.findings.filter(f => f.test_id !== activeVerifyItem.id);
            proj.findings.unshift(findingObj);
            proj.updated_at = new Date().toISOString().split("T")[0];

            saveProjects();
            closeModal("modalFinding");
            renderChecklistCards();
            updateChecklistProgressUI();
            refreshDashboardStats();

            const badgeCount = document.getElementById("wsFindingsBadgeCount");
            if (badgeCount) badgeCount.textContent = proj.findings.length;

            showToast("✓ Structured Finding Saved & Verified!", "success");
        });
    }

    // Modal Edit Item Actions
    const btnCloseEditModal = document.getElementById("btnCloseEditModal");
    const btnCancelEdit = document.getElementById("btnCancelEdit");
    const btnSaveEdit = document.getElementById("btnSaveEdit");

    if (btnCloseEditModal) btnCloseEditModal.addEventListener("click", () => closeModal("modalEditItem"));
    if (btnCancelEdit) btnCancelEdit.addEventListener("click", () => closeModal("modalEditItem"));

    if (btnSaveEdit) {
        btnSaveEdit.addEventListener("click", async () => {
            if (!activeEditItem) return;
            const proj = getActiveProject();

            const name = document.getElementById("editItemName").value.trim();
            const priority = document.getElementById("editItemPriority").value;
            const cwe = document.getElementById("editItemCwe").value.trim();
            const reason = document.getElementById("editItemReason").value.trim();
            const objective = document.getElementById("editItemObjective").value.trim();

            if (!name || !reason || !objective) {
                showToast("Test name, reason, and testing objective are required.", "error");
                return;
            }

            // Sync with backend API
            try {
                await fetch(`/api/checklist/${activeEditItem.id}`, {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        name: name,
                        priority: priority,
                        cwe: cwe || null,
                        reason: reason,
                        testing_objective: objective
                    })
                });
            } catch (err) {
                console.warn("[TRACEGATE] Edit checklist item API fallback:", err);
            }

            activeEditItem.name = name;
            activeEditItem.priority = priority;
            activeEditItem.cwe = cwe || null;
            activeEditItem.reason = reason;
            activeEditItem.testing_objective = objective;
            activeEditItem.source = "USER_MODIFIED";

            saveProjects();
            closeModal("modalEditItem");
            renderChecklistCards();
            updateChecklistProgressUI();
            showToast("Test details updated (marked User Modified)", "success");
        });
    }

    // Modal Add Custom Test Actions
    const btnAddCustomTestBtn = document.getElementById("btnAddCustomTestBtn");
    const btnCloseAddCustomModal = document.getElementById("btnCloseAddCustomModal");
    const btnCancelCustomTest = document.getElementById("btnCancelCustomTest");
    const btnSaveCustomTest = document.getElementById("btnSaveCustomTest");

    if (btnAddCustomTestBtn) btnAddCustomTestBtn.addEventListener("click", () => openModal("modalAddCustomTest"));
    if (btnCloseAddCustomModal) btnCloseAddCustomModal.addEventListener("click", () => closeModal("modalAddCustomTest"));
    if (btnCancelCustomTest) btnCancelCustomTest.addEventListener("click", () => closeModal("modalAddCustomTest"));

    if (btnSaveCustomTest) {
        btnSaveCustomTest.addEventListener("click", async () => {
            const proj = getActiveProject();
            if (!proj || !proj.checklist_data) {
                showToast("Please generate or initialize a checklist before adding tests.", "error");
                return;
            }

            const name = document.getElementById("customTestName").value.trim();
            const priority = document.getElementById("customTestPriority").value;
            const cwe = document.getElementById("customTestCwe").value.trim();
            const reason = document.getElementById("customTestReason").value.trim();
            const objective = document.getElementById("customTestObjective").value.trim();

            if (!name || !reason || !objective) {
                showToast("Name, reason, and objective are required.", "error");
                return;
            }

            let newItem = {
                id: "custom-" + Date.now(),
                name: name,
                priority: priority,
                cwe: cwe || null,
                reason: reason,
                testing_objective: objective,
                source: "USER",
                status: "NOT_TESTED",
                finding: null
            };

            // Call backend POST /api/projects/{id}/checklist/custom
            try {
                const res = await fetch(`/api/projects/${proj.id}/checklist/custom`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        name: name,
                        priority: priority,
                        cwe: cwe || null,
                        reason: reason,
                        testing_objective: objective
                    })
                });
                if (res.ok) {
                    const created = await res.json();
                    newItem = { ...newItem, ...created };
                }
            } catch (err) {
                console.warn("[TRACEGATE] Custom test API fallback:", err);
            }

            if (!proj.checklist_data.checklist) proj.checklist_data.checklist = [];
            proj.checklist_data.checklist.unshift(newItem);
            saveProjects();

            // Clear form
            document.getElementById("customTestName").value = "";
            document.getElementById("customTestCwe").value = "";
            document.getElementById("customTestReason").value = "";
            document.getElementById("customTestObjective").value = "";

            closeModal("modalAddCustomTest");
            renderChecklistCards();
            updateChecklistProgressUI();
            refreshDashboardStats();
            showToast("Custom test added to checklist (marked User Added)", "success");
        });
    }

    // ==========================================================================
    // 9. CHECKLIST DYNAMIC PROGRESS & COMPLETION BANNER
    // ==========================================================================
    function updateChecklistProgressUI() {
        const proj = getActiveProject();
        if (!proj || !proj.checklist_data || !proj.checklist_data.checklist) return;

        const m = calculateProjectMetrics(proj);

        const fillEl = document.getElementById("progressTrackFill");
        if (fillEl) fillEl.style.width = `${m.pct}%`;

        const pctText = document.getElementById("progressPctText");
        if (pctText) pctText.textContent = `${m.pct}%`;

        const fracEl = document.getElementById("statCompletedFraction");
        if (fracEl) fracEl.innerHTML = `<strong>${m.completed} / ${m.total}</strong> Tests Completed`;

        const remEl = document.getElementById("statRemainingCount");
        if (remEl) remEl.textContent = `${m.remaining} Remaining`;

        const vulnEl = document.getElementById("statVulnsBadge");
        if (vulnEl) vulnEl.textContent = `${m.vulns} Vulnerabilities Found`;

        const cleanEl = document.getElementById("statCleanBadge");
        if (cleanEl) cleanEl.textContent = `${m.clean} Clean`;

        // Completion Banner
        const completionBanner = document.getElementById("completionBanner");
        if (completionBanner) {
            if (m.pct === 100 && m.total > 0) {
                completionBanner.classList.add("active");
                if (proj.status !== "COMPLETED") {
                    proj.status = "COMPLETED";
                    saveProjects();
                }
            } else {
                completionBanner.classList.remove("active");
            }
        }
    }

    // ==========================================================================
    // 10. FILTERING & SORTING LISTENERS
    // ==========================================================================
    const checklistSearchInput = document.getElementById("checklistSearchInput");
    if (checklistSearchInput) {
        checklistSearchInput.addEventListener("input", (e) => {
            currentSearchTerm = e.target.value.toLowerCase().trim();
            renderChecklistCards();
        });
    }

    document.querySelectorAll("[data-priority]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-priority]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentPriorityFilter = btn.getAttribute("data-priority");
            renderChecklistCards();
        });
    });

    document.querySelectorAll("[data-status]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-status]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentStatusFilter = btn.getAttribute("data-status");
            renderChecklistCards();
        });
    });

    const sortChecklistSelect = document.getElementById("sortChecklistSelect");
    if (sortChecklistSelect) {
        sortChecklistSelect.addEventListener("change", (e) => {
            currentSortMode = e.target.value;
            renderChecklistCards();
        });
    }

    // ==========================================================================
    // 11. FINDINGS TAB CONTROLLER
    // ==========================================================================
    function renderWorkspaceFindings() {
        const listEl = document.getElementById("wsFindingsList");
        if (!listEl) return;
        listEl.innerHTML = "";

        const proj = getActiveProject();
        const allFindings = (proj && proj.findings) ? proj.findings : [];

        // 1. Update Metrics Cards
        const totalCount = allFindings.length;
        const critCount = allFindings.filter(f => f.priority === "CRITICAL").length;
        const highCount = allFindings.filter(f => f.priority === "HIGH").length;
        const medCount = allFindings.filter(f => f.priority === "MEDIUM").length;
        const lowCount = allFindings.filter(f => f.priority === "LOW").length;

        const statTot = document.getElementById("findingsStatTotal");
        const statCrit = document.getElementById("findingsStatCrit");
        const statHigh = document.getElementById("findingsStatHigh");
        const statMed = document.getElementById("findingsStatMed");
        const statLow = document.getElementById("findingsStatLow");

        if (statTot) statTot.textContent = totalCount;
        if (statCrit) statCrit.textContent = critCount;
        if (statHigh) statHigh.textContent = highCount;
        if (statMed) statMed.textContent = medCount;
        if (statLow) statLow.textContent = lowCount;

        if (totalCount === 0) {
            listEl.innerHTML = `
                <div style="text-align: center; padding: 40px; background: var(--bg-surface); border: 1px dashed var(--border-subtle); border-radius: var(--radius-lg); color: var(--text-muted);">
                    <p style="font-size: 1rem; font-weight: 600; margin-bottom: 4px;">No vulnerabilities confirmed yet.</p>
                    <p style="font-size: 0.82rem;">Execute tests in the Checklist Generator and select "Vulnerability Found" to document security findings with PoC evidence.</p>
                </div>
            `;
            return;
        }

        // 2. Filter findings
        let filtered = allFindings.filter(f => {
            const matchSeverity = currentFindingSeverityFilter === "ALL" || f.priority === currentFindingSeverityFilter;
            const matchSearch = !currentFindingSearchTerm ||
                f.finding_name.toLowerCase().includes(currentFindingSearchTerm) ||
                (f.description && f.description.toLowerCase().includes(currentFindingSearchTerm)) ||
                (f.testing_notes && f.testing_notes.toLowerCase().includes(currentFindingSearchTerm)) ||
                (f.poc_text && f.poc_text.toLowerCase().includes(currentFindingSearchTerm));
            return matchSeverity && matchSearch;
        });

        if (filtered.length === 0) {
            listEl.innerHTML = `
                <div style="text-align: center; padding: 40px; background: var(--bg-surface); border: 1px dashed var(--border-subtle); border-radius: var(--radius-lg); color: var(--text-muted);">
                    <p style="font-size: 0.95rem; font-weight: 600;">No findings match the selected filters.</p>
                    <p style="font-size: 0.8rem; margin-top: 4px;">Try selecting "All" severities or clearing the search query.</p>
                </div>
            `;
            return;
        }

        filtered.forEach(finding => {
            const card = document.createElement("div");
            card.className = "finding-record-card";

            // Find related checklist test if available
            let relatedTestName = "";
            if (proj.checklist_data && proj.checklist_data.checklist) {
                const matchedItem = proj.checklist_data.checklist.find(i => i.id === finding.test_id);
                if (matchedItem) {
                    relatedTestName = matchedItem.name;
                }
            }

            card.innerHTML = `
                <div class="finding-record-header">
                    <div class="finding-title-left">
                        <span class="badge badge-secondary" style="font-family: var(--font-mono); font-weight: 700; font-size: 0.78rem;">${finding.vuln_id || 'VULN-' + String(totalCount).padStart(3, '0')}</span>
                        <span class="badge badge-${(finding.priority || 'high').toLowerCase()}">${finding.priority || 'HIGH'}</span>
                        ${finding.fix_status ? `<span class="badge badge-completed" style="font-size: 0.72rem;">${escapeHtml(finding.fix_status)}</span>` : ''}
                        <span class="finding-record-name">${escapeHtml(finding.finding_name)}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 0.75rem; color: var(--text-light); font-family: var(--font-mono);">${finding.recorded_at || 'Recently'}</span>
                        <button type="button" class="btn btn-danger btn-sm btn-delete-finding" data-finding-id="${finding.id}">Delete</button>
                    </div>
                </div>

                ${relatedTestName ? `
                    <div style="font-size: 0.78rem; color: var(--text-muted); display: flex; align-items: center; gap: 6px;">
                        <span>Related Security Test:</span>
                        <strong style="color: var(--primary-700);">${escapeHtml(relatedTestName)}</strong>
                    </div>
                ` : ""}

                <div class="finding-body-block">
                    <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 4px;">
                        ${finding.cwe ? `<span class="cwe-pill">${escapeHtml(finding.cwe)}</span>` : ""}
                        ${finding.cvss_score ? `<span class="badge badge-needs-review">CVSS: ${finding.cvss_score}</span>` : ""}
                        <span class="badge ${finding.status === 'Remediated' ? 'badge-completed' : 'badge-in-progress'}">${escapeHtml(finding.status || 'Open')}</span>
                    </div>
                    ${finding.description ? `<div><strong>Observation:</strong> ${escapeHtml(finding.description)}</div>` : ""}
                    ${finding.impact ? `<div><strong>Impact:</strong> ${escapeHtml(finding.impact)}</div>` : ""}
                    ${(finding.reproduction_steps || finding.testing_notes) ? `<div><strong>Reproduction Steps:</strong> ${escapeHtml(finding.reproduction_steps || finding.testing_notes)}</div>` : ""}
                    ${finding.poc_text ? `
                        <div>
                            <strong>Proof of Concept (PoC) / Payload Snippet:</strong>
                            <pre class="finding-poc-box">${escapeHtml(finding.poc_text)}</pre>
                        </div>
                    ` : ""}
                    ${finding.remediation ? `<div><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</div>` : ""}
                    ${finding.mitigation ? `<div><strong>Mitigation:</strong> ${escapeHtml(finding.mitigation)}</div>` : ""}
                    ${finding.evidence_data ? `
                        <div style="margin-top: 6px;">
                            <strong>Attached PoC Evidence:</strong><br/>
                            <img src="${finding.evidence_data}" class="finding-evidence-img" alt="Evidence" />
                        </div>
                    ` : ""}
                </div>
            `;

            card.querySelector(".btn-delete-finding").addEventListener("click", async () => {
                if (confirm(`Delete finding "${finding.finding_name}"?`)) {
                    // Call backend DELETE /api/findings/{id}
                    try {
                        await fetch(`/api/findings/${finding.id}`, { method: "DELETE" });
                    } catch (err) {
                        console.warn("[TRACEGATE] Delete finding API fallback:", err);
                    }

                    proj.findings = proj.findings.filter(f => f.id !== finding.id);

                    // Also reset checklist item if associated
                    if (proj.checklist_data && proj.checklist_data.checklist) {
                        const item = proj.checklist_data.checklist.find(i => i.id === finding.test_id);
                        if (item) {
                            item.status = "NOT_TESTED";
                            item.finding = null;
                            try {
                                await fetch(`/api/checklist/${item.id}/status`, {
                                    method: "PUT",
                                    headers: { "Content-Type": "application/json" },
                                    body: JSON.stringify({ status: "NOT_TESTED" })
                                });
                            } catch (e) {}
                        }
                    }

                    saveProjects();
                    renderWorkspaceFindings();
                    updateChecklistProgressUI();
                    refreshDashboardStats();

                    const badgeCount = document.getElementById("wsFindingsBadgeCount");
                    if (badgeCount) badgeCount.textContent = proj.findings.length;

                    showToast("Finding removed.", "info");
                }
            });

            listEl.appendChild(card);
        });
    }

    // Findings Filter Event Listeners
    const findingsSearchInput = document.getElementById("findingsSearchInput");
    if (findingsSearchInput) {
        findingsSearchInput.addEventListener("input", (e) => {
            currentFindingSearchTerm = e.target.value.toLowerCase().trim();
            renderWorkspaceFindings();
        });
    }

    document.querySelectorAll("[data-finding-severity]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-finding-severity]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentFindingSeverityFilter = btn.getAttribute("data-finding-severity");
            renderWorkspaceFindings();
        });
    });

    // ==========================================================================
    // 12. REPORT GENERATION CONTROLLER (REAL DOCX & MARKDOWN EXPORT)
    // ==========================================================================
    let selectedFindingIdsForReport = new Set();
    let currentReportFindingFilter = "ALL";
    let reportSelectionInitializedProjId = null;

    function getFilteredFindings(findings, filter) {
        if (!filter || filter === "ALL") return findings;
        return findings.filter(f => {
            const p = (f.priority || "").toUpperCase();
            if (filter === "INFORMATIONAL" || filter === "INFO") {
                return p === "INFORMATIONAL" || p === "INFO";
            }
            return p === filter;
        });
    }

    function updateFilterBtnStyles() {
        const filters = [
            { id: "btnFilterAll", filter: "ALL" },
            { id: "btnFilterCrit", filter: "CRITICAL" },
            { id: "btnFilterHigh", filter: "HIGH" },
            { id: "btnFilterMed", filter: "MEDIUM" },
            { id: "btnFilterLow", filter: "LOW" },
            { id: "btnFilterInfo", filter: "INFORMATIONAL" }
        ];
        filters.forEach(f => {
            const btn = document.getElementById(f.id);
            if (!btn) return;
            if (currentReportFindingFilter === f.filter) {
                btn.classList.remove("btn-secondary");
                btn.classList.add("btn-primary");
            } else {
                btn.classList.remove("btn-primary");
                btn.classList.add("btn-secondary");
            }
        });
    }

    function renderReportFindingsSelection(proj) {
        const tbody = document.getElementById("reportFindingsSelectTbody");
        const badge = document.getElementById("reportSelectionBadge");
        const metricsPanel = document.getElementById("reportSelectedMetricsPanel");
        const cleanBox = document.getElementById("cleanReportOptionBox");
        const chkClean = document.getElementById("chkAllowCleanReport");
        const chkAllHeader = document.getElementById("chkReportSelectAllHeader");

        if (!tbody || !proj) return;

        const allFindings = proj.findings || [];
        const filteredFindings = getFilteredFindings(allFindings, currentReportFindingFilter);

        // Update clean report option box visibility (Section 27)
        if (cleanBox) {
            if (allFindings.length === 0 || selectedFindingIdsForReport.size === 0) {
                cleanBox.style.display = "flex";
            } else {
                cleanBox.style.display = "none";
                if (chkClean) chkClean.checked = false;
            }
        }

        // Update selection badge counter
        if (badge) {
            badge.textContent = `${selectedFindingIdsForReport.size} of ${allFindings.length} findings selected`;
            if (selectedFindingIdsForReport.size > 0) {
                badge.className = "badge badge-completed";
            } else {
                badge.className = "badge badge-needs-review";
            }
        }

        // Render Selection Table Rows
        if (allFindings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">No confirmed vulnerabilities recorded for this assessment. You may certify a Clean Assessment Report below.</td></tr>`;
            if (chkAllHeader) {
                chkAllHeader.checked = false;
                chkAllHeader.indeterminate = false;
                chkAllHeader.disabled = true;
            }
        } else if (filteredFindings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">No confirmed findings match the "${escapeHtml(currentReportFindingFilter)}" severity filter.</td></tr>`;
            if (chkAllHeader) {
                chkAllHeader.checked = false;
                chkAllHeader.indeterminate = false;
                chkAllHeader.disabled = true;
            }
        } else {
            if (chkAllHeader) chkAllHeader.disabled = false;
            let rowsHtml = "";
            let checkedVisibleCount = 0;

            filteredFindings.forEach((f, idx) => {
                const isSelected = selectedFindingIdsForReport.has(f.id);
                if (isSelected) checkedVisibleCount++;

                const priorityUpper = (f.priority || "HIGH").toUpperCase();
                const priorityClass = priorityUpper === "INFORMATIONAL" || priorityUpper === "INFO" ? "info" : priorityUpper.toLowerCase();
                const hasPoc = Boolean(f.poc_text && f.poc_text.trim());
                const hasEvidence = Boolean(f.evidence_filename || f.evidence_data);

                rowsHtml += `
                    <tr style="background: ${isSelected ? 'rgba(37, 99, 235, 0.05)' : 'transparent'};">
                        <td style="text-align: center;">
                            <input type="checkbox" class="chk-report-finding" data-id="${escapeHtml(f.id)}" ${isSelected ? 'checked' : ''} style="cursor: pointer; width: 16px; height: 16px;" />
                        </td>
                        <td><span style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 600;">#${idx + 1}</span></td>
                        <td>
                            <strong>${escapeHtml(f.finding_name || 'Vulnerability')}</strong>
                            ${f.description ? `<div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 2px; max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(f.description)}</div>` : ''}
                        </td>
                        <td><span class="badge badge-${priorityClass}">${escapeHtml(priorityUpper)}</span></td>
                        <td>${f.cwe ? `<span class="cwe-pill">${escapeHtml(f.cwe)}</span>` : '<span style="color:var(--text-muted);">-</span>'}</td>
                        <td><span style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(f.component || 'Web App')}</span></td>
                        <td>${hasPoc ? '<span class="badge badge-completed">Attached</span>' : '<span class="badge badge-needs-review">None</span>'}</td>
                        <td>${hasEvidence ? '<span class="badge badge-completed">Attached</span>' : '<span class="badge badge-needs-review">None</span>'}</td>
                    </tr>
                `;
            });

            tbody.innerHTML = rowsHtml;

            // Update header checkbox
            if (chkAllHeader) {
                if (checkedVisibleCount === filteredFindings.length) {
                    chkAllHeader.checked = true;
                    chkAllHeader.indeterminate = false;
                } else if (checkedVisibleCount > 0) {
                    chkAllHeader.checked = false;
                    chkAllHeader.indeterminate = true;
                } else {
                    chkAllHeader.checked = false;
                    chkAllHeader.indeterminate = false;
                }
            }

            // Wire row checkboxes
            tbody.querySelectorAll(".chk-report-finding").forEach(chk => {
                chk.addEventListener("change", (e) => {
                    const fid = e.target.getAttribute("data-id");
                    if (e.target.checked) {
                        selectedFindingIdsForReport.add(fid);
                    } else {
                        selectedFindingIdsForReport.delete(fid);
                    }
                    renderReportFindingsSelection(proj);
                });
            });
        }

        // Render Dynamic Metrics Summary Panel
        if (metricsPanel) {
            const selectedFindings = allFindings.filter(f => selectedFindingIdsForReport.has(f.id));
            const countCrit = selectedFindings.filter(f => (f.priority || '').toUpperCase() === 'CRITICAL').length;
            const countHigh = selectedFindings.filter(f => (f.priority || '').toUpperCase() === 'HIGH').length;
            const countMed = selectedFindings.filter(f => (f.priority || '').toUpperCase() === 'MEDIUM').length;
            const countLow = selectedFindings.filter(f => (f.priority || '').toUpperCase() === 'LOW').length;
            const countInfo = selectedFindings.filter(f => (f.priority || '').toUpperCase() === 'INFORMATIONAL' || (f.priority || '').toUpperCase() === 'INFO').length;
            const countPoc = selectedFindings.filter(f => Boolean(f.poc_text && f.poc_text.trim())).length;
            const countEvidence = selectedFindings.filter(f => Boolean(f.evidence_filename || f.evidence_data)).length;
            const countMissingRemediation = selectedFindings.filter(f => !f.remediation && !f.mitigation && !f.fix_guidance).length;

            metricsPanel.innerHTML = `
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Selected</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--primary-600);">${selectedFindings.length} / ${allFindings.length}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--crit-badge); font-weight: 700;">Critical</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--crit-badge);">${countCrit}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--high-badge); font-weight: 700;">High</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--high-badge);">${countHigh}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--med-badge); font-weight: 700;">Medium</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--med-badge);">${countMed}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--low-badge); font-weight: 700;">Low</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--low-badge);">${countLow}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: #0284c7; font-weight: 700;">Informational</span><br/>
                    <strong style="font-size: 1.05rem; color: #0284c7;">${countInfo}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">PoC Attached</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--text-primary);">${countPoc}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Evidence Attached</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--text-primary);">${countEvidence}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Missing Remediation</span><br/>
                    <strong style="font-size: 1.05rem; color: ${countMissingRemediation > 0 ? 'var(--med-badge)' : 'var(--clean-color)'};">${countMissingRemediation}</strong>
                </div>
            `;
        }
    }

    // Wire bulk buttons and filter selectors once
    const btnReportSelectAll = document.getElementById("btnReportSelectAll");
    if (btnReportSelectAll) {
        btnReportSelectAll.addEventListener("click", () => {
            const proj = getActiveProject();
            if (!proj) return;
            const allFindings = proj.findings || [];
            allFindings.forEach(f => selectedFindingIdsForReport.add(f.id));
            renderReportFindingsSelection(proj);
        });
    }

    const btnReportClearAll = document.getElementById("btnReportClearAll");
    if (btnReportClearAll) {
        btnReportClearAll.addEventListener("click", () => {
            const proj = getActiveProject();
            if (!proj) return;
            selectedFindingIdsForReport.clear();
            renderReportFindingsSelection(proj);
        });
    }

    const chkReportSelectAllHeader = document.getElementById("chkReportSelectAllHeader");
    if (chkReportSelectAllHeader) {
        chkReportSelectAllHeader.addEventListener("change", (e) => {
            const proj = getActiveProject();
            if (!proj) return;
            const filteredFindings = getFilteredFindings(proj.findings || [], currentReportFindingFilter);
            if (e.target.checked) {
                filteredFindings.forEach(f => selectedFindingIdsForReport.add(f.id));
            } else {
                filteredFindings.forEach(f => selectedFindingIdsForReport.delete(f.id));
            }
            renderReportFindingsSelection(proj);
        });
    }

    const reportFilterBtns = [
        { id: "btnFilterAll", filter: "ALL" },
        { id: "btnFilterCrit", filter: "CRITICAL" },
        { id: "btnFilterHigh", filter: "HIGH" },
        { id: "btnFilterMed", filter: "MEDIUM" },
        { id: "btnFilterLow", filter: "LOW" },
        { id: "btnFilterInfo", filter: "INFORMATIONAL" }
    ];
    reportFilterBtns.forEach(fb => {
        const el = document.getElementById(fb.id);
        if (el) {
            el.addEventListener("click", () => {
                currentReportFindingFilter = fb.filter;
                updateFilterBtnStyles();
                const proj = getActiveProject();
                if (proj) renderReportFindingsSelection(proj);
            });
        }
    });

    async function renderWorkspaceReport() {
        const contentEl = document.getElementById("reportSummaryContent");
        if (!contentEl) return;

        const proj = getActiveProject();
        if (!proj) return;

        // Fetch latest findings directly from backend to guarantee sync
        try {
            const findRes = await fetch(`/api/projects/${proj.id}/findings`);
            if (findRes.ok) {
                const rawFindings = await findRes.json();
                const findingsData = Array.isArray(rawFindings) ? rawFindings : (rawFindings.findings || []);
                if (Array.isArray(findingsData)) {
                    proj.findings = findingsData;
                }
            }
        } catch (e) {
            console.warn("[TRACEGATE] Failed to refresh findings for report:", e);
        }

        // Initialize selection state for this project
        const allFindings = proj.findings || [];
        const currentIds = new Set(allFindings.map(f => f.id));
        if (reportSelectionInitializedProjId !== proj.id) {
            selectedFindingIdsForReport = new Set(currentIds);
            reportSelectionInitializedProjId = proj.id;
            currentReportFindingFilter = "ALL";
        } else {
            // Keep only IDs that still exist
            selectedFindingIdsForReport = new Set([...selectedFindingIdsForReport].filter(id => currentIds.has(id)));
        }

        updateFilterBtnStyles();
        renderReportFindingsSelection(proj);

        const m = calculateProjectMetrics(proj);
        const vulns = allFindings;

        let tableRows = "";
        if (vulns.length === 0) {
            tableRows = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No vulnerabilities confirmed yet for this assessment scope.</td></tr>`;
        } else {
            vulns.forEach((v, idx) => {
                const priorityUpper = (v.priority || "HIGH").toUpperCase();
                const priorityClass = priorityUpper === "INFORMATIONAL" || priorityUpper === "INFO" ? "info" : priorityUpper.toLowerCase();
                tableRows += `
                    <tr>
                        <td><strong>#${idx + 1}</strong></td>
                        <td><span class="badge badge-${priorityClass}">${escapeHtml(priorityUpper)}</span></td>
                        <td><strong>${escapeHtml(v.finding_name)}</strong></td>
                        <td>${v.cwe ? `<span class="cwe-pill">${escapeHtml(v.cwe)}</span>` : '<span style="color:var(--text-muted);">-</span>'}</td>
                        <td>${v.poc_text ? '<span class="badge badge-completed">PoC Verified</span>' : '<span class="badge badge-needs-review">Notes Only</span>'}</td>
                    </tr>
                `;
            });
        }

        contentEl.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px;">
                <div style="background: #ffffff; padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                    <span style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Target Application</span><br/>
                    <strong style="font-family: var(--font-mono); font-size: 0.85rem;">${escapeHtml(proj.target_url)}</strong>
                </div>
                <div style="background: #ffffff; padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                    <span style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Scope Tests Evaluated</span><br/>
                    <strong style="font-size: 1.1rem; color: var(--primary-600);">${m.completed} / ${m.total} (${m.pct}%)</strong>
                </div>
                <div style="background: #ffffff; padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                    <span style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Confirmed Findings</span><br/>
                    <strong style="font-size: 1.1rem; color: var(--crit-color);">${vulns.length}</strong>
                </div>
                <div style="background: #ffffff; padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                    <span style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Verified Clean Controls</span><br/>
                    <strong style="font-size: 1.1rem; color: var(--clean-color);">${m.clean}</strong>
                </div>
            </div>

            <div style="margin-top: 10px;">
                <h5 style="font-size: 0.92rem; margin-bottom: 8px;">Consolidated Vulnerabilities Table</h5>
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Item</th>
                            <th>Severity</th>
                            <th>Vulnerability Title</th>
                            <th>CWE</th>
                            <th>Evidence Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${tableRows}
                    </tbody>
                </table>
            </div>
        `;

        // Pre-fill author name
        const authorInp = document.getElementById("docxAuthorName");
        if (authorInp && currentUser) {
            authorInp.value = currentUser.name;
        }

        // Load project reports history
        await loadProjectReports(proj.id);
    }

    async function loadProjectReports(projId) {
        const tbody = document.getElementById("reportHistoryTableBody");
        if (!tbody) return;

        try {
            const res = await fetch(`/api/projects/${projId}/reports`);
            if (res.ok) {
                const reports = await res.json();
                if (Array.isArray(reports) && reports.length > 0) {
                    let rows = "";
                    reports.forEach(r => {
                        rows += `
                            <tr>
                                <td><strong>${escapeHtml(r.version)}</strong></td>
                                <td>${escapeHtml(r.created_at || 'Recent')}</td>
                                <td>${escapeHtml(r.author_name || 'Security Assessor')}</td>
                                <td><span class="badge ${r.findings_count > 0 ? 'badge-critical' : 'badge-clean'}">${r.findings_count} Vulns</span></td>
                                <td><span class="badge badge-completed">.DOCX</span></td>
                                <td>
                                    <a href="/api/projects/${projId}/reports/${r.id}/download" class="btn btn-outline-primary btn-sm" download>
                                        📥 Download
                                    </a>
                                </td>
                            </tr>
                        `;
                    });
                    tbody.innerHTML = rows;
                    return;
                }
            }
        } catch (e) {
            console.warn("[TRACEGATE] Failed to load reports history:", e);
        }

        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 18px;">No previous report packages recorded for this project.</td></tr>`;
    }

    // Generate Official Microsoft Word (.docx) Report with 4-stage Stepper
    const btnGenerateDocxReport = document.getElementById("btnGenerateDocxReport");
    if (btnGenerateDocxReport) {
        btnGenerateDocxReport.addEventListener("click", async () => {
            const proj = getActiveProject();
            if (!proj) {
                showToast("No active project selected.", "error");
                return;
            }

            const isCleanAllowed = document.getElementById("chkAllowCleanReport")?.checked || false;
            const selectedIds = Array.from(selectedFindingIdsForReport);

            // Validation (Section 27 & 48)
            if (selectedIds.length === 0 && !isCleanAllowed) {
                showToast("Select at least one finding to include in the report, or check Clean Assessment Report to certify no vulnerabilities.", "warning");
                return;
            }

            const version = document.getElementById("docxReportVersion")?.value.trim() || "v1.0";
            const author = document.getElementById("docxAuthorName")?.value.trim() || currentUser?.name || "Security Learner";
            const methodology = document.getElementById("docxMethodologySelect")?.value || "owasp_wstg";

            const stepperBox = document.getElementById("reportGenStepperBox");
            const step1 = document.getElementById("loadingDocxStep1");
            const step2 = document.getElementById("loadingDocxStep2");
            const step3 = document.getElementById("loadingDocxStep3");
            const step4 = document.getElementById("loadingDocxStep4");

            btnGenerateDocxReport.disabled = true;
            if (stepperBox) stepperBox.classList.add("active");

            // Sequential 4-stage progress
            if (step1) {
                step1.className = "step-item running";
                step1.textContent = "● Consolidating assessment findings & methodology";
            }
            if (step2) {
                step2.className = "step-item pending";
                step2.textContent = "○ Calculating risk metrics & executive summaries";
            }
            if (step3) {
                step3.className = "step-item pending";
                step3.textContent = "○ Embedding PoC snippets & evidence screenshots";
            }
            if (step4) {
                step4.className = "step-item running";
                step4.textContent = "○ Compiling Microsoft Word (.docx) report package";
            }

            setTimeout(() => {
                if (step1) {
                    step1.className = "step-item done";
                    step1.textContent = "✓ Assessment findings & methodology consolidated";
                }
                if (step2) {
                    step2.className = "step-item running";
                    step2.textContent = "● Calculating risk metrics & executive summaries";
                }
            }, 300);

            setTimeout(() => {
                if (step2) {
                    step2.className = "step-item done";
                    step2.textContent = "✓ Risk metrics & executive summaries calculated";
                }
                if (step3) {
                    step3.className = "step-item running";
                    step3.textContent = "● Embedding PoC snippets & evidence screenshots";
                }
            }, 600);

            setTimeout(() => {
                if (step3) {
                    step3.className = "step-item done";
                    step3.textContent = "✓ PoC snippets & evidence figures embedded";
                }
                if (step4) {
                    step4.className = "step-item running";
                    step4.textContent = "● Compiling Microsoft Word (.docx) report package";
                }
            }, 900);

            try {
                const res = await fetch(`/api/projects/${proj.id}/reports`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        version: version,
                        author_name: author,
                        methodology: methodology,
                        selected_finding_ids: selectedIds,
                        allow_clean_report: isCleanAllowed
                    })
                });

                if (!res.ok) {
                    let errDetail = "Report generation failed.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    throw new Error(errDetail);
                }

                const reportRecord = await res.json();

                if (step4) {
                    step4.className = "step-item done";
                    step4.textContent = "✓ Microsoft Word (.docx) report compiled successfully!";
                }

                setTimeout(() => {
                    if (stepperBox) stepperBox.classList.remove("active");
                    btnGenerateDocxReport.disabled = false;

                    // Trigger direct browser download
                    const dlLink = document.createElement("a");
                    dlLink.href = `/api/projects/${proj.id}/reports/${reportRecord.id}/download`;
                    dlLink.download = reportRecord.filename || `${proj.name}_vapt_report_${version}.docx`;
                    document.body.appendChild(dlLink);
                    dlLink.click();
                    document.body.removeChild(dlLink);

                    showToast(`✓ Official DOCX Report (${version}) generated & downloaded!`, "success");
                    loadProjectReports(proj.id);
                }, 500);

            } catch (err) {
                if (stepperBox) stepperBox.classList.remove("active");
                btnGenerateDocxReport.disabled = false;
                showToast("Report Generation Error: " + err.message, "error");
            }
        });
    }

    const btnReportDownloadMarkdown = document.getElementById("btnReportDownloadMarkdown");
    if (btnReportDownloadMarkdown) {
        btnReportDownloadMarkdown.addEventListener("click", () => exportAssessmentMarkdown());
    }

    const btnReportCopyMarkdown = document.getElementById("btnReportCopyMarkdown");
    if (btnReportCopyMarkdown) {
        btnReportCopyMarkdown.addEventListener("click", () => copyAssessmentMarkdown());
    }

    const btnExportMarkdown = document.getElementById("btnExportMarkdown");
    if (btnExportMarkdown) {
        btnExportMarkdown.addEventListener("click", () => exportAssessmentMarkdown());
    }

    function buildAssessmentMarkdown(proj) {
        if (!proj) return "";

        const m = calculateProjectMetrics(proj);
        const vulns = proj.findings || [];
        const checklist = (proj.checklist_data && proj.checklist_data.checklist) ? proj.checklist_data.checklist : [];
        const pageType = proj.checklist_data?.page_type || "Web Application Target";
        const assessorName = currentUser ? currentUser.name : "Security Learner";
        const assessorEmail = currentUser ? currentUser.email : "learner@tracegate.lab";
        const methodology = currentUser?.methodology === "asvs_l2" ? "OWASP ASVS Level 2" : (currentUser?.methodology === "cwe_sans" ? "CWE/SANS Top 25" : "OWASP Top 10 Web (2025)");

        let md = `# Tracegate Security Assessment Report: ${proj.name}

`;
        md += `> **Confidential Security Assessment Document**  
`;
        md += `> Target: \`${proj.target_url}\` | Date: ${new Date().toISOString().split("T")[0]} | Lead Assessor: ${assessorName}

`;

        md += `## 1. Assessment Overview & Scope

`;
        md += `| Attribute | Details |
`;
        md += `| :--- | :--- |
`;
        md += `| **Project Name** | ${proj.name} |
`;
        md += `| **Target Application** | \`${proj.target_url}\` |
`;
        md += `| **Environment** | ${proj.environment || "Web Application (Staging)"} |
`;
        md += `| **Assessment Date** | ${new Date().toISOString().split("T")[0]} |
`;
        md += `| **Lead Assessor** | ${assessorName} (${assessorEmail}) |
`;
        md += `| **Methodology** | ${methodology} |
`;
        md += `| **Analyzed Surface** | ${pageType} |
`;
        if (proj.description) md += `| **Scope Description** | ${proj.description} |
`;
        if (proj.notes) md += `| **Testing Notes** | ${proj.notes} |
`;
        md += `
`;

        md += `## 2. Executive Assessment Summary

`;
        md += `A structured security verification was performed against the authorized target interface. Out of **${m.total}** planned security test procedures, **${m.completed}** were evaluated (**${m.pct}%** completion rate).

`;
        md += `- **Confirmed Vulnerabilities Logged**: **${vulns.length}**
`;
        md += `- **Verified Clean Controls (Tested & Not Found)**: **${m.clean}**
`;
        md += `- **Pending / Untested Controls**: **${m.remaining}**

`;

        // Severity Breakdown
        const critVulns = vulns.filter(v => v.priority === "CRITICAL").length;
        const highVulns = vulns.filter(v => v.priority === "HIGH").length;
        const medVulns = vulns.filter(v => v.priority === "MEDIUM").length;
        const lowVulns = vulns.filter(v => v.priority === "LOW").length;

        md += `### Findings Severity Breakdown

`;
        md += `| Severity | Count | Status |
`;
        md += `| :--- | :--- | :--- |
`;
        md += `| **CRITICAL** | ${critVulns} | ${critVulns > 0 ? "Immediate Remediation Required" : "None Identified"} |
`;
        md += `| **HIGH** | ${highVulns} | ${highVulns > 0 ? "Priority Remediation Recommended" : "None Identified"} |
`;
        md += `| **MEDIUM** | ${medVulns} | ${medVulns > 0 ? "Standard Remediation Required" : "None Identified"} |
`;
        md += `| **LOW** | ${lowVulns} | ${lowVulns > 0 ? "Best Practice Improvement" : "None Identified"} |

`;

        md += `## 3. Confirmed Vulnerability Findings & Proof of Concept

`;
        if (vulns.length === 0) {
            md += `*No security vulnerabilities were identified in the evaluated surfaces for this assessment scope.*

`;
        } else {
            vulns.forEach((v, idx) => {
                const linkedTest = checklist.find(i => i.id === v.test_id);
                md += `### 3.${idx + 1} [${v.priority}] ${v.finding_name}

`;
                if (v.cwe || linkedTest?.cwe) {
                    md += `- **Vulnerability Classification**: \`${v.cwe || linkedTest?.cwe}\`
`;
                }
                if (linkedTest) {
                    md += `- **Originating Security Test**: ${linkedTest.name}
`;
                }
                md += `- **Severity**: **${v.priority}**
`;
                md += `- **Logged At**: ${v.recorded_at || "Recent"}

`;

                if (v.description) {
                    md += `**Observation & Security Impact**:
`;
                    md += `${v.description}

`;
                }

                if (v.testing_notes || v.reproduction_steps) {
                    md += `**Reproduction Steps**:
`;
                    md += `${v.reproduction_steps || v.testing_notes}

`;
                }

                if (v.poc_text) {
                    md += `**Proof of Concept (PoC) / Payload Snippet**:

`;
                    md += `\`\`\`http
${v.poc_text}
\`\`\`

`;
                }

                if (v.remediation) {
                    md += `**Remediation Guidance**:
${v.remediation}

`;
                }

                if (v.evidence_filename) {
                    md += `*Attached PoC Evidence Artifact: \`${v.evidence_filename}\`*

`;
                }

                md += `---

`;
            });
        }

        md += `## 4. Verified Clean Security Controls (Tested — Not Found)

`;
        const cleanItems = checklist.filter(i => i.status === "TESTED_NOT_FOUND");
        if (cleanItems.length === 0) {
            md += `*No security tests have been marked as clean yet.*

`;
        } else {
            md += `The following controls were actively tested and confirmed clean:

`;
            md += `| Priority | Security Control Test | CWE | Verification Objective |
`;
            md += `| :--- | :--- | :--- | :--- |
`;
            cleanItems.forEach(item => {
                const cleanObj = (item.testing_objective || "").replace(/\r?\n/g, " ");
                md += `| **${item.priority}** | ${item.name} | \`${item.cwe || "N/A"}\` | ${cleanObj} |\n`;
            });
            md += `
`;
        }

        md += `## 5. Untested / Planned Assessment Scope

`;
        const untestedItems = checklist.filter(i => i.status === "NOT_TESTED" || !i.status);
        if (untestedItems.length === 0) {
            md += `*All planned checklist items have been fully executed and reviewed.*

`;
        } else {
            md += `The following procedures remain in the scope for subsequent testing phases:

`;
            untestedItems.forEach(item => {
                md += `- [ ] **[${item.priority}] ${item.name}** (\`${item.cwe || "N/A"}\`): ${item.testing_objective}
`;
            });
            md += `
`;
        }

        md += `## 6. General Remediation Guidance & Methodology

`;
        md += `1. **Input Validation & Parameterization**: Ensure all client-supplied parameters are validated against strict type-safe schemas and passed to database layers via parameterized prepared statements.
`;
        md += `2. **Defense in Depth**: Implement modern HTTP security headers (\`Content-Security-Policy\`, \`X-Frame-Options: DENY\`, \`Strict-Transport-Security\`).
`;
        md += `3. **Least Privilege**: Verify authorization on server-side controllers for all object access.

`;
        md += `*Assessment conducted with Tracegate AI-assisted VAPT Learning Platform for authorized security testing.*  
`;

        return md;
    }

    function exportAssessmentMarkdown() {
        const proj = getActiveProject();
        if (!proj) return;

        const md = buildAssessmentMarkdown(proj);

        const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${proj.name.toLowerCase().replace(/[^a-z0-9]/g, "_")}_vapt_report.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast("✓ Assessment Report downloaded as Markdown!", "success");
    }

    function copyAssessmentMarkdown() {
        const proj = getActiveProject();
        if (!proj) return;

        const md = buildAssessmentMarkdown(proj);
        if (!navigator.clipboard) {
            const ta = document.createElement("textarea");
            ta.value = md;
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            document.body.removeChild(ta);
            showToast("✓ Assessment Report copied to clipboard!", "success");
            return;
        }

        navigator.clipboard.writeText(md).then(() => {
            showToast("✓ Assessment Report copied to clipboard!", "success");
        }).catch(() => {
            showToast("Failed to copy report to clipboard.", "error");
        });
    }


    // ==========================================================================
    // 12. PAGE TYPE CHANGE & STALENESS CONTROLLER (Sections 18, 19)
    // ==========================================================================
    const pageTypeSelect = document.getElementById("pageTypeSelect");
    const pageTypeOtherContainer = document.getElementById("pageTypeOtherContainer");
    const pageTypeOtherInput = document.getElementById("pageTypeOtherInput");
    const staleAnalysisBanner = document.getElementById("staleAnalysisBanner");
    const btnRegenerateChecklist = document.getElementById("btnRegenerateChecklist");

    if (pageTypeSelect) {
        pageTypeSelect.addEventListener("change", () => {
            selectedPageType = pageTypeSelect.value;
            if (pageTypeSelect.value === "Other") {
                if (pageTypeOtherContainer) pageTypeOtherContainer.style.display = "block";
            } else {
                if (pageTypeOtherContainer) pageTypeOtherContainer.style.display = "none";
            }

            const activeProj = getActiveProject();
            if (activeProj && activeProj.checklist_data && lastGeneratedPageType !== null) {
                if (pageTypeSelect.value !== lastGeneratedPageType) {
                    checklistStatus = "NEEDS_REGENERATION";
                    if (staleAnalysisBanner) staleAnalysisBanner.style.display = "flex";
                } else {
                    checklistStatus = "CURRENT";
                    if (staleAnalysisBanner) staleAnalysisBanner.style.display = "none";
                }
            }
        });
    }

    if (pageTypeOtherInput) {
        pageTypeOtherInput.addEventListener("input", () => {
            const activeProj = getActiveProject();
            if (activeProj && activeProj.checklist_data && staleAnalysisBanner) {
                checklistStatus = "NEEDS_REGENERATION";
                staleAnalysisBanner.style.display = "flex";
            }
        });
    }

    // Section 19: Regenerate Checklist calls generateChecklist directly!
    if (btnRegenerateChecklist) {
        btnRegenerateChecklist.addEventListener("click", generateChecklist);
    }

    // ==========================================================================
    // 13. GITHUB AI FIX & CODE CONNECTOR CONTROLLER
    // ==========================================================================
    async function loadGitHubFixStatus() {
        try {
            const res = await fetch("/api/github/status");
            if (res.ok) {
                const data = await res.json();
                const statusLabel = document.getElementById("githubStatusLabel");
                if (statusLabel) {
                    statusLabel.textContent = data.connected ? `GitHub Connected (${data.username})` : "GitHub Ready (Lab Sandbox)";
                }
            }
        } catch (e) {
            console.warn("GitHub status check:", e);
        }
    }

    function renderWorkspaceAutoFix() {
        loadGitHubFixStatus();
        const wsSelect = document.getElementById("wsAutofixFindingSelect");
        const standSelect = document.getElementById("autofixFindingSelect");
        const proj = getActiveProject();
        const findings = (proj && proj.findings) ? proj.findings : [];

        [wsSelect, standSelect].forEach(sel => {
            if (!sel) return;
            sel.innerHTML = `<option value="">-- Select Confirmed Vulnerability --</option>`;
            findings.forEach((f, idx) => {
                const opt = document.createElement("option");
                opt.value = f.id;
                const vulnId = f.vuln_id || `VULN-${String(idx + 1).padStart(3, "0")}`;
                opt.textContent = `[${vulnId}] ${f.finding_name} (${f.priority})`;
                sel.appendChild(opt);
            });
        });
    }

    async function executeCodeFixAnalysis(repo, branch, findingId, isWorkspace = true) {
        if (!findingId) {
            showToast("Please select a confirmed vulnerability first.", "error");
            return;
        }

        try {
            showToast("Analyzing source code & generating unified diff...", "info");
            const res = await fetch("/api/github/analyze-code", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ repo, branch, finding_id: findingId })
            });

            if (!res.ok) throw new Error("Failed to analyze source code.");
            const data = await res.json();

            const diffWrap = document.getElementById(isWorkspace ? "wsDiffViewerWrapper" : "standaloneDiffWrapper");
            const diffContainer = document.getElementById(isWorkspace ? "wsDiffContainer" : "autofixOutputBox");
            const filePathEl = document.getElementById(isWorkspace ? "wsDiffFilePath" : "standaloneDiffFilePath");
            const expEl = document.getElementById("wsDiffExplanation");
            const safeEl = document.getElementById("wsDiffSafetyNotes");

            if (diffWrap) diffWrap.style.display = "flex";
            if (filePathEl) filePathEl.textContent = data.file_path;
            if (expEl) expEl.textContent = data.explanation;
            if (safeEl) safeEl.textContent = "Safety notice: " + (data.safety_notes || "Enforces least privilege boundaries.");

            if (diffContainer) {
                diffContainer.innerHTML = "";
                const lines = data.diff_unified.split("\n");
                lines.forEach(line => {
                    const span = document.createElement("span");
                    if (line.startsWith("+") && !line.startsWith("+++")) {
                        span.className = "diff-line-add";
                    } else if (line.startsWith("-") && !line.startsWith("---")) {
                        span.className = "diff-line-del";
                    } else if (line.startsWith("@@")) {
                        span.className = "diff-line-info";
                    }
                    span.textContent = line + "\n";
                    diffContainer.appendChild(span);
                });
            }

            window._currentAnalysisData = data;
            showToast("Unified diff generated successfully!", "success");
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    async function executeApplyFix(isWorkspace = true) {
        const data = window._currentAnalysisData;
        if (!data) {
            showToast("No analysis diff to apply.", "error");
            return;
        }

        try {
            showToast("Applying fix to dedicated branch & running tests...", "info");
            const res = await fetch("/api/github/apply-fix", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    repo: data.repo,
                    target_branch: data.branch,
                    finding_id: data.finding_id,
                    file_path: data.file_path,
                    diff_or_fixed_code: data.proposed_code
                })
            });

            if (!res.ok) throw new Error("Failed to apply fix.");
            const fixResult = await res.json();
            window._currentFixResult = fixResult;

            const card = document.getElementById(isWorkspace ? "wsFixAppliedCard" : "standaloneFixAppliedCard");
            const branchEl = document.getElementById(isWorkspace ? "wsFixBranchName" : "standaloneFixBranch");
            const shaEl = document.getElementById("wsFixCommitSha");

            if (card) card.style.display = "flex";
            if (branchEl) branchEl.textContent = fixResult.branch_name;
            if (shaEl) shaEl.textContent = fixResult.commit_sha;

            const proj = getActiveProject();
            if (proj && proj.findings) {
                const f = proj.findings.find(item => item.id === data.finding_id);
                if (f) {
                    f.fix_status = "Fix Applied";
                    saveProjects();
                    renderWorkspaceFindings();
                }
            }

            showToast("✓ Fix successfully committed to " + fixResult.branch_name, "success");
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    async function executeCreatePR(isWorkspace = true) {
        const data = window._currentAnalysisData;
        const fixResult = window._currentFixResult;
        if (!data || !fixResult) {
            showToast("Please apply the fix first before creating a Pull Request.", "error");
            return;
        }

        try {
            showToast("Creating GitHub Pull Request...", "info");
            const res = await fetch("/api/github/create-pr", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    repo: data.repo,
                    fix_branch: fixResult.branch_name,
                    base_branch: data.branch,
                    title: `Security Fix (${fixResult.branch_name}): Remediate finding`,
                    body: `Automated security remediation generated by Tracegate for finding ${data.finding_id}.`,
                    finding_id: data.finding_id
                })
            });

            if (!res.ok) throw new Error("Failed to create Pull Request.");
            const prResult = await res.json();

            const prRow = document.getElementById(isWorkspace ? "wsPRResultRow" : "standalonePRResultRow");
            const prLink = document.getElementById(isWorkspace ? "wsPRLink" : "standalonePRLink");

            if (prRow) prRow.style.display = "flex";
            if (prLink) {
                prLink.href = prResult.pr_url;
                prLink.textContent = `Pull Request #${prResult.pr_number} Created (${prResult.pr_url})`;
            }

            const proj = getActiveProject();
            if (proj && proj.findings) {
                const f = proj.findings.find(item => item.id === data.finding_id);
                if (f) {
                    f.fix_status = "PR Created";
                    saveProjects();
                    renderWorkspaceFindings();
                }
            }

            showToast("✓ GitHub Pull Request #" + prResult.pr_number + " created!", "success");
        } catch (err) {
            showToast(err.message, "error");
        }
    }

    // Connect Workspace AI Fix Buttons
    const btnWsAnalyzeCodeFix = document.getElementById("btnWsAnalyzeCodeFix");
    if (btnWsAnalyzeCodeFix) {
        btnWsAnalyzeCodeFix.addEventListener("click", () => {
            const repo = document.getElementById("wsAutofixRepoSelect")?.value || "tracegate-lab/ecommerce-platform";
            const branch = document.getElementById("wsAutofixBranchSelect")?.value || "main";
            const findingId = document.getElementById("wsAutofixFindingSelect")?.value;
            executeCodeFixAnalysis(repo, branch, findingId, true);
        });
    }

    const btnWsRejectFix = document.getElementById("btnWsRejectFix");
    if (btnWsRejectFix) {
        btnWsRejectFix.addEventListener("click", () => {
            const diffWrap = document.getElementById("wsDiffViewerWrapper");
            if (diffWrap) diffWrap.style.display = "none";
            showToast("Fix proposal rejected.", "info");
        });
    }

    const btnWsApplyFix = document.getElementById("btnWsApplyFix");
    if (btnWsApplyFix) {
        btnWsApplyFix.addEventListener("click", () => {
            executeApplyFix(true);
        });
    }

    const btnWsCreatePR = document.getElementById("btnWsCreatePR");
    if (btnWsCreatePR) {
        btnWsCreatePR.addEventListener("click", () => {
            executeCreatePR(true);
        });
    }

    // Connect Standalone AI Fix Buttons
    const btnRunAutoFixPreview = document.getElementById("btnRunAutoFixPreview");
    if (btnRunAutoFixPreview) {
        btnRunAutoFixPreview.addEventListener("click", () => {
            const repo = document.getElementById("standaloneRepoSelect")?.value || "tracegate-lab/ecommerce-platform";
            const branch = document.getElementById("standaloneBranchSelect")?.value || "main";
            const findingId = document.getElementById("autofixFindingSelect")?.value;
            executeCodeFixAnalysis(repo, branch, findingId, false);
        });
    }

    const btnStandaloneReject = document.getElementById("btnStandaloneReject");
    if (btnStandaloneReject) {
        btnStandaloneReject.addEventListener("click", () => {
            const diffWrap = document.getElementById("standaloneDiffWrapper");
            if (diffWrap) diffWrap.style.display = "none";
            showToast("Fix proposal rejected.", "info");
        });
    }

    const btnApplyAutoFix = document.getElementById("btnApplyAutoFix");
    if (btnApplyAutoFix) {
        btnApplyAutoFix.addEventListener("click", () => {
            executeApplyFix(false);
        });
    }

    const btnStandaloneCreatePR = document.getElementById("btnStandaloneCreatePR");
    if (btnStandaloneCreatePR) {
        btnStandaloneCreatePR.addEventListener("click", () => {
            executeCreatePR(false);
        });
    }


    // ==========================================================================
    // 14. PROFILE VIEW CONTROLLER
    // ==========================================================================
    const btnSaveProfile = document.getElementById("btnSaveProfile");
    if (btnSaveProfile) {
        btnSaveProfile.addEventListener("click", () => {
            const name = document.getElementById("profileInputName").value.trim();
            const email = document.getElementById("profileInputEmail").value.trim();
            const meth = document.getElementById("profileSelectMethodology").value;

            if (!name || !email) {
                showToast("Name and email cannot be empty.", "error");
                return;
            }

            currentUser.name = name;
            currentUser.email = email;
            currentUser.methodology = meth;
            localStorage.setItem("tg_user", JSON.stringify(currentUser));
            updateUserUI();

            showToast("Profile preferences updated successfully!", "success");
        });
    }

    // ==========================================================================
    // 15. MODAL HELPERS & TOAST COMPONENT
    // ==========================================================================
    function openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.add("active");
    }

    function closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.remove("active");
    }

    // Close on overlay backdrop click
    document.querySelectorAll(".modal-overlay").forEach(modal => {
        modal.addEventListener("click", (e) => {
            if (e.target === modal) {
                modal.classList.remove("active");
            }
        });
    });

    function showToast(message, type = "info") {
        const container = document.getElementById("toastContainer");
        if (!container) return;

        const pill = document.createElement("div");
        pill.className = `toast-pill toast-${type}`;

        let icon = "ℹ️";
        if (type === "success") icon = "✓";
        if (type === "error") icon = "⚠️";

        pill.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;
        container.appendChild(pill);

        setTimeout(() => {
            pill.style.opacity = "0";
            pill.style.transform = "translateY(10px)";
            pill.style.transition = "all 0.3s ease";
            setTimeout(() => {
                if (pill.parentNode) pill.parentNode.removeChild(pill);
            }, 300);
        }, 3200);
    }

    function escapeHtml(str) {
        if (typeof str !== "string") return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Initialize application on load
    initState();
    navigateTo(window.location.hash);
});
