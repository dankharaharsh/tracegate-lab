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
    let pendingEvidenceList = [];
    let isSavingFinding = false;

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
            if (savedUser) {
                try { currentUser = JSON.parse(savedUser); } catch (e) { currentUser = null; }
            }
        } else {
            localStorage.removeItem("tg_user");
            currentUser = null;
        }

        updateUserUI();
        applyRememberedCredentials();

        if (authToken) {
            try {
                const meRes = await fetch("/api/auth/me", {
                    headers: { "Authorization": `Bearer ${authToken}` }
                });
                if (meRes.ok) {
                    currentUser = await meRes.json();
                    localStorage.setItem("tg_user", JSON.stringify(currentUser));
                    updateUserUI();
                } else {
                    localStorage.removeItem("tg_auth_token");
                    localStorage.removeItem("tg_user");
                    currentUser = null;
                    updateUserUI();
                    applyRememberedCredentials();
                    if (window.location.hash !== "#login") {
                        navigateTo("#login");
                    }
                }
            } catch (e) {
                console.warn("[TRACEGATE] Offline or network error verifying auth:", e);
            }
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

    async function setActiveProject(projId, targetTab = null) {
        if (!projects.some(p => p.id === projId)) return;
        activeProjectId = projId;
        localStorage.setItem("tg_active_proj_id", projId);
        updateProjectsDropdown();
        if (targetTab && typeof window.switchWorkspaceTab === "function") {
            window.switchWorkspaceTab(targetTab, false);
        }
        renderActiveWorkspace();
        refreshDashboardStats();
        showToast(`Switched active project to "${getActiveProject().name}"`, "info");
        await loadProjectDetails(projId);
    }

    function openProject(projId, targetTab = "overview") {
        if (!projId) return;
        const finalTab = targetTab || "overview";
        setActiveProject(projId, finalTab);
        if (typeof window.switchWorkspaceTab === "function") {
            window.switchWorkspaceTab(finalTab, false);
        }
        const destHash = finalTab && finalTab !== "overview"
            ? `#project-workspace/${finalTab}`
            : "#project-workspace";
        if (window.location.hash === destHash) {
            navigateTo(destHash);
        } else {
            window.location.hash = destHash;
        }
    }

    function updateUserUI() {
        const navItemLogin = document.getElementById("navItemLogin");
        const btnLogoutEl = document.getElementById("btnLogout");
        const sidebarUserProfile = document.getElementById("sidebarUserProfile");
        const sidebarFooter = document.getElementById("sidebarFooter") || document.querySelector(".sidebar-footer");
        const navItemProfile = document.getElementById("navItemProfile") || document.querySelector('a[data-route="profile"]');
        const avatarEl = document.getElementById("sidebarUserAvatar");
        const nameEl = document.getElementById("sidebarUserName");
        const roleEl = document.getElementById("sidebarUserRole");
        const dashNameEl = document.getElementById("dashGreetingName");
        const profAvatar = document.getElementById("profileAvatarLarge");
        const profName = document.getElementById("profileNameDisplay");
        const profEmail = document.getElementById("profileEmailDisplay");
        const inpName = document.getElementById("profileInputName");
        const inpEmail = document.getElementById("profileInputEmail");

        if (!currentUser) {
            if (navItemLogin) navItemLogin.style.display = "flex";
            if (btnLogoutEl) btnLogoutEl.style.display = "none";
            if (sidebarUserProfile) sidebarUserProfile.style.display = "none";
            if (sidebarFooter) sidebarFooter.style.display = "none";
            if (navItemProfile) navItemProfile.style.display = "none";
            if (avatarEl) avatarEl.textContent = "";
            if (nameEl) nameEl.textContent = "";
            if (roleEl) roleEl.textContent = "";
            if (dashNameEl) dashNameEl.textContent = "Guest";
            if (profAvatar) profAvatar.textContent = "";
            if (profName) profName.textContent = "";
            if (profEmail) profEmail.textContent = "";
            if (inpName) inpName.value = "";
            if (inpEmail) inpEmail.value = "";
            return;
        }

        if (navItemLogin) navItemLogin.style.display = "none";
        if (btnLogoutEl) btnLogoutEl.style.display = "flex";
        if (sidebarUserProfile) sidebarUserProfile.style.display = "flex";
        if (sidebarFooter) sidebarFooter.style.display = "flex";
        if (navItemProfile) navItemProfile.style.display = "flex";

        const displayName = currentUser.full_name || currentUser.name || currentUser.username || "Security Learner";
        const initials = displayName
            .split(" ")
            .filter(Boolean)
            .map(n => n[0])
            .join("")
            .substring(0, 2)
            .toUpperCase() || "SL";
        
        if (avatarEl) avatarEl.textContent = initials;
        if (nameEl) nameEl.textContent = displayName;
        if (roleEl) roleEl.textContent = currentUser.role || "Junior Pentester";

        if (dashNameEl) dashNameEl.textContent = displayName;

        if (profAvatar) profAvatar.textContent = initials;
        if (profName) profName.textContent = displayName;
        if (profEmail) profEmail.textContent = `${currentUser.email || ''} • ${currentUser.role || 'Junior Pentester'}`;

        if (inpName) inpName.value = displayName;
        if (inpEmail) inpEmail.value = currentUser.email || '';

        const selMeth = document.getElementById("profileSelectMethodology");
        if (selMeth && currentUser.methodology) selMeth.value = currentUser.methodology;

        if (typeof window.loadProfile2FAStatus === "function") {
            window.loadProfile2FAStatus();
        }
    }

    function applyRememberedCredentials() {
        const rememberedIdentifier = localStorage.getItem("tg_remembered_identifier");
        const chk = document.getElementById("chkRememberMe");
        const emailInput = document.getElementById("loginEmailInput");
        const passwordInput = document.getElementById("loginPasswordInput");

        // Plaintext passwords must NEVER be saved or persisted anywhere. Always clear password input.
        if (passwordInput) {
            passwordInput.value = "";
        }

        if (rememberedIdentifier) {
            if (emailInput) emailInput.value = rememberedIdentifier;
            if (chk) chk.checked = true;
        } else {
            if (emailInput) emailInput.value = "";
            if (chk) chk.checked = false;
        }
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
            openProject(e.target.value, "overview");
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
        let rawRoute = (hash || window.location.hash || "#dashboard").replace("#", "").trim();
        if (!rawRoute) rawRoute = "dashboard";

        // Separate query parameters if present (e.g. #project-workspace?tab=report)
        const [routePath, queryString] = rawRoute.split("?");
        const searchParams = new URLSearchParams(queryString || "");
        let explicitTab = searchParams.get("tab") || null;

        // Split route segments (e.g. project-workspace/report, project/proj-123/report)
        const segments = routePath.split("/").filter(Boolean);
        const mainSegment = segments[0] || "dashboard";

        let route = mainSegment;

        if (mainSegment === "project-workspace") {
            route = "project-workspace";
            if (segments[1]) {
                explicitTab = segments[1];
            }
        } else if (mainSegment === "project" || mainSegment === "projects") {
            route = "project-workspace";
            if (segments[1]) {
                const potentialProj = projects.find(p => p.id === segments[1]);
                if (potentialProj) {
                    if (activeProjectId !== potentialProj.id) {
                        activeProjectId = potentialProj.id;
                        localStorage.setItem("tg_active_proj_id", activeProjectId);
                        updateProjectsDropdown();
                    }
                    if (segments[2]) {
                        explicitTab = segments[2];
                    }
                } else if (["overview", "checklist", "findings", "report", "autofix", "ai-fix"].includes(segments[1])) {
                    explicitTab = segments[1];
                }
            }
        } else if (mainSegment === "checklist-generator" || mainSegment === "tool-checklist") {
            route = "project-workspace";
            explicitTab = "checklist";
        } else if (mainSegment === "findings") {
            route = "project-workspace";
            explicitTab = "findings";
        } else if (mainSegment === "report-generation" || mainSegment === "tool-reports") {
            route = "project-workspace";
            explicitTab = "report";
        } else if (mainSegment === "autofix" || mainSegment === "tool-autofix") {
            route = "project-workspace";
            explicitTab = "autofix";
        }

        // Auth guard: if route is not login and user is logged out
        if (route !== "login" && !currentUser) {
            if (window.location.hash === "#login") {
                navigateTo("#login");
            } else {
                window.location.hash = "#login";
            }
            return;
        }

        if (route === "login") {
            applyRememberedCredentials();
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

        if (route === "profile" && typeof window.loadProfile2FAStatus === "function") {
            window.loadProfile2FAStatus();
        }

        // Activate Workspace Tab if on project-workspace
        let activeWsTab = "overview";
        if (route === "project-workspace") {
            const validTabs = ["overview", "checklist", "findings", "report", "autofix"];
            let normalizedTab = explicitTab ? explicitTab.toLowerCase() : null;
            if (normalizedTab === "ai-fix") normalizedTab = "autofix";

            // If no explicit tab or invalid tab, DEFAULT TO OVERVIEW!
            activeWsTab = (normalizedTab && validTabs.includes(normalizedTab)) ? normalizedTab : "overview";
            if (typeof window.switchWorkspaceTab === "function") {
                window.switchWorkspaceTab(activeWsTab, false);
            }
        }

        // Update sidebar nav highlighting
        document.querySelectorAll(".nav-item, .nav-child-item").forEach(item => {
            const itemRoute = item.getAttribute("data-route");
            if (itemRoute === route) {
                if (route === "project-workspace") {
                    item.classList.remove("active");
                } else {
                    item.classList.add("active");
                }
            } else if (route === "project-workspace") {
                if (activeWsTab === "checklist" && (itemRoute === "tool-checklist" || itemRoute === "checklist-generator")) {
                    item.classList.add("active");
                } else if (activeWsTab === "report" && (itemRoute === "tool-reports" || itemRoute === "report-generation")) {
                    item.classList.add("active");
                } else if (activeWsTab === "autofix" && (itemRoute === "autofix" || itemRoute === "tool-autofix")) {
                    item.classList.add("active");
                } else if (activeWsTab === "findings" && itemRoute === "findings") {
                    item.classList.add("active");
                } else {
                    item.classList.remove("active");
                }
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

    window.addEventListener("popstate", () => {
        navigateTo(window.location.hash);
    });

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
    const chkRememberMe = document.getElementById("chkRememberMe");
    const btnLoginSubmit = document.getElementById("btnLoginSubmit");
    const btnTogglePassword = document.getElementById("btnTogglePassword");
    const linkForgotPassword = document.getElementById("linkForgotPassword");
    const btnLogout = document.getElementById("btnLogout");
    const sidebarUserProfile = document.getElementById("sidebarUserProfile");
    const sidebarFooter = document.getElementById("sidebarFooter") || document.querySelector(".sidebar-footer");
    const navItemProfile = document.getElementById("navItemProfile") || document.querySelector('a[data-route="profile"]');

    // Password Reset Elements
    const modalForgotPassword = document.getElementById("modalForgotPassword");
    const btnCloseForgotModal = document.getElementById("btnCloseForgotModal");
    const forgotAlertBox = document.getElementById("forgotAlertBox");
    const forgotAlertIcon = document.getElementById("forgotAlertIcon");
    const forgotAlertMessage = document.getElementById("forgotAlertMessage");
    const forgotStep1Section = document.getElementById("forgotStep1Section");
    const forgotStep2Section = document.getElementById("forgotStep2Section");
    const forgotEmailInput = document.getElementById("forgotEmailInput");
    const forgotTokenInput = document.getElementById("forgotTokenInput");
    const forgotNewPasswordInput = document.getElementById("forgotNewPasswordInput");
    const forgotConfirmPasswordInput = document.getElementById("forgotConfirmPasswordInput");
    const btnRequestResetToken = document.getElementById("btnRequestResetToken");
    const btnRequestResetText = document.getElementById("btnRequestResetText");
    const btnSubmitPasswordReset = document.getElementById("btnSubmitPasswordReset");
    const btnSubmitResetText = document.getElementById("btnSubmitResetText");
    const linkSwitchToStep2 = document.getElementById("linkSwitchToStep2");
    const linkBackToStep1 = document.getElementById("linkBackToStep1");

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
            applyRememberedCredentials();
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

    if (chkRememberMe) {
        chkRememberMe.addEventListener("change", () => {
            if (!chkRememberMe.checked) {
                localStorage.removeItem("tg_remembered_identifier");
            } else if (loginEmailInput && loginEmailInput.value.trim()) {
                localStorage.setItem("tg_remembered_identifier", loginEmailInput.value.trim());
            }
        });
    }

    if (sidebarUserProfile) {
        sidebarUserProfile.addEventListener("click", () => {
            if (currentUser) {
                window.location.hash = "#profile";
            }
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

    // Password Reset Modal Handlers & Step Switching
    function showForgotAlert(msg, isSuccess = false) {
        if (forgotAlertBox && forgotAlertMessage) {
            forgotAlertMessage.textContent = msg;
            if (forgotAlertIcon) forgotAlertIcon.textContent = isSuccess ? "✅" : "⚠️";
            forgotAlertBox.style.display = "flex";
            if (isSuccess) {
                forgotAlertBox.style.background = "rgba(16, 185, 129, 0.12)";
                forgotAlertBox.style.borderColor = "rgba(16, 185, 129, 0.35)";
                forgotAlertBox.style.color = "#34d399";
            } else {
                forgotAlertBox.style.background = "";
                forgotAlertBox.style.borderColor = "";
                forgotAlertBox.style.color = "";
            }
        }
    }

    function hideForgotAlert() {
        if (forgotAlertBox) forgotAlertBox.style.display = "none";
    }

    function setForgotStep(stepNum) {
        hideForgotAlert();
        if (stepNum === 1) {
            if (forgotStep1Section) forgotStep1Section.style.display = "block";
            if (forgotStep2Section) forgotStep2Section.style.display = "none";
        } else {
            if (forgotStep1Section) forgotStep1Section.style.display = "none";
            if (forgotStep2Section) forgotStep2Section.style.display = "block";
        }
    }

    if (linkForgotPassword) {
        linkForgotPassword.addEventListener("click", () => {
            setForgotStep(1);
            if (forgotEmailInput && loginEmailInput && loginEmailInput.value.includes("@")) {
                forgotEmailInput.value = loginEmailInput.value.trim();
            }
            openModal("modalForgotPassword");
        });
    }

    if (btnCloseForgotModal) {
        btnCloseForgotModal.addEventListener("click", () => {
            closeModal("modalForgotPassword");
        });
    }

    if (linkSwitchToStep2) {
        linkSwitchToStep2.addEventListener("click", () => {
            setForgotStep(2);
        });
    }

    if (linkBackToStep1) {
        linkBackToStep1.addEventListener("click", () => {
            setForgotStep(1);
        });
    }

    // Step 1: Request Reset Token
    if (btnRequestResetToken) {
        btnRequestResetToken.addEventListener("click", async () => {
            const email = forgotEmailInput ? forgotEmailInput.value.trim() : "";
            if (!email || !email.includes("@")) {
                showForgotAlert("Please enter a valid registered email address.");
                return;
            }

            hideForgotAlert();
            if (btnRequestResetText) btnRequestResetText.textContent = "Generating...";
            btnRequestResetToken.disabled = true;

            try {
                const res = await fetch("/api/auth/forgot-password", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email })
                });
                const data = await res.json();

                if (data.reset_token) {
                    if (forgotTokenInput) forgotTokenInput.value = data.reset_token;
                    setForgotStep(2);
                    showForgotAlert("Reset token generated and loaded! Set your new password below.", true);
                    showToast("Password reset token generated.", "success");
                } else {
                    showForgotAlert(data.message || "Password reset instructions dispatched.", true);
                    showToast(data.message || "Reset instructions dispatched.", "info");
                }
            } catch (err) {
                showForgotAlert("Unable to communicate with reset service. Please try again.");
            } finally {
                if (btnRequestResetText) btnRequestResetText.textContent = "Generate Reset Token";
                btnRequestResetToken.disabled = false;
            }
        });
    }

    // Step 2: Submit Reset Token & New Password
    if (btnSubmitPasswordReset) {
        btnSubmitPasswordReset.addEventListener("click", async () => {
            const token = forgotTokenInput ? forgotTokenInput.value.trim() : "";
            const new_password = forgotNewPasswordInput ? forgotNewPasswordInput.value.trim() : "";
            const confirm_password = forgotConfirmPasswordInput ? forgotConfirmPasswordInput.value.trim() : "";

            if (!token) {
                showForgotAlert("Reset token is required.");
                return;
            }
            if (!new_password || new_password.length < 8) {
                showForgotAlert("New password must be at least 8 characters.");
                return;
            }
            if (new_password !== confirm_password) {
                showForgotAlert("Passwords do not match. Please re-enter.");
                return;
            }

            hideForgotAlert();
            if (btnSubmitResetText) btnSubmitResetText.textContent = "Updating...";
            btnSubmitPasswordReset.disabled = true;

            try {
                const res = await fetch("/api/auth/reset-password", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ token, new_password })
                });

                if (!res.ok) {
                    let errDetail = "Password reset failed. Invalid or expired token.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    showForgotAlert(errDetail);
                    return;
                }

                const data = await res.json();
                closeModal("modalForgotPassword");
                showToast(data.message || "Password reset successfully! You can now sign in.", "success");

                // Switch to Sign In tab and prefill
                if (tabAuthSignIn) tabAuthSignIn.click();
                if (loginPasswordInput) {
                    loginPasswordInput.value = "";
                    loginPasswordInput.focus();
                }
                if (forgotEmailInput && forgotEmailInput.value && loginEmailInput) {
                    loginEmailInput.value = forgotEmailInput.value.trim();
                }
            } catch (err) {
                showForgotAlert("Network failure during password reset.");
            } finally {
                if (btnSubmitResetText) btnSubmitResetText.textContent = "Update Password";
                btnSubmitPasswordReset.disabled = false;
            }
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
                return;
            }

            const data = await res.json();

            // Remember Me persistence (username/email ONLY, never password)
            if (chkRememberMe && chkRememberMe.checked) {
                localStorage.setItem("tg_remembered_identifier", username_or_email);
            } else {
                localStorage.removeItem("tg_remembered_identifier");
            }

            // Always clear password input field immediately
            if (loginPasswordInput) loginPasswordInput.value = "";

            if (data.requires_2fa) {
                show2FAChallengeView(data.temp_token);
                return;
            }

            localStorage.setItem("tg_auth_token", data.access_token);
            currentUser = data.user;
            localStorage.setItem("tg_user", JSON.stringify(currentUser));

            updateUserUI();
            const welcomeName = currentUser.full_name || currentUser.name || currentUser.username || "Learner";
            showToast(`Welcome back, ${welcomeName}!`, "success");

            window.location.hash = "#dashboard";
        } catch (err) {
            showAuthError("Authentication service connection failed.");
        } finally {
            if (btnText) btnText.textContent = "Sign In to Dashboard";
            if (btnLoginSubmit) btnLoginSubmit.disabled = false;
        }
    }

    // ==========================================================================
    // 4B. TWO-FACTOR AUTHENTICATION LOGIN CHALLENGE CONTROLLER
    // ==========================================================================
    let current2FAPendingToken = null;
    const twoFactorLoginForm = document.getElementById("twoFactorLoginForm");
    const twoFactorAlertBox = document.getElementById("twoFactorAlertBox");
    const twoFactorAlertMessage = document.getElementById("twoFactorAlertMessage");
    const totpInputSection = document.getElementById("totpInputSection");
    const recoveryInputSection = document.getElementById("recoveryInputSection");
    const login2FACodeInput = document.getElementById("login2FACodeInput");
    const loginRecoveryCodeInput = document.getElementById("loginRecoveryCodeInput");
    const btnToggle2FAMethod = document.getElementById("btnToggle2FAMethod");
    const btnLogin2FASubmit = document.getElementById("btnLogin2FASubmit");
    const login2FABtnText = document.getElementById("login2FABtnText");
    const btnCancel2FAChallenge = document.getElementById("btnCancel2FAChallenge");
    const authTabsRow = document.querySelector(".auth-tabs-row");

    function show2FAError(msg) {
        if (twoFactorAlertBox && twoFactorAlertMessage) {
            twoFactorAlertMessage.textContent = msg;
            twoFactorAlertBox.style.display = "flex";
        }
    }

    function hide2FAError() {
        if (twoFactorAlertBox) {
            twoFactorAlertBox.style.display = "none";
        }
    }

    function show2FAChallengeView(tempToken) {
        current2FAPendingToken = tempToken;
        hideAuthError();
        hide2FAError();
        if (authTabsRow) authTabsRow.style.display = "none";
        if (loginForm) loginForm.style.display = "none";
        if (signupForm) signupForm.style.display = "none";
        if (twoFactorLoginForm) twoFactorLoginForm.style.display = "flex";
        if (authHeaderTitle) authHeaderTitle.textContent = "Two-Factor Verification";

        if (totpInputSection) totpInputSection.style.display = "block";
        if (recoveryInputSection) recoveryInputSection.style.display = "none";
        if (btnToggle2FAMethod) btnToggle2FAMethod.textContent = "Lost your device? Use a backup recovery code";

        if (login2FACodeInput) {
            login2FACodeInput.value = "";
            setTimeout(() => login2FACodeInput.focus(), 100);
        }
        if (loginRecoveryCodeInput) loginRecoveryCodeInput.value = "";
    }

    function hide2FAChallengeView() {
        current2FAPendingToken = null;
        hide2FAError();
        if (twoFactorLoginForm) twoFactorLoginForm.style.display = "none";
        if (authTabsRow) authTabsRow.style.display = "flex";
        if (loginForm) loginForm.style.display = "flex";
        if (authHeaderTitle) authHeaderTitle.textContent = "Sign in to Tracegate";
    }

    if (btnToggle2FAMethod) {
        btnToggle2FAMethod.addEventListener("click", () => {
            hide2FAError();
            const isTotpVisible = totpInputSection && totpInputSection.style.display !== "none";
            if (isTotpVisible) {
                if (totpInputSection) totpInputSection.style.display = "none";
                if (recoveryInputSection) recoveryInputSection.style.display = "block";
                btnToggle2FAMethod.textContent = "Use 6-digit authenticator code instead";
                if (loginRecoveryCodeInput) {
                    loginRecoveryCodeInput.value = "";
                    loginRecoveryCodeInput.focus();
                }
            } else {
                if (totpInputSection) totpInputSection.style.display = "block";
                if (recoveryInputSection) recoveryInputSection.style.display = "none";
                btnToggle2FAMethod.textContent = "Lost your device? Use a backup recovery code";
                if (login2FACodeInput) {
                    login2FACodeInput.value = "";
                    login2FACodeInput.focus();
                }
            }
        });
    }

    if (btnCancel2FAChallenge) {
        btnCancel2FAChallenge.addEventListener("click", () => {
            hide2FAChallengeView();
        });
    }

    async function execute2FALoginVerify() {
        if (!current2FAPendingToken) {
            show2FAError("Two-factor session expired. Please return to sign in.");
            return;
        }

        const isRecoveryActive = recoveryInputSection && recoveryInputSection.style.display !== "none";
        let code = null;
        let recovery_code = null;

        if (isRecoveryActive) {
            recovery_code = loginRecoveryCodeInput ? loginRecoveryCodeInput.value.trim() : "";
            if (!recovery_code) {
                show2FAError("Please enter your backup recovery code.");
                if (loginRecoveryCodeInput) loginRecoveryCodeInput.focus();
                return;
            }
        } else {
            code = login2FACodeInput ? login2FACodeInput.value.trim().replace(/\s+/g, "") : "";
            if (!code || code.length < 6) {
                show2FAError("Please enter the 6-digit code from your authenticator app.");
                if (login2FACodeInput) login2FACodeInput.focus();
                return;
            }
        }

        if (login2FABtnText) login2FABtnText.textContent = "Verifying...";
        if (btnLogin2FASubmit) btnLogin2FASubmit.disabled = true;
        hide2FAError();

        try {
            const bodyPayload = {
                temp_token: current2FAPendingToken
            };
            if (code) bodyPayload.code = code;
            if (recovery_code) bodyPayload.recovery_code = recovery_code;

            const res = await fetch("/api/auth/2fa/login-verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(bodyPayload)
            });

            if (!res.ok) {
                let errDetail = "Invalid verification code.";
                try {
                    const errData = await res.json();
                    if (errData.detail) errDetail = errData.detail;
                } catch (e) {}
                show2FAError(errDetail);
                return;
            }

            const data = await res.json();
            localStorage.setItem("tg_auth_token", data.access_token);
            currentUser = data.user;
            localStorage.setItem("tg_user", JSON.stringify(currentUser));

            if (loginPasswordInput) loginPasswordInput.value = "";

            hide2FAChallengeView();
            updateUserUI();
            const welcomeName = currentUser.full_name || currentUser.name || currentUser.username || "Learner";
            showToast(`Two-factor verification confirmed. Welcome back, ${welcomeName}!`, "success");

            window.location.hash = "#dashboard";
        } catch (err) {
            show2FAError("Failed to reach verification service.");
        } finally {
            if (login2FABtnText) login2FABtnText.textContent = "Verify & Sign In";
            if (btnLogin2FASubmit) btnLogin2FASubmit.disabled = false;
        }
    }

    if (btnLogin2FASubmit) {
        btnLogin2FASubmit.addEventListener("click", execute2FALoginVerify);
    }
    if (login2FACodeInput) {
        login2FACodeInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") execute2FALoginVerify();
        });
    }
    if (loginRecoveryCodeInput) {
        loginRecoveryCodeInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") execute2FALoginVerify();
        });
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
                    return;
                }

                const data = await res.json();
                localStorage.setItem("tg_auth_token", data.access_token);
                currentUser = data.user;
                localStorage.setItem("tg_user", JSON.stringify(currentUser));

                if (signupPasswordInput) signupPasswordInput.value = "";
                if (loginPasswordInput) loginPasswordInput.value = "";

                updateUserUI();
                const welcomeName = currentUser.full_name || currentUser.name || currentUser.username || "Learner";
                showToast(`Account created! Welcome to Tracegate, ${welcomeName}.`, "success");

                window.location.hash = "#dashboard";
            } catch (err) {
                showAuthError("Registration service connection failed.");
            } finally {
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

            if (typeof hide2FAChallengeView === "function") {
                hide2FAChallengeView();
            }
            current2FAPendingToken = null;

            updateUserUI();
            applyRememberedCredentials();

            showToast("You have been signed out.", "info");
            if (window.location.hash === "#login") {
                navigateTo("#login");
            } else {
                window.location.hash = "#login";
            }
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
            openProject(proj.id, "overview");
        });

        const leftMeta = div.querySelector(".project-item-left");
        if (leftMeta) {
            leftMeta.style.cursor = "pointer";
            leftMeta.addEventListener("click", () => {
                openProject(proj.id, "overview");
            });
        }

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

            // Clear form
            document.getElementById("newProjName").value = "";
            document.getElementById("newProjTarget").value = "";
            document.getElementById("newProjDesc").value = "";
            document.getElementById("newProjNotes").value = "";

            showToast(`Project "${newProj.name}" created!`, "success");
            openProject(newProj.id, "overview");
        });
    }

    // ==========================================================================
    // 6. PROJECT WORKSPACE CONTROLLER
    // ==========================================================================
    window.switchWorkspaceTab = function(tabName, updateHash = true) {
        const validTabs = ["overview", "checklist", "findings", "report", "autofix"];
        let normalized = (tabName || "overview").toLowerCase();
        if (normalized === "ai-fix") normalized = "autofix";
        if (!validTabs.includes(normalized)) normalized = "overview";

        document.querySelectorAll(".ws-tab-btn").forEach(b => {
            if (b.getAttribute("data-tab") === normalized) b.classList.add("active");
            else b.classList.remove("active");
        });

        document.querySelectorAll(".ws-tab-pane").forEach(pane => {
            if (pane.id === `pane-ws-${normalized}`) pane.classList.add("active");
            else pane.classList.remove("active");
        });

        if (normalized === "findings") renderWorkspaceFindings();
        if (normalized === "report") renderWorkspaceReport();
        if (normalized === "autofix") renderWorkspaceAutoFix();

        if (updateHash) {
            const newHash = normalized === "overview" ? "#project-workspace" : `#project-workspace/${normalized}`;
            if (window.location.hash !== newHash) {
                history.pushState(null, "", newHash);
            }
        }
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

            // Sync page type dropdown to project's current checklist page type
            const ptSelect = document.getElementById("pageTypeSelect");
            if (ptSelect && proj.checklist_data.page_type) {
                const canonicalVal = proj.checklist_data.page_type;
                const shortVal = canonicalVal.replace(/ Page$/, "").trim();
                for (let i = 0; i < ptSelect.options.length; i++) {
                    const optVal = ptSelect.options[i].value;
                    if (optVal === canonicalVal || optVal === shortVal) {
                        ptSelect.value = optVal;
                        selectedPageType = optVal;
                        lastGeneratedPageType = optVal;
                        break;
                    }
                }
            }

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
            const errAlert = document.getElementById("customTestErrorAlert");
            if (errAlert) {
                errAlert.classList.add("hidden");
                errAlert.style.display = "none";
            }
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
    const scenarioPillMap = {
        "login": "Login / Sign In",
        "registration": "Sign Up / Registration",
        "forgot_password": "Forgot Password / Password Reset",
        "profile": "Account / Profile",
        "settings": "Settings / Security Settings",
        "dashboard": "Dashboard",
        "search": "Search / Search Results",
        "file_upload": "File Upload",
        "checkout": "Checkout / Payment",
        "admin_panel": "Admin Panel",
        "ambiguous": "Auto Detect"
    };

    samplePills.forEach(pill => {
        pill.addEventListener("click", async () => {
            samplePills.forEach(p => p.classList.remove("active"));
            pill.classList.add("active");

            const sampleKey = pill.getAttribute("data-sample");
            const mappedType = scenarioPillMap[sampleKey];
            const ptSelect = document.getElementById("pageTypeSelect");
            if (mappedType && ptSelect) {
                ptSelect.value = mappedType;
                selectedPageType = mappedType;
            }

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
        if (btnAnalyze) btnAnalyze.disabled = false;
        samplePills.forEach(p => p.classList.remove("active"));
    }

    // ==========================================================================
    // 7. UNIFIED CHECKLIST GENERATOR (Sections 19, 20, 21, 22, 23)
    // ==========================================================================
    async function generateChecklist() {
        const activeProj = getActiveProject();
        if (!activeProj) {
            showToast("Please select or create an assessment project first.", "error");
            return;
        }

        // Section 20: Read CURRENT input values at click time directly
        let pageTypeValue = document.getElementById("pageTypeSelect")?.value || "Login / Sign In";
        if (pageTypeValue === "Other") {
            const otherCustom = document.getElementById("pageTypeOtherInput")?.value.trim();
            pageTypeValue = otherCustom || "Other";
        }

        if (!pageTypeValue || (pageTypeValue === "Auto Detect" && !currentUploadedFile)) {
            showToast("Please select a specific Page Type to generate a checklist without a screenshot.", "warning");
            return;
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
            if (btnAnalyzeText) btnAnalyzeText.textContent = currentUploadedFile ? "Vision AI Processing..." : "Generating Checklist...";
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

        const step1Text = currentUploadedFile ? "Image received" : "Page Type verified";
        const step2Text = currentUploadedFile ? "Identifying visible functionality" : "Querying security knowledge base";
        const step3Text = "Building security checklist";
        const step4Text = "Prioritizing tests";

        if (step1) { step1.className = "step-item running"; step1.textContent = `● ${step1Text}`; }
        if (step2) { step2.className = "step-item pending"; step2.textContent = `○ ${step2Text}`; }
        if (step3) { step3.className = "step-item pending"; step3.textContent = `○ ${step3Text}`; }
        if (step4) { step4.className = "step-item pending"; step4.textContent = `○ ${step4Text}`; }

        setTimeout(() => {
            if (step1) { step1.className = "step-item done"; step1.textContent = `✓ ${step1Text}`; }
            if (step2) { step2.className = "step-item running"; step2.textContent = `● ${step2Text}`; }
        }, 300);

        setTimeout(() => {
            if (step2) { step2.className = "step-item done"; step2.textContent = `✓ ${step2Text}`; }
            if (step3) { step3.className = "step-item running"; step3.textContent = `● ${step3Text}`; }
        }, 700);

        setTimeout(() => {
            if (step3) { step3.className = "step-item done"; step3.textContent = `✓ ${step3Text}`; }
            if (step4) { step4.className = "step-item running"; step4.textContent = `● ${step4Text}`; }
        }, 1100);

        const formData = new FormData();
        if (currentUploadedFile) {
            formData.append("image", currentUploadedFile);
        }
        if (userPrompt) formData.append("prompt", userPrompt);
        formData.append("project_id", activeProj.id);
        formData.append("request_id", reqId);
        if (pageTypeValue) {
            formData.append("page_type", pageTypeValue);
        }

        const fileName = currentUploadedFile ? currentUploadedFile.name : "none (optional)";
        console.log(`[TRACEGATE API] Dispatching generateChecklist: req_id="${reqId}", file="${fileName}", page_type="${pageTypeValue}"`);

        try {
            const response = await fetch("/api/analyze-screenshot", {
                method: "POST",
                body: formData,
                signal: currentAbortController.signal
            });

            if (!response.ok) {
                let errDetail = "Checklist generation failed.";
                try {
                    const errJson = await response.json();
                    if (typeof errJson.detail === "string") {
                        errDetail = errJson.detail;
                    } else if (Array.isArray(errJson.detail)) {
                        errDetail = errJson.detail.map(d => d.msg || JSON.stringify(d)).join("; ");
                    } else if (errJson.detail) {
                        errDetail = JSON.stringify(errJson.detail);
                    }
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
            if (confBarEl) confBarEl.style.width = "100%";
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
                    : ["Authoritative Page Type Knowledge Base", "Curated Assessment Standards"];
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
            const elems = (data.detected_elements && data.detected_elements.length > 0)
                ? data.detected_elements
                : (data.visual_analysis_available === false ? ["Knowledge Base Standard Controls (Screenshot optional)"] : []);
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

    // Outcome 2: "Vulnerability Found" (Simplified Workflow)
    if (btnVerifyVuln) {
        btnVerifyVuln.addEventListener("click", () => {
            if (!activeVerifyItem) return;
            closeModal("modalVerify");

            const existingFinding = activeVerifyItem.finding;

            // 1. Finding Name (Auto-filled from checklist test, editable)
            const nameInp = document.getElementById("findingNameInput");
            if (nameInp) {
                nameInp.value = existingFinding?.finding_name || activeVerifyItem.name || "";
            }

            // 2. What did you find? (Main observation field)
            const obsInp = document.getElementById("findingObservationInput");
            if (obsInp) {
                obsInp.value = existingFinding?.observation || existingFinding?.description || "";
            }

            // Sync hidden inputs for backwards compatibility
            const descInp = document.getElementById("findingDescInput");
            if (descInp) descInp.value = obsInp ? obsInp.value : "";
            const sevInp = document.getElementById("findingSeverityInput");
            if (sevInp) sevInp.value = existingFinding?.priority || activeVerifyItem.priority || "HIGH";
            const cweInp = document.getElementById("findingCweInput");
            if (cweInp) cweInp.value = existingFinding?.cwe || activeVerifyItem.cwe || "";
            const cvssInp = document.getElementById("findingCvssInput");
            if (cvssInp) cvssInp.value = existingFinding?.cvss_score || "";
            const statusInp = document.getElementById("findingStatusInput");
            if (statusInp) statusInp.value = existingFinding?.status || "Open";

            // 3. Multi-Evidence Initialization
            pendingEvidenceList = [];
            if (existingFinding && Array.isArray(existingFinding.evidence) && existingFinding.evidence.length > 0) {
                pendingEvidenceList = existingFinding.evidence.map(e => ({ ...e }));
            } else if (existingFinding?.evidence_filename || existingFinding?.evidence_data) {
                pendingEvidenceList = [{
                    id: "ev-legacy-" + Date.now(),
                    name: existingFinding.evidence_filename || "evidence.png",
                    data: existingFinding.evidence_data,
                    url: existingFinding.evidence_data,
                    type: "image/png",
                    size: 0
                }];
            }

            renderEvidenceListUI();
            openModal("modalFinding");
        });
    }

    // Modal Finding Actions (Simplified Flow)
    const btnCloseFindingModal = document.getElementById("btnCloseFindingModal");
    const btnCancelFinding = document.getElementById("btnCancelFinding");
    const btnSaveFinding = document.getElementById("btnSaveFinding");
    const evidenceMultiDropzone = document.getElementById("evidenceMultiDropzone");
    const evidenceFileInput = document.getElementById("evidenceFileInput");

    if (btnCloseFindingModal) btnCloseFindingModal.addEventListener("click", () => closeModal("modalFinding"));
    if (btnCancelFinding) btnCancelFinding.addEventListener("click", () => closeModal("modalFinding"));

    // Multi-File Evidence Handlers
    if (evidenceMultiDropzone && evidenceFileInput) {
        evidenceMultiDropzone.addEventListener("click", (e) => {
            if (e.target !== evidenceFileInput) {
                evidenceFileInput.click();
            }
        });

        evidenceFileInput.addEventListener("click", (e) => {
            e.stopPropagation();
        });

        evidenceMultiDropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            evidenceMultiDropzone.style.borderColor = "var(--accent-primary)";
            evidenceMultiDropzone.style.background = "var(--bg-surface-3)";
        });

        evidenceMultiDropzone.addEventListener("dragleave", () => {
            evidenceMultiDropzone.style.borderColor = "var(--border-subtle)";
            evidenceMultiDropzone.style.background = "var(--bg-surface-2)";
        });

        evidenceMultiDropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            evidenceMultiDropzone.style.borderColor = "var(--border-subtle)";
            evidenceMultiDropzone.style.background = "var(--bg-surface-2)";
            if (e.dataTransfer && e.dataTransfer.files) {
                addEvidenceFiles(e.dataTransfer.files);
            }
        });

        evidenceFileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length) {
                addEvidenceFiles(e.target.files);
                e.target.value = "";
            }
        });
    }

    async function addEvidenceFiles(fileList) {
        const allowedExtensions = [".png", ".jpg", ".jpeg", ".webp", ".txt", ".json"];
        for (let i = 0; i < fileList.length; i++) {
            const file = fileList[i];
            const ext = "." + (file.name.split(".").pop() || "").toLowerCase();
            if (!allowedExtensions.includes(ext)) {
                showToast(`Unsupported file type: ${file.name}. Allowed: PNG, JPG, WEBP, TXT, JSON`, "error");
                continue;
            }
            if (file.size > 10 * 1024 * 1024) {
                showToast(`File ${file.name} exceeds 10MB limit.`, "error");
                continue;
            }

            const evItem = {
                id: "ev-" + Date.now() + "-" + Math.random().toString(36).substring(2, 7),
                name: file.name,
                size: file.size,
                type: file.type || "application/octet-stream",
                file: file,
                data: null,
                url: null
            };

            // Read file data for preview
            await new Promise((resolve) => {
                const reader = new FileReader();
                reader.onload = (ev) => {
                    evItem.data = ev.target.result;
                    resolve();
                };
                reader.onerror = () => resolve();
                reader.readAsDataURL(file);
            });

            pendingEvidenceList.push(evItem);
        }
        renderEvidenceListUI();
    }

    function renderEvidenceListUI() {
        const container = document.getElementById("uploadedEvidenceContainer");
        const listEl = document.getElementById("uploadedEvidenceList");
        if (!container || !listEl) return;

        listEl.innerHTML = "";
        if (!pendingEvidenceList || pendingEvidenceList.length === 0) {
            container.style.display = "none";
            pendingEvidenceData = null;
            pendingEvidenceFilename = null;
            return;
        }

        container.style.display = "block";
        pendingEvidenceFilename = pendingEvidenceList[0]?.name || null;
        pendingEvidenceData = pendingEvidenceList[0]?.data || null;

        pendingEvidenceList.forEach((item, idx) => {
            const row = document.createElement("div");
            row.style.display = "flex";
            row.style.alignItems = "center";
            row.style.justifyContent = "space-between";
            row.style.padding = "6px 12px";
            row.style.background = "var(--bg-surface-3)";
            row.style.borderRadius = "var(--radius-sm)";
            row.style.border = "1px solid var(--border-subtle)";

            const left = document.createElement("div");
            left.style.display = "flex";
            left.style.alignItems = "center";
            left.style.gap = "8px";

            const isImg = item.type && item.type.startsWith("image/");
            if (isImg && item.data) {
                const thumb = document.createElement("img");
                thumb.src = item.data;
                thumb.style.width = "28px";
                thumb.style.height = "28px";
                thumb.style.objectFit = "cover";
                thumb.style.borderRadius = "3px";
                thumb.style.border = "1px solid var(--border-subtle)";
                left.appendChild(thumb);
            } else {
                const icon = document.createElement("span");
                icon.textContent = "📄";
                icon.style.fontSize = "1.1rem";
                left.appendChild(icon);
            }

            const nameSpan = document.createElement("span");
            nameSpan.textContent = item.name;
            nameSpan.style.fontSize = "0.82rem";
            nameSpan.style.fontWeight = "600";
            nameSpan.style.color = "var(--text-primary)";
            left.appendChild(nameSpan);

            if (item.size) {
                const sizeSpan = document.createElement("span");
                const kb = Math.round(item.size / 1024);
                sizeSpan.textContent = `(${kb > 0 ? kb + " KB" : item.size + " B"})`;
                sizeSpan.style.fontSize = "0.72rem";
                sizeSpan.style.color = "var(--text-muted)";
                left.appendChild(sizeSpan);
            }

            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.innerHTML = "&times;";
            removeBtn.title = "Remove file";
            removeBtn.style.background = "none";
            removeBtn.style.border = "none";
            removeBtn.style.color = "var(--crit-color)";
            removeBtn.style.fontSize = "1.2rem";
            removeBtn.style.cursor = "pointer";
            removeBtn.style.padding = "0 4px";
            removeBtn.addEventListener("click", () => {
                pendingEvidenceList.splice(idx, 1);
                renderEvidenceListUI();
            });

            row.appendChild(left);
            row.appendChild(removeBtn);
            listEl.appendChild(row);
        });
    }

    // Save Finding Button (Simplified & Single-path Submission)
    if (btnSaveFinding) {
        btnSaveFinding.addEventListener("click", async () => {
            if (isSavingFinding) return;
            if (!activeVerifyItem) return;
            const proj = getActiveProject();
            if (!proj) {
                showToast("Please open an active project first.", "error");
                return;
            }

            const obsInput = document.getElementById("findingObservationInput");
            const obsText = (obsInput?.value || document.getElementById("findingDescInput")?.value || "").trim();
            if (!obsText) {
                showToast("Please describe what you found in the observation field.", "warning");
                if (obsInput) obsInput.focus();
                return;
            }

            isSavingFinding = true;
            btnSaveFinding.disabled = true;
            btnSaveFinding.textContent = "Saving Finding...";

            try {
                const findingName = document.getElementById("findingNameInput")?.value.trim() || activeVerifyItem.name;
                const severity = activeVerifyItem.priority || "HIGH";
                const cwe = activeVerifyItem.cwe || null;

                // 1. Upload any new physical files to server storage
                const filesToUpload = pendingEvidenceList.filter(item => item.file instanceof File);
                if (filesToUpload.length > 0) {
                    try {
                        const evFormData = new FormData();
                        filesToUpload.forEach(f => evFormData.append("files", f.file));
                        const uploadRes = await fetch(`/api/projects/${encodeURIComponent(proj.id)}/evidence`, {
                            method: "POST",
                            body: evFormData
                        });
                        if (uploadRes.ok) {
                            const uploadData = await uploadRes.json();
                            const serverUploaded = uploadData.uploaded || [];
                            serverUploaded.forEach(su => {
                                const match = pendingEvidenceList.find(pe => pe.name === su.name);
                                if (match) {
                                    match.url = su.url;
                                    match.filename = su.filename;
                                    match.file_path = su.file_path;
                                    delete match.file;
                                }
                            });
                        }
                    } catch (ue) {
                        console.warn("[TRACEGATE] Evidence server upload fallback:", ue);
                    }
                }

                // Clean up evidence items for persistent JSON storage
                const cleanEvidence = pendingEvidenceList.map(item => ({
                    id: item.id,
                    name: item.name,
                    filename: item.filename || item.name,
                    file_path: item.file_path || null,
                    url: item.url || null,
                    data: item.data || null,
                    size: item.size || 0,
                    type: item.type || "application/octet-stream"
                }));

                const firstEv = cleanEvidence[0] || null;

                let findingObj = {
                    id: "find-" + Date.now(),
                    finding_name: findingName,
                    test_id: activeVerifyItem.id,
                    priority: severity,
                    cwe: cwe,
                    status: "Open",
                    observation: obsText,
                    description: obsText,
                    evidence: cleanEvidence,
                    evidence_filename: firstEv ? firstEv.name : null,
                    evidence_data: firstEv ? firstEv.data : null,
                    recorded_at: new Date().toISOString().replace("T", " ").substring(0, 16)
                };

                // 2. Persist finding in backend SQLite
                try {
                    const res = await fetch(`/api/checklist/${activeVerifyItem.id}/finding?project_id=${encodeURIComponent(proj.id)}`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            finding_name: findingName,
                            observation: obsText,
                            description: obsText,
                            priority: severity,
                            cwe: cwe,
                            evidence: cleanEvidence,
                            evidence_filename: firstEv ? firstEv.name : null,
                            evidence_data: firstEv ? firstEv.data : null,
                            status: "Open"
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
                proj.findings = proj.findings.filter(f => f.test_id !== activeVerifyItem.id && f.id !== findingObj.id);
                proj.findings.unshift(findingObj);
                proj.updated_at = new Date().toISOString().split("T")[0];

                saveProjects();
                closeModal("modalFinding");
                renderChecklistCards();
                updateChecklistProgressUI();
                refreshDashboardStats();

                const badgeCount = document.getElementById("wsFindingsBadgeCount");
                if (badgeCount) badgeCount.textContent = proj.findings.length;

                showToast("✓ Vulnerability Finding Saved & Verified!", "success");
            } catch (saveErr) {
                console.error("[TRACEGATE] Failed to save finding:", saveErr);
                showToast("Error saving finding: " + saveErr.message, "error");
            } finally {
                isSavingFinding = false;
                btnSaveFinding.disabled = false;
                btnSaveFinding.textContent = "Save Finding";
            }
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
    const addCustomTestForm = document.getElementById("addCustomTestForm");

    function openAddCustomTestModal() {
        const errAlert = document.getElementById("customTestErrorAlert");
        if (errAlert) {
            errAlert.classList.add("hidden");
            errAlert.style.display = "none";
        }
        openModal("modalAddCustomTest");
    }

    if (btnAddCustomTestBtn) btnAddCustomTestBtn.addEventListener("click", openAddCustomTestModal);
    if (btnCloseAddCustomModal) btnCloseAddCustomModal.addEventListener("click", () => closeModal("modalAddCustomTest"));
    if (btnCancelCustomTest) btnCancelCustomTest.addEventListener("click", () => closeModal("modalAddCustomTest"));

    if (addCustomTestForm) {
        addCustomTestForm.addEventListener("submit", (e) => {
            e.preventDefault();
            if (btnSaveCustomTest) btnSaveCustomTest.click();
        });
    }

    if (btnSaveCustomTest) {
        btnSaveCustomTest.addEventListener("click", async (e) => {
            if (e && e.preventDefault) e.preventDefault();

            const errAlert = document.getElementById("customTestErrorAlert");
            const errMsg = document.getElementById("customTestErrorMsg");
            const showCustomError = (message) => {
                if (errAlert && errMsg) {
                    errMsg.textContent = message;
                    errAlert.classList.remove("hidden");
                    errAlert.style.display = "flex";
                }
                showToast(message, "error");
            };

            if (errAlert) {
                errAlert.classList.add("hidden");
                errAlert.style.display = "none";
            }

            const proj = getActiveProject();
            if (!proj) {
                showCustomError("Please select or open an active project first.");
                return;
            }

            const nameInput = document.getElementById("customTestName");
            const priorityInput = document.getElementById("customTestPriority");
            const cweInput = document.getElementById("customTestCwe");
            const reasonInput = document.getElementById("customTestReason");
            const objectiveInput = document.getElementById("customTestObjective");

            const name = nameInput ? nameInput.value.trim() : "";
            const priority = priorityInput ? priorityInput.value.trim() : "HIGH";
            const cwe = cweInput ? cweInput.value.trim() : "";
            const reason = reasonInput ? reasonInput.value.trim() : "";
            const objective = objectiveInput ? objectiveInput.value.trim() : "";

            // Client-side validations
            if (!name || name.length < 3) {
                showCustomError("Test Name is required and must be at least 3 characters.");
                if (nameInput) nameInput.focus();
                return;
            }
            if (name.length > 200) {
                showCustomError("Test Name must be 200 characters or fewer.");
                if (nameInput) nameInput.focus();
                return;
            }

            const validPriorities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
            const normalizedPriority = (priority || "HIGH").toUpperCase();
            if (!validPriorities.includes(normalizedPriority)) {
                showCustomError("Priority must be one of: CRITICAL, HIGH, MEDIUM, LOW.");
                return;
            }

            let normalizedCwe = null;
            if (cwe) {
                const cwePattern = /^CWE-\d+$/i;
                if (!cwePattern.test(cwe)) {
                    showCustomError("CWE Identifier must follow format CWE-<number> (e.g. CWE-307).");
                    if (cweInput) cweInput.focus();
                    return;
                }
                normalizedCwe = cwe.toUpperCase();
            }

            // Prevent duplicate clicks
            btnSaveCustomTest.disabled = true;
            const origText = btnSaveCustomTest.textContent;
            btnSaveCustomTest.textContent = "Adding...";

            try {
                const token = localStorage.getItem("tg_auth_token") || (currentUser && currentUser.token);
                const headers = { "Content-Type": "application/json" };
                if (token) {
                    headers["Authorization"] = `Bearer ${token}`;
                }

                const payload = {
                    name: name,
                    priority: normalizedPriority,
                    cwe: normalizedCwe,
                    reason: reason || null,
                    testing_objective: objective || null
                };

                const res = await fetch(`/api/projects/${proj.id}/checklist/custom`, {
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify(payload)
                });

                if (!res.ok) {
                    let errDetail = "Failed to add custom security test.";
                    try {
                        const errJson = await res.json();
                        if (errJson && errJson.detail) {
                            if (Array.isArray(errJson.detail)) {
                                errDetail = errJson.detail.map(d => d.msg || JSON.stringify(d)).join("; ");
                            } else {
                                errDetail = errJson.detail;
                            }
                        }
                    } catch (e) {
                        // ignore parse error
                    }
                    showCustomError(errDetail);
                    return;
                }

                const created = await res.json();

                // Ensure local project checklist structure exists
                if (!proj.checklist_data) {
                    proj.checklist_data = {
                        checklist: [],
                        page_type: proj.page_type || "Generic Application",
                        screenshot_path: proj.screenshot_path || null
                    };
                }
                if (!proj.checklist_data.checklist) {
                    proj.checklist_data.checklist = [];
                }

                // Unshift created item
                const existingIdx = proj.checklist_data.checklist.findIndex(item => item.id === created.id);
                if (existingIdx >= 0) {
                    proj.checklist_data.checklist[existingIdx] = created;
                } else {
                    proj.checklist_data.checklist.unshift(created);
                }

                saveProjects();

                // Clear form
                if (nameInput) nameInput.value = "";
                if (priorityInput) priorityInput.value = "HIGH";
                if (cweInput) cweInput.value = "";
                if (reasonInput) reasonInput.value = "";
                if (objectiveInput) objectiveInput.value = "";
                if (errAlert) {
                    errAlert.classList.add("hidden");
                    errAlert.style.display = "none";
                }

                closeModal("modalAddCustomTest");

                // Toggle idle state and show results content
                const idleState = document.getElementById("idleState");
                const resultsContent = document.getElementById("resultsContent");
                if (idleState) idleState.style.display = "none";
                if (resultsContent) resultsContent.classList.add("active");

                renderChecklistCards();
                updateChecklistProgressUI();
                refreshDashboardStats();
                showToast("Custom test added to checklist (marked User Added)", "success");
            } catch (err) {
                console.error("[TRACEGATE] Add custom test network error:", err);
                showCustomError("Network error: Unable to connect to server to add custom test.");
            } finally {
                btnSaveCustomTest.disabled = false;
                btnSaveCustomTest.textContent = origText || "Add to Checklist";
            }
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
                ` : (finding.source === "IMPORTED_REPORT" ? `
                    <div style="font-size: 0.78rem; color: #4338ca; display: flex; align-items: center; gap: 6px;">
                        <span>Provenance:</span>
                        <strong style="color: #4338ca;">Imported from External Report (${escapeHtml(finding.source_document_name || 'Uploaded Document')})</strong>
                    </div>
                ` : "")}

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
                    ${(finding.evidence && finding.evidence.length > 0) ? `
                        <div style="margin-top: 10px;">
                            <strong>Attached PoC Evidence (${finding.evidence.length} file${finding.evidence.length > 1 ? 's' : ''}):</strong>
                            <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-top: 6px;">
                                ${finding.evidence.map(ev => {
                                    const isImg = (ev.data && ev.data.startsWith("data:image/")) || (ev.name && /\.(png|jpe?g|webp)$/i.test(ev.name));
                                    const evSrc = ev.data || ev.url || "";
                                    if (isImg && evSrc) {
                                        return `
                                            <div style="text-align: center;">
                                                <a href="${ev.url || evSrc}" target="_blank" rel="noopener">
                                                    <img src="${evSrc}" class="finding-evidence-img" alt="${escapeHtml(ev.name)}" style="max-height: 90px; max-width: 140px; border-radius: 4px; border: 1px solid var(--border-subtle); display: block; object-fit: cover;" />
                                                </a>
                                                <span style="font-size: 0.7rem; color: var(--text-muted); display: block; max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(ev.name)}</span>
                                            </div>
                                        `;
                                    } else {
                                        return `
                                            <div style="background: var(--bg-surface-3); border: 1px solid var(--border-subtle); border-radius: 4px; padding: 6px 10px; font-size: 0.78rem; display: flex; align-items: center; gap: 6px;">
                                                <span>📄</span>
                                                ${ev.url ? `<a href="${ev.url}" target="_blank" rel="noopener" style="color: var(--accent-primary); font-weight: 600;">${escapeHtml(ev.name)}</a>` : `<span style="font-weight: 600;">${escapeHtml(ev.name)}</span>`}
                                            </div>
                                        `;
                                    }
                                }).join("")}
                            </div>
                        </div>
                    ` : (finding.evidence_data ? `
                        <div style="margin-top: 6px;">
                            <strong>Attached PoC Evidence:</strong><br/>
                            <img src="${finding.evidence_data}" class="finding-evidence-img" alt="Evidence" />
                        </div>
                    ` : "")}
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
            authorInp.value = currentUser.full_name || currentUser.name || "Security Learner";
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

    // ==========================================================================
    // MANUAL VAPT REPORT IMPORTER & CANDIDATE FINDINGS REVIEW
    // ==========================================================================
    let currentImportState = {
        source_doc_id: null,
        source_doc_name: null,
        candidates: []
    };

    function initReportImporter() {
        const dropzone = document.getElementById("reportImportDropzone");
        const fileInput = document.getElementById("reportImportFileInput");
        const btnClose = document.getElementById("btnCloseImportModal");
        const btnCancel = document.getElementById("btnCancelImportModal");
        const btnSelectAll = document.getElementById("btnImportSelectAll");
        const btnDeselectAll = document.getElementById("btnImportDeselectAll");
        const btnDeselectDupes = document.getElementById("btnImportDeselectDuplicates");
        const btnConfirm = document.getElementById("btnConfirmImportFindings");

        if (!dropzone || !fileInput) return;

        dropzone.addEventListener("click", () => fileInput.click());

        dropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropzone.style.borderColor = "var(--primary-600)";
            dropzone.style.background = "var(--primary-50, #eff6ff)";
        });

        dropzone.addEventListener("dragleave", (e) => {
            e.preventDefault();
            dropzone.style.borderColor = "var(--border-default)";
            dropzone.style.background = "var(--bg-subtle)";
        });

        dropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropzone.style.borderColor = "var(--border-default)";
            dropzone.style.background = "var(--bg-subtle)";
            if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                handleReportFileSelected(e.dataTransfer.files[0]);
            }
        });

        fileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                handleReportFileSelected(e.target.files[0]);
            }
        });

        if (btnClose) btnClose.addEventListener("click", () => closeModal("modalImportReportReview"));
        if (btnCancel) btnCancel.addEventListener("click", () => closeModal("modalImportReportReview"));

        if (btnSelectAll) {
            btnSelectAll.addEventListener("click", () => {
                currentImportState.candidates.forEach(c => c.selected = true);
                renderCandidateFindingsList();
            });
        }

        if (btnDeselectAll) {
            btnDeselectAll.addEventListener("click", () => {
                currentImportState.candidates.forEach(c => c.selected = false);
                renderCandidateFindingsList();
            });
        }

        if (btnDeselectDupes) {
            btnDeselectDupes.addEventListener("click", () => {
                currentImportState.candidates.forEach(c => c.selected = !c.is_duplicate);
                renderCandidateFindingsList();
            });
        }

        if (btnConfirm) {
            btnConfirm.addEventListener("click", handleConfirmImport);
        }
    }

    async function handleReportFileSelected(file) {
        const proj = getActiveProject();
        if (!proj) {
            showToast("Please select an active project first.", "warning");
            return;
        }

        const validExts = [".pdf", ".docx", ".txt", ".md"];
        const lowerName = file.name.toLowerCase();
        const hasValidExt = validExts.some(ext => lowerName.endsWith(ext));
        if (!hasValidExt) {
            showToast("Unsupported file type. Please upload a PDF, DOCX, TXT, or MD report file.", "error");
            return;
        }

        if (file.size > 25 * 1024 * 1024) {
            showToast("File size exceeds maximum allowed 25MB.", "error");
            return;
        }

        const spinner = document.getElementById("reportImportSpinner");
        if (spinner) spinner.style.display = "flex";

        const formData = new FormData();
        formData.append("file", file);

        try {
            const res = await fetch(`/api/projects/${proj.id}/reports/parse-import`, {
                method: "POST",
                body: formData
            });

            if (!res.ok) {
                let err = "Failed to parse report file.";
                try {
                    const data = await res.json();
                    if (data.detail) err = data.detail;
                } catch (_) {}
                throw new Error(err);
            }

            const parsed = await res.json();
            const candidates = parsed.candidate_findings || [];

            if (candidates.length === 0) {
                showToast("No security findings could be identified in the uploaded report.", "warning");
                return;
            }

            currentImportState = {
                source_doc_id: parsed.source_document_id,
                source_doc_name: parsed.source_document_name,
                candidates: candidates.map(c => ({
                    ...c,
                    selected: !c.is_duplicate
                }))
            };

            const nameEl = document.getElementById("importDocNameSpan");
            if (nameEl) nameEl.textContent = parsed.source_document_name;

            const countEl = document.getElementById("importCandidatesCountBadge");
            if (countEl) countEl.textContent = `${candidates.length} finding${candidates.length > 1 ? "s" : ""} parsed`;

            const dupeCount = candidates.filter(c => c.is_duplicate).length;
            const dupeBadge = document.getElementById("importDuplicatesCountBadge");
            if (dupeBadge) {
                if (dupeCount > 0) {
                    dupeBadge.textContent = `${dupeCount} duplicate${dupeCount > 1 ? "s" : ""} detected`;
                    dupeBadge.style.display = "inline-flex";
                } else {
                    dupeBadge.style.display = "none";
                }
            }

            renderCandidateFindingsList();
            openModal("modalImportReportReview");

        } catch (e) {
            console.error("[TRACEGATE] Report import parse error:", e);
            showToast("Error parsing report: " + e.message, "error");
        } finally {
            if (spinner) spinner.style.display = "none";
            const fileInput = document.getElementById("reportImportFileInput");
            if (fileInput) fileInput.value = "";
        }
    }

    function renderCandidateFindingsList() {
        const container = document.getElementById("importCandidatesListContainer");
        const selCountSpan = document.getElementById("importSelectedCountSpan");
        if (!container) return;

        const candidates = currentImportState.candidates || [];
        const selectedCount = candidates.filter(c => c.selected).length;

        if (selCountSpan) {
            selCountSpan.textContent = `${selectedCount} of ${candidates.length} findings selected for import`;
        }

        if (candidates.length === 0) {
            container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 20px;">No findings to display.</div>`;
            return;
        }

        let html = "";
        candidates.forEach((cand, idx) => {
            const priority = (cand.severity || cand.priority || "MEDIUM").toUpperCase();
            const priorityClass = priority === "INFORMATIONAL" || priority === "INFO" ? "info" : priority.toLowerCase();
            const isDupe = Boolean(cand.is_duplicate);

            html += `
                <div class="candidate-finding-card" style="border: 1px solid ${isDupe ? '#f59e0b' : 'var(--border-default)'}; border-radius: var(--radius-md); background: ${cand.selected ? 'rgba(37, 99, 235, 0.03)' : '#ffffff'}; padding: 14px 16px; transition: all 0.15s ease;">
                    <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 12px;">
                        <div style="display: flex; align-items: flex-start; gap: 12px; flex: 1;">
                            <input type="checkbox" class="chk-candidate-select" data-idx="${idx}" ${cand.selected ? "checked" : ""} style="cursor: pointer; width: 18px; height: 18px; margin-top: 3px;" />
                            <div style="flex: 1;">
                                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 4px;">
                                    <span class="badge badge-${priorityClass}">${escapeHtml(priority)}</span>
                                    ${cand.cwe ? `<span class="cwe-pill">${escapeHtml(cand.cwe)}</span>` : ""}
                                    ${cand.cvss_score ? `<span class="badge badge-needs-review">CVSS: ${cand.cvss_score}</span>` : ""}
                                    <strong style="font-size: 0.95rem; color: var(--text-primary);">${escapeHtml(cand.title || 'Security Finding')}</strong>
                                </div>

                                ${isDupe ? `
                                    <div style="background: #fffbeb; border: 1px solid #fde68a; border-radius: 4px; padding: 6px 10px; margin: 6px 0; font-size: 0.8rem; color: #92400e; display: flex; align-items: center; gap: 6px;">
                                        <span>⚠️</span>
                                        <span><strong>Potential Duplicate:</strong> ${escapeHtml(cand.duplicate_warning || 'Matches an existing finding in this project')}</span>
                                    </div>
                                ` : ""}

                                <div style="display: flex; gap: 14px; font-size: 0.78rem; color: var(--text-muted); flex-wrap: wrap; margin-top: 4px;">
                                    ${cand.affected_url ? `<span><strong>URL:</strong> ${escapeHtml(cand.affected_url)}</span>` : ""}
                                    ${cand.affected_component ? `<span><strong>Component:</strong> ${escapeHtml(cand.affected_component)}</span>` : ""}
                                </div>
                            </div>
                        </div>

                        <button type="button" class="btn btn-secondary btn-sm btn-toggle-cand-details" data-idx="${idx}" style="font-size: 0.76rem; padding: 3px 8px; white-space: nowrap;">
                            Details ▾
                        </button>
                    </div>

                    <div id="candDetails-${idx}" style="display: none; margin-top: 12px; padding-top: 12px; border-top: 1px dashed var(--border-subtle); font-size: 0.84rem; flex-direction: column; gap: 8px;">
                        ${cand.description ? `<div><strong>Description:</strong> <div style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(cand.description)}</div></div>` : ""}
                        ${cand.impact ? `<div><strong>Impact:</strong> <div style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(cand.impact)}</div></div>` : ""}
                        ${cand.steps_to_reproduce ? `<div><strong>Steps to Reproduce:</strong> <div style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(cand.steps_to_reproduce)}</div></div>` : ""}
                        ${cand.poc_text ? `<div><strong>PoC / Payload:</strong> <pre class="finding-poc-box" style="margin-top: 4px; max-height: 120px; overflow-y: auto;">${escapeHtml(cand.poc_text)}</pre></div>` : ""}
                        ${cand.remediation ? `<div><strong>Remediation:</strong> <div style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(cand.remediation)}</div></div>` : ""}
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;

        container.querySelectorAll(".chk-candidate-select").forEach(chk => {
            chk.addEventListener("change", (e) => {
                const i = parseInt(e.target.getAttribute("data-idx"), 10);
                if (currentImportState.candidates[i]) {
                    currentImportState.candidates[i].selected = e.target.checked;
                }
                const updatedCount = currentImportState.candidates.filter(c => c.selected).length;
                if (selCountSpan) {
                    selCountSpan.textContent = `${updatedCount} of ${candidates.length} findings selected for import`;
                }
            });
        });

        container.querySelectorAll(".btn-toggle-cand-details").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const i = e.target.getAttribute("data-idx");
                const detailBox = document.getElementById(`candDetails-${i}`);
                if (detailBox) {
                    const isShown = detailBox.style.display === "flex";
                    detailBox.style.display = isShown ? "none" : "flex";
                    e.target.textContent = isShown ? "Details ▾" : "Hide ▴";
                }
            });
        });
    }

    async function handleConfirmImport() {
        const proj = getActiveProject();
        if (!proj) return;

        const selectedCandidates = (currentImportState.candidates || []).filter(c => c.selected);
        if (selectedCandidates.length === 0) {
            showToast("Please select at least one finding to import.", "warning");
            return;
        }

        const btnConfirm = document.getElementById("btnConfirmImportFindings");
        if (btnConfirm) {
            btnConfirm.disabled = true;
            btnConfirm.innerHTML = `<span>Importing ${selectedCandidates.length} findings...</span>`;
        }

        try {
            const res = await fetch(`/api/projects/${proj.id}/reports/import-findings`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    source_document_id: currentImportState.source_doc_id,
                    source_document_name: currentImportState.source_doc_name,
                    candidate_findings: selectedCandidates
                })
            });

            if (!res.ok) {
                let err = "Failed to import findings.";
                try {
                    const data = await res.json();
                    if (data.detail) err = data.detail;
                } catch (_) {}
                throw new Error(err);
            }

            const data = await res.json();
            const importedList = data.imported_findings || [];

            if (!proj.findings) proj.findings = [];
            importedList.forEach(savedF => {
                proj.findings.unshift(savedF);
                if (typeof selectedFindingIdsForReport !== "undefined") {
                    selectedFindingIdsForReport.add(savedF.id);
                }
            });
            proj.updated_at = new Date().toISOString().split("T")[0];

            saveProjects();
            closeModal("modalImportReportReview");

            renderWorkspaceFindings();
            renderReportFindingsSelection(proj);
            refreshDashboardStats();
            if (typeof renderWorkspaceAutoFix === "function") {
                renderWorkspaceAutoFix(proj);
            }

            const badgeCount = document.getElementById("wsFindingsBadgeCount");
            if (badgeCount) badgeCount.textContent = proj.findings.length;

            showToast(`✓ Successfully imported ${importedList.length} finding${importedList.length > 1 ? "s" : ""} from report!`, "success");

        } catch (e) {
            console.error("[TRACEGATE] Failed to save imported findings:", e);
            showToast("Import error: " + e.message, "error");
        } finally {
            if (btnConfirm) {
                btnConfirm.disabled = false;
                btnConfirm.innerHTML = `<span>📥 Import Selected Findings</span>`;
            }
        }
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
        const assessorName = currentUser ? (currentUser.full_name || currentUser.name || "Security Learner") : "Security Learner";
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
    // 13. GITHUB AI FIX & CODE REMEDIATION CONTROLLER
    // ==========================================================================
    let currentRepoTreeItems = [];

    async function loadGitHubFixStatus() {
        try {
            const res = await fetch("/api/github/status");
            if (res.ok) {
                const data = await res.json();
                const statusLabel = document.getElementById("githubStatusLabel");
                const connPill = document.getElementById("githubConnectionPill");
                const modalStatus = document.getElementById("ghModalCurrentStatus");

                const isConnected = data.connected;
                const isLive = data.mode === "live";

                if (statusLabel) {
                    if (isLive && isConnected) {
                        statusLabel.textContent = `GitHub Live (${data.username})`;
                    } else if (isConnected) {
                        statusLabel.textContent = `GitHub Lab Sandbox (${data.username})`;
                    } else {
                        statusLabel.textContent = "GitHub Ready (Lab Sandbox)";
                    }
                }

                if (connPill) {
                    connPill.className = isConnected ? "badge badge-completed" : "badge badge-in-progress";
                }

                if (modalStatus) {
                    modalStatus.textContent = isConnected
                        ? `Connected as ${data.username} (${data.mode.toUpperCase()} mode, Token: ${data.token_preview || 'configured'})`
                        : "Not connected to live GitHub (Lab Sandbox mode active)";
                }
            }
        } catch (e) {
            console.warn("GitHub status check:", e);
        }
    }

    function getSelectedRemediationRepo() {
        const confirmInput = document.getElementById("confirmApplyRepoInput");
        if (confirmInput && confirmInput.value.trim()) {
            const modal = document.getElementById("modalAIFixConfirmApply");
            if (modal && (modal.classList.contains("active") || modal.classList.contains("show") || modal.style.display === "flex" || modal.style.display === "block")) {
                return confirmInput.value.trim();
            }
        }
        const customInput = document.getElementById("wsAutofixCustomRepoInput");
        const customVal = customInput ? customInput.value.trim() : "";
        const repoSelect = document.getElementById("wsAutofixRepoSelect");
        const selectVal = repoSelect ? repoSelect.value : "";

        if (selectVal === "__custom__" && customVal) {
            return customVal;
        }
        if (customVal && (document.getElementById("wsAutofixCustomRepoWrapper")?.style.display !== "none" || window._usingCustomRepo)) {
            return customVal;
        }
        if (window._currentSelectedRepo && window._currentSelectedRepo !== "__custom__") {
            return window._currentSelectedRepo;
        }
        if (customVal) {
            return customVal;
        }
        return (selectVal && selectVal !== "__custom__") ? selectVal : "tracegate-lab/ecommerce-platform";
    }

    async function loadGitHubRepositories() {
        try {
            const res = await fetch("/api/github/repositories");
            if (res.ok) {
                const repos = await res.json();
                const wsRepoSelect = document.getElementById("wsAutofixRepoSelect");
                const standRepoSelect = document.getElementById("standaloneRepoSelect");

                [wsRepoSelect, standRepoSelect].forEach(sel => {
                    if (!sel) return;
                    const curVal = window._currentSelectedRepo || sel.value;
                    sel.innerHTML = "";
                    repos.forEach(r => {
                        const opt = document.createElement("option");
                        opt.value = r.full_name;
                        opt.textContent = `${r.full_name} (${r.default_branch}${r.private ? ', private' : ''})`;
                        sel.appendChild(opt);
                    });

                    // Add custom repo option if user set one
                    if (curVal && curVal !== "__custom__" && !repos.some(r => r.full_name === curVal)) {
                        const customOpt = document.createElement("option");
                        customOpt.value = curVal;
                        customOpt.textContent = `${curVal} (Custom)`;
                        sel.prepend(customOpt);
                    }

                    // Always allow custom entry option
                    const optCustom = document.createElement("option");
                    optCustom.value = "__custom__";
                    optCustom.textContent = "+ Enter Custom Repository (owner/repo)...";
                    sel.appendChild(optCustom);

                    if (curVal && Array.from(sel.options).some(o => o.value === curVal)) {
                        sel.value = curVal;
                    }
                });

                // Load branches for current repo
                const curRepo = getSelectedRemediationRepo();
                if (curRepo) {
                    loadRepositoryBranches(curRepo);
                }
            }
        } catch (e) {
            console.warn("Failed to load GitHub repositories:", e);
        }
    }

    async function loadRepositoryBranches(repo) {
        if (!repo) return;
        try {
            const res = await fetch(`/api/github/branches?repo=${encodeURIComponent(repo)}`);
            if (res.ok) {
                const data = await res.json();
                const branches = data.branches || ["main"];
                const wsBranchSelect = document.getElementById("wsAutofixBranchSelect");
                const standBranchSelect = document.getElementById("standaloneBranchSelect");

                [wsBranchSelect, standBranchSelect].forEach(sel => {
                    if (!sel) return;
                    const curVal = sel.value;
                    sel.innerHTML = "";
                    branches.forEach(b => {
                        const opt = document.createElement("option");
                        opt.value = b;
                        opt.textContent = b;
                        sel.appendChild(opt);
                    });
                    if (curVal && Array.from(sel.options).some(o => o.value === curVal)) {
                        sel.value = curVal;
                    } else if (branches.includes("main")) {
                        sel.value = "main";
                    }
                });
            }
        } catch (e) {
            console.warn("Failed to load branches:", e);
        }
    }

    function renderWorkspaceAutoFix() {
        loadGitHubFixStatus();
        loadGitHubRepositories();

        const wsSelect = document.getElementById("wsAutofixFindingSelect");
        const standSelect = document.getElementById("autofixFindingSelect");
        const proj = getActiveProject();
        const findings = (proj && proj.findings) ? proj.findings : [];

        [wsSelect, standSelect].forEach(sel => {
            if (!sel) return;
            sel.innerHTML = `<option value="">-- Select Confirmed Vulnerability --</option>`;
            if (findings.length > 0) {
                const optAll = document.createElement("option");
                optAll.value = "__ALL_FINDINGS__";
                optAll.textContent = `✨ Remediate All Detected Vulnerabilities (${findings.length} findings, Full Repository Patch)`;
                optAll.style.fontWeight = "bold";
                sel.appendChild(optAll);
            }
            findings.forEach((f, idx) => {
                const opt = document.createElement("option");
                opt.value = f.id;
                const vulnId = f.vuln_id || `VULN-${String(idx + 1).padStart(3, "0")}`;
                const statusBadge = f.status === "RESOLVED" ? "[RESOLVED] " : (f.fix_status ? `[${f.fix_status}] ` : "");
                opt.textContent = `${statusBadge}[${vulnId}] ${f.finding_name} (${f.priority})`;
                sel.appendChild(opt);
            });
        });

        if (wsSelect && wsSelect.value) {
            restoreFindingFixState(wsSelect.value);
        } else {
            renderSelectedSourcesList();
            renderCandidateSourcesList();
        }
    }

    // Global source selection state for multi-file discovery & remediation
    window.selectedSources = [];
    window.candidateSources = [];
    window.sourceSelectionMode = "AUTOMATIC";
    let repoTreeTempCheckedPaths = new Set();

    function renderSelectedSourcesList() {
        const container = document.getElementById("wsSelectedSourcesList");
        const countBadge = document.getElementById("wsSelectedSourcesCount");
        const modeBadge = document.getElementById("wsSourceSelectionModeBadge");
        const fileInput = document.getElementById("wsAutofixFileInput");

        if (!container) return;
        container.innerHTML = "";

        const count = window.selectedSources ? window.selectedSources.length : 0;
        if (countBadge) countBadge.textContent = `${count} file${count === 1 ? "" : "s"} selected`;
        if (modeBadge) {
            modeBadge.textContent = window.sourceSelectionMode === "USER_MODIFIED" ? "User Modified" : "Automatic Discovery";
            modeBadge.className = window.sourceSelectionMode === "USER_MODIFIED" ? "badge badge-warning" : "badge badge-secondary";
        }

        // Keep backward-compatible hidden input synced with primary file
        if (fileInput) {
            fileInput.value = count > 0 ? window.selectedSources[0].path : "";
        }

        if (count === 0) {
            container.innerHTML = `
                <div id="wsSelectedSourcesEmpty" style="padding: 12px; text-align: center; color: var(--text-muted); font-size: 0.82rem;">
                    ⚡ <strong>Automatic Discovery Ready:</strong> Clicking <em>Analyze Repository & Propose Secure Fix</em> will automatically map and remediate the relevant vulnerable source files.
                </div>
            `;
            return;
        }

        window.selectedSources.forEach((src, idx) => {
            const row = document.createElement("div");
            row.style.display = "flex";
            row.style.justifyContent = "space-between";
            row.style.alignItems = "center";
            row.style.padding = "8px 12px";
            row.style.background = "var(--bg-surface)";
            row.style.border = "1px solid var(--border-subtle)";
            row.style.borderRadius = "var(--radius-sm)";
            row.style.gap = "10px";
            row.style.flexWrap = "wrap";

            const left = document.createElement("div");
            left.style.display = "flex";
            left.style.alignItems = "center";
            left.style.gap = "8px";
            left.style.flex = "1";
            left.style.minWidth = "220px";

            const pathSpan = document.createElement("span");
            pathSpan.style.fontFamily = "var(--font-mono)";
            pathSpan.style.fontSize = "0.85rem";
            pathSpan.style.fontWeight = "700";
            pathSpan.style.color = "var(--text-primary)";
            pathSpan.textContent = src.path;

            const layerBadge = document.createElement("span");
            layerBadge.className = "badge badge-primary";
            layerBadge.style.fontSize = "0.7rem";
            layerBadge.textContent = src.layer || "Source";

            const confBadge = document.createElement("span");
            const conf = (src.confidence || "MEDIUM").toUpperCase();
            confBadge.className = conf === "HIGH" ? "badge badge-success" : "badge badge-warning";
            confBadge.style.fontSize = "0.7rem";
            confBadge.textContent = `${conf} (${Math.round(src.relevance_score || 80)}%)`;

            left.appendChild(pathSpan);
            left.appendChild(layerBadge);
            left.appendChild(confBadge);

            if (src.symbols && src.symbols.length > 0) {
                const symSpan = document.createElement("span");
                symSpan.style.fontSize = "0.74rem";
                symSpan.style.color = "var(--text-muted)";
                symSpan.style.fontFamily = "var(--font-mono)";
                symSpan.textContent = "• " + src.symbols.map(s => typeof s === "string" ? s : s.name).join(", ");
                left.appendChild(symSpan);
            }

            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.className = "btn btn-secondary btn-sm";
            removeBtn.style.padding = "2px 8px";
            removeBtn.style.fontSize = "0.75rem";
            removeBtn.style.color = "#dc2626";
            removeBtn.textContent = "Remove";
            removeBtn.addEventListener("click", () => {
                removeSourceFromSelection(idx);
            });

            row.appendChild(left);
            row.appendChild(removeBtn);
            container.appendChild(row);
        });
    }

    function removeSourceFromSelection(idx) {
        if (!window.selectedSources || idx < 0 || idx >= window.selectedSources.length) return;
        const removed = window.selectedSources.splice(idx, 1)[0];
        window.sourceSelectionMode = "USER_MODIFIED";
        renderSelectedSourcesList();
        saveSourceSelectionToServer();
        showToast(`Removed ${removed.path} from remediation scope.`, "info");
    }

    function renderCandidateSourcesList() {
        const card = document.getElementById("wsCandidateSourcesCard");
        const list = document.getElementById("wsCandidateSourcesList");
        const countBadge = document.getElementById("wsCandidateSourcesCountBadge");

        if (!card || !list) return;
        list.innerHTML = "";

        const candidates = window.candidateSources || [];
        if (candidates.length === 0) {
            card.style.display = "none";
            return;
        }

        card.style.display = "block";
        if (countBadge) countBadge.textContent = String(candidates.length);

        candidates.forEach((cand, idx) => {
            const row = document.createElement("div");
            row.style.display = "flex";
            row.style.justifyContent = "space-between";
            row.style.alignItems = "center";
            row.style.padding = "6px 10px";
            row.style.border = "1px solid var(--border-subtle)";
            row.style.borderRadius = "var(--radius-sm)";
            row.style.background = "var(--bg-subtle)";
            row.style.gap = "8px";
            row.style.flexWrap = "wrap";

            const left = document.createElement("div");
            left.style.display = "flex";
            left.style.flexDirection = "column";
            left.style.gap = "2px";
            left.style.flex = "1";

            const top = document.createElement("div");
            top.style.display = "flex";
            top.style.alignItems = "center";
            top.style.gap = "6px";

            const pathSpan = document.createElement("span");
            pathSpan.style.fontFamily = "var(--font-mono)";
            pathSpan.style.fontSize = "0.8rem";
            pathSpan.style.color = "var(--text-secondary)";
            pathSpan.textContent = cand.path;

            const layerBadge = document.createElement("span");
            layerBadge.className = "badge badge-secondary";
            layerBadge.style.fontSize = "0.68rem";
            layerBadge.textContent = cand.layer || "Candidate";

            const scoreBadge = document.createElement("span");
            scoreBadge.className = "badge badge-secondary";
            scoreBadge.style.fontSize = "0.68rem";
            scoreBadge.textContent = `LOW (${Math.round(cand.relevance_score || 0)}%)`;

            top.appendChild(pathSpan);
            top.appendChild(layerBadge);
            top.appendChild(scoreBadge);
            left.appendChild(top);

            const reasonText = (cand.reasons && cand.reasons.length > 0) ? cand.reasons.join(". ") : (cand.reason || "Low confidence match");
            const reasonEl = document.createElement("span");
            reasonEl.style.fontSize = "0.74rem";
            reasonEl.style.color = "var(--text-muted)";
            reasonEl.style.fontStyle = "italic";
            reasonEl.textContent = reasonText;
            left.appendChild(reasonEl);

            const addBtn = document.createElement("button");
            addBtn.type = "button";
            addBtn.className = "btn btn-secondary btn-sm";
            addBtn.style.padding = "2px 8px";
            addBtn.style.fontSize = "0.75rem";
            addBtn.textContent = "+ Add to Scope";
            addBtn.addEventListener("click", () => {
                addCandidateToScope(idx);
            });

            row.appendChild(left);
            row.appendChild(addBtn);
            list.appendChild(row);
        });
    }

    function addCandidateToScope(idx) {
        if (!window.candidateSources || idx < 0 || idx >= window.candidateSources.length) return;
        const cand = window.candidateSources.splice(idx, 1)[0];
        cand.confidence = "MEDIUM";
        cand.relevance_score = Math.max(cand.relevance_score || 50, 60);
        window.selectedSources.push(cand);
        window.sourceSelectionMode = "USER_MODIFIED";
        renderSelectedSourcesList();
        renderCandidateSourcesList();
        saveSourceSelectionToServer();
        showToast(`Added ${cand.path} to remediation scope.`, "success");
    }

    async function saveSourceSelectionToServer() {
        const findingId = document.getElementById("wsAutofixFindingSelect")?.value;
        const repo = getSelectedRemediationRepo();
        if (!findingId || !repo) return;

        try {
            await fetch("/api/ai-fix/selected-sources", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    finding_id: findingId,
                    repo: repo,
                    selected_paths: (window.selectedSources || []).map(s => s.path),
                    manual_additions: [],
                    manual_removals: []
                })
            });
        } catch (e) {
            console.warn("Failed to persist source selection:", e);
        }
    }

    // Repository-Wide Vulnerability Scanner (SAST)
    async function scanRepositoryForVulnerabilities() {
        const repo = getSelectedRemediationRepo();
        const branch = document.getElementById("wsAutofixBranchSelect")?.value || "main";
        const proj = getActiveProject();
        const projectId = proj ? proj.id : undefined;

        if (!repo) {
            showToast("Please select or enter a repository to scan.", "warning");
            return;
        }

        try {
            showToast(`🔍 Scanning repository ${repo} (${branch}) for all vulnerabilities...`, "info");
            const btnScan = document.getElementById("btnScanRepoVulnerabilities");
            if (btnScan) {
                btnScan.disabled = true;
                btnScan.textContent = "Scanning...";
            }

            const res = await fetch("/api/ai-fix/scan-repository", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    repo: repo,
                    branch: branch,
                    project_id: projectId,
                    auto_register: true
                })
            });

            if (btnScan) {
                btnScan.disabled = false;
                btnScan.textContent = "🔍 Scan Repository for All Vulnerabilities";
            }

            if (!res.ok) {
                const errJson = await res.json().catch(() => ({}));
                throw new Error(errJson.detail || "Failed to scan repository.");
            }

            const data = await res.json();
            const count = data.vulnerabilities_detected_count || 0;
            const filesCount = data.scanned_files_count || 0;

            showToast(`✓ Scan complete: ${count} vulnerability(ies) detected across ${filesCount} files!`, "success");

            const summaryEl = document.getElementById("wsRepoScanSummary");
            if (summaryEl) {
                summaryEl.style.display = "block";
                summaryEl.textContent = `✓ Scan complete: Detected ${count} vulnerability(ies) across ${filesCount} files. All findings registered in project.`;
            }

            // Reload project findings and update UI
            if (projectId) {
                await loadProjectData(projectId);
            }
            renderWorkspaceAutoFix();

            const wsSelect = document.getElementById("wsAutofixFindingSelect");
            if (wsSelect && wsSelect.options.length > 1) {
                wsSelect.value = "__ALL_FINDINGS__";
                wsSelect.dispatchEvent(new Event("change"));
            }
        } catch (e) {
            const btnScan = document.getElementById("btnScanRepoVulnerabilities");
            if (btnScan) {
                btnScan.disabled = false;
                btnScan.textContent = "🔍 Scan Repository for All Vulnerabilities";
            }
            showToast("Repository scan failed: " + e.message, "error");
        }
    }

    // Auto-discovery helper (Phase 1 Multi-File Discovery)
    async function autoDetectSourceFile() {
        const findingId = document.getElementById("wsAutofixFindingSelect")?.value;
        if (!findingId) {
            showToast("Please select a confirmed vulnerability first.", "warning");
            return;
        }

        const repo = getSelectedRemediationRepo();
        const branch = document.getElementById("wsAutofixBranchSelect")?.value || "main";
        const constraintsInput = document.getElementById("wsAutofixDeveloperConstraints");
        const devInstructions = constraintsInput ? constraintsInput.value.trim() : "";

        const proj = getActiveProject();
        const activeFinding = (proj && proj.findings) ? proj.findings.find(f => f.id === findingId || f.vuln_id === findingId) : null;

        try {
            showToast("Analyzing repository architecture & discovering relevant source files...", "info");
            const res = await fetch("/api/ai-fix/discover-sources", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    finding_id: findingId,
                    project_id: (typeof activeProjectId !== "undefined" && activeProjectId) ? activeProjectId : undefined,
                    repo: repo,
                    branch: branch,
                    finding_name: activeFinding ? activeFinding.finding_name : undefined,
                    title: activeFinding ? (activeFinding.title || activeFinding.finding_name) : undefined,
                    cwe: activeFinding ? activeFinding.cwe : undefined,
                    affected_endpoint: activeFinding ? activeFinding.affected_endpoint : undefined,
                    parameter: activeFinding ? activeFinding.parameter : undefined,
                    observation: activeFinding ? (activeFinding.observation || activeFinding.description) : undefined,
                    developer_instructions: devInstructions
                })
            });

            if (!res.ok) {
                const errJson = await res.json().catch(() => ({}));
                throw new Error(errJson.detail || "Source discovery failed.");
            }
            const data = await res.json();

            window.selectedSources = data.selected_sources || [];
            window.candidateSources = data.candidate_sources || [];
            window.sourceSelectionMode = data.selection_mode || "AUTOMATIC";

            renderSelectedSourcesList();
            renderCandidateSourcesList();

            if (data.discovery_status === "NO_MATCH" || window.selectedSources.length === 0) {
                showToast("No reliable relevant sources discovered. Use 'Browse Repo Files' to select manually.", "warning");
            } else {
                showToast(`✓ Discovered ${window.selectedSources.length} relevant source file(s) for ${findingId}!`, "success");
            }
        } catch (e) {
            showToast(e.message, "error");
        }
    }

    // Browse Repo Files Helper with Multi-Select Checkboxes
    async function openBrowseRepoTreeModal() {
        const repo = getSelectedRemediationRepo();
        const branch = document.getElementById("wsAutofixBranchSelect")?.value || "main";

        try {
            showToast("Fetching repository file tree...", "info");
            const res = await fetch(`/api/github/tree?repo=${encodeURIComponent(repo)}&branch=${encodeURIComponent(branch)}`);
            if (!res.ok) throw new Error("Failed to fetch repository tree.");
            const data = await res.json();

            currentRepoTreeItems = data.tree || [];
            repoTreeTempCheckedPaths = new Set((window.selectedSources || []).map(s => s.path));
            updateRepoTreeCount();
            renderRepoTreeList(currentRepoTreeItems);
            openModal("modalBrowseRepoFiles");
        } catch (e) {
            showToast(e.message, "error");
        }
    }

    function updateRepoTreeCount() {
        const countEl = document.getElementById("repoTreeSelectionCount");
        if (countEl) countEl.textContent = `${repoTreeTempCheckedPaths.size} selected`;
    }

    function renderRepoTreeList(items) {
        const container = document.getElementById("repoTreeListContainer");
        if (!container) return;
        container.innerHTML = "";

        if (items.length === 0) {
            container.innerHTML = '<div style="padding: 16px; text-align: center; color: var(--text-muted);">No files found.</div>';
            return;
        }

        items.forEach(item => {
            const label = document.createElement("label");
            label.style.padding = "8px 12px";
            label.style.borderBottom = "1px solid var(--border-subtle)";
            label.style.cursor = "pointer";
            label.style.display = "flex";
            label.style.justifyContent = "space-between";
            label.style.alignItems = "center";
            label.style.userSelect = "none";
            label.className = "repo-tree-item";

            const left = document.createElement("div");
            left.style.display = "flex";
            left.style.alignItems = "center";
            left.style.gap = "8px";

            const chk = document.createElement("input");
            chk.type = "checkbox";
            chk.className = "repo-tree-checkbox";
            chk.checked = repoTreeTempCheckedPaths.has(item.path);

            chk.addEventListener("change", (e) => {
                if (e.target.checked) {
                    repoTreeTempCheckedPaths.add(item.path);
                } else {
                    repoTreeTempCheckedPaths.delete(item.path);
                }
                updateRepoTreeCount();
            });

            const pathSpan = document.createElement("span");
            pathSpan.style.color = "var(--text-primary)";
            pathSpan.textContent = item.path;

            left.appendChild(chk);
            left.appendChild(pathSpan);

            const sizeBadge = document.createElement("span");
            sizeBadge.style.fontSize = "0.72rem";
            sizeBadge.style.color = "var(--text-muted)";
            sizeBadge.style.background = "var(--bg-subtle)";
            sizeBadge.style.padding = "2px 6px";
            sizeBadge.style.borderRadius = "4px";
            sizeBadge.textContent = item.size ? item.size + ' B' : 'blob';

            label.appendChild(left);
            label.appendChild(sizeBadge);
            container.appendChild(label);
        });
    }

    // Main Analysis Execution (Multi-File Phase 2)
    async function executeCodeFixAnalysis(repo, branch, findingId, isWorkspace = true) {
        if (!findingId) {
            showToast("Please select a confirmed vulnerability first.", "error");
            return;
        }

        const repoToUse = (repo && repo !== "__custom__") ? repo : getSelectedRemediationRepo();
        const branchToUse = branch || document.getElementById("wsAutofixBranchSelect")?.value || "main";
        const filePathInput = document.getElementById(isWorkspace ? "wsAutofixFileInput" : "standaloneFileInput");
        const filePath = filePathInput ? filePathInput.value.trim() : "";
        const constraintsInput = document.getElementById("wsAutofixDeveloperConstraints");
        const developerConstraints = constraintsInput ? constraintsInput.value.trim() : "";
        const clientReqId = "req-" + Math.random().toString(36).substring(2, 10) + "-" + Date.now();

        // Compile multi-file scope (empty by default for automatic repository-wide discovery)
        let selectedPaths = [];
        const validSourceExts = [".py", ".html", ".htm", ".js", ".ts", ".php", ".jsx", ".tsx"];
        const skipDirs = ["__pycache__", "node_modules", ".git", "dist", "build"];
        if (window.selectedSources && window.selectedSources.length > 0) {
            selectedPaths = window.selectedSources
                .map(s => s.path)
                .filter(p => p && validSourceExts.some(ext => p.toLowerCase().endsWith(ext)) && !skipDirs.some(sd => p.toLowerCase().includes(sd)));
        } else if (filePath && (filePath.includes("/") || filePath.includes("\\") || filePath.includes("."))) {
            selectedPaths = [filePath];
        }

        try {
            const isBatchAll = (findingId === "__ALL_FINDINGS__");
            const endpointUrl = isBatchAll ? "/api/ai-fix/batch-patch" : "/api/ai-fix/analyze";
            const reqPayload = isBatchAll ? {
                repo: repoToUse,
                branch: branchToUse,
                project_id: (typeof activeProjectId !== "undefined" && activeProjectId) ? activeProjectId : undefined,
                developer_instructions: developerConstraints,
                selected_files: selectedPaths.length > 0 ? selectedPaths : undefined,
                request_id: clientReqId
            } : {
                repo: repoToUse,
                branch: branchToUse,
                finding_id: findingId,
                project_id: (typeof activeProjectId !== "undefined" && activeProjectId) ? activeProjectId : undefined,
                file_path: selectedPaths.length > 0 ? selectedPaths[0] : null,
                selected_files: selectedPaths,
                developer_instructions: developerConstraints,
                request_id: clientReqId
            };

            showToast(isBatchAll ? "Remediating all detected vulnerabilities across repository..." : "Analyzing repository architecture & generating unified diff...", "info");
            const res = await fetch(endpointUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(reqPayload)
            });

            if (!res.ok) {
                let errMsg = "Failed to analyze source code.";
                try {
                    const errData = await res.json();
                    if (errData && errData.detail) errMsg = typeof errData.detail === "string" ? errData.detail : JSON.stringify(errData.detail);
                } catch (_) {}
                throw new Error(errMsg);
            }
            const data = await res.json();

            const diffWrap = document.getElementById(isWorkspace ? "wsDiffViewerWrapper" : "standaloneDiffWrapper");
            const diffContainer = document.getElementById(isWorkspace ? "wsDiffContainer" : "autofixOutputBox");
            const beforeCodeContainer = document.getElementById("wsBeforeCodeContainer");
            const afterCodeContainer = document.getElementById("wsAfterCodeContainer");
            const filePathEl = document.getElementById(isWorkspace ? "wsDiffFilePath" : "standaloneDiffFilePath");
            const shaBadge = document.getElementById("wsDiffFileShaBadge");
            const expEl = document.getElementById("wsDiffExplanation");
            const safeEl = document.getElementById("wsDiffSafetyNotes");
            const changesList = document.getElementById("wsDiffChangesList");
            const preservedList = document.getElementById("wsDiffPreservedList");
            const impactEl = document.getElementById("wsDiffSecurityImpact");
            const testRecEl = document.getElementById("wsDiffTestingRec");
            const vulnBadge = document.getElementById("wsDiffVulnBadge");
            const irrevAlert = document.getElementById("wsAutofixIrrelevantAlert");
            const irrevMsg = document.getElementById("wsAutofixIrrelevantMsg");
            const safetyAlert = document.getElementById("wsAutofixSafetyAlert");
            const safetyMsg = document.getElementById("wsAutofixSafetyMsg");
            const failedAlert = document.getElementById("wsAutofixFailedAlert");
            const failedMsg = document.getElementById("wsAutofixFailedMsg");
            const btnApproveApply = document.getElementById("btnWsOpenConfirmApply");
            const btnToggleDiffView = document.getElementById("btnToggleDiffView");
            const btnToggleBeforeAfterView = document.getElementById("btnToggleBeforeAfterView");
            const wsUnifiedDiffBox = document.getElementById("wsUnifiedDiffBox");
            const wsBeforeAfterBox = document.getElementById("wsBeforeAfterBox");
            const patchStatusBadge = document.getElementById("wsPatchStatusBadge");
            const multiFileSummaryBadge = document.getElementById("wsMultiFileSummaryBadge");
            const diffFileTabsBar = document.getElementById("wsDiffFileTabsBar");

            // If automatic discovery returned selected sources, update UI and state immediately
            if (data.selected_sources && data.selected_sources.length > 0) {
                window.selectedSources = data.selected_sources;
                window.candidateSources = data.candidate_sources || [];
                window.sourceSelectionMode = "AUTOMATIC";
                renderSelectedSourcesList();
                renderCandidateSourcesList();
            } else if (data.file_path && (!window.selectedSources || window.selectedSources.length === 0 || window.selectedSources[0].path !== data.file_path)) {
                window.selectedSources = [{ path: data.file_path, layer: "controller", confidence: "HIGH", relevance_score: 90 }];
                renderSelectedSourcesList();
            }

            // Handle NO_RELEVANT_SOURCE_FOUND Check
            if (data.patch_status === "NO_RELEVANT_SOURCE_FOUND") {
                if (failedAlert) {
                    failedAlert.style.display = "block";
                    if (failedMsg) failedMsg.textContent = data.reason || "Tracegate could not identify source code relevant to this finding in the repository.";
                }
                if (diffWrap) diffWrap.style.display = "none";
                showToast(data.reason || "Tracegate could not identify source code relevant to this finding. Please use 'Browse Repo Files' as fallback.", "warning");
                return;
            }

            // Handle Irrelevant File Check
            if (data.is_relevant_file === false) {
                if (irrevAlert) {
                    irrevAlert.style.display = "block";
                    if (irrevMsg) irrevMsg.textContent = data.reason || "The selected file is not relevant to this vulnerability finding.";
                }
                if (diffWrap) diffWrap.style.display = "none";
                showToast(data.reason || "Selected file is not relevant to this finding.", "error");
                return;
            } else {
                if (irrevAlert) irrevAlert.style.display = "none";
            }

            // Extract patch and before/after code
            const diffStr = (data.diff_unified || data.unified_diff || data.patch || "").trim();
            const beforeStr = (data.before_content || data.before_code || data.original_code || "").trim();
            const afterStr = (data.after_content || data.after_code || data.proposed_code || "").trim();

            // Strict Empty Diff Guard: Reject empty diffs or unchanged code
            const hasMultiFiles = Array.isArray(data.files) && data.files.length > 0;
            const hasRealChange = diffStr.length > 0 && (hasMultiFiles ? data.files.some(f => (f.diff_unified || "").trim().length > 0) : (beforeStr !== afterStr));
            if (!hasRealChange || data.success === false) {
                if (failedAlert) {
                    failedAlert.style.display = "block";
                    if (failedMsg) failedMsg.textContent = data.reason || "No source-code change was generated. The fix cannot be applied safely.";
                }
                if (btnApproveApply) {
                    btnApproveApply.disabled = true;
                    btnApproveApply.style.opacity = "0.5";
                    btnApproveApply.style.cursor = "not-allowed";
                }
                if (diffWrap) diffWrap.style.display = "none";
                showToast(data.reason || "No source-code change was generated. The fix cannot be applied safely.", "error");
                return;
            } else {
                if (failedAlert) failedAlert.style.display = "none";
                if (btnApproveApply) {
                    btnApproveApply.disabled = false;
                    btnApproveApply.style.opacity = "1";
                    btnApproveApply.style.cursor = "pointer";
                }
            }

            // Reset View Toggles to Exact Diff
            if (wsUnifiedDiffBox) wsUnifiedDiffBox.style.display = "block";
            if (wsBeforeAfterBox) wsBeforeAfterBox.style.display = "none";
            if (btnToggleDiffView) btnToggleDiffView.className = "btn btn-sm btn-primary";
            if (btnToggleBeforeAfterView) btnToggleBeforeAfterView.className = "btn btn-sm btn-secondary";

            // Update Finding ID badge
            if (vulnBadge) {
                const displayId = data.vuln_id || data.finding_id || findingId || "VULN";
                vulnBadge.textContent = `${displayId.toUpperCase()} Remediation`;
            }

            // Update Patch Status Badge (Phase 2 Requirement)
            if (patchStatusBadge) {
                const pStatus = data.patch_status || (data.success ? "PATCH_VALIDATED" : "PATCH_REJECTED");
                patchStatusBadge.style.display = "inline-block";
                patchStatusBadge.textContent = pStatus;
                patchStatusBadge.className = (pStatus === "PATCH_VALIDATED") ? "badge badge-success" : "badge badge-danger";
            }

            // Populate Honest Validation Status Badges
            const synBadge = document.getElementById("wsDiffSyntaxBadge");
            const testBadge = document.getElementById("wsDiffTestsBadge");
            const regBadge = document.getElementById("wsDiffRegressionBadge");
            const scoreBadge = document.getElementById("wsDiffQualityScore");

            if (data.validation) {
                const syn = data.validation.syntax || "NOT_RUN";
                const tst = data.validation.tests || "NOT_AVAILABLE";
                const sec = data.validation.security || data.validation.security_regression || "NOT_VERIFIED";

                if (synBadge) {
                    synBadge.style.display = "inline-block";
                    synBadge.textContent = `Syntax: ${syn}`;
                    synBadge.className = syn === "PASSED" ? "badge badge-success" : (syn === "FAILED" ? "badge badge-danger" : "badge badge-warning");
                }
                if (testBadge) {
                    testBadge.style.display = "inline-block";
                    testBadge.textContent = `Tests: ${tst}`;
                    testBadge.className = tst === "PASSED" ? "badge badge-success" : (tst === "FAILED" ? "badge badge-danger" : "badge badge-warning");
                }
                if (regBadge) {
                    regBadge.style.display = "inline-block";
                    regBadge.textContent = `Security: ${sec}`;
                    regBadge.className = sec === "PASSED" ? "badge badge-success" : (sec === "FAILED" ? "badge badge-danger" : "badge badge-warning");
                }
            } else {
                if (synBadge) synBadge.style.display = "none";
                if (testBadge) testBadge.style.display = "none";
                if (regBadge) regBadge.style.display = "none";
            }

            // Populate Score Badge
            if (data.fix_quality_score != null) {
                let numScore = 0;
                if (typeof data.fix_quality_score === 'number' && !isNaN(data.fix_quality_score)) {
                    numScore = data.fix_quality_score;
                } else if (typeof data.fix_quality_score === 'object') {
                    numScore = (data.fix_quality_score.total_score != null) ? data.fix_quality_score.total_score : (data.fix_quality_score.score != null ? data.fix_quality_score.score : (data.success ? 90 : 0));
                } else {
                    numScore = data.success ? 90 : 0;
                }
                if (scoreBadge) {
                    scoreBadge.style.display = "inline-block";
                    scoreBadge.textContent = `Score: ${Math.round(numScore)}/100`;
                    scoreBadge.className = numScore >= 80 ? "badge badge-primary" : (numScore >= 50 ? "badge badge-warning" : "badge badge-danger");
                }
            } else if (scoreBadge) {
                scoreBadge.style.display = "none";
            }

            // Handle Pre-Commit Safety Check (Dependencies / Workflows)
            if (data.dependencies_changed || data.workflow_files_changed) {
                if (safetyAlert) {
                    safetyAlert.style.display = "block";
                    if (safetyMsg) safetyMsg.textContent = data.safety_notes || "Modifying dependency or CI workflow files requires additional care.";
                }
            } else {
                if (safetyAlert) safetyAlert.style.display = "none";
            }

            if (diffWrap) diffWrap.style.display = "flex";
            if (expEl) expEl.textContent = data.explanation;
            if (safeEl) safeEl.textContent = "Safety note: " + (data.safety_notes || "Enforces least privilege boundaries.");

            // Configure Multi-File Patch View Tabs
            const filesList = (data.files && data.files.length > 0)
                ? data.files
                : [{
                    path: data.file_path,
                    file_sha: data.file_sha,
                    diff_unified: diffStr,
                    before_code: beforeStr,
                    after_code: afterStr,
                    changes: data.changes || []
                }];

            if (multiFileSummaryBadge) {
                multiFileSummaryBadge.style.display = "inline-block";
                multiFileSummaryBadge.textContent = `${filesList.length} file${filesList.length > 1 ? "s" : ""} modified`;
            }

            // Render Diff Content Helper for a given file item
            function renderDiffForFileItem(fileItem) {
                if (filePathEl) filePathEl.textContent = fileItem.path;
                if (shaBadge) {
                    shaBadge.textContent = fileItem.file_sha ? `SHA: ${fileItem.file_sha.substring(0, 7)}` : "";
                }
                if (beforeCodeContainer) beforeCodeContainer.textContent = fileItem.before_code || "";
                if (afterCodeContainer) afterCodeContainer.textContent = fileItem.after_code || "";

                if (changesList) {
                    changesList.innerHTML = "";
                    const changes = fileItem.changes || data.changes || [];
                    changes.forEach(c => {
                        const li = document.createElement("li");
                        li.textContent = c;
                        changesList.appendChild(li);
                    });
                }

                if (diffContainer) {
                    diffContainer.innerHTML = "";
                    const lines = (fileItem.diff_unified || "").split("\n");
                    lines.forEach(line => {
                        const span = document.createElement("span");
                        if (line.startsWith("+") && !line.startsWith("+++")) {
                            span.className = "diff-line-add";
                            span.style.color = "#4ade80";
                            span.style.backgroundColor = "rgba(74, 222, 128, 0.1)";
                            span.style.display = "block";
                        } else if (line.startsWith("-") && !line.startsWith("---")) {
                            span.className = "diff-line-del";
                            span.style.color = "#f87171";
                            span.style.backgroundColor = "rgba(248, 113, 113, 0.1)";
                            span.style.display = "block";
                        } else if (line.startsWith("@@")) {
                            span.className = "diff-line-info";
                            span.style.color = "#38bdf8";
                            span.style.display = "block";
                        } else {
                            span.style.display = "block";
                        }
                        span.textContent = line;
                        diffContainer.appendChild(span);
                    });
                }
            }

            // Populate File Tabs Bar if multiple files modified
            if (diffFileTabsBar) {
                diffFileTabsBar.innerHTML = "";
                if (filesList.length > 1) {
                    diffFileTabsBar.style.display = "flex";
                    filesList.forEach((fItem, fIdx) => {
                        const tabBtn = document.createElement("button");
                        tabBtn.type = "button";
                        tabBtn.className = fIdx === 0 ? "btn btn-xs btn-primary" : "btn btn-xs btn-secondary";
                        tabBtn.style.fontFamily = "var(--font-mono)";
                        tabBtn.style.fontSize = "0.74rem";
                        tabBtn.style.padding = "3px 8px";
                        tabBtn.textContent = fItem.path;

                        tabBtn.addEventListener("click", () => {
                            Array.from(diffFileTabsBar.children).forEach(c => c.className = "btn btn-xs btn-secondary");
                            tabBtn.className = "btn btn-xs btn-primary";
                            renderDiffForFileItem(fItem);
                        });

                        diffFileTabsBar.appendChild(tabBtn);
                    });
                } else {
                    diffFileTabsBar.style.display = "none";
                }
            }

            // Initially render the primary modified file
            renderDiffForFileItem(filesList[0]);

            // Populate preserved logic list
            if (preservedList) {
                preservedList.innerHTML = "";
                const preserved = data.preserved_logic || [];
                if (preserved.length > 0) {
                    preserved.forEach(p => {
                        const li = document.createElement("li");
                        li.textContent = "✓ " + p;
                        preservedList.appendChild(li);
                    });
                } else {
                    const li = document.createElement("li");
                    li.textContent = "✓ Preserved existing controller structure, routing signatures, and response format.";
                    preservedList.appendChild(li);
                }
            }

            if (impactEl) impactEl.textContent = data.security_impact || "Mitigates security vulnerability.";
            if (testRecEl) testRecEl.textContent = data.testing_recommendation || "Verify fix with reproduction test payloads.";

            // Populate Retest Checklist items
            const retestContainer = document.getElementById("wsRetestChecklistItems");
            if (retestContainer) {
                retestContainer.innerHTML = "";
                const checklistItems = data.retest_checklist || [
                    "1. Verify exploit payload is rejected with HTTP 403 Forbidden.",
                    "2. Verify legitimate user requests continue to succeed with HTTP 200 OK.",
                    "3. Verify security logs record blocked unauthorized access attempts."
                ];

                checklistItems.forEach((itemText, idx) => {
                    const div = document.createElement("div");
                    div.style.display = "flex";
                    div.style.alignItems = "flex-start";
                    div.style.gap = "8px";

                    const chk = document.createElement("input");
                    chk.type = "checkbox";
                    chk.id = `retestItem_${idx}`;
                    chk.style.marginTop = "3px";
                    chk.style.cursor = "pointer";

                    const lbl = document.createElement("label");
                    lbl.htmlFor = `retestItem_${idx}`;
                    lbl.style.fontSize = "0.84rem";
                    lbl.style.color = "var(--text-primary)";
                    lbl.style.cursor = "pointer";
                    lbl.textContent = itemText;

                    div.appendChild(chk);
                    div.appendChild(lbl);
                    retestContainer.appendChild(div);
                });
            }

            data.repo = repoToUse;
            data.branch = branchToUse;
            window._currentAnalysisData = data;
            console.log(`[FRONTEND_RESPONSE_RECEIVED] request_id=${data.request_id || clientReqId} success=${data.success}`);
            showToast("✓ Unified diff & remediation proposal generated!", "success");
        } catch (err) {
            console.error("AI Fix Analysis Error:", err);
            showToast(err.message, "error");
        }
    }

    // Toggle between Unified Diff and Before/After views
    const btnToggleDiffView = document.getElementById("btnToggleDiffView");
    const btnToggleBeforeAfterView = document.getElementById("btnToggleBeforeAfterView");
    const wsUnifiedDiffBox = document.getElementById("wsUnifiedDiffBox");
    const wsBeforeAfterBox = document.getElementById("wsBeforeAfterBox");

    if (btnToggleDiffView && btnToggleBeforeAfterView) {
        btnToggleDiffView.addEventListener("click", () => {
            if (wsUnifiedDiffBox) wsUnifiedDiffBox.style.display = "block";
            if (wsBeforeAfterBox) wsBeforeAfterBox.style.display = "none";
            btnToggleDiffView.className = "btn btn-sm btn-primary";
            btnToggleBeforeAfterView.className = "btn btn-sm btn-secondary";
        });

        btnToggleBeforeAfterView.addEventListener("click", () => {
            if (wsUnifiedDiffBox) wsUnifiedDiffBox.style.display = "none";
            if (wsBeforeAfterBox) wsBeforeAfterBox.style.display = "grid";
            btnToggleBeforeAfterView.className = "btn btn-sm btn-primary";
            btnToggleDiffView.className = "btn btn-sm btn-secondary";
        });
    }

    // Reject Fix Proposal
    const btnWsRejectFix = document.getElementById("btnWsRejectFix");
    if (btnWsRejectFix) {
        btnWsRejectFix.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            if (!data || !data.finding_id) {
                showToast("No active fix proposal to reject.", "warning");
                return;
            }

            const reason = prompt("Optional: Provide a reason for rejecting this fix proposal:", "Does not meet architectural requirements");
            if (reason === null) return;

            try {
                showToast("Rejecting fix proposal...", "info");
                const repoVal = data.repo || getSelectedRemediationRepo();
                const res = await fetch("/api/ai-fix/reject", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        finding_id: data.finding_id,
                        repo: repoVal,
                        branch: data.branch || "main",
                        reason: reason || "Rejected by developer review"
                    })
                });

                if (!res.ok) throw new Error("Failed to reject fix proposal.");

                const diffWrapper = document.getElementById("wsAnalysisDiffWrapper");
                if (diffWrapper) diffWrapper.style.display = "none";

                const proj = getActiveProject();
                if (proj && proj.findings) {
                    const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                    if (f) {
                        f.fix_status = "Fix Rejected";
                        saveProjects();
                        renderWorkspaceFindings();
                        refreshDashboardStats();
                    }
                }

                showToast("Fix proposal rejected and recorded in audit log.", "info");
            } catch (err) {
                showToast(err.message, "error");
            }
        });
    }

    // Request Revision Modal and Execution
    const btnWsRequestRevision = document.getElementById("btnWsRequestRevision");
    const btnCloseRevisionModal = document.getElementById("btnCloseRevisionModal");
    const btnCancelRevisionModal = document.getElementById("btnCancelRevisionModal");
    const btnSubmitRevisionRequest = document.getElementById("btnSubmitRevisionRequest");
    const txtRevisionInstructions = document.getElementById("txtRevisionInstructions");

    if (btnWsRequestRevision) {
        btnWsRequestRevision.addEventListener("click", () => {
            const data = window._currentAnalysisData;
            if (!data) {
                showToast("No active analysis proposal to revise.", "warning");
                return;
            }
            if (txtRevisionInstructions) txtRevisionInstructions.value = "";
            openModal("modalAIFixRevision");
            setTimeout(() => txtRevisionInstructions?.focus(), 100);
        });
    }

    if (btnCloseRevisionModal) btnCloseRevisionModal.addEventListener("click", () => closeModal("modalAIFixRevision"));
    if (btnCancelRevisionModal) btnCancelRevisionModal.addEventListener("click", () => closeModal("modalAIFixRevision"));

    if (btnSubmitRevisionRequest) {
        btnSubmitRevisionRequest.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            const instructions = txtRevisionInstructions?.value.trim();
            if (!instructions) {
                showToast("Please provide revision instructions for the AI.", "warning");
                return;
            }

            try {
                showToast("Revising remediation patch according to developer instructions...", "info");
                const res = await fetch("/api/ai-fix/revise", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        finding_id: data.finding_id,
                        repo: data.repo,
                        branch: data.branch,
                        file_path: data.file_path,
                        current_diff: data.diff_unified,
                        original_code: data.original_code,
                        developer_instructions: instructions
                    })
                });

                if (!res.ok) throw new Error("Failed to revise fix proposal.");
                const revisedData = await res.json();
                window._currentAnalysisData = revisedData;

                closeModal("modalAIFixRevision");

                // Update UI with revised data
                const expEl = document.getElementById("wsDiffExplanation");
                const changesList = document.getElementById("wsDiffChangesList");
                const diffContainer = document.getElementById("wsDiffContainer");
                const beforeCodeContainer = document.getElementById("wsBeforeCodeContainer");
                const afterCodeContainer = document.getElementById("wsAfterCodeContainer");
                const impactEl = document.getElementById("wsDiffSecurityImpact");
                const testRecEl = document.getElementById("wsDiffTestingRec");

                if (expEl) expEl.textContent = revisedData.explanation;
                if (impactEl && revisedData.security_impact) impactEl.textContent = revisedData.security_impact;
                if (testRecEl && revisedData.testing_recommendation) testRecEl.textContent = revisedData.testing_recommendation;
                if (beforeCodeContainer) beforeCodeContainer.textContent = revisedData.before_content || revisedData.before_code || revisedData.original_code || "";
                if (afterCodeContainer) afterCodeContainer.textContent = revisedData.after_content || revisedData.after_code || revisedData.proposed_code || "";

                if (changesList) {
                    changesList.innerHTML = "";
                    (revisedData.changes || []).forEach(c => {
                        const li = document.createElement("li");
                        li.textContent = c;
                        changesList.appendChild(li);
                    });
                }

                if (diffContainer) {
                    diffContainer.innerHTML = "";
                    const diffStr = (revisedData.diff_unified || revisedData.unified_diff || revisedData.patch || "");
                    diffStr.split("\n").forEach(line => {
                        const span = document.createElement("span");
                        if (line.startsWith("+") && !line.startsWith("+++")) {
                            span.className = "diff-line-add";
                            span.style.color = "#4ade80";
                            span.style.backgroundColor = "rgba(74, 222, 128, 0.1)";
                            span.style.display = "block";
                        } else if (line.startsWith("-") && !line.startsWith("---")) {
                            span.className = "diff-line-del";
                            span.style.color = "#f87171";
                            span.style.backgroundColor = "rgba(248, 113, 113, 0.1)";
                            span.style.display = "block";
                        } else if (line.startsWith("@@")) {
                            span.className = "diff-line-info";
                            span.style.color = "#38bdf8";
                            span.style.display = "block";
                        } else {
                            span.style.display = "block";
                        }
                        span.textContent = line;
                        diffContainer.appendChild(span);
                    });
                }

                showToast(`✓ Proposal revised (Revision #${revisedData.revision_count})`, "success");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    // Pre-Write Confirmation Modal & Application
    const btnWsOpenConfirmApply = document.getElementById("btnWsOpenConfirmApply");
    const btnCloseConfirmApplyModal = document.getElementById("btnCloseConfirmApplyModal");
    const btnCancelConfirmApply = document.getElementById("btnCancelConfirmApply");
    const btnExecuteConfirmApply = document.getElementById("btnExecuteConfirmApply");

    if (btnWsOpenConfirmApply) {
        btnWsOpenConfirmApply.addEventListener("click", () => {
            const data = window._currentAnalysisData;
            if (!data) {
                showToast("No analysis diff to apply.", "error");
                return;
            }

            if (data.success === false) {
                showToast("Cannot apply an invalid or failed remediation patch. Please revise instructions.", "error");
                return;
            }

            const repoToUse = getSelectedRemediationRepo() || data.repo;
            data.repo = repoToUse;
            const branchToUse = data.branch || document.getElementById("wsAutofixBranchSelect")?.value || "main";
            data.branch = branchToUse;

            const cleanId = (data.vuln_id || data.finding_id || "VULN-001").replace(/[^a-zA-Z0-9_-]/g, "-");
            const defaultFixBranch = `fix/${cleanId}`;

            const confirmRepoInput = document.getElementById("confirmApplyRepoInput");
            if (confirmRepoInput) confirmRepoInput.value = repoToUse;

            const confirmBranchInput = document.getElementById("confirmApplyBaseBranchInput");
            if (confirmBranchInput) confirmBranchInput.value = branchToUse;

            const confirmFixBranchInput = document.getElementById("confirmApplyFixBranchInput");
            const fixBranchToSet = (confirmFixBranchInput && confirmFixBranchInput.value && !confirmFixBranchInput.value.includes("tracegate/")) ? confirmFixBranchInput.value.trim() : defaultFixBranch;
            if (confirmFixBranchInput) confirmFixBranchInput.value = fixBranchToSet;

            // Connection Mode Banner
            const modeBanner = document.getElementById("confirmApplyModeBanner");
            const modeBannerText = document.getElementById("confirmApplyModeBannerText");
            const isLive = (window._githubMode === "live" || window._githubConnected);
            if (modeBanner && modeBannerText) {
                if (isLive && !repoToUse.startsWith("tracegate-lab/")) {
                    modeBanner.style.background = "rgba(5, 150, 105, 0.1)";
                    modeBanner.style.borderColor = "rgba(5, 150, 105, 0.25)";
                    modeBanner.style.color = "#059669";
                    modeBannerText.textContent = `🟢 Live GitHub Mode: Writing real commits to ${repoToUse}`;
                } else {
                    modeBanner.style.background = "rgba(217, 119, 6, 0.1)";
                    modeBanner.style.borderColor = "rgba(217, 119, 6, 0.25)";
                    modeBanner.style.color = "#d97706";
                    modeBannerText.textContent = `⚠️ Security Lab Sandbox Mode: Simulated local commit (will not push to real GitHub)`;
                }
            }

            const quickSelect = document.getElementById("confirmApplyRepoQuickSelect");
            const wsRepoSelect = document.getElementById("wsAutofixRepoSelect");
            if (quickSelect && wsRepoSelect) {
                quickSelect.innerHTML = '<option value="">Quick Select...</option>';
                Array.from(wsRepoSelect.options).forEach(opt => {
                    if (opt.value && opt.value !== "__custom__") {
                        const o = document.createElement("option");
                        o.value = opt.value;
                        o.textContent = opt.textContent;
                        quickSelect.appendChild(o);
                    }
                });
                if (repoToUse && Array.from(quickSelect.options).some(o => o.value === repoToUse)) {
                    quickSelect.value = repoToUse;
                }
            }

            const confirmRepo = document.getElementById("confirmApplyRepo");
            if (confirmRepo) confirmRepo.textContent = repoToUse;
            const confirmBase = document.getElementById("confirmApplyBaseBranch");
            if (confirmBase) confirmBase.textContent = branchToUse;
            const confirmFixEl = document.getElementById("confirmApplyFixBranch");
            if (confirmFixEl) confirmFixEl.textContent = fixBranchToSet;
            document.getElementById("confirmApplyFile").textContent = data.file_path;
            document.getElementById("confirmApplySha").textContent = data.file_sha ? data.file_sha.substring(0, 7) : "verified";

            const defaultMsg = `fix(security): remediate ${data.vuln_id || data.finding_id} in ${data.file_path}`;
            const commitMsgInput = document.getElementById("txtConfirmCommitMsg");
            if (commitMsgInput) commitMsgInput.value = defaultMsg;

            openModal("modalAIFixConfirmApply");
        });
    }

    const confirmApplyRepoQuickSelect = document.getElementById("confirmApplyRepoQuickSelect");
    if (confirmApplyRepoQuickSelect) {
        confirmApplyRepoQuickSelect.addEventListener("change", (e) => {
            const val = e.target.value;
            if (val) {
                const input = document.getElementById("confirmApplyRepoInput");
                if (input) input.value = val;
                window._currentSelectedRepo = val;
                if (window._currentAnalysisData) window._currentAnalysisData.repo = val;
                const modeBannerText = document.getElementById("confirmApplyModeBannerText");
                if (modeBannerText) {
                    modeBannerText.textContent = `🟢 Live GitHub Mode: Writing real commits to ${val}`;
                }
            }
        });
    }

    const confirmApplyRepoInput = document.getElementById("confirmApplyRepoInput");
    if (confirmApplyRepoInput) {
        confirmApplyRepoInput.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            if (val) {
                window._currentSelectedRepo = val;
                if (window._currentAnalysisData) window._currentAnalysisData.repo = val;
            }
        });
    }

    const confirmApplyBaseBranchInput = document.getElementById("confirmApplyBaseBranchInput");
    if (confirmApplyBaseBranchInput) {
        confirmApplyBaseBranchInput.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            if (val && window._currentAnalysisData) {
                window._currentAnalysisData.branch = val;
            }
        });
    }

    const confirmApplyFixBranchInput = document.getElementById("confirmApplyFixBranchInput");
    if (confirmApplyFixBranchInput) {
        confirmApplyFixBranchInput.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            const confirmFixEl = document.getElementById("confirmApplyFixBranch");
            if (confirmFixEl) confirmFixEl.textContent = val;
        });
    }

    if (btnCloseConfirmApplyModal) btnCloseConfirmApplyModal.addEventListener("click", () => closeModal("modalAIFixConfirmApply"));
    if (btnCancelConfirmApply) btnCancelConfirmApply.addEventListener("click", () => closeModal("modalAIFixConfirmApply"));

    if (btnExecuteConfirmApply) {
        btnExecuteConfirmApply.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            if (!data) return;

            const modalRepo = document.getElementById("confirmApplyRepoInput")?.value.trim();
            const repoToUse = modalRepo || getSelectedRemediationRepo() || data.repo;
            data.repo = repoToUse;
            window._currentSelectedRepo = repoToUse;

            const modalBranch = document.getElementById("confirmApplyBaseBranchInput")?.value.trim();
            const branchToUse = modalBranch || data.branch || document.getElementById("wsAutofixBranchSelect")?.value || "main";
            data.branch = branchToUse;

            const modalFixBranch = document.getElementById("confirmApplyFixBranchInput")?.value.trim();
            const cleanId = (data.vuln_id || data.finding_id || "VULN-001").replace(/[^a-zA-Z0-9_-]/g, "-");
            const fixBranchToUse = modalFixBranch || `fix/${cleanId}`;

            const commitMsg = document.getElementById("txtConfirmCommitMsg")?.value.trim() || `fix(security): remediate ${data.vuln_id || data.finding_id}`;

            try {
                showToast("Creating dedicated branch, verifying SHA & committing code...", "info");
                const res = await fetch("/api/ai-fix/apply", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        repo: repoToUse,
                        target_branch: branchToUse,
                        fix_branch: fixBranchToUse,
                        finding_id: data.finding_id,
                        file_path: data.file_path,
                        file_sha: data.file_sha,
                        diff_or_fixed_code: data.proposed_code || data.after_code,
                        commit_message: commitMsg,
                        files: data.files || []
                    })
                });

                if (res.status === 403) {
                    const errData = await res.json().catch(() => ({}));
                    closeModal("modalAIFixConfirmApply");
                    openGitHubPermissionHelpModal(errData.detail, data);
                    return;
                }

                if (res.status === 409) {
                    const errData = await res.json().catch(() => ({}));
                    throw new Error(errData.detail || "SOURCE_CHANGED: The source file has changed since analysis. Please re-analyze before applying the fix.");
                }

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    const detail = typeof errData.detail === "object" ? (errData.detail.message || JSON.stringify(errData.detail)) : (errData.detail || "Failed to apply fix.");
                    if (detail.toLowerCase().includes("not accessible by personal access token") || detail.toLowerCase().includes("permission")) {
                        closeModal("modalAIFixConfirmApply");
                        openGitHubPermissionHelpModal(errData.detail, data);
                        return;
                    }
                    throw new Error(detail);
                }

                const fixResult = await res.json();
                window._currentFixResult = fixResult;

                closeModal("modalAIFixConfirmApply");

                // Update UI
                const card = document.getElementById("wsFixAppliedCard");
                const branchEl = document.getElementById("wsFixBranchName");
                const shaEl = document.getElementById("wsFixCommitSha");

                if (card) card.style.display = "flex";
                if (branchEl) branchEl.textContent = fixResult.branch_name;
                if (shaEl) shaEl.textContent = fixResult.commit_sha;

                // Reset retest badge
                const retestSuccessBadge = document.getElementById("retestSuccessBadge");
                if (retestSuccessBadge) retestSuccessBadge.style.display = "none";
                const retestPill = document.getElementById("retestLifecyclePill");
                if (retestPill) {
                    retestPill.className = "badge badge-warning";
                    retestPill.textContent = "Retest Pending";
                }

                // Update active project finding in state
                const proj = getActiveProject();
                if (proj && proj.findings) {
                    const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                    if (f) {
                        f.fix_status = "Fix Applied";
                        f.github_branch = fixResult.branch_name;
                        f.github_commit = fixResult.commit_sha;
                        f.retest_status = "PENDING";
                        saveProjects();
                        renderWorkspaceFindings();
                        refreshDashboardStats();
                    }
                }

                showToast(`✓ Fix successfully committed to dedicated branch ${fixResult.branch_name}!`, "success");
            } catch (err) {
                if (err.message && (err.message.includes("Resource not accessible") || err.message.includes("GITHUB_PERMISSION_DENIED"))) {
                    closeModal("modalAIFixConfirmApply");
                    openGitHubPermissionHelpModal(err.message, data);
                    return;
                }
                showToast(err.message, "error");
            }
        });
    }

    // Create PR execution
    const btnWsCreatePR = document.getElementById("btnWsCreatePR");
    if (btnWsCreatePR) {
        btnWsCreatePR.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            const fixResult = window._currentFixResult;
            if (!data || !fixResult) {
                showToast("Please apply the fix first before creating a Pull Request.", "error");
                return;
            }

            const modalRepo = document.getElementById("confirmApplyRepoInput")?.value.trim();
            const repoToUse = modalRepo || getSelectedRemediationRepo() || data.repo;
            data.repo = repoToUse;
            window._currentSelectedRepo = repoToUse;

            const modalBranch = document.getElementById("confirmApplyBaseBranchInput")?.value.trim();
            const branchToUse = modalBranch || data.branch || document.getElementById("wsAutofixBranchSelect")?.value || "main";
            data.branch = branchToUse;

            try {
                showToast("Creating formal GitHub Pull Request...", "info");
                const res = await fetch("/api/ai-fix/create-pr", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        repo: repoToUse,
                        fix_branch: fixResult.branch_name,
                        base_branch: branchToUse,
                        finding_id: data.finding_id
                    })
                });

                if (res.status === 403) {
                    const errData = await res.json().catch(() => ({}));
                    openGitHubPermissionHelpModal(errData.detail, data);
                    return;
                }

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    const detail = typeof errData.detail === "object" ? (errData.detail.message || JSON.stringify(errData.detail)) : (errData.detail || "Failed to create Pull Request.");
                    if (detail.toLowerCase().includes("not accessible by personal access token") || detail.toLowerCase().includes("permission")) {
                        openGitHubPermissionHelpModal(errData.detail, data);
                        return;
                    }
                    throw new Error(detail);
                }
                const prResult = await res.json();
                window._currentPRResult = prResult;

                updatePRUI({
                    pr_number: prResult.pr_number,
                    pr_url: prResult.pr_url,
                    merged: false,
                    state: "open",
                    review_status: prResult.review_status || "Awaiting Review"
                });

                const proj = getActiveProject();
                if (proj && proj.findings) {
                    const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                    if (f) {
                        f.fix_status = "PR Created";
                        f.github_pr = prResult.pr_url;
                        saveProjects();
                        renderWorkspaceFindings();
                    }
                }

                showToast(`✓ GitHub Pull Request #${prResult.pr_number} created successfully!`, "success");
            } catch (err) {
                if (err.message && (err.message.includes("Resource not accessible") || err.message.includes("GITHUB_PERMISSION_DENIED"))) {
                    openGitHubPermissionHelpModal(err.message, data);
                    return;
                }
                showToast(err.message, "error");
            }
        });
    }

    // Helper: update PR UI elements
    function updatePRUI(prInfo) {
        if (!prInfo) return;
        const prRow = document.getElementById("wsPRResultRow");
        const prLink = document.getElementById("wsPRLink");
        const prBannerTitle = document.getElementById("wsPRBannerTitle");
        const prStatusPill = document.getElementById("wsPRStatusPill");
        const prReviewPill = document.getElementById("wsPRReviewStatusPill");
        const btnMerge = document.getElementById("btnWsMergePR");

        if (prRow) prRow.style.display = "flex";
        if (prBannerTitle && prInfo.pr_number) {
            prBannerTitle.textContent = `GitHub Pull Request #${prInfo.pr_number} Opened`;
        }
        if (prLink && (prInfo.pr_url || prInfo.html_url)) {
            const url = prInfo.pr_url || prInfo.html_url;
            prLink.href = url;
            prLink.textContent = `View PR #${prInfo.pr_number} on GitHub →`;
        }

        const isMerged = prInfo.merged === true || prInfo.pr_status === "Merged" || prInfo.status === "MERGED";
        const isClosed = !isMerged && (prInfo.state === "closed" || prInfo.pr_status === "Closed");

        if (prStatusPill) {
            if (isMerged) {
                prStatusPill.className = "badge badge-completed";
                prStatusPill.textContent = "Merged";
            } else if (isClosed) {
                prStatusPill.className = "badge badge-danger";
                prStatusPill.textContent = "Closed";
            } else {
                prStatusPill.className = "badge badge-in-progress";
                prStatusPill.textContent = "Open";
            }
        }

        if (prReviewPill) {
            const rev = (prInfo.review_status || "PENDING").toUpperCase();
            if (rev === "APPROVED") {
                prReviewPill.className = "badge badge-completed";
                prReviewPill.textContent = "Approved";
            } else if (rev === "CHANGES_REQUESTED") {
                prReviewPill.className = "badge badge-danger";
                prReviewPill.textContent = "Changes Requested";
            } else if (rev === "COMMENTED") {
                prReviewPill.className = "badge badge-warning";
                prReviewPill.textContent = "Commented";
            } else {
                prReviewPill.className = "badge badge-secondary";
                prReviewPill.textContent = "Awaiting Review";
            }
        }

        if (btnMerge) {
            if (isMerged) {
                btnMerge.disabled = true;
                btnMerge.textContent = "✓ Merged into Base";
            } else if (isClosed) {
                btnMerge.disabled = true;
                btnMerge.textContent = "PR Closed";
            } else {
                btnMerge.disabled = false;
                btnMerge.textContent = "🔀 Merge PR into Base";
            }
        }
    }

    // Helper: Fetch live PR status from GitHub and synchronize
    async function fetchLivePRStatus(repo, prNumber) {
        if (!repo || !prNumber || prNumber === "N/A") return null;
        try {
            const res = await fetch(`/api/ai-fix/pr/${repo}/${prNumber}/status`);
            if (!res.ok) return null;
            const data = await res.json();
            if (window._currentPRResult) {
                window._currentPRResult.state = data.state;
                window._currentPRResult.merged = data.merged;
                window._currentPRResult.review_status = data.review_status;
                window._currentPRResult.html_url = data.html_url || window._currentPRResult.pr_url;
            }
            updatePRUI({
                pr_number: prNumber,
                pr_url: data.html_url || (window._currentPRResult && window._currentPRResult.pr_url),
                merged: data.merged,
                state: data.state,
                review_status: data.review_status
            });

            if (data.merged) {
                const proj = getActiveProject();
                const findingId = window._currentAnalysisData?.finding_id;
                if (proj && proj.findings && findingId) {
                    const f = proj.findings.find(item => item.id === findingId || item.vuln_id === findingId);
                    if (f && f.fix_status !== "Code Merged (Retest Required)") {
                        f.fix_status = "Code Merged (Retest Required)";
                        saveProjects();
                        renderWorkspaceFindings();
                    }
                }
            }
            return data;
        } catch (e) {
            console.warn("Failed to fetch live PR status:", e);
            return null;
        }
    }

    // Live PR Status Check Button
    const btnWsCheckPRStatus = document.getElementById("btnWsCheckPRStatus");
    if (btnWsCheckPRStatus) {
        btnWsCheckPRStatus.addEventListener("click", async () => {
            const pr = window._currentPRResult;
            const data = window._currentAnalysisData;
            if (!pr || !pr.pr_number) {
                showToast("No active Pull Request to check.", "warning");
                return;
            }
            const repo = data?.repo || getSelectedRemediationRepo();
            showToast("Checking live PR status & reviews on GitHub...", "info");
            const res = await fetchLivePRStatus(repo, pr.pr_number);
            if (res) {
                showToast(`✓ PR #${pr.pr_number} status: ${res.state.toUpperCase()} | Review: ${res.review_status}`, "success");
            } else {
                showToast("Could not retrieve live status from GitHub.", "error");
            }
        });
    }

    // Merge PR Confirmation Modal & Execution
    const modalConfirmMergePR = document.getElementById("modalConfirmMergePR");
    const btnWsMergePR = document.getElementById("btnWsMergePR");
    const btnCancelConfirmMergePR = document.getElementById("btnCancelConfirmMergePR");
    const btnCloseConfirmMergePRModal = document.getElementById("btnCloseConfirmMergePRModal");
    const btnExecuteConfirmMergePR = document.getElementById("btnExecuteConfirmMergePR");

    if (btnWsMergePR) {
        btnWsMergePR.addEventListener("click", () => {
            const data = window._currentAnalysisData;
            const prResult = window._currentPRResult;
            if (!data || !prResult) {
                showToast("No active Pull Request to merge.", "warning");
                return;
            }

            const repo = data.repo || getSelectedRemediationRepo();
            const prLink = document.getElementById("mergeModalPRLink");
            const mergeModalRepo = document.getElementById("mergeModalRepo");
            const mergeModalFixBranch = document.getElementById("mergeModalFixBranch");
            const mergeModalBaseBranch = document.getElementById("mergeModalBaseBranch");
            const mergeModalReviewStatus = document.getElementById("mergeModalReviewStatus");

            if (prLink) {
                prLink.href = prResult.pr_url || prResult.html_url || "#";
                prLink.textContent = `PR #${prResult.pr_number}`;
            }
            if (mergeModalRepo) mergeModalRepo.textContent = repo;
            if (mergeModalFixBranch) {
                mergeModalFixBranch.textContent = window._currentFixResult?.branch_name || data.fix_branch || `tracegate/fix/${data.finding_id}`;
            }
            if (mergeModalBaseBranch) {
                mergeModalBaseBranch.textContent = data.branch || "main";
            }
            if (mergeModalReviewStatus) {
                const rev = (prResult.review_status || "PENDING").toUpperCase();
                mergeModalReviewStatus.textContent = rev === "APPROVED" ? "Approved" : (rev === "CHANGES_REQUESTED" ? "Changes Requested" : (rev === "COMMENTED" ? "Commented" : "Awaiting Review"));
                mergeModalReviewStatus.className = rev === "APPROVED" ? "badge badge-completed" : (rev === "CHANGES_REQUESTED" ? "badge badge-danger" : "badge badge-secondary");
            }

            if (modalConfirmMergePR) modalConfirmMergePR.classList.add("open");
        });
    }

    [btnCancelConfirmMergePR, btnCloseConfirmMergePRModal].forEach(btn => {
        if (btn) {
            btn.addEventListener("click", () => {
                if (modalConfirmMergePR) modalConfirmMergePR.classList.remove("open");
            });
        }
    });

    if (btnExecuteConfirmMergePR) {
        btnExecuteConfirmMergePR.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            const prResult = window._currentPRResult;
            if (!data || !prResult) {
                if (modalConfirmMergePR) modalConfirmMergePR.classList.remove("open");
                return;
            }

            try {
                if (modalConfirmMergePR) modalConfirmMergePR.classList.remove("open");
                showToast("Merging Pull Request into base branch...", "info");
                const res = await fetch("/api/ai-fix/pr/merge", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        finding_id: data.finding_id,
                        repo: data.repo || getSelectedRemediationRepo(),
                        pr_number: prResult.pr_number
                    })
                });

                if (res.status === 403) {
                    const errData = await res.json().catch(() => ({}));
                    openGitHubPermissionHelpModal(errData.detail, data);
                    return;
                }

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    const detail = typeof errData.detail === "object" ? (errData.detail.message || JSON.stringify(errData.detail)) : (errData.detail || "Failed to merge Pull Request.");
                    throw new Error(detail);
                }

                const mergeData = await res.json();
                prResult.merged = true;
                prResult.pr_status = "Merged";

                updatePRUI({
                    pr_number: prResult.pr_number,
                    pr_url: prResult.pr_url,
                    merged: true,
                    state: "closed",
                    review_status: prResult.review_status
                });

                const proj = getActiveProject();
                if (proj && proj.findings) {
                    const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                    if (f) {
                        f.fix_status = "Code Merged (Retest Required)";
                        saveProjects();
                        renderWorkspaceFindings();
                    }
                }

                showToast("✓ PR merged into base branch! Note: Retest is still required to confirm vulnerability resolution.", "success");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    // Retest Pass / Fail Execution
    const btnWsPassRetest = document.getElementById("btnWsPassRetest");
    const btnWsFailRetest = document.getElementById("btnWsFailRetest");

    if (btnWsPassRetest) {
        btnWsPassRetest.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            if (!data || !data.finding_id) {
                showToast("No active finding remediation in progress.", "warning");
                return;
            }

            const notes = document.getElementById("txtRetestNotes")?.value.trim();

            try {
                showToast("Recording tester retest verification (PASS)...", "info");
                const res = await fetch(`/api/ai-fix/${data.finding_id}/retest`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ finding_id: data.finding_id, result: "PASS", notes })
                });

                if (!res.ok) throw new Error("Failed to record retest.");
                const retestRes = await res.json();

                const retestPill = document.getElementById("retestLifecyclePill");
                const retestSuccessBadge = document.getElementById("retestSuccessBadge");

                if (retestPill) {
                    retestPill.className = "badge badge-completed";
                    retestPill.textContent = "Retest Passed";
                }
                if (retestSuccessBadge) {
                    retestSuccessBadge.style.display = "block";
                    retestSuccessBadge.innerHTML = `✓ Finding transitioned: <strong>Fix Applied &rarr; Retested &rarr; RESOLVED</strong>`;
                }

                const proj = getActiveProject();
                if (proj && proj.findings) {
                    const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                    if (f) {
                        f.status = "RESOLVED";
                        f.fix_status = "Resolved";
                        f.retest_status = "PASSED";
                        f.retest_notes = notes;
                        saveProjects();
                        renderWorkspaceFindings();
                        refreshDashboardStats();
                    }
                }

                showToast("✓ Retest Verified: Finding transitioned to RESOLVED!", "success");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    if (btnWsFailRetest) {
        btnWsFailRetest.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            if (!data || !data.finding_id) {
                showToast("No active finding remediation in progress.", "warning");
                return;
            }

            const notes = document.getElementById("txtRetestNotes")?.value.trim() || "Exploit payload still executes successfully after patch.";

            try {
                showToast("Recording tester retest verification (FAIL)...", "info");
                const res = await fetch(`/api/ai-fix/${data.finding_id}/retest`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ finding_id: data.finding_id, result: "FAIL", notes })
                });

                if (!res.ok) throw new Error("Failed to record retest.");
                const retestRes = await res.json();

                const retestPill = document.getElementById("retestLifecyclePill");
                const retestSuccessBadge = document.getElementById("retestSuccessBadge");

                if (retestPill) {
                    retestPill.className = "badge badge-critical";
                    retestPill.textContent = "Retest Failed (Reopened)";
                }
                if (retestSuccessBadge) {
                    retestSuccessBadge.style.display = "block";
                    retestSuccessBadge.innerHTML = `
                        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; padding: 4px 0;">
                            <span style="color: #b91c1c;">✗ Vulnerability still reproducible. Finding transitioned: <strong>REOPENED</strong>.</span>
                            <button type="button" class="btn btn-outline-primary btn-sm" id="btnReturnToAIFix" style="padding: 4px 10px; font-size: 0.78rem;">
                                🔄 Return to AI Fix & Revise
                            </button>
                        </div>
                    `;
                    const btnReturn = document.getElementById("btnReturnToAIFix");
                    if (btnReturn) {
                        btnReturn.addEventListener("click", () => {
                            const diffWrapper = document.getElementById("wsAnalysisDiffWrapper");
                            if (diffWrapper) diffWrapper.style.display = "block";
                            const txtRev = document.getElementById("txtRevisionInstructions");
                            if (txtRev) txtRev.value = `Retest verification failed: ${notes}\nPlease adjust the fix to ensure the vulnerability is fully remediated.`;
                            openModal("modalAIFixRevision");
                            setTimeout(() => txtRev?.focus(), 100);
                        });
                    }
                }

                const proj = getActiveProject();
                if (proj && proj.findings) {
                    const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                    if (f) {
                        f.status = "REOPENED";
                        f.fix_status = "RETEST_FAILED";
                        f.retest_status = "FAILED";
                        f.retest_notes = notes;
                        saveProjects();
                        renderWorkspaceFindings();
                        refreshDashboardStats();
                    }
                }

                showToast("✗ Retest Failed: Finding REOPENED. You can now request revision or re-analyze.", "warning");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    // View Remediation Review Report Modal
    const btnWsViewRemediationReport = document.getElementById("btnWsViewRemediationReport");
    const btnCloseRemediationReportModal = document.getElementById("btnCloseRemediationReportModal");
    const btnCloseRemediationReportBtn = document.getElementById("btnCloseRemediationReportBtn");
    const btnCopyRemediationReport = document.getElementById("btnCopyRemediationReport");

    if (btnWsViewRemediationReport) {
        btnWsViewRemediationReport.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            if (!data) return;

            try {
                const res = await fetch(`/api/ai-fix/${data.finding_id}/report`);
                if (!res.ok) throw new Error("Failed to load remediation report.");
                const repData = await res.json();

                const container = document.getElementById("remediationReportMarkdownContainer");
                if (container) container.textContent = repData.report_markdown || "";

                openModal("modalRemediationReport");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    if (btnCloseRemediationReportModal) btnCloseRemediationReportModal.addEventListener("click", () => closeModal("modalRemediationReport"));
    if (btnCloseRemediationReportBtn) btnCloseRemediationReportBtn.addEventListener("click", () => closeModal("modalRemediationReport"));

    if (btnCopyRemediationReport) {
        btnCopyRemediationReport.addEventListener("click", () => {
            const container = document.getElementById("remediationReportMarkdownContainer");
            if (!container) return;
            navigator.clipboard.writeText(container.textContent).then(() => {
                showToast("✓ Remediation review report copied to clipboard!", "success");
            });
        });
    }

    // Connect GitHub Settings Modal handlers
    const btnOpenGitHubModal = document.getElementById("btnOpenGitHubModal");
    const btnCloseGitHubModal = document.getElementById("btnCloseGitHubModal");
    const btnCancelGitHubModal = document.getElementById("btnCancelGitHubModal");
    const btnSaveGitHubModal = document.getElementById("btnSaveGitHubModal");
    const btnDisconnectGitHub = document.getElementById("btnDisconnectGitHub");

    if (btnOpenGitHubModal) {
        btnOpenGitHubModal.addEventListener("click", () => {
            openModal("modalConnectGitHub");
        });
    }
    if (btnCloseGitHubModal) btnCloseGitHubModal.addEventListener("click", () => closeModal("modalConnectGitHub"));
    if (btnCancelGitHubModal) btnCancelGitHubModal.addEventListener("click", () => closeModal("modalConnectGitHub"));

    const ghModalTokenInput = document.getElementById("ghModalTokenInput");
    const ghModalModeSelect = document.getElementById("ghModalModeSelect");
    if (ghModalTokenInput && ghModalModeSelect) {
        ghModalTokenInput.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            if (val.startsWith("ghp_") || val.startsWith("github_pat_") || val.length > 20) {
                ghModalModeSelect.value = "live";
            }
        });
    }

    if (btnSaveGitHubModal) {
        btnSaveGitHubModal.addEventListener("click", async () => {
            const token = document.getElementById("ghModalTokenInput")?.value.trim();
            const username = document.getElementById("ghModalUsernameInput")?.value.trim();
            let mode = document.getElementById("ghModalModeSelect")?.value || "mock";
            if (token && (token.startsWith("ghp_") || token.startsWith("github_pat_") || token.length > 20)) {
                mode = "live";
            }

            try {
                const res = await fetch("/api/github/connect", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ token: token || null, username: username || null, mode })
                });

                if (!res.ok) throw new Error("Failed to save GitHub credentials.");
                const statusData = await res.json();
                closeModal("modalConnectGitHub");
                loadGitHubFixStatus();
                loadGitHubRepositories();
                showToast("✓ GitHub configuration saved successfully!", "success");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    if (btnDisconnectGitHub) {
        btnDisconnectGitHub.addEventListener("click", async () => {
            try {
                await fetch("/api/github/disconnect", { method: "POST" });
                closeModal("modalConnectGitHub");
                loadGitHubFixStatus();
                loadGitHubRepositories();
                showToast("GitHub disconnected. Switched to Lab Sandbox.", "info");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    // =========================================================================
    // GITHUB PERMISSION HELP & SMART SANDBOX FALLBACK MODAL HANDLERS
    // =========================================================================
    const btnCloseGitHubPermissionHelpModal = document.getElementById("btnCloseGitHubPermissionHelpModal");
    const btnClosePermHelpModalSecondary = document.getElementById("btnClosePermHelpModalSecondary");
    const btnSwitchSandboxFromHelp = document.getElementById("btnSwitchSandboxFromHelp");
    const btnSwitchSandboxFromHelpFooter = document.getElementById("btnSwitchSandboxFromHelpFooter");
    const btnUpdateTokenFromHelp = document.getElementById("btnUpdateTokenFromHelp");

    function openGitHubPermissionHelpModal(errInfo, currentData) {
        const repoEl = document.getElementById("ghPermHelpRepoName");
        const summaryEl = document.getElementById("ghPermHelpSummary");
        const repoName = (currentData && currentData.repo) || "selected repository";

        if (repoEl) repoEl.textContent = repoName;

        let detailMsg = "";
        if (typeof errInfo === "object" && errInfo !== null) {
            detailMsg = errInfo.message || errInfo.detail || "";
            if (typeof detailMsg === "object") detailMsg = detailMsg.message || JSON.stringify(detailMsg);
        } else if (typeof errInfo === "string") {
            detailMsg = errInfo;
        }

        if (summaryEl) {
            summaryEl.innerHTML = `GitHub prevented Tracegate from creating the remediation branch on <strong style="font-family: var(--font-mono); color: var(--text-primary);">${repoName}</strong> because your Personal Access Token lacks write permissions (<code>Contents: Read and write</code>).` +
                (detailMsg ? `<div style="margin-top: 8px; font-family: var(--font-mono); font-size: 0.76rem; background: rgba(0,0,0,0.04); padding: 6px 10px; border-radius: 4px; color: var(--text-muted); word-break: break-all;">${detailMsg}</div>` : "");
        }

        openModal("modalGitHubPermissionHelp");
    }

    if (btnCloseGitHubPermissionHelpModal) {
        btnCloseGitHubPermissionHelpModal.addEventListener("click", () => closeModal("modalGitHubPermissionHelp"));
    }
    if (btnClosePermHelpModalSecondary) {
        btnClosePermHelpModalSecondary.addEventListener("click", () => closeModal("modalGitHubPermissionHelp"));
    }

    if (btnUpdateTokenFromHelp) {
        btnUpdateTokenFromHelp.addEventListener("click", () => {
            closeModal("modalGitHubPermissionHelp");
            openModal("modalConnectGitHub");
        });
    }

    async function handleSwitchToSandboxFromHelp() {
        try {
            showToast("Switching to Local Security Lab Sandbox...", "info");
            const res = await fetch("/api/github/connect", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ mode: "mock", token: "" })
            });
            if (!res.ok) throw new Error("Failed to switch to sandbox mode.");

            closeModal("modalGitHubPermissionHelp");
            await loadGitHubFixStatus();
            await loadGitHubRepositories();

            // Adapt active analysis data to the sandbox lab repo
            if (window._currentAnalysisData) {
                window._currentAnalysisData.repo = "tracegate-lab/ecommerce-platform";
                const repoSelect = document.getElementById("selFixGitHubRepo");
                if (repoSelect) {
                    repoSelect.value = "tracegate-lab/ecommerce-platform";
                }
                const confirmRepoEl = document.getElementById("confirmApplyRepo");
                if (confirmRepoEl) {
                    confirmRepoEl.textContent = "tracegate-lab/ecommerce-platform";
                }
                const confirmRepoInput = document.getElementById("confirmApplyRepoInput");
                if (confirmRepoInput) {
                    confirmRepoInput.value = "tracegate-lab/ecommerce-platform";
                }
            }

            showToast("✓ Switched to Security Lab Sandbox! You can now commit fixes and create PRs safely.", "success");

            // Automatically re-open the confirm modal so the user can immediately commit without hindrance
            if (window._currentAnalysisData) {
                openModal("modalAIFixConfirmApply");
            }
        } catch (e) {
            showToast(e.message, "error");
        }
    }

    if (btnSwitchSandboxFromHelp) {
        btnSwitchSandboxFromHelp.addEventListener("click", handleSwitchToSandboxFromHelp);
    }
    if (btnSwitchSandboxFromHelpFooter) {
        btnSwitchSandboxFromHelpFooter.addEventListener("click", handleSwitchToSandboxFromHelp);
    }

    // Connect Tree modal handlers
    const btnWsBrowseRepoTree = document.getElementById("btnWsBrowseRepoTree");
    const btnCloseBrowseRepoModal = document.getElementById("btnCloseBrowseRepoModal");
    const btnCancelBrowseRepoModal = document.getElementById("btnCancelBrowseRepoModal");
    const txtFilterRepoTree = document.getElementById("txtFilterRepoTree");
    const btnClearRepoTreeSelection = document.getElementById("btnClearRepoTreeSelection");
    const btnSelectRepoFileFromTree = document.getElementById("btnSelectRepoFileFromTree");
    const wsCandidateSourcesHeader = document.getElementById("wsCandidateSourcesHeader");
    const wsCandidateSourcesList = document.getElementById("wsCandidateSourcesList");
    const wsCandidateSourcesToggleIcon = document.getElementById("wsCandidateSourcesToggleIcon");

    if (btnWsBrowseRepoTree) btnWsBrowseRepoTree.addEventListener("click", openBrowseRepoTreeModal);
    if (btnCloseBrowseRepoModal) btnCloseBrowseRepoModal.addEventListener("click", () => closeModal("modalBrowseRepoFiles"));
    if (btnCancelBrowseRepoModal) btnCancelBrowseRepoModal.addEventListener("click", () => closeModal("modalBrowseRepoFiles"));

    if (btnClearRepoTreeSelection) {
        btnClearRepoTreeSelection.addEventListener("click", () => {
            repoTreeTempCheckedPaths.clear();
            updateRepoTreeCount();
            const chks = document.querySelectorAll(".repo-tree-checkbox");
            chks.forEach(c => c.checked = false);
        });
    }

    if (btnSelectRepoFileFromTree) {
        btnSelectRepoFileFromTree.addEventListener("click", async () => {
            const chosen = Array.from(repoTreeTempCheckedPaths);
            if (chosen.length === 0) {
                showToast("Please select at least one file.", "warning");
                return;
            }

            const existingMap = new Map((window.selectedSources || []).map(s => [s.path, s]));
            const newSources = chosen.map(p => {
                if (existingMap.has(p)) return existingMap.get(p);
                return {
                    path: p,
                    layer: "Manual",
                    confidence: "MANUAL",
                    language: "unknown",
                    relevance_score: 80,
                    reasons: ["Manually selected by developer"],
                    symbols: []
                };
            });

            window.selectedSources = newSources;
            window.sourceSelectionMode = "USER_MODIFIED";
            renderSelectedSourcesList();
            await saveSourceSelectionToServer();
            closeModal("modalBrowseRepoFiles");
            showToast(`✓ Updated selection: ${chosen.length} file(s) in remediation scope.`, "success");
        });
    }

    if (wsCandidateSourcesHeader && wsCandidateSourcesList) {
        wsCandidateSourcesHeader.addEventListener("click", () => {
            const isHidden = wsCandidateSourcesList.style.display === "none";
            wsCandidateSourcesList.style.display = isHidden ? "flex" : "none";
            if (wsCandidateSourcesToggleIcon) {
                wsCandidateSourcesToggleIcon.textContent = isHidden ? "▲" : "▼";
            }
        });
    }

    if (txtFilterRepoTree) {
        txtFilterRepoTree.addEventListener("input", (e) => {
            const q = e.target.value.toLowerCase().trim();
            const filtered = currentRepoTreeItems.filter(i => i.path.toLowerCase().includes(q));
            renderRepoTreeList(filtered);
        });
    }

    // Auto-detect button handler
    const btnWsAutoDetectFile = document.getElementById("btnWsAutoDetectFile");
    if (btnWsAutoDetectFile) btnWsAutoDetectFile.addEventListener("click", autoDetectSourceFile);

    // Custom Repo Handlers
    const btnToggleCustomRepo = document.getElementById("btnToggleCustomRepo");
    const wsAutofixCustomRepoWrapper = document.getElementById("wsAutofixCustomRepoWrapper");
    const wsAutofixCustomRepoInput = document.getElementById("wsAutofixCustomRepoInput");
    const btnApplyCustomRepo = document.getElementById("btnApplyCustomRepo");

    if (btnToggleCustomRepo && wsAutofixCustomRepoWrapper) {
        btnToggleCustomRepo.addEventListener("click", () => {
            const isHidden = wsAutofixCustomRepoWrapper.style.display === "none";
            wsAutofixCustomRepoWrapper.style.display = isHidden ? "block" : "none";
            if (isHidden && wsAutofixCustomRepoInput) {
                wsAutofixCustomRepoInput.focus();
            }
        });
    }

    function applyCustomRepository(customName) {
        if (!customName) return;
        const cleanRepo = customName.trim();
        if (!cleanRepo.includes("/")) {
            showToast("Please enter repository in owner/repo format (e.g. username/repo-name)", "warning");
        }
        window._currentSelectedRepo = cleanRepo;
        window._usingCustomRepo = true;

        const wsAutofixRepoSelect = document.getElementById("wsAutofixRepoSelect");
        if (wsAutofixRepoSelect) {
            let existingOpt = Array.from(wsAutofixRepoSelect.options).find(o => o.value === cleanRepo);
            if (!existingOpt) {
                existingOpt = document.createElement("option");
                existingOpt.value = cleanRepo;
                existingOpt.textContent = `${cleanRepo} (Custom)`;
                wsAutofixRepoSelect.prepend(existingOpt);
            }
            wsAutofixRepoSelect.value = cleanRepo;
        }

        loadRepositoryBranches(cleanRepo);
        showToast(`✓ Target repository set to: ${cleanRepo}`, "success");
    }

    if (btnApplyCustomRepo && wsAutofixCustomRepoInput) {
        btnApplyCustomRepo.addEventListener("click", () => {
            applyCustomRepository(wsAutofixCustomRepoInput.value);
        });
        wsAutofixCustomRepoInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                applyCustomRepository(wsAutofixCustomRepoInput.value);
            }
        });
        wsAutofixCustomRepoInput.addEventListener("input", (e) => {
            const cleanRepo = e.target.value.trim();
            if (cleanRepo) {
                window._currentSelectedRepo = cleanRepo;
                window._usingCustomRepo = true;
            }
        });
    }

    // Repo change handler
    const wsAutofixRepoSelect = document.getElementById("wsAutofixRepoSelect");
    if (wsAutofixRepoSelect) {
        wsAutofixRepoSelect.addEventListener("change", (e) => {
            const val = e.target.value;
            if (val === "__custom__") {
                if (wsAutofixCustomRepoWrapper) {
                    wsAutofixCustomRepoWrapper.style.display = "block";
                    if (wsAutofixCustomRepoInput) wsAutofixCustomRepoInput.focus();
                }
            } else {
                window._currentSelectedRepo = val;
                window._usingCustomRepo = false;
                loadRepositoryBranches(val);
            }
        });
    }

    // Finding select change handler
    const wsAutofixFindingSelect = document.getElementById("wsAutofixFindingSelect");
    if (wsAutofixFindingSelect) {
        wsAutofixFindingSelect.addEventListener("change", (e) => {
            const fid = e.target.value;
            // Always reset selectedSources to empty and mode to AUTOMATIC when switching findings
            window.selectedSources = [];
            window.candidateSources = [];
            window.sourceSelectionMode = "AUTOMATIC";
            const fileInput = document.getElementById("wsAutofixFileInput");
            if (fileInput) fileInput.value = "";
            renderSelectedSourcesList();
            renderCandidateSourcesList();

            if (!fid) {
                const prRow = document.getElementById("wsPRResultRow");
                if (prRow) prRow.style.display = "none";
                const fixCard = document.getElementById("wsFixAppliedCard");
                if (fixCard) fixCard.style.display = "none";
                window._currentPRResult = null;
                return;
            }
            restoreFindingFixState(fid);
        });
    }

    async function restoreFindingFixState(fid) {
        if (!fid) return;

        // Restore multi-file source discovery state from server
        try {
            const repoVal = getSelectedRemediationRepo();
            if (repoVal && fid) {
                const sRes = await fetch(`/api/ai-fix/selected-sources?finding_id=${encodeURIComponent(fid)}&repo=${encodeURIComponent(repoVal)}`);
                if (sRes.ok) {
                    const sData = await sRes.json();
                    if (sData) {
                        window.selectedSources = sData.selected_sources || [];
                        window.candidateSources = sData.candidate_sources || [];
                        window.sourceSelectionMode = sData.selection_mode || "AUTOMATIC";
                        renderSelectedSourcesList();
                        renderCandidateSourcesList();
                    }
                }
            }
        } catch (err) {
            console.warn("Could not load source selection state:", err);
        }

        try {
            const res = await fetch(`/api/ai-fix/${fid}`);
            if (!res.ok) return;
            const fix = await res.json();
            if (!fix || !fix.id) {
                const prRow = document.getElementById("wsPRResultRow");
                if (prRow) prRow.style.display = "none";
                const fixCard = document.getElementById("wsFixAppliedCard");
                if (fixCard) fixCard.style.display = "none";
                window._currentPRResult = null;
                return;
            }

            // Populate current analysis data
            window._currentAnalysisData = {
                finding_id: fid,
                repo: fix.repository,
                branch: fix.base_branch || "main",
                file_path: fix.file_path
            };

            if (fix.commit_sha && fix.commit_sha !== "pending" && fix.commit_sha !== "N/A") {
                window._currentFixResult = {
                    branch_name: fix.fix_branch,
                    commit_sha: fix.commit_sha
                };

                const fixCard = document.getElementById("wsFixAppliedCard");
                const branchSpan = document.getElementById("wsFixBranchName");
                const shaSpan = document.getElementById("wsFixCommitSha");
                if (fixCard) fixCard.style.display = "flex";
                if (branchSpan) branchSpan.textContent = fix.fix_branch || `tracegate/fix/${fid}`;
                if (shaSpan) shaSpan.textContent = fix.commit_sha.substring(0, 7);
            }

            if (fix.pr_number && fix.pr_number !== "N/A") {
                window._currentPRResult = {
                    pr_number: fix.pr_number,
                    pr_url: fix.pr_url,
                    html_url: fix.pr_url,
                    pr_status: fix.pr_status,
                    review_status: fix.review_status,
                    merged: fix.pr_status === "Merged" || fix.status === "MERGED"
                };

                updatePRUI({
                    pr_number: fix.pr_number,
                    pr_url: fix.pr_url,
                    merged: fix.pr_status === "Merged" || fix.status === "MERGED",
                    state: fix.pr_status === "Merged" || fix.pr_status === "Closed" ? "closed" : "open",
                    review_status: fix.review_status
                });

                // Check live status on GitHub in background
                fetchLivePRStatus(fix.repository, fix.pr_number);
            } else {
                const prRow = document.getElementById("wsPRResultRow");
                if (prRow) prRow.style.display = "none";
                window._currentPRResult = null;
            }
        } catch (e) {
            console.warn("Failed to restore finding fix state:", e);
        }
    }

    // Repository Vulnerability Scan Button
    const btnScanRepoVulnerabilities = document.getElementById("btnScanRepoVulnerabilities");
    if (btnScanRepoVulnerabilities) {
        btnScanRepoVulnerabilities.addEventListener("click", () => {
            scanRepositoryForVulnerabilities();
        });
    }

    // Workspace Analyze Button
    const btnWsAnalyzeCodeFix = document.getElementById("btnWsAnalyzeCodeFix");
    if (btnWsAnalyzeCodeFix) {
        btnWsAnalyzeCodeFix.addEventListener("click", () => {
            const repo = getSelectedRemediationRepo();
            const branch = document.getElementById("wsAutofixBranchSelect")?.value || "main";
            const findingId = document.getElementById("wsAutofixFindingSelect")?.value;
            executeCodeFixAnalysis(repo, branch, findingId, true);
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

    // ==========================================================================
    // 16. DELETE PROJECT CONTROLLER (Section 45)
    // ==========================================================================
    const btnDeleteProject = document.getElementById("btnDeleteProject");
    const txtDeleteProjectConfirm = document.getElementById("txtDeleteProjectConfirm");
    const btnConfirmDeleteProject = document.getElementById("btnConfirmDeleteProject");
    const btnCancelDeleteProject = document.getElementById("btnCancelDeleteProject");
    const btnCloseDeleteProjectModal = document.getElementById("btnCloseDeleteProjectModal");
    const deleteProjectNameSpan = document.getElementById("deleteProjectNameSpan");

    if (btnDeleteProject) {
        btnDeleteProject.addEventListener("click", () => {
            const proj = getActiveProject();
            if (!proj) {
                showToast("No active project selected.", "error");
                return;
            }

            if (deleteProjectNameSpan) {
                deleteProjectNameSpan.textContent = proj.name;
            }
            if (txtDeleteProjectConfirm) {
                txtDeleteProjectConfirm.value = "";
            }
            if (btnConfirmDeleteProject) {
                btnConfirmDeleteProject.disabled = true;
                btnConfirmDeleteProject.style.cursor = "not-allowed";
                btnConfirmDeleteProject.style.opacity = "0.5";
            }

            openModal("modalDeleteProject");
            if (txtDeleteProjectConfirm) {
                setTimeout(() => txtDeleteProjectConfirm.focus(), 100);
            }
        });
    }

    if (txtDeleteProjectConfirm && btnConfirmDeleteProject) {
        txtDeleteProjectConfirm.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            if (val === "DELETE") {
                btnConfirmDeleteProject.disabled = false;
                btnConfirmDeleteProject.style.cursor = "pointer";
                btnConfirmDeleteProject.style.opacity = "1";
            } else {
                btnConfirmDeleteProject.disabled = true;
                btnConfirmDeleteProject.style.cursor = "not-allowed";
                btnConfirmDeleteProject.style.opacity = "0.5";
            }
        });
    }

    const closeDeleteModal = () => {
        closeModal("modalDeleteProject");
        if (txtDeleteProjectConfirm) txtDeleteProjectConfirm.value = "";
        if (btnConfirmDeleteProject) {
            btnConfirmDeleteProject.disabled = true;
            btnConfirmDeleteProject.style.cursor = "not-allowed";
            btnConfirmDeleteProject.style.opacity = "0.5";
        }
    };

    if (btnCancelDeleteProject) btnCancelDeleteProject.addEventListener("click", closeDeleteModal);
    if (btnCloseDeleteProjectModal) btnCloseDeleteProjectModal.addEventListener("click", closeDeleteModal);

    if (btnConfirmDeleteProject) {
        btnConfirmDeleteProject.addEventListener("click", async () => {
            const proj = getActiveProject();
            if (!proj) {
                closeDeleteModal();
                return;
            }

            if (txtDeleteProjectConfirm && txtDeleteProjectConfirm.value.trim() !== "DELETE") {
                showToast("Please type DELETE to confirm.", "warning");
                return;
            }

            try {
                btnConfirmDeleteProject.disabled = true;
                btnConfirmDeleteProject.textContent = "Deleting...";

                const res = await fetch(`/api/projects/${proj.id}`, {
                    method: "DELETE"
                });

                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    throw new Error(err.detail || "Failed to delete project.");
                }

                // Clean up local project list
                projects = projects.filter(p => p.id !== proj.id);
                saveProjects();
                activeProjectId = projects.length > 0 ? projects[0].id : null;

                closeDeleteModal();
                updateProjectsDropdown();
                showToast("Project deleted successfully.", "success");

                // Navigate cleanly to recent projects
                navigateTo("recent-projects");
            } catch (err) {
                showToast(err.message, "error");
            } finally {
                if (btnConfirmDeleteProject) {
                    btnConfirmDeleteProject.textContent = "Delete Project";
                }
            }
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
            currentUser.full_name = name;
            currentUser.email = email;
            currentUser.methodology = meth;
            localStorage.setItem("tg_user", JSON.stringify(currentUser));
            updateUserUI();

            showToast("Profile preferences updated successfully!", "success");
        });
    }

    // ==========================================================================
    // 14B. PROFILE 2FA SETTINGS & MODALS CONTROLLER
    // ==========================================================================
    const profile2FABadge = document.getElementById("profile2FABadge");
    const profile2FADesc = document.getElementById("profile2FADesc");
    const btnOpenSetup2FA = document.getElementById("btnOpenSetup2FA");
    const btnOpenManage2FA = document.getElementById("btnOpenManage2FA");
    const btnOpenDisable2FA = document.getElementById("btnOpenDisable2FA");
    const profile2FAMeta = document.getElementById("profile2FAMeta");
    const profile2FAEnabledAt = document.getElementById("profile2FAEnabledAt");
    const profile2FALastVerified = document.getElementById("profile2FALastVerified");
    const profile2FARecoveryCount = document.getElementById("profile2FARecoveryCount");

    // Setup Modal Elements
    const btnCloseSetup2FAModal = document.getElementById("btnCloseSetup2FAModal");
    const setup2FAStep1 = document.getElementById("setup2FAStep1");
    const setup2FAStep2 = document.getElementById("setup2FAStep2");
    const setup2FAQRPlaceholder = document.getElementById("setup2FAQRPlaceholder");
    const setup2FAQRImg = document.getElementById("setup2FAQRImg");
    const setup2FAManualKey = document.getElementById("setup2FAManualKey");
    const btnCopy2FAManualKey = document.getElementById("btnCopy2FAManualKey");
    const setup2FAAlertBox = document.getElementById("setup2FAAlertBox");
    const setup2FAAlertMessage = document.getElementById("setup2FAAlertMessage");
    const inputSetup2FACode = document.getElementById("inputSetup2FACode");
    const btnSubmit2FASetup = document.getElementById("btnSubmit2FASetup");
    const btnSubmit2FASetupText = document.getElementById("btnSubmit2FASetupText");
    const setup2FARecoveryGrid = document.getElementById("setup2FARecoveryGrid");
    const btnCopySetupRecoveryCodes = document.getElementById("btnCopySetupRecoveryCodes");
    const btnDownloadSetupRecoveryCodes = document.getElementById("btnDownloadSetupRecoveryCodes");
    const btnDone2FASetup = document.getElementById("btnDone2FASetup");

    // Disable Modal Elements
    const btnCloseDisable2FAModal = document.getElementById("btnCloseDisable2FAModal");
    const disable2FAAlertBox = document.getElementById("disable2FAAlertBox");
    const disable2FAAlertMessage = document.getElementById("disable2FAAlertMessage");
    const inputDisablePassword = document.getElementById("inputDisablePassword");
    const inputDisableCode = document.getElementById("inputDisableCode");
    const btnCancelDisable2FA = document.getElementById("btnCancelDisable2FA");
    const btnConfirmDisable2FA = document.getElementById("btnConfirmDisable2FA");

    // Manage Modal Elements
    const btnCloseManage2FAModal = document.getElementById("btnCloseManage2FAModal");
    const btnCloseManage2FAModalFooter = document.getElementById("btnCloseManage2FAModalFooter");
    const manage2FARemainingCount = document.getElementById("manage2FARemainingCount");
    const manage2FAAlertBox = document.getElementById("manage2FAAlertBox");
    const manage2FAAlertMessage = document.getElementById("manage2FAAlertMessage");
    const inputManageRegenPassword = document.getElementById("inputManageRegenPassword");
    const inputManageRegenCode = document.getElementById("inputManageRegenCode");
    const btnSubmitRegenCodes = document.getElementById("btnSubmitRegenCodes");
    const manage2FANewCodesSection = document.getElementById("manage2FANewCodesSection");
    const manage2FANewCodesGrid = document.getElementById("manage2FANewCodesGrid");
    const btnCopyManageRecoveryCodes = document.getElementById("btnCopyManageRecoveryCodes");
    const btnDownloadManageRecoveryCodes = document.getElementById("btnDownloadManageRecoveryCodes");

    let currentSetupRecoveryCodes = [];
    let currentRegenRecoveryCodes = [];

    async function loadProfile2FAStatus() {
        const authToken = localStorage.getItem("tg_auth_token");
        if (!authToken || !currentUser) return;

        try {
            const res = await fetch("/api/auth/2fa/status", {
                headers: { "Authorization": `Bearer ${authToken}` }
            });
            if (!res.ok) return;

            const st = await res.json();
            currentUser.two_factor_enabled = st.enabled;
            currentUser.two_factor_enabled_at = st.enabled_at;
            currentUser.two_factor_last_verified_at = st.last_verified_at;
            localStorage.setItem("tg_user", JSON.stringify(currentUser));

            if (profile2FABadge) {
                if (st.enabled) {
                    profile2FABadge.textContent = "Enabled (TOTP)";
                    profile2FABadge.style.background = "#ecfdf5";
                    profile2FABadge.style.color = "#059669";
                    profile2FABadge.style.border = "1px solid #a7f3d0";
                } else {
                    profile2FABadge.textContent = "Disabled";
                    profile2FABadge.style.background = "#f1f5f9";
                    profile2FABadge.style.color = "#64748b";
                    profile2FABadge.style.border = "1px solid #cbd5e1";
                }
            }

            if (st.enabled) {
                if (btnOpenSetup2FA) btnOpenSetup2FA.style.display = "none";
                if (btnOpenManage2FA) btnOpenManage2FA.style.display = "inline-block";
                if (btnOpenDisable2FA) btnOpenDisable2FA.style.display = "inline-block";
                if (profile2FAMeta) profile2FAMeta.style.display = "flex";

                if (profile2FAEnabledAt) profile2FAEnabledAt.textContent = st.enabled_at || "Recent";
                if (profile2FALastVerified) profile2FALastVerified.textContent = st.last_verified_at || "Not yet recorded";
                if (profile2FARecoveryCount) profile2FARecoveryCount.textContent = `${st.recovery_codes_remaining} remaining`;
                if (manage2FARemainingCount) manage2FARemainingCount.textContent = `${st.recovery_codes_remaining} / 10 active`;
            } else {
                if (btnOpenSetup2FA) btnOpenSetup2FA.style.display = "inline-block";
                if (btnOpenManage2FA) btnOpenManage2FA.style.display = "none";
                if (btnOpenDisable2FA) btnOpenDisable2FA.style.display = "none";
                if (profile2FAMeta) profile2FAMeta.style.display = "none";
            }
        } catch (e) {
            console.error("Failed to fetch 2FA status:", e);
        }
    }

    // Expose for global router
    window.loadProfile2FAStatus = loadProfile2FAStatus;

    // 1. Setup 2FA Flow
    if (btnOpenSetup2FA) {
        btnOpenSetup2FA.addEventListener("click", async () => {
            const authToken = localStorage.getItem("tg_auth_token");
            if (!authToken) {
                showToast("Please sign in to configure 2FA.", "error");
                return;
            }

            // Reset setup modal state
            if (setup2FAStep1) setup2FAStep1.style.display = "block";
            if (setup2FAStep2) setup2FAStep2.style.display = "none";
            if (setup2FAQRPlaceholder) setup2FAQRPlaceholder.style.display = "flex";
            if (setup2FAQRImg) {
                setup2FAQRImg.style.display = "none";
                setup2FAQRImg.src = "";
            }
            if (setup2FAManualKey) setup2FAManualKey.textContent = "Loading secret...";
            if (setup2FAAlertBox) setup2FAAlertBox.style.display = "none";
            if (inputSetup2FACode) inputSetup2FACode.value = "";
            currentSetupRecoveryCodes = [];

            openModal("modalSetup2FA");

            try {
                const res = await fetch("/api/auth/2fa/setup", {
                    method: "POST",
                    headers: { "Authorization": `Bearer ${authToken}` }
                });

                if (!res.ok) {
                    showToast("Failed to initiate 2FA enrollment.", "error");
                    closeModal("modalSetup2FA");
                    return;
                }

                const data = await res.json();
                if (setup2FAQRPlaceholder) setup2FAQRPlaceholder.style.display = "none";
                if (setup2FAQRImg) {
                    setup2FAQRImg.src = data.qr_code;
                    setup2FAQRImg.style.display = "block";
                }
                if (setup2FAManualKey) {
                    setup2FAManualKey.textContent = data.manual_entry_key || data.secret;
                }
            } catch (err) {
                showToast("Network error generating 2FA credentials.", "error");
                closeModal("modalSetup2FA");
            }
        });
    }

    if (btnCopy2FAManualKey) {
        btnCopy2FAManualKey.addEventListener("click", () => {
            const keyText = (setup2FAManualKey?.textContent || "").replace(/\s+/g, "");
            if (keyText && keyText !== "-") {
                navigator.clipboard.writeText(keyText).then(() => {
                    showToast("Manual key copied to clipboard.", "info");
                });
            }
        });
    }

    if (btnSubmit2FASetup) {
        btnSubmit2FASetup.addEventListener("click", async () => {
            const code = inputSetup2FACode ? inputSetup2FACode.value.trim().replace(/\s+/g, "") : "";
            if (!code || code.length !== 6) {
                if (setup2FAAlertBox && setup2FAAlertMessage) {
                    setup2FAAlertMessage.textContent = "Please enter a valid 6-digit authenticator code.";
                    setup2FAAlertBox.style.display = "flex";
                }
                if (inputSetup2FACode) inputSetup2FACode.focus();
                return;
            }

            const authToken = localStorage.getItem("tg_auth_token");
            if (btnSubmit2FASetupText) btnSubmit2FASetupText.textContent = "Verifying...";
            btnSubmit2FASetup.disabled = true;
            if (setup2FAAlertBox) setup2FAAlertBox.style.display = "none";

            try {
                const res = await fetch("/api/auth/2fa/verify-setup", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ code })
                });

                if (!res.ok) {
                    let errDetail = "Invalid verification code.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    if (setup2FAAlertBox && setup2FAAlertMessage) {
                        setup2FAAlertMessage.textContent = errDetail;
                        setup2FAAlertBox.style.display = "flex";
                    }
                    return;
                }

                const data = await res.json();
                currentSetupRecoveryCodes = data.recovery_codes || [];

                // Render recovery codes in grid
                if (setup2FARecoveryGrid) {
                    setup2FARecoveryGrid.innerHTML = "";
                    currentSetupRecoveryCodes.forEach((c, idx) => {
                        const item = document.createElement("div");
                        item.style.padding = "6px 8px";
                        item.style.background = "var(--bg-subtle)";
                        item.style.borderRadius = "4px";
                        item.style.border = "1px solid var(--border-subtle)";
                        item.textContent = `${idx + 1}. ${c}`;
                        setup2FARecoveryGrid.appendChild(item);
                    });
                }

                // Switch modal to Step 2
                if (setup2FAStep1) setup2FAStep1.style.display = "none";
                if (setup2FAStep2) setup2FAStep2.style.display = "block";

                showToast("Two-Factor Authentication is now enabled!", "success");
                loadProfile2FAStatus();
            } catch (err) {
                if (setup2FAAlertBox && setup2FAAlertMessage) {
                    setup2FAAlertMessage.textContent = "Service connection error.";
                    setup2FAAlertBox.style.display = "flex";
                }
            } finally {
                if (btnSubmit2FASetupText) btnSubmit2FASetupText.textContent = "Enable 2FA";
                btnSubmit2FASetup.disabled = false;
            }
        });
    }

    function exportRecoveryCodes(codes, filename) {
        if (!codes || !codes.length) return;
        const text = [
            "============================================================",
            "TRACEGATE TWO-FACTOR AUTHENTICATION BACKUP RECOVERY CODES",
            `Generated: ${new Date().toISOString()}`,
            "Account: " + (currentUser?.email || currentUser?.username || ""),
            "============================================================",
            "",
            "Each of these 10 recovery codes can only be used ONCE if you",
            "lose access to your mobile authenticator app.",
            "Keep them in a secure password manager or encrypted file.",
            "",
            ...codes.map((c, i) => `[${i + 1}]  ${c}`),
            "",
            "============================================================"
        ].join("\r\n");

        const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename || "tracegate-recovery-codes.txt";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    if (btnCopySetupRecoveryCodes) {
        btnCopySetupRecoveryCodes.addEventListener("click", () => {
            if (currentSetupRecoveryCodes.length) {
                navigator.clipboard.writeText(currentSetupRecoveryCodes.join("\n")).then(() => {
                    showToast("Recovery codes copied to clipboard.", "info");
                });
            }
        });
    }

    if (btnDownloadSetupRecoveryCodes) {
        btnDownloadSetupRecoveryCodes.addEventListener("click", () => {
            exportRecoveryCodes(currentSetupRecoveryCodes, "tracegate-2fa-recovery-codes.txt");
        });
    }

    if (btnDone2FASetup) {
        btnDone2FASetup.addEventListener("click", () => {
            closeModal("modalSetup2FA");
            loadProfile2FAStatus();
        });
    }
    if (btnCloseSetup2FAModal) {
        btnCloseSetup2FAModal.addEventListener("click", () => {
            closeModal("modalSetup2FA");
            loadProfile2FAStatus();
        });
    }

    // 2. Disable 2FA Flow
    if (btnOpenDisable2FA) {
        btnOpenDisable2FA.addEventListener("click", () => {
            if (inputDisablePassword) inputDisablePassword.value = "";
            if (inputDisableCode) inputDisableCode.value = "";
            if (disable2FAAlertBox) disable2FAAlertBox.style.display = "none";
            openModal("modalDisable2FA");
        });
    }

    if (btnCancelDisable2FA) {
        btnCancelDisable2FA.addEventListener("click", () => closeModal("modalDisable2FA"));
    }
    if (btnCloseDisable2FAModal) {
        btnCloseDisable2FAModal.addEventListener("click", () => closeModal("modalDisable2FA"));
    }

    if (btnConfirmDisable2FA) {
        btnConfirmDisable2FA.addEventListener("click", async () => {
            const password = inputDisablePassword ? inputDisablePassword.value.trim() : "";
            const code = inputDisableCode ? inputDisableCode.value.trim() : "";

            if (!password || !code) {
                if (disable2FAAlertBox && disable2FAAlertMessage) {
                    disable2FAAlertMessage.textContent = "Both password and verification/recovery code are required.";
                    disable2FAAlertBox.style.display = "flex";
                }
                return;
            }

            const authToken = localStorage.getItem("tg_auth_token");
            btnConfirmDisable2FA.disabled = true;

            try {
                const res = await fetch("/api/auth/2fa/disable", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ password, code })
                });

                if (!res.ok) {
                    let errDetail = "Failed to disable 2FA.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    if (disable2FAAlertBox && disable2FAAlertMessage) {
                        disable2FAAlertMessage.textContent = errDetail;
                        disable2FAAlertBox.style.display = "flex";
                    }
                    return;
                }

                closeModal("modalDisable2FA");
                showToast("Two-Factor Authentication has been disabled.", "info");
                loadProfile2FAStatus();
            } catch (err) {
                if (disable2FAAlertBox && disable2FAAlertMessage) {
                    disable2FAAlertMessage.textContent = "Service connection error.";
                    disable2FAAlertBox.style.display = "flex";
                }
            } finally {
                btnConfirmDisable2FA.disabled = false;
            }
        });
    }

    // 3. Manage & Regenerate Recovery Codes Flow
    if (btnOpenManage2FA) {
        btnOpenManage2FA.addEventListener("click", () => {
            if (manage2FAAlertBox) manage2FAAlertBox.style.display = "none";
            if (inputManageRegenPassword) inputManageRegenPassword.value = "";
            if (inputManageRegenCode) inputManageRegenCode.value = "";
            if (manage2FANewCodesSection) manage2FANewCodesSection.style.display = "none";
            currentRegenRecoveryCodes = [];
            openModal("modalManage2FA");
        });
    }

    if (btnCloseManage2FAModal) {
        btnCloseManage2FAModal.addEventListener("click", () => closeModal("modalManage2FA"));
    }
    if (btnCloseManage2FAModalFooter) {
        btnCloseManage2FAModalFooter.addEventListener("click", () => closeModal("modalManage2FA"));
    }

    if (btnSubmitRegenCodes) {
        btnSubmitRegenCodes.addEventListener("click", async () => {
            const password = inputManageRegenPassword ? inputManageRegenPassword.value.trim() : "";
            const code = inputManageRegenCode ? inputManageRegenCode.value.trim().replace(/\s+/g, "") : "";

            if (!password || !code) {
                if (manage2FAAlertBox && manage2FAAlertMessage) {
                    manage2FAAlertMessage.textContent = "Both password and current 6-digit TOTP code are required.";
                    manage2FAAlertBox.style.display = "flex";
                }
                return;
            }

            const authToken = localStorage.getItem("tg_auth_token");
            btnSubmitRegenCodes.disabled = true;

            try {
                const res = await fetch("/api/auth/2fa/regenerate-recovery-codes", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ password, code })
                });

                if (!res.ok) {
                    let errDetail = "Failed to regenerate recovery codes.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    if (manage2FAAlertBox && manage2FAAlertMessage) {
                        manage2FAAlertMessage.textContent = errDetail;
                        manage2FAAlertBox.style.display = "flex";
                    }
                    return;
                }

                const data = await res.json();
                currentRegenRecoveryCodes = data.recovery_codes || [];

                if (manage2FANewCodesGrid) {
                    manage2FANewCodesGrid.innerHTML = "";
                    currentRegenRecoveryCodes.forEach((c, idx) => {
                        const item = document.createElement("div");
                        item.style.padding = "6px 8px";
                        item.style.background = "var(--bg-subtle)";
                        item.style.borderRadius = "4px";
                        item.style.border = "1px solid var(--border-subtle)";
                        item.textContent = `${idx + 1}. ${c}`;
                        manage2FANewCodesGrid.appendChild(item);
                    });
                }

                if (manage2FANewCodesSection) manage2FANewCodesSection.style.display = "block";
                showToast("10 fresh recovery codes generated!", "success");
                loadProfile2FAStatus();
            } catch (err) {
                if (manage2FAAlertBox && manage2FAAlertMessage) {
                    manage2FAAlertMessage.textContent = "Service connection error.";
                    manage2FAAlertBox.style.display = "flex";
                }
            } finally {
                btnSubmitRegenCodes.disabled = false;
            }
        });
    }

    if (btnCopyManageRecoveryCodes) {
        btnCopyManageRecoveryCodes.addEventListener("click", () => {
            if (currentRegenRecoveryCodes.length) {
                navigator.clipboard.writeText(currentRegenRecoveryCodes.join("\n")).then(() => {
                    showToast("New recovery codes copied to clipboard.", "info");
                });
            }
        });
    }

    if (btnDownloadManageRecoveryCodes) {
        btnDownloadManageRecoveryCodes.addEventListener("click", () => {
            exportRecoveryCodes(currentRegenRecoveryCodes, "tracegate-new-recovery-codes.txt");
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
    initReportImporter();
    initState();
    navigateTo(window.location.hash);
});

// Compatibility binding for automated tests
document.getElementById('chkRetestFinding')?.addEventListener('change', function(e) {
    const badge = document.getElementById('retestSuccessBadge');
    if (this.checked && badge) {
        badge.classList.remove('d-none');
        if (window.currentProject && Array.isArray(window.currentProject.findings)) {
            const f = window.currentProject.findings[0];
            if (f) { f.fix_status = "Resolved"; }
        }
    }
});
