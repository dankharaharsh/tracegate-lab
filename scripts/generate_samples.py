import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "samples"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

WIDTH, HEIGHT = 1000, 680

def get_font(size=14, bold=False):
    candidates = [
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\calibri.ttf"
    ]
    if bold:
        candidates = [
            "C:\\Windows\\Fonts\\segoeuib.ttf",
            "C:\\Windows\\Fonts\\arialbd.ttf",
            "C:\\Windows\\Fonts\\calibrib.ttf"
        ] + candidates
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                pass
    return ImageFont.load_default()

def draw_browser_chrome(draw, url: str):
    draw.rectangle([0, 0, WIDTH, 48], fill="#1e293b")
    draw.ellipse([14, 18, 26, 30], fill="#ef4444")
    draw.ellipse([34, 18, 46, 30], fill="#f59e0b")
    draw.ellipse([54, 18, 66, 30], fill="#10b981")
    draw.rounded_rectangle([100, 10, WIDTH - 40, 38], radius=6, fill="#0f172a", outline="#334155")
    font = get_font(12)
    draw.text((120, 16), f"🔒 {url}", fill="#94a3b8", font=font)

def create_login_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0f172a")
    draw = ImageDraw.Draw(img)
    draw_browser_chrome(draw, "https://securecorp.internal/auth/login")

    card_x0, card_y0, card_x1, card_y1 = 280, 110, 720, 580
    draw.rounded_rectangle([card_x0, card_y0, card_x1, card_y1], radius=12, fill="#1e293b", outline="#334155", width=2)

    draw.text((360, 150), "SecureCorp Portal", fill="#38bdf8", font=get_font(24, bold=True))
    draw.text((345, 190), "Sign in to your corporate account", fill="#94a3b8", font=get_font(14))

    draw.text((320, 240), "Username or Corporate Email", fill="#e2e8f0", font=get_font(13, bold=True))
    draw.rounded_rectangle([320, 265, 680, 305], radius=6, fill="#0f172a", outline="#475569")
    draw.text((335, 277), "user@securecorp.internal", fill="#64748b", font=get_font(13))

    draw.text((320, 330), "Password", fill="#e2e8f0", font=get_font(13, bold=True))
    draw.rounded_rectangle([320, 355, 680, 395], radius=6, fill="#0f172a", outline="#475569")
    draw.text((335, 367), "••••••••••••••••", fill="#64748b", font=get_font(13))

    draw.rounded_rectangle([320, 420, 334, 434], radius=3, fill="#0f172a", outline="#64748b")
    draw.text((342, 420), "Remember this device", fill="#94a3b8", font=get_font(12))
    draw.text((560, 420), "Forgot password?", fill="#38bdf8", font=get_font(12))

    draw.rounded_rectangle([320, 465, 680, 510], radius=6, fill="#2563eb")
    draw.text((465, 477), "Sign In", fill="#ffffff", font=get_font(15, bold=True))

    draw.text((430, 535), "Or continue with Single Sign-On (SSO)", fill="#64748b", font=get_font(12))

    img.save(OUTPUT_DIR / "login.png")
    print("Saved login.png")

def create_registration_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#090d16")
    draw = ImageDraw.Draw(img)
    draw_browser_chrome(draw, "https://securecorp.internal/auth/register")

    card_x0, card_y0, card_x1, card_y1 = 250, 80, 750, 630
    draw.rounded_rectangle([card_x0, card_y0, card_x1, card_y1], radius=12, fill="#131b2e", outline="#25334d", width=2)

    draw.text((340, 110), "Create Security Account", fill="#10b981", font=get_font(22, bold=True))
    draw.text((350, 145), "Join the internal research platform", fill="#94a3b8", font=get_font(13))

    fields = [
        ("Full Name", "Alex Mercer", 185),
        ("Work Email", "alex.mercer@company.org", 255),
        ("Desired Username", "alexm_sec", 325),
        ("Master Password", "••••••••••••", 395),
        ("Confirm Password", "••••••••••••", 465),
    ]

    for label, placeholder, y in fields:
        draw.text((290, y), label, fill="#cbd5e1", font=get_font(12, bold=True))
        draw.rounded_rectangle([290, y + 20, 710, y + 52], radius=6, fill="#0a0f1d", outline="#334155")
        draw.text((305, y + 28), placeholder, fill="#475569", font=get_font(12))

    draw.rounded_rectangle([290, 535, 304, 549], radius=3, fill="#10b981")
    draw.text((312, 535), "I accept the Security Usage Terms & VAPT Policy", fill="#94a3b8", font=get_font(12))

    draw.rounded_rectangle([290, 565, 710, 605], radius=6, fill="#059669")
    draw.text((450, 575), "Create Account", fill="#ffffff", font=get_font(14, bold=True))

    img.save(OUTPUT_DIR / "registration.png")
    print("Saved registration.png")

def create_forgot_password_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0f172a")
    draw = ImageDraw.Draw(img)
    draw_browser_chrome(draw, "https://securecorp.internal/auth/password-recovery")

    card_x0, card_y0, card_x1, card_y1 = 260, 120, 740, 560
    draw.rounded_rectangle([card_x0, card_y0, card_x1, card_y1], radius=12, fill="#1e293b", outline="#334155", width=2)

    draw.text((360, 160), "Reset Your Password", fill="#f59e0b", font=get_font(22, bold=True))
    draw.text((310, 205), "Enter your registered email to receive a password reset link", fill="#94a3b8", font=get_font(13))

    draw.text((310, 260), "Corporate Email Address", fill="#e2e8f0", font=get_font(13, bold=True))
    draw.rounded_rectangle([310, 285, 690, 330], radius=6, fill="#0f172a", outline="#475569")
    draw.text((325, 298), "analyst@securecorp.internal", fill="#64748b", font=get_font(13))

    draw.rounded_rectangle([310, 355, 690, 420], radius=6, fill="#131e33", outline="#1e3a5f")
    draw.text((330, 370), "🛡️ Bot Verification: Cloudflare Turnstile / reCAPTCHA v3 Active", fill="#38bdf8", font=get_font(12))
    draw.text((330, 395), "IP address and request origin will be verified prior to token dispatch.", fill="#64748b", font=get_font(11))

    draw.rounded_rectangle([310, 445, 690, 490], radius=6, fill="#d97706")
    draw.text((450, 458), "Send Reset Link", fill="#ffffff", font=get_font(14, bold=True))
    draw.text((440, 515), "← Back to Login Portal", fill="#38bdf8", font=get_font(12))

    img.save(OUTPUT_DIR / "forgot_password.png")
    print("Saved forgot_password.png")

def create_profile_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0b1120")
    draw = ImageDraw.Draw(img)
    draw_browser_chrome(draw, "https://securecorp.internal/dashboard/settings/profile")

    draw.rectangle([0, 48, WIDTH, 100], fill="#131d33")
    draw.text((40, 65), "SecureCorp Console", fill="#38bdf8", font=get_font(16, bold=True))
    draw.text((800, 65), "Role: SecOps Analyst #4092", fill="#10b981", font=get_font(12))

    draw.rounded_rectangle([50, 120, 950, 640], radius=10, fill="#1a243b", outline="#2c3a58")
    draw.text((80, 140), "Account & Profile Settings", fill="#f8fafc", font=get_font(20, bold=True))

    draw.ellipse([80, 190, 160, 270], fill="#2563eb")
    draw.text((107, 215), "HM", fill="#ffffff", font=get_font(22, bold=True))
    draw.rounded_rectangle([180, 215, 290, 245], radius=5, fill="#334155")
    draw.text((195, 222), "Change Avatar", fill="#e2e8f0", font=get_font(11, bold=True))

    draw.text((80, 295), "Display Name", fill="#94a3b8", font=get_font(12, bold=True))
    draw.rounded_rectangle([80, 315, 460, 350], radius=5, fill="#0f172a", outline="#334155")
    draw.text((95, 325), "Harsh (Lead Assessor)", fill="#f1f5f9", font=get_font(12))

    draw.text((80, 375), "Email Address (Verified)", fill="#94a3b8", font=get_font(12, bold=True))
    draw.rounded_rectangle([80, 395, 460, 430], radius=5, fill="#0f172a", outline="#334155")
    draw.text((95, 405), "harsh@securecorp.internal", fill="#94a3b8", font=get_font(12))

    draw.text((80, 455), "Bio / Security Focus", fill="#94a3b8", font=get_font(12, bold=True))
    draw.rounded_rectangle([80, 475, 460, 550], radius=5, fill="#0f172a", outline="#334155")
    draw.text((95, 485), "Web Application VAPT, OWASP Top 10, API testing.", fill="#cbd5e1", font=get_font(12))

    draw.text((500, 190), "Security & Authentication", fill="#f8fafc", font=get_font(15, bold=True))
    draw.text((500, 230), "Current Password", fill="#94a3b8", font=get_font(12))
    draw.rounded_rectangle([500, 250, 890, 285], radius=5, fill="#0f172a", outline="#334155")
    draw.text((515, 260), "••••••••••••••••", fill="#64748b", font=get_font(12))

    draw.text((500, 305), "New Password", fill="#94a3b8", font=get_font(12))
    draw.rounded_rectangle([500, 325, 890, 360], radius=5, fill="#0f172a", outline="#334155")
    draw.text((515, 335), "••••••••••••••••", fill="#64748b", font=get_font(12))

    draw.rounded_rectangle([80, 580, 220, 615], radius=6, fill="#2563eb")
    draw.text((110, 590), "Save Changes", fill="#ffffff", font=get_font(13, bold=True))

    img.save(OUTPUT_DIR / "profile.png")
    print("Saved profile.png")

def create_file_upload_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#080d1a")
    draw = ImageDraw.Draw(img)
    draw_browser_chrome(draw, "https://securecorp.internal/documents/upload-portal")

    card_x0, card_y0, card_x1, card_y1 = 180, 90, 820, 620
    draw.rounded_rectangle([card_x0, card_y0, card_x1, card_y1], radius=12, fill="#111827", outline="#1f293d", width=2)

    draw.text((310, 120), "Evidence & Document Upload", fill="#a855f7", font=get_font(22, bold=True))
    draw.text((280, 160), "Submit assessment artifacts, report attachments, or binary logs", fill="#94a3b8", font=get_font(13))

    drop_x0, drop_y0, drop_x1, drop_y1 = 220, 200, 780, 420
    draw.rounded_rectangle([drop_x0, drop_y0, drop_x1, drop_y1], radius=10, fill="#172138", outline="#4c1d95", width=2)

    draw.text((475, 240), "📁", fill="#c084fc", font=get_font(36))
    draw.text((360, 300), "Drag and drop your document or evidence here", fill="#e2e8f0", font=get_font(14, bold=True))
    draw.text((410, 330), "Supported formats: PDF, PNG, JPG, DOCX", fill="#94a3b8", font=get_font(12))

    draw.rounded_rectangle([420, 360, 580, 395], radius=5, fill="#7e22ce")
    draw.text((460, 370), "Browse Files...", fill="#ffffff", font=get_font(12, bold=True))

    draw.text((230, 440), "Max upload limit: 25MB per file • Direct S3 multipart upload enabled", fill="#64748b", font=get_font(12))

    draw.rounded_rectangle([550, 505, 780, 540], radius=6, fill="#9333ea")
    draw.text((615, 515), "Upload & Process", fill="#ffffff", font=get_font(13, bold=True))

    img.save(OUTPUT_DIR / "file_upload.png")
    print("Saved file_upload.png")

def create_settings_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0b1220")
    draw = ImageDraw.Draw(img)
    draw_browser_chrome(draw, "https://securecorp.internal/settings/security")

    draw.text((60, 75), "Security & Privacy Settings", fill="#38bdf8", font=get_font(22, bold=True))
    draw.text((60, 110), "Configure multi-factor authentication, active sessions, and access keys", fill="#94a3b8", font=get_font(13))

    # Box 1: 2FA
    draw.rounded_rectangle([60, 150, 940, 290], radius=8, fill="#152033", outline="#223354")
    draw.text((85, 170), "Two-Factor Authentication (2FA)", fill="#f8fafc", font=get_font(16, bold=True))
    draw.text((85, 198), "Protect your account with Time-Based One-Time Password (TOTP) verification.", fill="#94a3b8", font=get_font(12))
    draw.rounded_rectangle([85, 230, 230, 265], radius=6, fill="#059669")
    draw.text((105, 240), "✓ 2FA Enabled", fill="#ffffff", font=get_font(12, bold=True))
    draw.rounded_rectangle([250, 230, 430, 265], radius=6, fill="#1e293b", outline="#475569")
    draw.text((270, 240), "View Recovery Codes", fill="#cbd5e1", font=get_font(12))

    # Box 2: Sessions
    draw.rounded_rectangle([60, 310, 940, 470], radius=8, fill="#152033", outline="#223354")
    draw.text((85, 330), "Active Logged-In Sessions", fill="#f8fafc", font=get_font(16, bold=True))
    draw.text((85, 360), "• Chrome 128 on Windows 11 (Current Session) — IP 192.168.1.104", fill="#10b981", font=get_font(12))
    draw.text((85, 390), "• Mobile Safari on iOS 17.5 — IP 10.24.8.42 (Last active 2 hrs ago)", fill="#94a3b8", font=get_font(12))
    draw.rounded_rectangle([85, 420, 270, 455], radius=6, fill="#b91c1c")
    draw.text((105, 430), "Log Out All Devices", fill="#ffffff", font=get_font(12, bold=True))

    # Box 3: API Tokens
    draw.rounded_rectangle([60, 490, 940, 630], radius=8, fill="#152033", outline="#223354")
    draw.text((85, 510), "Personal API Tokens", fill="#f8fafc", font=get_font(16, bold=True))
    draw.text((85, 538), "Generate personal bearer tokens to access automation and VAPT API endpoints.", fill="#94a3b8", font=get_font(12))
    draw.rounded_rectangle([85, 570, 260, 605], radius=6, fill="#2563eb")
    draw.text((105, 580), "+ Generate New Token", fill="#ffffff", font=get_font(12, bold=True))

    img.save(OUTPUT_DIR / "settings.png")
    print("Saved settings.png")

def create_dashboard_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#090e1a")
    draw = ImageDraw.Draw(img)
    draw_browser_chrome(draw, "https://securecorp.internal/dashboard")

    # Top search bar
    draw.rounded_rectangle([60, 65, 500, 100], radius=6, fill="#131d33", outline="#243454")
    draw.text((80, 75), "🔍 Search scans, targets, reports, and audit logs...", fill="#64748b", font=get_font(12))

    draw.rounded_rectangle([750, 65, 940, 100], radius=6, fill="#2563eb")
    draw.text((790, 75), "+ Launch New Scan", fill="#ffffff", font=get_font(12, bold=True))

    # Metrics
    metrics = [
        ("Total Targets", "128", "#38bdf8", 60),
        ("High/Crit Vulns", "34", "#ef4444", 290),
        ("Completed Audits", "892", "#10b981", 520),
        ("Active Nodes", "12", "#f59e0b", 750)
    ]
    for title, val, color, x in metrics:
        draw.rounded_rectangle([x, 120, x + 190, 200], radius=8, fill="#131d33", outline="#223354")
        draw.text((x + 20, 135), title, fill="#94a3b8", font=get_font(11, bold=True))
        draw.text((x + 20, 155), val, fill=color, font=get_font(24, bold=True))

    # Activity Table
    draw.rounded_rectangle([60, 220, 940, 630], radius=8, fill="#131d33", outline="#223354")
    draw.text((85, 240), "Recent VAPT Assessment Activities", fill="#f8fafc", font=get_font(16, bold=True))

    headers = ["TARGET URL", "ASSESSOR", "STATUS", "FINDINGS", "ACTIONS"]
    xs = [85, 340, 520, 680, 830]
    for h, x in zip(headers, xs):
        draw.text((x, 280), h, fill="#64748b", font=get_font(11, bold=True))

    rows = [
        ("api.payment-gateway.internal", "Harsh M.", "COMPLETED", "3 Critical", 315),
        ("auth-sso.corp.internal", "Alex R.", "IN PROGRESS", "1 High", 365),
        ("portal.staging.internal", "DevSecTeam", "SCHEDULED", "Pending", 415),
        ("docs.internal-share.org", "Harsh M.", "COMPLETED", "0 Found", 465),
    ]
    for url, user, stat, finds, y in rows:
        draw.text((85, y), url, fill="#cbd5e1", font=get_font(12))
        draw.text((340, y), user, fill="#94a3b8", font=get_font(12))
        draw.text((520, y), stat, fill="#38bdf8", font=get_font(11, bold=True))
        draw.text((680, y), finds, fill="#f87171" if "Crit" in finds else "#10b981", font=get_font(11, bold=True))
        draw.text((830, y), "View ↗", fill="#38bdf8", font=get_font(11))

    img.save(OUTPUT_DIR / "dashboard.png")
    print("Saved dashboard.png")

def create_search_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#0a0f1d")
    draw = ImageDraw.Draw(img)
    draw_browser_chrome(draw, "https://securecorp.internal/vulnerabilities/search?q=injection&category=cwe")

    # Big search bar
    draw.rounded_rectangle([60, 70, 800, 115], radius=8, fill="#121b2d", outline="#3b82f6", width=2)
    draw.text((85, 82), "injection vulnerability payloads AND cwe:89", fill="#f8fafc", font=get_font(14))
    draw.rounded_rectangle([820, 70, 940, 115], radius=8, fill="#2563eb")
    draw.text((855, 83), "Search", fill="#ffffff", font=get_font(14, bold=True))

    # Filters Left Sidebar
    draw.rounded_rectangle([60, 140, 280, 630], radius=8, fill="#121b2d", outline="#1e293b")
    draw.text((80, 160), "Filter Facets", fill="#38bdf8", font=get_font(14, bold=True))
    draw.text((80, 200), "CWE Category", fill="#cbd5e1", font=get_font(12, bold=True))
    draw.text((95, 230), "☑ CWE-89 (SQLi)", fill="#94a3b8", font=get_font(11))
    draw.text((95, 260), "☐ CWE-79 (XSS)", fill="#94a3b8", font=get_font(11))
    draw.text((95, 290), "☐ CWE-78 (Cmd Inj)", fill="#94a3b8", font=get_font(11))

    draw.text((80, 340), "Severity Level", fill="#cbd5e1", font=get_font(12, bold=True))
    draw.text((95, 370), "☑ Critical", fill="#f43f5e", font=get_font(11))
    draw.text((95, 400), "☑ High", fill="#fb923c", font=get_font(11))
    draw.text((95, 430), "☐ Medium", fill="#fbbf24", font=get_font(11))

    # Results Right Column
    draw.text((310, 145), "Found 142 Security Records for 'injection'", fill="#94a3b8", font=get_font(12))

    res_items = [
        ("SQL Injection via Authenticated Query Parameter", "CWE-89 • High Severity • Database Access", 180),
        ("Blind NoSQL Operator Injection in JSON Body", "CWE-943 • Critical Severity • Authentication Bypass", 280),
        ("Command Injection in Network Diagnostic Tool", "CWE-78 • Critical Severity • Remote Code Execution", 380),
        ("Second-Order SQL Injection in User Profile Name", "CWE-89 • Medium Severity • Data Exfiltration", 480),
    ]

    for title, meta, y in res_items:
        draw.rounded_rectangle([310, y, 940, y + 80], radius=8, fill="#121b2d", outline="#1e293b")
        draw.text((330, y + 15), title, fill="#f8fafc", font=get_font(13, bold=True))
        draw.text((330, y + 42), meta, fill="#64748b", font=get_font(11))

    # Pagination
    draw.text((580, 595), "Page: [ 1 ]  2   3   4 ...  Next »", fill="#38bdf8", font=get_font(12, bold=True))

    img.save(OUTPUT_DIR / "search.png")
    print("Saved search.png")

def create_checkout_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#090e17")
    draw = ImageDraw.Draw(img)
    draw_browser_chrome(draw, "https://store.securecorp.internal/checkout/order-summary")

    draw.text((60, 70), "Checkout & Order Finalization", fill="#38bdf8", font=get_font(22, bold=True))

    # Left: Billing & Payment Card
    draw.rounded_rectangle([60, 115, 580, 630], radius=10, fill="#131c2d", outline="#22324f")
    draw.text((90, 140), "Payment Method", fill="#f8fafc", font=get_font(16, bold=True))

    fields = [
        ("Cardholder Full Name", "Jane Doe", 180),
        ("Card Number (Credit / Debit)", "4111 •••• •••• 9021", 255),
        ("Expiration Date (MM/YY)", "08/29", 330),
        ("Security Code (CVV)", "•••", 405),
        ("Billing Street Address", "100 Security Blvd, Suite 400", 480)
    ]
    for label, val, y in fields:
        draw.text((90, y), label, fill="#94a3b8", font=get_font(11, bold=True))
        draw.rounded_rectangle([90, y + 20, 550, y + 55], radius=6, fill="#0a101b", outline="#334155")
        draw.text((105, y + 28), val, fill="#cbd5e1", font=get_font(12))

    draw.rounded_rectangle([90, 565, 550, 605], radius=6, fill="#10b981")
    draw.text((250, 575), "🔒 Complete Payment ($1,299.00)", fill="#ffffff", font=get_font(14, bold=True))

    # Right: Order Summary
    draw.rounded_rectangle([610, 115, 940, 480], radius=10, fill="#131c2d", outline="#22324f")
    draw.text((635, 140), "Order Summary", fill="#f8fafc", font=get_font(16, bold=True))
    draw.text((635, 180), "Tracegate VAPT Pro - 1 Year License", fill="#cbd5e1", font=get_font(12, bold=True))
    draw.text((860, 180), "$1,200.00", fill="#f8fafc", font=get_font(12))
    draw.text((635, 210), "Standard Cloud Sandboxing Addon", fill="#94a3b8", font=get_font(12))
    draw.text((880, 210), "$99.00", fill="#f8fafc", font=get_font(12))

    # Promo Code input
    draw.text((635, 270), "Discount / Voucher Code", fill="#94a3b8", font=get_font(11, bold=True))
    draw.rounded_rectangle([635, 290, 820, 325], radius=6, fill="#0a101b", outline="#334155")
    draw.text((645, 298), "SUMMERVAPT20", fill="#38bdf8", font=get_font(11))
    draw.rounded_rectangle([830, 290, 915, 325], radius=6, fill="#2563eb")
    draw.text((850, 298), "Apply", fill="#ffffff", font=get_font(11, bold=True))

    draw.line([635, 360, 915, 360], fill="#334155", width=1)
    draw.text((635, 385), "Total Due Today:", fill="#f8fafc", font=get_font(15, bold=True))
    draw.text((840, 385), "$1,299.00", fill="#10b981", font=get_font(16, bold=True))

    img.save(OUTPUT_DIR / "checkout.png")
    print("Saved checkout.png")

def create_admin_panel_page():
    img = Image.new("RGB", (WIDTH, HEIGHT), "#080c14")
    draw = ImageDraw.Draw(img)
    draw_browser_chrome(draw, "https://securecorp.internal/admin/console/users-and-roles")

    # Header
    draw.text((60, 70), "Global Administration & RBAC Console", fill="#f43f5e", font=get_font(20, bold=True))
    draw.text((60, 100), "Manage user permissions, enterprise tenants, and system debug audit logs", fill="#94a3b8", font=get_font(12))

    # Action Toolbar
    draw.rounded_rectangle([60, 130, 220, 165], radius=6, fill="#e11d48")
    draw.text((80, 140), "+ Invite Superuser", fill="#ffffff", font=get_font(12, bold=True))

    draw.rounded_rectangle([240, 130, 420, 165], radius=6, fill="#1e293b", outline="#475569")
    draw.text((260, 140), "Export Full Audit Log (CSV)", fill="#cbd5e1", font=get_font(11))

    # User Management Table
    draw.rounded_rectangle([60, 185, 940, 630], radius=10, fill="#111827", outline="#1f293d")
    draw.text((85, 205), "Active System Accounts & Privilege Matrix", fill="#f8fafc", font=get_font(14, bold=True))

    headers = ["USER ID", "ACCOUNT NAME", "ASSIGNED ROLE", "2FA STATUS", "ADMIN ACTIONS"]
    xs = [85, 220, 450, 650, 800]
    for h, x in zip(headers, xs):
        draw.text((x, 245), h, fill="#64748b", font=get_font(11, bold=True))

    rows = [
        ("USR-001", "root_admin@securecorp.internal", "SuperAdmin (All Grants)", "ENFORCED", 285),
        ("USR-042", "sarah.lead@securecorp.internal", "Auditor / Assessor", "ENFORCED", 345),
        ("USR-108", "contractor_temp@partner.org", "External Pentester", "DISABLED", 405),
        ("USR-999", "service_daemon_cron", "API Service Agent", "N/A (Key Only)", 465),
    ]

    for uid, name, role, tfa, y in rows:
        draw.text((85, y), uid, fill="#38bdf8", font=get_font(11))
        draw.text((220, y), name, fill="#cbd5e1", font=get_font(12))
        draw.text((450, y), role, fill="#f59e0b" if "Super" in role else "#94a3b8", font=get_font(11, bold=True))
        draw.text((650, y), tfa, fill="#10b981" if tfa == "ENFORCED" else "#ef4444", font=get_font(11, bold=True))
        draw.text((800, y), "[Edit]  [Revoke]", fill="#f43f5e", font=get_font(11))

    img.save(OUTPUT_DIR / "admin_panel.png")
    print("Saved admin_panel.png")

def create_ambiguous_page():
    # An abstract diagram with no web application inputs or browser chrome
    img = Image.new("RGB", (WIDTH, HEIGHT), "#18181b")
    draw = ImageDraw.Draw(img)

    draw.text((250, 100), "Abstract System Dataflow Architecture", fill="#a1a1aa", font=get_font(20, bold=True))

    # Flowchart boxes
    boxes = [
        (150, 220, 350, 320, "Sensor Node A\nTelemetry Source", "#27272a"),
        (450, 220, 650, 320, "Stream Aggregator\nKafka Queue", "#27272a"),
        (750, 220, 950, 320, "Time-Series Store\nInfluxDB Cluster", "#27272a")
    ]
    for x0, y0, x1, y1, label, color in boxes:
        draw.rounded_rectangle([x0, y0, x1, y1], radius=10, fill=color, outline="#3f3f46", width=2)
        draw.text((x0 + 25, y0 + 35), label, fill="#f4f4f5", font=get_font(14))

    # Arrows
    draw.line([350, 270, 450, 270], fill="#38bdf8", width=3)
    draw.line([650, 270, 750, 270], fill="#38bdf8", width=3)

    draw.text((320, 450), "Non-interactive conceptual diagram without web form controls", fill="#71717a", font=get_font(13))

    img.save(OUTPUT_DIR / "ambiguous.png")
    print("Saved ambiguous.png")

if __name__ == "__main__":
    create_login_page()
    create_registration_page()
    create_forgot_password_page()
    create_profile_page()
    create_file_upload_page()
    create_settings_page()
    create_dashboard_page()
    create_search_page()
    create_checkout_page()
    create_admin_panel_page()
    create_ambiguous_page()
    print("All 10 + 1 sample screenshots generated successfully!")
