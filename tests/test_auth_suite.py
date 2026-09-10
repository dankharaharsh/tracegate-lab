import io
import os
import sys
import time
import uuid
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to sys.path
BASE_DIR = Path(r"C:\Users\Harsh\Desktop\tracegate")
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend.database import (
    get_db_connection,
    init_db,
    hash_password,
    verify_password,
    seed_default_users_if_empty
)

client = TestClient(app)

def run_all_auth_tests():
    print("================================================================")
    print(" TRACEGATE COMPREHENSIVE AUTHENTICATION TEST SUITE (18 CASES)")
    print("================================================================")

    init_db()
    seed_default_users_if_empty()

    uid = uuid.uuid4().hex[:8]
    test_username = f"authtest_{uid}"
    test_email = f"authtest_{uid}@tracegate.lab"
    test_password = "SecurePassword123!"
    test_fullname = f"Auth Tester {uid}"

    # TEST 1: User Registration with Valid Data
    print("\n[TEST 1] User Registration with Valid Data...")
    reg_resp = client.post("/api/auth/register", json={
        "username": test_username,
        "email": test_email,
        "password": test_password,
        "full_name": test_fullname,
        "role": "Junior Pentester"
    })
    assert reg_resp.status_code == 201, f"Expected 201, got {reg_resp.status_code}: {reg_resp.text}"
    reg_data = reg_resp.json()
    assert "access_token" in reg_data
    assert "user" in reg_data
    assert reg_data["user"]["username"] == test_username.lower()
    assert reg_data["user"]["email"] == test_email.lower()
    assert reg_data["user"]["full_name"] == test_fullname
    assert reg_data["user"]["name"] == test_fullname
    print(f"  [PASS] Registered user {test_username} successfully with token.")

    # TEST 2: Duplicate Username Rejected
    print("\n[TEST 2] Duplicate Username Rejected...")
    dup_u_resp = client.post("/api/auth/register", json={
        "username": test_username,
        "email": f"diff_{uid}@tracegate.lab",
        "password": "OtherPassword123!",
        "full_name": "Duplicate User"
    })
    assert dup_u_resp.status_code == 409, f"Expected 409, got {dup_u_resp.status_code}: {dup_u_resp.text}"
    assert "already taken" in dup_u_resp.json()["detail"].lower()
    print("  [PASS] Duplicate username correctly rejected with 409 Conflict.")

    # TEST 3: Duplicate Email Rejected
    print("\n[TEST 3] Duplicate Email Rejected...")
    dup_e_resp = client.post("/api/auth/register", json={
        "username": f"diff_{uid}",
        "email": test_email,
        "password": "OtherPassword123!",
        "full_name": "Duplicate Email"
    })
    assert dup_e_resp.status_code == 409, f"Expected 409, got {dup_e_resp.status_code}: {dup_e_resp.text}"
    assert "already registered" in dup_e_resp.json()["detail"].lower()
    print("  [PASS] Duplicate email correctly rejected with 409 Conflict.")

    # TEST 4: Case-Insensitive Uniqueness Enforcement
    print("\n[TEST 4] Case-Insensitive Uniqueness Enforcement...")
    upper_u_resp = client.post("/api/auth/register", json={
        "username": test_username.upper(),
        "email": f"another_{uid}@tracegate.lab",
        "password": "OtherPassword123!",
        "full_name": "Case Bypass User"
    })
    assert upper_u_resp.status_code == 409, f"Expected 409, got {upper_u_resp.status_code}"
    upper_e_resp = client.post("/api/auth/register", json={
        "username": f"another_u_{uid}",
        "email": test_email.upper(),
        "password": "OtherPassword123!",
        "full_name": "Case Bypass Email"
    })
    assert upper_e_resp.status_code == 409, f"Expected 409, got {upper_e_resp.status_code}"
    print("  [PASS] Case variations (e.g. UPPERCASE) correctly rejected.")

    # TEST 5: Login with Username
    print("\n[TEST 5] Login with Username...")
    login_u = client.post("/api/auth/login", json={
        "username_or_email": test_username,
        "password": test_password
    })
    assert login_u.status_code == 200, f"Expected 200, got {login_u.status_code}: {login_u.text}"
    u_data = login_u.json()
    assert u_data["user"]["username"] == test_username.lower()
    assert u_data["user"]["name"] == test_fullname
    token_u = u_data["access_token"]
    print(f"  [PASS] Logged in using username {test_username}.")

    # TEST 6: Login with Email
    print("\n[TEST 6] Login with Email...")
    login_e = client.post("/api/auth/login", json={
        "username_or_email": test_email,
        "password": test_password
    })
    assert login_e.status_code == 200, f"Expected 200, got {login_e.status_code}: {login_e.text}"
    e_data = login_e.json()
    assert e_data["user"]["email"] == test_email.lower()
    print(f"  [PASS] Logged in using email {test_email}.")

    # TEST 7: Login Case-Insensitivity
    print("\n[TEST 7] Login Case-Insensitivity...")
    login_upper = client.post("/api/auth/login", json={
        "username_or_email": test_email.upper(),
        "password": test_password
    })
    assert login_upper.status_code == 200, f"Expected 200, got {login_upper.status_code}"
    print("  [PASS] Uppercase email logged in successfully.")

    # TEST 8: Login with Wrong Password
    print("\n[TEST 8] Login with Wrong Password...")
    login_wrong = client.post("/api/auth/login", json={
        "username_or_email": test_username,
        "password": "DefinatelyWrongPassword!"
    })
    assert login_wrong.status_code == 401, f"Expected 401, got {login_wrong.status_code}"
    assert "invalid email/username or password" in login_wrong.json()["detail"].lower()
    print("  [PASS] Wrong password rejected with 401 Unauthorized.")

    # TEST 9: Login with Non-Existent User
    print("\n[TEST 9] Login with Non-Existent User...")
    login_ghost = client.post("/api/auth/login", json={
        "username_or_email": "non_existent_ghost_user_9999",
        "password": "SomePassword123!"
    })
    assert login_ghost.status_code == 401, f"Expected 401, got {login_ghost.status_code}"
    print("  [PASS] Non-existent user rejected with 401 Unauthorized.")

    # TEST 10: scrypt Password Hashing in SQLite
    print("\n[TEST 10] scrypt Password Hashing in SQLite...")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (test_username.lower(),))
    row = cursor.fetchone()
    conn.close()
    assert row is not None
    stored_hash = row["password_hash"]
    assert stored_hash.startswith("scrypt$"), f"Expected scrypt hash, got {stored_hash}"
    assert test_password not in stored_hash
    parts = stored_hash.split("$")
    assert len(parts) == 6
    assert parts[1] == "16384"
    assert parts[2] == "8"
    assert parts[3] == "1"
    print(f"  [PASS] Password stored with memory-hard scrypt: {stored_hash[:32]}...")

    # TEST 11: Database Persistence Across Connections
    print("\n[TEST 11] Database Persistence Across Connections...")
    conn2 = get_db_connection()
    cursor2 = conn2.cursor()
    cursor2.execute("SELECT id, username, email, full_name FROM users WHERE username = ?", (test_username.lower(),))
    persisted = cursor2.fetchone()
    conn2.close()
    assert persisted is not None
    assert persisted["email"] == test_email.lower()
    print("  [PASS] User record reliably persisted in SQLite tracegate.db.")

    # TEST 12: Session Generation & /api/auth/me Profile Verification
    print("\n[TEST 12] Session Generation & /api/auth/me Profile Verification...")
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_u}"})
    assert me_resp.status_code == 200, f"Expected 200, got {me_resp.status_code}: {me_resp.text}"
    me_data = me_resp.json()
    assert me_data["username"] == test_username.lower()
    assert me_data["name"] == test_fullname
    assert me_data["full_name"] == test_fullname
    print(f"  [PASS] /api/auth/me validated session: {me_data['name']} ({me_data['email']}).")

    # TEST 13: Invalid / Expired Session Token Rejection
    print("\n[TEST 13] Invalid / Expired Session Token Rejection...")
    invalid_me = client.get("/api/auth/me", headers={"Authorization": "Bearer fake_token_1234567890"})
    assert invalid_me.status_code == 401, f"Expected 401, got {invalid_me.status_code}"
    no_auth_me = client.get("/api/auth/me")
    assert no_auth_me.status_code == 401
    print("  [PASS] Invalid and missing session tokens rejected with 401.")

    # TEST 14: Logout Invalidates Session
    print("\n[TEST 14] Logout Invalidates Session...")
    logout_resp = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token_u}"})
    assert logout_resp.status_code == 200
    post_logout_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_u}"})
    assert post_logout_me.status_code == 401, f"Expected 401 after logout, got {post_logout_me.status_code}"
    print("  [PASS] Session successfully invalidated upon logout.")

    # TEST 15: Forgot Password Generates Reset Token
    print("\n[TEST 15] Forgot Password Generates Reset Token...")
    forgot_resp = client.post("/api/auth/forgot-password", json={"email": test_email})
    assert forgot_resp.status_code == 200, f"Expected 200, got {forgot_resp.status_code}: {forgot_resp.text}"
    forgot_data = forgot_resp.json()
    assert "reset_token" in forgot_data
    reset_token = forgot_data["reset_token"]
    assert reset_token is not None and len(reset_token) > 16
    print(f"  [PASS] Reset token generated: {reset_token[:18]}...")

    # TEST 16: Reset Password Updates Password & Enables Login
    print("\n[TEST 16] Reset Password Updates Password & Enables Login...")
    new_test_password = "BrandNewPassword2026!"
    reset_resp = client.post("/api/auth/reset-password", json={
        "token": reset_token,
        "new_password": new_test_password
    })
    assert reset_resp.status_code == 200, f"Expected 200, got {reset_resp.status_code}: {reset_resp.text}"

    old_login = client.post("/api/auth/login", json={
        "username_or_email": test_username,
        "password": test_password
    })
    assert old_login.status_code == 401, "Old password should not work after reset!"

    new_login = client.post("/api/auth/login", json={
        "username_or_email": test_username,
        "password": new_test_password
    })
    assert new_login.status_code == 200, f"Expected 200 with new password, got {new_login.status_code}"
    print("  [PASS] Password successfully changed. Old password revoked; new password authenticates.")

    # TEST 17: Reset Password Token Cannot Be Reused
    print("\n[TEST 17] Reset Password Token Single-Use (Replay Prevention)...")
    reuse_resp = client.post("/api/auth/reset-password", json={
        "token": reset_token,
        "new_password": "YetAnotherPassword123!"
    })
    assert reuse_resp.status_code == 400, f"Expected 400 on reused token, got {reuse_resp.status_code}"
    assert "already been used" in reuse_resp.json()["detail"].lower()
    print("  [PASS] Single-use enforcement confirmed: used reset token rejected.")

    # TEST 18: Expired Reset Token Rejection
    print("\n[TEST 18] Expired Reset Token Rejection...")
    forgot2 = client.post("/api/auth/forgot-password", json={"email": test_email})
    tok2 = forgot2.json()["reset_token"]

    conn_exp = get_db_connection()
    c_exp = conn_exp.cursor()
    past_time = (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    import hashlib
    tok2_hash = hashlib.sha256(tok2.encode("utf-8")).hexdigest()
    c_exp.execute("UPDATE password_resets SET expires_at = ? WHERE token_hash = ?", (past_time, tok2_hash))
    conn_exp.commit()
    conn_exp.close()

    expired_resp = client.post("/api/auth/reset-password", json={
        "token": tok2,
        "new_password": "ExpiredTokenTestPassword123!"
    })
    assert expired_resp.status_code == 400, f"Expected 400 on expired token, got {expired_resp.status_code}"
    assert "expired" in expired_resp.json()["detail"].lower()
    print("  [PASS] Expired reset token correctly rejected.")

    print("\n================================================================")
    print(" ALL 18 AUTHENTICATION TESTS PASSED WITH 100% SUCCESS!")
    print("================================================================")

if __name__ == "__main__":
    run_all_auth_tests()
