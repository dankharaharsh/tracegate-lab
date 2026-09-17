import os
import sys
import unittest
import time
import pyotp
from datetime import datetime
from fastapi.testclient import TestClient

# Ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app import app
from backend.database import (
    init_db,
    get_db_connection,
    get_user_by_id_raw,
    get_user_2fa_status,
    delete_user_sessions
)
from backend.totp_service import (
    decrypt_secret,
    encrypt_secret,
    verify_totp_code,
    hash_recovery_code
)

class TestTracegate2FASuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        # Register a unique user for each test to ensure complete isolation
        self.username = f"tester_{int(time.time()*1000)}"
        self.email = f"{self.username}@test.lab"
        self.password = "Secur3Password!2026"
        
        reg_res = self.client.post("/api/auth/register", json={
            "email": self.email,
            "username": self.username,
            "password": self.password,
            "full_name": "Test User",
            "role": "Security Learner"
        })
        self.assertEqual(reg_res.status_code, 201)
        data = reg_res.json()
        self.token = data["access_token"]
        self.user_id = data["user"]["id"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    # 1. Default user has 2FA disabled
    def test_01_default_user_2fa_disabled(self):
        status_res = self.client.get("/api/auth/2fa/status", headers=self.headers)
        self.assertEqual(status_res.status_code, 200)
        data = status_res.json()
        self.assertFalse(data["enabled"])
        self.assertEqual(data["recovery_codes_remaining"], 0)

        # In DB
        raw = get_user_by_id_raw(self.user_id)
        self.assertEqual(raw.get("two_factor_enabled"), 0)
        self.assertIsNone(raw.get("two_factor_secret_encrypted"))

    # 2. Setup generates secret, manual entry key, and base64 PNG QR code
    def test_02_setup_generates_secret_and_qr(self):
        res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("secret", data)
        self.assertEqual(len(data["secret"]), 32)
        self.assertIn("qr_code", data)
        self.assertTrue(data["qr_code"].startswith("data:image/png;base64,"))
        self.assertIn("manual_entry_key", data)
        self.assertIn("expires_at", data)

    # 3. Setup remains pending until confirmed
    def test_03_setup_remains_pending_until_verified(self):
        # Call setup
        self.client.post("/api/auth/2fa/setup", headers=self.headers)
        
        # User status must still be disabled
        st_res = self.client.get("/api/auth/2fa/status", headers=self.headers)
        self.assertFalse(st_res.json()["enabled"])

        # Login must still work normally without 2FA
        login_res = self.client.post("/api/auth/login", json={
            "username_or_email": self.username,
            "password": self.password
        })
        self.assertEqual(login_res.status_code, 200)
        self.assertFalse(login_res.json().get("requires_2fa"))
        self.assertIsNotNone(login_res.json().get("access_token"))

    # 4. Secret is encrypted at rest in SQLite
    def test_04_secret_encrypted_at_rest(self):
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]

        # Check pending enrollment in DB
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT secret_encrypted FROM two_factor_pending_enrollments WHERE user_id = ?", (self.user_id,))
        row = cur.fetchone()
        conn.close()
        self.assertIsNotNone(row)
        encrypted_val = row["secret_encrypted"]
        
        # Encrypted ciphertext must not equal raw base32 secret
        self.assertNotEqual(encrypted_val, secret)
        self.assertTrue(encrypted_val.startswith("gAAAAA"))
        
        # Must decrypt cleanly to original secret
        decrypted = decrypt_secret(encrypted_val)
        self.assertEqual(decrypted, secret)

    # 5. Verify setup rejects invalid code
    def test_05_verify_setup_rejects_invalid_code(self):
        self.client.post("/api/auth/2fa/setup", headers=self.headers)
        res = self.client.post("/api/auth/2fa/verify-setup", json={"code": "000000"}, headers=self.headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid authenticator code", res.json()["detail"])

        # Status still disabled
        st = self.client.get("/api/auth/2fa/status", headers=self.headers).json()
        self.assertFalse(st["enabled"])

    # 6. Verify setup activates 2FA and returns 10 recovery codes
    def test_06_verify_setup_activates_2fa_and_issues_recovery_codes(self):
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        valid_code = pyotp.TOTP(secret).now()

        res = self.client.post("/api/auth/2fa/verify-setup", json={"code": valid_code}, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["recovery_codes"]), 10)
        for rc in data["recovery_codes"]:
            parts = rc.split("-")
            self.assertEqual(len(parts), 3)
            self.assertEqual(len(parts[0]), 4)

        # Status is now enabled
        st = self.client.get("/api/auth/2fa/status", headers=self.headers).json()
        self.assertTrue(st["enabled"])
        self.assertEqual(st["recovery_codes_remaining"], 10)

    # 7. Recovery codes are hashed at rest in DB
    def test_07_recovery_codes_hashed_at_rest(self):
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        valid_code = pyotp.TOTP(secret).now()
        data = self.client.post("/api/auth/2fa/verify-setup", json={"code": valid_code}, headers=self.headers).json()
        plaintext_codes = data["recovery_codes"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT code_hash, used_at FROM two_factor_recovery_codes WHERE user_id = ?", (self.user_id,))
        rows = cur.fetchall()
        conn.close()

        self.assertEqual(len(rows), 10)
        db_hashes = {r["code_hash"] for r in rows}
        for pc in plaintext_codes:
            # The plaintext must NEVER be in DB
            self.assertNotIn(pc, db_hashes)
            # Its sha256 hash must be in DB
            expected_hash = hash_recovery_code(pc)
            self.assertIn(expected_hash, db_hashes)

    # 8. Login challenge issued when 2FA enabled
    def test_08_login_challenge_issued_when_2fa_enabled(self):
        # Enable 2FA
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        self.client.post("/api/auth/2fa/verify-setup", json={"code": pyotp.TOTP(secret).now()}, headers=self.headers)

        # Attempt standard password login
        login_res = self.client.post("/api/auth/login", json={
            "username_or_email": self.username,
            "password": self.password
        })
        self.assertEqual(login_res.status_code, 200)
        data = login_res.json()
        self.assertTrue(data.get("requires_2fa"))
        self.assertIsNone(data.get("access_token"))
        self.assertIsNotNone(data.get("temp_token"))
        self.assertTrue(data["temp_token"].startswith("2fa_pend_"))

    # 9. Temporary challenge token cannot access protected APIs
    def test_09_temp_token_cannot_access_protected_apis(self):
        # Enable 2FA
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        self.client.post("/api/auth/2fa/verify-setup", json={"code": pyotp.TOTP(secret).now()}, headers=self.headers)

        # Get temp token
        login_res = self.client.post("/api/auth/login", json={
            "username_or_email": self.username,
            "password": self.password
        })
        temp_token = login_res.json()["temp_token"]

        # Call /api/auth/me with temp token -> MUST FAIL 401
        res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {temp_token}"})
        self.assertEqual(res.status_code, 401)

        # Call /api/projects with temp token -> MUST FAIL 401
        res2 = self.client.get("/api/projects", headers={"Authorization": f"Bearer {temp_token}"})
        # projects endpoint is public or checks token, let's check /api/auth/2fa/status
        res3 = self.client.get("/api/auth/2fa/status", headers={"Authorization": f"Bearer {temp_token}"})
        self.assertEqual(res3.status_code, 401)

    # 10. Login verify with valid TOTP code
    def test_10_login_verify_with_totp_code(self):
        # Enable 2FA
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        self.client.post("/api/auth/2fa/verify-setup", json={"code": pyotp.TOTP(secret).now()}, headers=self.headers)

        # Login challenge
        login_res = self.client.post("/api/auth/login", json={
            "username_or_email": self.username,
            "password": self.password
        })
        temp_token = login_res.json()["temp_token"]

        # Verify challenge
        totp_code = pyotp.TOTP(secret).now()
        v_res = self.client.post("/api/auth/2fa/login-verify", json={
            "temp_token": temp_token,
            "code": totp_code
        })
        self.assertEqual(v_res.status_code, 200)
        v_data = v_res.json()
        self.assertFalse(v_data.get("requires_2fa"))
        self.assertIsNotNone(v_data.get("access_token"))
        self.assertEqual(v_data["user"]["id"], self.user_id)

        # Use the returned session token to access protected API
        me = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {v_data['access_token']}"})
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["username"], self.username)

    # 11. Rate limiting on 2FA login verification (max 5 attempts)
    def test_11_login_verify_rate_limiting(self):
        # Enable 2FA
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        self.client.post("/api/auth/2fa/verify-setup", json={"code": pyotp.TOTP(secret).now()}, headers=self.headers)

        login_res = self.client.post("/api/auth/login", json={
            "username_or_email": self.username,
            "password": self.password
        })
        temp_token = login_res.json()["temp_token"]

        # Attempts 1 to 4 should return 401 with remaining count
        for attempt in range(1, 5):
            res = self.client.post("/api/auth/2fa/login-verify", json={
                "temp_token": temp_token,
                "code": "111111"
            })
            self.assertEqual(res.status_code, 401)
            self.assertIn(f"{5 - attempt} attempt(s) remaining", res.json()["detail"])

        # Attempt 5 should trigger rate limit lockout (429)
        res5 = self.client.post("/api/auth/2fa/login-verify", json={
            "temp_token": temp_token,
            "code": "111111"
        })
        self.assertEqual(res5.status_code, 429)
        self.assertIn("Too many invalid", res5.json()["detail"])

        # Subsequent attempt on dead temp_token returns 401 invalid/expired
        res6 = self.client.post("/api/auth/2fa/login-verify", json={
            "temp_token": temp_token,
            "code": "111111"
        })
        self.assertEqual(res6.status_code, 401)

    # 12. Login verify with backup recovery code
    def test_12_login_verify_with_recovery_code(self):
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        vsetup = self.client.post("/api/auth/2fa/verify-setup", json={"code": pyotp.TOTP(secret).now()}, headers=self.headers).json()
        recovery_code = vsetup["recovery_codes"][0]

        login_res = self.client.post("/api/auth/login", json={
            "username_or_email": self.username,
            "password": self.password
        })
        temp_token = login_res.json()["temp_token"]

        v_res = self.client.post("/api/auth/2fa/login-verify", json={
            "temp_token": temp_token,
            "recovery_code": recovery_code
        })
        self.assertEqual(v_res.status_code, 200)
        self.assertIsNotNone(v_res.json().get("access_token"))

    # 13. Recovery code is single-use
    def test_13_recovery_code_is_single_use(self):
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        vsetup = self.client.post("/api/auth/2fa/verify-setup", json={"code": pyotp.TOTP(secret).now()}, headers=self.headers).json()
        recovery_code = vsetup["recovery_codes"][0]

        # Use recovery code once
        login1 = self.client.post("/api/auth/login", json={"username_or_email": self.username, "password": self.password})
        res1 = self.client.post("/api/auth/2fa/login-verify", json={
            "temp_token": login1.json()["temp_token"],
            "recovery_code": recovery_code
        })
        self.assertEqual(res1.status_code, 200)

        # Try to use the SAME recovery code on a second login
        login2 = self.client.post("/api/auth/login", json={"username_or_email": self.username, "password": self.password})
        res2 = self.client.post("/api/auth/2fa/login-verify", json={
            "temp_token": login2.json()["temp_token"],
            "recovery_code": recovery_code
        })
        self.assertEqual(res2.status_code, 401)
        self.assertIn("Invalid verification code", res2.json()["detail"])

        # Remaining recovery count in status is now 9
        st = self.client.get("/api/auth/2fa/status", headers={"Authorization": f"Bearer {res1.json()['access_token']}"}).json()
        self.assertEqual(st["recovery_codes_remaining"], 9)

    # 14. Disable 2FA requires password and code
    def test_14_disable_2fa_requires_password_and_code(self):
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        self.client.post("/api/auth/2fa/verify-setup", json={"code": pyotp.TOTP(secret).now()}, headers=self.headers)

        # Wrong password
        r1 = self.client.post("/api/auth/2fa/disable", json={
            "password": "WrongPassword!",
            "code": pyotp.TOTP(secret).now()
        }, headers=self.headers)
        self.assertEqual(r1.status_code, 401)
        self.assertIn("Incorrect account password", r1.json()["detail"])

        # Wrong code
        r2 = self.client.post("/api/auth/2fa/disable", json={
            "password": self.password,
            "code": "999999"
        }, headers=self.headers)
        self.assertEqual(r2.status_code, 401)
        self.assertIn("authenticator code", r2.json()["detail"])

        # Correct password + code
        r3 = self.client.post("/api/auth/2fa/disable", json={
            "password": self.password,
            "code": pyotp.TOTP(secret).now()
        }, headers=self.headers)
        self.assertEqual(r3.status_code, 200)
        self.assertIn("successfully disabled", r3.json()["message"])

    # 15. Status reflects disabled after disable
    def test_15_status_reflects_disabled_after_disable(self):
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        self.client.post("/api/auth/2fa/verify-setup", json={"code": pyotp.TOTP(secret).now()}, headers=self.headers)
        self.client.post("/api/auth/2fa/disable", json={"password": self.password, "code": pyotp.TOTP(secret).now()}, headers=self.headers)

        st = self.client.get("/api/auth/2fa/status", headers=self.headers).json()
        self.assertFalse(st["enabled"])
        self.assertEqual(st["recovery_codes_remaining"], 0)

        # Login directly succeeds without 2FA challenge
        login_res = self.client.post("/api/auth/login", json={"username_or_email": self.username, "password": self.password})
        self.assertEqual(login_res.status_code, 200)
        self.assertFalse(login_res.json().get("requires_2fa"))
        self.assertIsNotNone(login_res.json().get("access_token"))

    # 16. Regenerate recovery codes
    def test_16_regenerate_recovery_codes(self):
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        vsetup = self.client.post("/api/auth/2fa/verify-setup", json={"code": pyotp.TOTP(secret).now()}, headers=self.headers).json()
        old_codes = vsetup["recovery_codes"]

        # Regenerate with password + TOTP
        regen_res = self.client.post("/api/auth/2fa/regenerate-recovery-codes", json={
            "password": self.password,
            "code": pyotp.TOTP(secret).now()
        }, headers=self.headers)
        self.assertEqual(regen_res.status_code, 200)
        new_codes = regen_res.json()["recovery_codes"]
        self.assertEqual(len(new_codes), 10)
        self.assertNotEqual(old_codes, new_codes)

        # Old codes should now fail on login
        login_res = self.client.post("/api/auth/login", json={"username_or_email": self.username, "password": self.password})
        fail_res = self.client.post("/api/auth/2fa/login-verify", json={
            "temp_token": login_res.json()["temp_token"],
            "recovery_code": old_codes[0]
        })
        self.assertEqual(fail_res.status_code, 401)

        # New code should succeed on login
        login_res2 = self.client.post("/api/auth/login", json={"username_or_email": self.username, "password": self.password})
        succ_res = self.client.post("/api/auth/2fa/login-verify", json={
            "temp_token": login_res2.json()["temp_token"],
            "recovery_code": new_codes[0]
        })
        self.assertEqual(succ_res.status_code, 200)

    # 17. Password reset preserves 2FA
    def test_17_password_reset_preserves_2fa(self):
        setup_res = self.client.post("/api/auth/2fa/setup", headers=self.headers)
        secret = setup_res.json()["secret"]
        self.client.post("/api/auth/2fa/verify-setup", json={"code": pyotp.TOTP(secret).now()}, headers=self.headers)

        # Request reset token
        forgot_res = self.client.post("/api/auth/forgot-password", json={"email": self.email})
        reset_token = forgot_res.json()["reset_token"]
        self.assertIsNotNone(reset_token)

        # Reset password
        new_password = "BrandNewPassword2026!"
        reset_res = self.client.post("/api/auth/reset-password", json={
            "token": reset_token,
            "new_password": new_password
        })
        self.assertEqual(reset_res.status_code, 200)

        # Sign in with new password -> 2FA MUST STILL BE ENFORCED!
        login_res = self.client.post("/api/auth/login", json={
            "username_or_email": self.username,
            "password": new_password
        })
        self.assertEqual(login_res.status_code, 200)
        self.assertTrue(login_res.json().get("requires_2fa"))
        self.assertIsNone(login_res.json().get("access_token"))

        # Verifying with original secret must still succeed
        v_res = self.client.post("/api/auth/2fa/login-verify", json={
            "temp_token": login_res.json()["temp_token"],
            "code": pyotp.TOTP(secret).now()
        })
        self.assertEqual(v_res.status_code, 200)
        self.assertIsNotNone(v_res.json().get("access_token"))

    # 18. TOTP clock drift tolerance (+/- 1 time step / 30s)
    def test_18_totp_clock_drift_window(self):
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        
        # Current time code
        now_code = totp.now()
        self.assertTrue(verify_totp_code(secret, now_code))

        # Code from 30 seconds in past (-1 window)
        past_code = totp.at(int(time.time()) - 30)
        self.assertTrue(verify_totp_code(secret, past_code))

        # Code from 30 seconds in future (+1 window)
        future_code = totp.at(int(time.time()) + 30)
        self.assertTrue(verify_totp_code(secret, future_code))

        # Code from 90 seconds in past (outside window) -> False
        far_past_code = totp.at(int(time.time()) - 90)
        self.assertFalse(verify_totp_code(secret, far_past_code))

if __name__ == "__main__":
    unittest.main()
