import sys
import random
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)

def test_random_filenames_no_prompt():
    categories = [
        ("login.png", "Login / Sign-in Page"),
        ("registration.png", "Sign-up / Registration Page"),
        ("forgot_password.png", "Forgot Password / Password Reset Page"),
        ("profile.png", "Account / Profile Page"),
        ("settings.png", "Settings / Security Settings Page"),
        ("dashboard.png", "Home / Dashboard Page"),
        ("search.png", "Search / Search Results Page"),
        ("file_upload.png", "File Upload Page"),
        ("checkout.png", "Checkout / Payment Page"),
        ("admin_panel.png", "Admin Dashboard / Admin Panel"),
        ("ambiguous.png", "Unknown / Ambiguous")
    ]

    print("\n--- TESTING PERCEPTUAL CLASSIFICATION WITH DUMMY FILENAMES & NO PROMPT ---")
    for filename, expected_page in categories:
        filepath = Path("samples") / filename
        with open(filepath, "rb") as f:
            img_bytes = f.read()

        dummy_name = f"screencap_{random.randint(1000, 9999)}.png"
        resp = client.post(
            "/api/analyze-screenshot",
            files={"image": (dummy_name, img_bytes, "image/png")},
            data={}
        )
        assert resp.status_code == 200, f"Request failed for {filename}: {resp.text}"
        data = resp.json()
        assert data["page_type"] == expected_page, f"Failed for {filename}: expected {expected_page}, got {data['page_type']}"
        print(f"  [PASS] {filename:<20} (uploaded as {dummy_name:<18}) -> {data['page_type']} (conf={data['confidence']})")

    print("\nALL 11 CATEGORIES IDENTIFIED ACCURATELY SOLELY FROM VISUAL IMAGE BYTES!")

if __name__ == "__main__":
    test_random_filenames_no_prompt()
