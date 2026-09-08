# AI-Powered VAPT Checklist Generator (Prototype)

A standalone prototype page for testing screenshot-to-checklist capabilities for authorized Vulnerability Assessment and Penetration Testing (VAPT).

## Features
- **Screenshot Ingestion**: Drag & drop or file selection supporting PNG, JPG, and WEBP (up to 10MB).
- **Vision AI Assessment**: Secure backend API (`POST /api/analyze-screenshot`) with strict Pydantic JSON schema.
- **Dynamic Prioritization**: Testing checklist automatically sorted by `CRITICAL` -> `HIGH` -> `MEDIUM` -> `LOW`.
- **Educational Context**: Every item includes a testing objective, rationale ("Why is this relevant?"), and associated CWE.
- **Interactive Testing Tracker**: Interactive `Mark as Tested` checkboxes with live progress tracking and priority filtering.
- **Markdown Export**: 1-click export of VAPT assessment checklists.
- **5 Realistic Test Cases**: Quick-load sample buttons for Login, Registration, Password Reset, Profile Settings, and File Upload.
- **Zero-Config Offline Simulation**: Runs immediately without an API key for quick offline testing, with plug-and-play live Gemini (`gemini-2.5-flash`) and OpenAI (`gpt-4o`) support when configured in `.env`.

## Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API Key (Optional)
Copy `.env.example` to `.env` and set your key:
```bash
cp .env.example .env
```
Add your `GEMINI_API_KEY=your_key_here` or `OPENAI_API_KEY=your_key_here`.
If left blank, the app will run in offline simulation mode.

### 3. Launch the Server
```bash
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8080 --reload
```

Access the interface at: `http://127.0.0.1:8080`

### 4. Run Automated Tests
```bash
python tests/test_api.py
```
