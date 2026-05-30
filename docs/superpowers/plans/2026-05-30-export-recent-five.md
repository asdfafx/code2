# Export Recent Five Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the export page choose one or more of the user's most recent five imports and download each selected batch as a separate CSV, HTML, or JSON file.

**Architecture:** Keep the backend export routes single-batch and reuse them by passing an explicit `import_id` from the frontend. Add lightweight backend helpers for validating ownership and generating distinct filenames, then update the export page to load the latest five imports and trigger one download request per selected batch.

**Tech Stack:** Flask, Flask-SQLAlchemy, Jinja templates, vanilla JavaScript, unittest

---

### Task 1: Add backend regression tests for explicit batch export

**Files:**
- Create: `tests/test_export_routes.py`
- Test: `tests/test_export_routes.py`

- [ ] **Step 1: Write the failing tests**

```python
import csv
import io
import json
import os
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from app import db
from app.models import AnalysisResult, LogEntry, LogImport, User
from app import create_app
import config as app_config


class ExportRouteTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "test.db"
        session_dir = Path(self.temp_dir.name) / "sessions"
        upload_dir = Path(self.temp_dir.name) / "uploads"
        session_dir.mkdir()
        upload_dir.mkdir()

        app_config.config["testing"].SQLALCHEMY_DATABASE_URI = f"sqlite:///{database_path.as_posix()}"
        self.app = create_app("testing")
        self.app.config.update(
            SESSION_FILE_DIR=str(session_dir),
            UPLOAD_FOLDER=str(upload_dir),
            SECRET_KEY="test-secret",
        )
        self.client = self.app.test_client()

        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.user_id, self.import_a_id, self.import_b_id = self._seed_data()

        with self.client.session_transaction() as session:
            session["user_id"] = self.user_id
            session["username"] = "tester"
            session["role"] = "user"

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
        self.temp_dir.cleanup()

    def _seed_data(self):
        user = User(username="tester", email="tester@example.com", role="user")
        user.set_password("secret123")
        db.session.add(user)
        db.session.commit()

        import_a = LogImport(
            user_id=user.user_id,
            filename="alpha.log",
            total_lines=1,
            parsed_lines=1,
            status="completed",
        )
        import_b = LogImport(
            user_id=user.user_id,
            filename="beta.log",
            total_lines=1,
            parsed_lines=1,
            status="completed",
        )
        db.session.add_all([import_a, import_b])
        db.session.commit()

        entry_a = LogEntry(
            import_id=import_a.import_id,
            ip_address="10.0.0.1",
            method="GET",
            url="/alpha",
            parameters="a=1",
            raw_log="alpha raw",
            is_analyzed=True,
        )
        entry_b = LogEntry(
            import_id=import_b.import_id,
            ip_address="10.0.0.2",
            method="POST",
            url="/beta",
            parameters="b=2",
            raw_log="beta raw",
            is_analyzed=True,
        )
        db.session.add_all([entry_a, entry_b])
        db.session.commit()

        result_a = AnalysisResult(
            entry_id=entry_a.entry_id,
            filename="alpha.log",
            attack_type="SQL注入",
            risk_level="高风险",
            llm_conclusion="alpha conclusion",
            analysis_reason="alpha reason",
            confidence_score=Decimal("0.90"),
        )
        result_b = AnalysisResult(
            entry_id=entry_b.entry_id,
            filename="beta.log",
            attack_type="XSS攻击",
            risk_level="中风险",
            llm_conclusion="beta conclusion",
            analysis_reason="beta reason",
            confidence_score=Decimal("0.75"),
        )
        db.session.add_all([result_a, result_b])
        db.session.commit()

        return user.user_id, import_a.import_id, import_b.import_id

    def test_export_csv_uses_explicit_import_id_only(self):
        response = self.client.post("/api/export/csv", json={"import_id": self.import_b_id})

        self.assertEqual(response.status_code, 200)
        rows = list(csv.reader(io.StringIO(response.data.decode("utf-8-sig"))))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][0], "10.0.0.2")
        self.assertEqual(rows[1][3], "/beta")
        self.assertIn("beta", response.headers["Content-Disposition"])

    def test_export_json_returns_matching_import_info(self):
        response = self.client.post("/api/export/json", json={"import_id": self.import_a_id})

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.data.decode("utf-8"))
        self.assertEqual(payload["import_info"]["filename"], "alpha.log")
        self.assertEqual(payload["total_records"], 1)
        self.assertEqual(payload["results"][0]["url"], "/alpha")
        self.assertIn("alpha", response.headers["Content-Disposition"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_export_routes -v`
Expected: FAIL because export filenames do not yet include batch-specific information and the test module does not exist before creation.

- [ ] **Step 3: Write minimal implementation**

```python
def _get_user_import_or_404(import_id):
    ...


def _build_export_filename(log_import, extension):
    ...
```

Use the helper in all three export routes so explicit `import_id` is validated against the current user and the download filename includes the source batch.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_export_routes -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_export_routes.py app/routes/export.py
git commit -m "feat: support distinct filenames for explicit exports"
```

### Task 2: Update export page for recent-five multi-select batch downloads

**Files:**
- Modify: `app/templates/export.html`
- Test: `tests/test_export_routes.py`

- [ ] **Step 1: Write the failing test**

```python
def test_logs_list_returns_latest_five_imports_descending(self):
    with self.app.app_context():
        for index in range(6):
            extra_import = LogImport(
                user_id=self.user_id,
                filename=f"extra-{index}.log",
                total_lines=1,
                parsed_lines=1,
                status="completed",
            )
            db.session.add(extra_import)
        db.session.commit()

    response = self.client.get("/api/logs/list?per_page=5")

    self.assertEqual(response.status_code, 200)
    payload = response.get_json()
    self.assertEqual(len(payload["imports"]), 5)
    self.assertGreater(payload["imports"][0]["import_id"], payload["imports"][-1]["import_id"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_export_routes.ExportRouteTestCase.test_logs_list_returns_latest_five_imports_descending -v`
Expected: FAIL until the test method exists and the fixture is updated.

- [ ] **Step 3: Write minimal implementation**

```javascript
let recentImports = [];
let selectedImportIds = new Set();

async function loadRecentImports() {
  ...
}

async function exportSelected(format) {
  ...
}
```

Render the latest five imports as checkboxes, default-select the newest item, disable buttons when nothing is available, and POST one request per selected `import_id`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_export_routes -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/templates/export.html tests/test_export_routes.py
git commit -m "feat: add multi-select export for recent imports"
```

### Task 3: Verify end-to-end behavior

**Files:**
- Modify: `docs/superpowers/plans/2026-05-30-export-recent-five.md`

- [ ] **Step 1: Run backend verification**

Run: `python -m unittest tests.test_export_routes -v`
Expected: PASS

- [ ] **Step 2: Run manual sanity checks**

Run: `git diff -- app/routes/export.py app/templates/export.html tests/test_export_routes.py`
Expected: Only the targeted export-related changes appear.

- [ ] **Step 3: Note any remaining gaps**

```text
Frontend batch downloads verified by code inspection and manual browser run if a server is started; no dedicated browser automation exists yet.
```

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/plans/2026-05-30-export-recent-five.md
git commit -m "docs: record export recent-five implementation plan"
```
