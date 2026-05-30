import csv
import io
import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

import config as app_config
from app import create_app, db
from app.models import AnalysisResult, LogEntry, LogImport, User


class ExportRouteTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        session_dir = Path(self.temp_dir.name) / "sessions"
        upload_dir = Path(self.temp_dir.name) / "uploads"
        session_dir.mkdir()
        upload_dir.mkdir()

        app_config.config["testing"].SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
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
        self.assertGreater(
            payload["imports"][0]["import_id"], payload["imports"][-1]["import_id"]
        )

    def test_export_page_uses_multi_select_dropdown(self):
        response = self.client.get("/export")

        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn('id="recentImportDropdownButton"', html)
        self.assertIn('id="recentImportDropdownMenu"', html)
        self.assertIn("renderRecentImportOptions", html)
        self.assertNotIn("recent-import-checkbox", html)


if __name__ == "__main__":
    unittest.main()
