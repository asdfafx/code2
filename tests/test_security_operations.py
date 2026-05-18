import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["FLASK_CONFIG"] = "testing"

from app import create_app, db
from app.models import LogEntry, LogImport, User


class SecurityOperationsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

        with self.app.app_context():
            db.drop_all()
            db.create_all()

            user = User(username="ops-admin", email="ops@example.com", role="admin")
            user.set_password("password123")
            db.session.add(user)
            db.session.flush()
            self.user_id = user.user_id

            log_import = LogImport(
                user_id=self.user_id,
                filename="ops-fixture.log",
                log_format="apache",
                total_lines=14,
                parsed_lines=14,
                status="completed",
            )
            db.session.add(log_import)
            db.session.flush()
            self.import_id = log_import.import_id

            base_time = datetime.now(timezone.utc) - timedelta(minutes=20)
            fixture_rows = [
                ("10.0.0.5", "/index.html", 200, 0, "Mozilla/5.0"),
                ("10.0.0.5", "/login", 200, 15, "Mozilla/5.0"),
                ("10.0.0.9", "/admin?user=1' or '1'='1", 500, 85, "curl/8"),
                ("10.0.0.9", "/admin?union=select", 500, 90, "curl/8"),
                ("10.0.0.9", "/etc/passwd", 404, 72, "curl/8"),
                ("192.168.1.44", "/search?q=<script>alert(1)</script>", 400, 78, "scanner"),
                ("192.168.1.44", "/../../etc/shadow", 404, 82, "scanner"),
                ("172.16.0.7", "/api/users", 200, 5, "Mozilla/5.0"),
                ("172.16.0.7", "/api/orders", 200, 5, "Mozilla/5.0"),
                ("172.16.0.8", "/wp-admin", 403, 65, "bot"),
                ("172.16.0.8", "/phpmyadmin", 403, 65, "bot"),
                ("172.16.0.8", "/.env", 404, 70, "bot"),
                ("10.1.0.3", "/health", 200, 0, "monitor"),
                ("10.1.0.3", "/assets/app.js", 200, 0, "Mozilla/5.0"),
            ]
            for index, (ip, url, status, risk, ua) in enumerate(fixture_rows):
                db.session.add(
                    LogEntry(
                        import_id=log_import.import_id,
                        ip_address=ip,
                        request_time=base_time + timedelta(seconds=index * 30),
                        method="GET",
                        url=url,
                        parameters="",
                        status_code=status,
                        response_size=512 + index,
                        user_agent=ua,
                        raw_log=f"{ip} GET {url}",
                        initial_risk_score=risk,
                    )
                )
            db.session.commit()

        with self.client.session_transaction() as session:
            session["user_id"] = self.user_id
            session["username"] = "ops-admin"
            session["role"] = "admin"

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_operations_page_exposes_requested_modules(self):
        response = self.client.get("/operations")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("地理分析与行为时间线", body)
        self.assertIn("行为事件时间轴", body)
        self.assertIn("/timeline/ip/", body)
        self.assertIn("机器学习异常检测", body)
        self.assertIn("实时监控", body)
        self.assertIn("告警", body)

    def test_obsolete_standalone_pages_are_removed(self):
        obsolete_paths = ["/analyze", "/stream", "/geo", "/timeline", "/realtime"]
        obsolete_templates = [
            "analyze.html",
            "stream.html",
            "geo.html",
            "timeline.html",
            "realtime.html",
        ]

        for path in obsolete_paths:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

        templates_dir = Path(__file__).resolve().parents[1] / "app" / "templates"
        for template in obsolete_templates:
            with self.subTest(template=template):
                self.assertFalse((templates_dir / template).exists())

    def test_module_api_contracts_return_frontend_ready_payloads(self):
        geo = self.client.get("/api/geo/stats").get_json()
        attackers = self.client.get("/api/timeline/top-attackers?limit=5").get_json()
        patterns = self.client.get("/api/timeline/patterns").get_json()
        ml = self.client.get("/api/ml/detect?threshold=0").get_json()
        stream_stats = self.client.get("/api/stream/statistics").get_json()
        alerts = self.client.get("/api/alerts/history").get_json()

        self.assertIn("location_distribution", geo)
        self.assertIn("attackers", attackers)
        self.assertIn("summary", patterns)
        self.assertGreaterEqual(ml["total_entries"], 10)
        self.assertIn("anomalies", ml)
        self.assertIn("total_analyzed", stream_stats)
        self.assertIn("alerts", alerts)

    def test_stream_import_analysis_handles_normal_entries_without_attack_type(self):
        response = self.client.post(
            "/api/stream/analyze-import",
            json={"import_id": self.import_id},
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["import_id"], self.import_id)
        self.assertNotIn(None, data["attack_types"])
        self.assertIn("正常请求", data["attack_types"])


if __name__ == "__main__":
    unittest.main()
