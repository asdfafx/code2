from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read_template(name):
    return (ROOT / "app" / "templates" / name).read_text(encoding="utf-8")


class OperationsFrontendTestCase(unittest.TestCase):
    def test_operations_groups_features_into_page_tabs(self):
        html = read_template("operations.html")

        expected_pages = [
            ('data-ops-page="geo"', "地理分析"),
            ('data-ops-page="ml"', "机器学习异常检测"),
            ('data-ops-page="realtime"', "实时监控和告警"),
            ('data-ops-page="behavior"', "行为分析"),
        ]
        for marker, label in expected_pages:
            self.assertIn(marker, html)
            self.assertIn(label, html)

        ml_section = html.index('id="page-ml"')
        realtime_section = html.index('id="page-realtime"')
        behavior_section = html.index('id="page-behavior"')

        self.assertLess(html.index("机器学习异常检测", ml_section), realtime_section)
        self.assertLess(html.index("ML 与规则检测对比", ml_section), realtime_section)
        self.assertLess(html.index("实时监控", realtime_section), behavior_section)
        self.assertLess(html.index("告警", realtime_section), behavior_section)
        self.assertGreater(html.index("行为事件时间轴", behavior_section), behavior_section)
        self.assertGreater(html.index("攻击链路", behavior_section), behavior_section)
        self.assertGreater(html.index("行为模式", behavior_section), behavior_section)

    def test_operations_navigation_is_geo_analysis(self):
        base = read_template("base.html")
        operations = read_template("operations.html")

        self.assertIn("🛡️ 地理分析", base)
        self.assertNotIn("智能监控", base)
        self.assertIn("{% block title %}地理分析 - 日志分析系统{% endblock %}", operations)
        self.assertIn("<h2>地理分析</h2>", operations)

    def test_geo_page_labels_non_public_ip_ownership_explicitly(self):
        operations = read_template("operations.html")
        geo_section = operations[
            operations.index('id="page-geo"'):operations.index('id="page-ml"')
        ]

        self.assertIn("本地网络", geo_section)
        self.assertIn("保留地址", geo_section)
        self.assertIn("归属类型/地区", geo_section)
        self.assertNotIn("<th>国家/地区</th>", geo_section)


if __name__ == "__main__":
    unittest.main()
