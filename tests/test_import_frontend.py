from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read_template(name):
    return (ROOT / "app" / "templates" / name).read_text(encoding="utf-8")


class ImportFrontendTestCase(unittest.TestCase):
    def test_import_history_uses_dropdown_limited_to_five_records(self):
        html = read_template("import.html")

        self.assertIn('id="importSelect"', html)
        self.assertIn('selectImportFromDropdown(this)', html)
        self.assertIn("/logs/list?per_page=5", html)
        self.assertIn("(data.imports || []).slice(0, 5)", html)
        self.assertNotIn('tbody id="importList"', html)


if __name__ == "__main__":
    unittest.main()
