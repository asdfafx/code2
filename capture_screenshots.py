
from pathlib import Path
from playwright.sync_api import sync_playwright

base = 'http://127.0.0.1:8081'
out = Path(r'F:\Code 2\screenshots')
out.mkdir(exist_ok=True)
chrome = r'C:\Program Files\Google\Chrome\Application\chrome.exe'

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, executable_path=chrome)
    context = browser.new_context(viewport={'width': 1440, 'height': 1000}, device_scale_factor=1)
    page = context.new_page()
    page.set_default_timeout(15000)

    page.goto(base + '/login', wait_until='domcontentloaded')
    page.wait_for_timeout(700)
    page.screenshot(path=str(out / '01-login.png'), full_page=True)

    page.fill('#loginUsername', 'admin')
    page.fill('#loginPassword', 'admin123')
    page.evaluate('login()')
    page.wait_for_url('**/dashboard', timeout=15000)
    page.wait_for_load_state('domcontentloaded')
    page.wait_for_timeout(1500)
    page.screenshot(path=str(out / '02-dashboard.png'), full_page=True)

    targets = [
        ('03-import.png', '/import'),
        ('04-operations.png', '/operations'),
        ('05-export.png', '/export'),
        ('06-admin.png', '/admin'),
    ]
    for filename, path in targets:
        page.goto(base + path, wait_until='domcontentloaded')
        page.wait_for_timeout(1800)
        page.screenshot(path=str(out / filename), full_page=True)
    browser.close()
print(out)
