"""Static frontend smoke with isolated fixture APIs; no real account or external traffic."""
import http.server
import json
import pathlib
import threading
import unittest
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ResearchUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Static(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(ROOT / 'web' / 'out'), **kwargs)

            def log_message(*args):
                pass

        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Static)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f'http://127.0.0.1:{cls.server.server_address[1]}'
        cls.output = ROOT / 'dist' / 'pentagi-tests' / 'ui'
        cls.output.mkdir(parents=True, exist_ok=True)
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(headless=True, chromium_sandbox=True)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_research_settings_on_notebook_and_mobile(self):
        for width, height in ((1365, 660), (390, 844), (320, 740)):
            with self.subTest(viewport=f'{width}x{height}'):
                saved = []
                settings = {'enabled': True, 'backend': 'mwmbl', 'fallbacks': [], 'tavily_key_set': False, 'exa_key_set': False, 'linkup_key_set': False}
                context = self.browser.new_context(viewport={'width': width, 'height': height})
                page = context.new_page()
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))

                def route(request_route):
                    url = urlsplit(request_route.request.url)
                    if not request_route.request.url.startswith(self.origin + '/'):
                        request_route.abort('blockedbyclient')
                        return
                    if not url.path.startswith('/api/'):
                        request_route.continue_()
                        return
                    data = []
                    if url.path == '/api/auth/session':
                        data = {'id': '1', 'role': 'user', 'email': 'fixture@fixture.invalid'}
                    elif url.path == '/api/auth/status':
                        data = {'saas_mode': True, 'initialized': True, 'public_signup': True}
                    elif url.path == '/api/account/search':
                        if request_route.request.method == 'PUT':
                            patch = request_route.request.post_data_json
                            saved.append(patch)
                            settings.update(patch)
                        data = settings
                    elif url.path == '/api/operator-requests':
                        data = {'items': []}
                    elif url.path == '/api/health':
                        data = {'ok': True, 'version': 'local-fixture'}
                    elif url.path.endswith('/settings'):
                        data = {}
                    request_route.fulfill(status=200, content_type='application/json', body=json.dumps(data))

                context.route('**/*', route)
                page.goto(self.origin + '/system/research/')
                page.get_by_role('heading', name='Research', exact=True).wait_for()
                page.locator('#fallback-ddgs').wait_for()
                self.assertTrue(page.locator('#fallback-tavily').is_disabled())
                page.locator('#fallback-ddgs').click()
                self.assertEqual(page.locator('#fallback-ddgs').get_attribute('aria-checked'), 'true')
                page.get_by_role('button', name='Save research settings', exact=True).click()
                page.get_by_text('Research settings saved', exact=True).wait_for()
                self.assertEqual(saved[-1]['fallbacks'], ['ddgs'])
                self.assertEqual(saved[-1]['backend'], 'mwmbl')
                self.assertFalse(any('key' in field for field in saved[-1]))
                self.assertLessEqual(page.evaluate('document.documentElement.scrollWidth'), width + 1)
                for button in page.locator('header button').all():
                    if button.is_visible():
                        bounds = button.bounding_box()
                        self.assertLessEqual(bounds['x'] + bounds['width'], width + 1)
                page.screenshot(path=str(self.output / f'research-{width}.png'), full_page=True)
                self.assertEqual(errors, [])
                context.close()


if __name__ == '__main__':
    unittest.main()
