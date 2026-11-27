"""Local synthetic browser regression. No real accounts, targets or model calls."""
import contextlib
import http.server
import io
import json
import os
import pathlib
import runpy
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'server' / 'browser_session.py'
HELPERS = runpy.run_path(str(SOURCE))


class BrowserRegression(unittest.TestCase):
    def setUp(self):
        self.previous = pathlib.Path.cwd()
        temporary_root = ROOT / 'dist' / 'pentagi-tests'
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=temporary_root, prefix='browser-fixture-')
        os.chdir(self.directory.name)
        self.foreign_hits = []

        class Foreign(http.server.BaseHTTPRequestHandler):
            def do_GET(handler):
                self.foreign_hits.append(handler.path)
                handler.send_response(200)
                handler.end_headers()

            def log_message(*args):
                pass

        self.foreign = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Foreign)
        foreign_port = self.foreign.server_address[1]

        class Application(http.server.BaseHTTPRequestHandler):
            def do_GET(handler):
                handler.send_response(200)
                handler.send_header('Content-Type', 'text/html; charset=utf-8')
                handler.end_headers()
                if handler.path == '/private':
                    authorized = 'fixture_session=accepted' in handler.headers.get('Cookie', '')
                    body = '<h1>Authorized fixture</h1>' if authorized else '<h1>Not authenticated</h1>'
                else:
                    body = '<form method="post" action="/login"><input name="username"><input name="password" type="password"><button>Sign in</button></form>'
                    body += f'<img src="http://127.0.0.1:{foreign_port}/blocked"><iframe src="http://127.0.0.1:{foreign_port}/frame"></iframe>'
                    body += f'<script>fetch("http://127.0.0.1:{foreign_port}/fetch").catch(()=>{{}});new WebSocket("ws://127.0.0.1:{foreign_port}/ws");</script>'
                handler.wfile.write(body.encode())

            def do_POST(handler):
                body = handler.rfile.read(int(handler.headers.get('Content-Length', '0'))).decode()
                values = parse_qs(body)
                if values.get('password') != ['fixture-browser-password']:
                    handler.send_error(403)
                    return
                handler.send_response(303)
                handler.send_header('Set-Cookie', 'fixture_session=accepted; HttpOnly; SameSite=Strict; Path=/')
                handler.send_header('Location', '/private')
                handler.end_headers()

            def log_message(*args):
                pass

        self.application = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Application)
        self.threads = []
        for server in (self.application, self.foreign):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)
        self.url = f'http://127.0.0.1:{self.application.server_address[1]}'
        self.deadline = int(time.time()) + 600
        os.environ['VULNETIC_CRED_1_PASSWORD'] = 'fixture-browser-password'

    def tearDown(self):
        self.application.shutdown()
        self.foreign.shutdown()
        self.application.server_close()
        self.foreign.server_close()
        for thread in self.threads:
            thread.join(timeout=3)
        os.environ.pop('VULNETIC_CRED_1_PASSWORD', None)
        os.chdir(self.previous)
        self.directory.cleanup()

    def invoke(self, path='/', actions=None, deadline=None):
        params = {'url': self.url + path, 'actions': actions or [{'kind': 'read'}], 'deadline': deadline or self.deadline, 'scope': 'a' * 32, 'pinned_ip': '127.0.0.1'}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runpy.run_path(str(SOURCE), init_globals={'params': params})
        return json.loads(output.getvalue())

    def test_authenticated_session_origin_blocks_and_original_expiry(self):
        first = self.invoke(actions=[
            {'kind': 'fill', 'selector': '[name=username]', 'value': 'tester'},
            {'kind': 'fill', 'selector': '[name=password]', 'env_key': 'VULNETIC_CRED_1_PASSWORD'},
            {'kind': 'click', 'selector': 'button'}, {'kind': 'read'}, {'kind': 'screenshot'},
        ])
        self.assertNotIn('error', first, first)
        self.assertIn('Authorized fixture', first['text'])
        self.assertGreater(first['blocked_requests'], 0)
        self.assertEqual(self.foreign_hits, [])
        self.assertNotIn('fixture-browser-password', json.dumps(first))
        self.assertNotIn('fixture_session', json.dumps(first))
        self.assertTrue(pathlib.Path(first['screenshots'][0]['path']).is_file())
        second = self.invoke('/private', deadline=self.deadline + 3600)
        self.assertNotIn('error', second, second)
        self.assertIn('Authorized fixture', second['text'])
        self.assertEqual(second['session_expires_at'], first['session_expires_at'])
        expired = self.invoke(deadline=int(time.time()) - 1)
        self.assertEqual(expired['error'], 'browser_authorization_expired')

    def test_password_literal_is_refused(self):
        result = self.invoke(actions=[{'kind': 'fill', 'selector': '[name=password]', 'value': 'not-a-scoped-reference'}])
        self.assertEqual(result['error'], 'browser_password_requires_credential_reference')

    def test_origin_normalization(self):
        origin = HELPERS['origin_of']
        self.assertEqual(origin('https://EXAMPLE.test/a'), origin('https://example.test:443/b'))
        for url in ('file:///tmp/a', 'https://user:secret@example.test/', 'javascript:alert(1)', 'https://example.test:bad/'):
            self.assertIsNone(origin(url))
        self.assertNotEqual(origin(self.url), origin('http://127.0.0.1:1/'))


if __name__ == '__main__':
    unittest.main()
