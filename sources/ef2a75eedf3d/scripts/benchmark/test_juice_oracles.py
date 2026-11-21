import base64
import json
import unittest

from juice_oracles import check


class OracleTest(unittest.TestCase):
    def test_proof_requires_controls_and_actual_content(self):
        claims = base64.urlsafe_b64encode(json.dumps({"data": {"role": "admin"}}).encode()).decode().rstrip("=")
        def request(method, path, payload):
            if path == "/ftp/acquisitions.md":
                return 200, b"confidential document"
            if path == "/rest/user/login":
                return (200, json.dumps({"authentication": {"token": "header." + claims + ".signature"}}).encode()) if payload["email"].startswith("'") else (401, b"invalid")
            if path.endswith("%27"):
                return 500, b'{"error":"SQLITE_ERROR","stack":"/juice-shop/app.js"}'
            return 200, b"control"
        self.assertTrue(all(row["reproduced"] for row in check(request)))
        # A 200 response alone (including an SPA shell) confirms nothing.
        self.assertFalse(any(row["reproduced"] for row in check(lambda *_: (200, b"SPA shell"))))


if __name__ == "__main__":
    unittest.main()
