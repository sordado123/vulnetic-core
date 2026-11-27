"""Small HTTP replay oracles for the isolated Juice Shop comparison fixture.

These measure the target, not discovery. Count a product finding only after its
own execution evidence has been reviewed against a corresponding replay.
"""
import argparse
import base64
import hashlib
import json
import urllib.error
import urllib.request


def check(request):
    results = []
    def observation(name, code, body, confirmed):
        results.append({"oracle": name, "status": code, "body_sha256": hashlib.sha256(body).hexdigest(), "reproduced": bool(confirmed)})
    control, _ = request("GET", "/", None)
    code, body = request("GET", "/ftp/acquisitions.md", None)
    observation("GT-004", code, body, control == 200 and code == 200 and b"confidential" in body.lower())
    invalid, _ = request("POST", "/rest/user/login", {"email": "invalid-benchmark@example.invalid", "password": "invalid-benchmark"})
    code, body = request("POST", "/rest/user/login", {"email": "' OR 1=1--", "password": "invalid-benchmark"})
    admin = False
    try:
        token = json.loads(body)["authentication"]["token"]
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==="))
        admin = claims.get("data", {}).get("role") == "admin"
    except (KeyError, ValueError, IndexError, TypeError):
        pass
    observation("GT-001", code, body, invalid in (400, 401, 403) and code == 200 and admin)
    control, _ = request("GET", "/rest/products/search?q=apple", None)
    code, body = request("GET", "/rest/products/search?q=%27", None)
    observation("GT-006", code, body, control == 200 and code == 500 and b"SQLITE_ERROR" in body and (b"stack" in body.lower() or b"/juice-shop/" in body))
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default="http://127.0.0.1:3037", choices=["http://127.0.0.1:3037"])
    args = parser.parse_args()
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_):
            return None
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def request(method, path, payload):
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(args.origin + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            response = client.open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise ValueError("oracle response limit exceeded")
            return response.code, body
    print(json.dumps({"origin": args.origin, "results": check(request)}))


if __name__ == "__main__":
    main()
