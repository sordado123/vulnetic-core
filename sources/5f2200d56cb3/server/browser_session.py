"""Customer-executor browser adapter. Never imported or run by the SaaS process."""
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import time
from urllib.parse import urlsplit


def origin_of(value):
    try:
        u = urlsplit(value)
        if u.scheme not in ('http', 'https') or not u.hostname or u.username is not None or u.password is not None:
            return None
        return (u.scheme, u.hostname.lower().rstrip('.'), u.port or (443 if u.scheme == 'https' else 80))
    except (ValueError, TypeError):
        return None


def browser_main(p):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {'error': 'browser_dependency_missing', 'note': 'Install Playwright and its Chromium browser on this executor as an explicit setup action. No installation or privilege change was attempted.'}
    expected = origin_of(p['url'])
    if expected is None or int(p['deadline']) <= time.time():
        return {'error': 'browser_authorization_expired'}
    root = pathlib.Path(os.getcwd())
    directory = root / ('.vulnetic-browser-' + p['scope'])
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return {'error': 'browser_workspace_invalid'}
    if hasattr(os, 'getuid') and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        return {'error': 'browser_workspace_permissions'}
    state_file = directory / 'state.json'
    state = None
    expires = min(time.time() + 1800, int(p['deadline']))
    if state_file.exists():
        if state_file.is_symlink() or not state_file.is_file() or state_file.stat().st_size > 2 * 1024 * 1024:
            return {'error': 'browser_state_invalid'}
        previous = json.loads(state_file.read_text(encoding='utf-8'))
        if previous.get('scope') == p['scope'] and previous.get('expires', 0) > time.time():
            state = previous.get('state')
            expires = min(previous['expires'], int(p['deadline']))
    result = {'steps': [], 'blocked_requests': 0, 'untrusted': True, 'verified': False}
    browser = None
    context = None
    try:
        with sync_playwright() as pw:
            # Keep Chromium's sandbox enabled. Missing OS prerequisites fail closed.
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True, args=[
                '--host-resolver-rules=MAP ' + expected[1] + ' ' + p['pinned_ip'] + ', MAP * ~NOTFOUND',
                '--disable-background-networking', '--disable-component-update', '--no-first-run',
                '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            ])
            try:
                context = browser.new_context(storage_state=state, accept_downloads=False, service_workers='block')
                context.set_default_timeout(10000)

                def route(request_route):
                    if origin_of(request_route.request.url) != expected or time.time() >= int(p['deadline']):
                        result['blocked_requests'] += 1
                        request_route.abort('blockedbyclient')
                    else:
                        request_route.continue_()

                context.route('**/*', route)
                if not hasattr(context, 'route_web_socket'):
                    return {'error': 'browser_version_unsupported', 'note': 'WebSocket blocking support is required.'}
                context.route_web_socket('**/*', lambda websocket: websocket.close())
                page = context.new_page()
                context.on('page', lambda popup: popup.close() if popup != page else None)
                page.on('dialog', lambda dialog: dialog.dismiss())
                page.goto(p['url'], wait_until='domcontentloaded', timeout=20000)
                for i, action in enumerate(p['actions']):
                    if time.time() >= int(p['deadline']):
                        result['error'] = 'browser_authorization_expired'
                        break
                    kind = action['kind']
                    locator = page.locator(action['selector']).first if action.get('selector') else None
                    if kind == 'fill':
                        value = action.get('value', '')
                        if action.get('env_key'):
                            if action['env_key'] not in os.environ:
                                result['error'] = 'browser_input_unavailable'
                                break
                            value = os.environ[action['env_key']]
                        elif locator.get_attribute('type') == 'password':
                            result['error'] = 'browser_password_requires_credential_reference'
                            break
                        locator.fill(value)
                    elif kind == 'click':
                        locator.click()
                    elif kind == 'read':
                        text = page.locator('body').inner_text(timeout=5000)
                        result['text'] = text[:16000]
                        result['text_truncated'] = len(text) > 16000
                    elif kind == 'screenshot':
                        image = directory / ('capture-' + os.urandom(8).hex() + '.png')
                        page.screenshot(path=str(image), mask=[page.locator('input[type=password]')])
                        os.chmod(image, 0o600)
                        result.setdefault('screenshots', []).append({'path': str(image.relative_to(root)), 'sha256': hashlib.sha256(image.read_bytes()).hexdigest()})
                    result['steps'].append({'index': i, 'kind': kind, 'completed': True})
                result['url'] = page.url
                result['session_expires_at'] = expires
                result['note'] = 'Only this origin was allowed. Cookies remain on this executor; this session deadline and executor authorization were not renewed. Browser content is not finding verification.'
            finally:
                if context is not None:
                    if time.time() < expires:
                        snapshot = {'scope': p['scope'], 'expires': expires, 'state': context.storage_state()}
                        fd, temporary = tempfile.mkstemp(dir=directory, prefix='.state-')
                        try:
                            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                                json.dump(snapshot, stream)
                            os.chmod(temporary, 0o600)
                            os.replace(temporary, state_file)
                        finally:
                            if os.path.exists(temporary):
                                os.unlink(temporary)
                    context.close()
                browser.close()
    except Exception as error:
        result['error'] = 'browser_operation_failed'
        result['error_type'] = type(error).__name__
        result['note'] = 'Inspect installed browser dependencies, sandbox support, selectors and target reachability. No sandbox downgrade or root fallback was attempted.'
    return result


if 'params' in globals():
    try:
        answer = browser_main(params)
    except Exception as error:
        answer = {'error': 'browser_setup_failed', 'error_type': type(error).__name__}
    print(json.dumps(answer, separators=(',', ':')))
