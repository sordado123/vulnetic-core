"""Exercise the pilot compose in a unique, disposable local project."""
import json
import hashlib
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def main():
    root = Path(__file__).resolve().parents[1]
    if not (root / 'dist/amd64/vulnetic').is_file():
        raise SystemExit('Build dist/amd64/vulnetic with embedui first.')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = dict(os.environ, POSTGRES_PASSWORD=secrets.token_hex(32),
               POSTGRES_APP_PASSWORD=secrets.token_hex(32),
               VULNETIC_SIGNUP_ALLOWLIST='', VULNETIC_BETA_PORT=str(port),VULNETIC_PUBLIC_URL=f'http://127.0.0.1:{port}')
    project = 'vulnetic-beta-check-' + secrets.token_hex(5)
    fixtures = tempfile.TemporaryDirectory(prefix='vulnetic-deployment-')
    token_file = Path(fixtures.name)/'gateway-token'
    token_file.write_text(secrets.token_hex(32),encoding='ascii')
    token_file.chmod(0o444)
    mount = {'type':'bind','source':str(token_file),'target':'/run/gateway-token','read_only':True}
    overlay = Path(fixtures.name)/'gateway.json'
    overlay.write_text(json.dumps({'services':{
      'gateway':{'image':'vulnetic-gateway:local','build':{'context':str(root),'dockerfile':'deploy/beta/Dockerfile.gateway'},'user':'10002:10002','read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'volumes':[mount], 'environment':{'VULNETIC_GATEWAY_TOKEN_FILE':'/run/gateway-token','VULNETIC_AGENT_PUBLIC_URL':f'http://127.0.0.1:{port}','VULNETIC_AGENT_BINARY_DIR':'/usr/local/lib/vulnetic/agents'}},
      'app':{'volumes':[mount],'environment':{'VULNETIC_GATEWAY_URL':'http://gateway:8789','VULNETIC_GATEWAY_PUBLIC_URL':'http://gateway:8788','VULNETIC_GATEWAY_TOKEN_FILE':'/run/gateway-token'}}}}),encoding='utf-8')
    args = ['docker', 'compose', '--project-name', project, '-f', 'docker-compose.beta.yml', '-f', str(overlay)]
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = f'http://127.0.0.1:{port}'
    with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as log:
        def compose(*command, check=True, input=None):
            return subprocess.run(args + list(command), cwd=root, env=env,
                                  stdout=log, stderr=log, check=check, timeout=600,input=input.encode('utf-8') if input is not None else None)
        invalid = dict(env, POSTGRES_APP_PASSWORD='')
        result = subprocess.run(args + ['config', '--quiet'], cwd=root, env=invalid,
                                stdout=log, stderr=log, timeout=30)
        assert result.returncode != 0, 'Missing RLS password was accepted'
        compose('config', '--quiet')
        try:
            compose('build','app','gateway')
            compose('up','-d','postgres')
            compose('run','--rm','prepare')
            compose('up','-d','app','gateway')
            for _ in range(60):
                try:
                    with client.open(base + '/api/auth/status', timeout=2) as response:
                        status = json.load(response)
                    assert status['saas_mode'] is True
                    break
                except OSError:
                    time.sleep(1)
            else:
                raise AssertionError('Application did not become ready')
            with client.open(base+'/agent/install.sh',timeout=5) as response:
                installer=response.read().decode()
            compose('exec','-T','app','sh','-n',input=installer)
            for arch in ('amd64','arm64'):
                with client.open(base+'/agent/binary/'+arch,timeout=10) as response:
                    binary=response.read()
                with client.open(base+'/agent/checksum/'+arch,timeout=5) as response:
                    digest=response.read().decode().split()[0]
                assert binary.startswith(b'\x7fELF') and hashlib.sha256(binary).hexdigest()==digest, 'Invalid agent binary/checksum'
            data = json.dumps({'account_name': 'Uninvited fixture', 'email': 'fixture@example.invalid', 'password': secrets.token_urlsafe(24)}).encode()
            request = urllib.request.Request(base + '/api/auth/init', data=data, headers={'Content-Type': 'application/json'})
            try:
                with client.open(request, timeout=10):
                    raise AssertionError('Empty allowlist allowed registration')
            except urllib.error.HTTPError as error:
                assert error.code == 403, 'Expected closed registration'
            container = subprocess.check_output(args + ['ps', '-q', 'app'], cwd=root, env=env, text=True).strip()
            info = json.loads(subprocess.check_output(['docker', 'inspect', container], text=True))[0]
            assert info['Config']['User'] == '10001:10001'
            assert info['HostConfig']['ReadonlyRootfs']
            runtime_env=dict(item.split('=',1) for item in info['Config']['Env'] if '=' in item)
            assert 'postgres://vulnetic_app:' in runtime_env['VULNETIC_PG_DSN'], 'Owner credential remained in runtime'
            gateway_id=subprocess.check_output(args+['ps','-q','gateway'],cwd=root,env=env,text=True).strip()
            gateway_info=json.loads(subprocess.check_output(['docker','inspect',gateway_id],text=True))[0]
            assert gateway_info['HostConfig']['ReadonlyRootfs'] and gateway_info['Config']['User']=='10002:10002'
            assert not any('PG_DSN=' in value or 'JWT' in value or 'VAULT' in value for value in gateway_info['Config']['Env'])
            assert len(gateway_info['Mounts'])==1, 'Unexpected platform mount in gateway'
            assert all(p['HostIp'] == '127.0.0.1' for p in info['HostConfig']['PortBindings']['8787/tcp'])
            compose('exec', '-T', 'app', 'sh', '-c', 'test -s /var/lib/vulnetic/vault.key && test -s /var/lib/vulnetic/jwt.key && test ! -e /var/lib/vulnetic/data/vault.key && test ! -e /var/lib/vulnetic/data/jwt.key')
            print('Pilot deployment passed: SaaS, required RLS, closed registration, non-root, read-only image, loopback, persistent keys, agent binaries/checksums and installer syntax.')
        except Exception:
            compose('logs', '--no-color', check=False)
            # Print diagnostic logs with generated database passwords removed.
            log.seek(0)
            details = log.read()[-12000:]
            for name in ('POSTGRES_PASSWORD', 'POSTGRES_APP_PASSWORD'):
                details = details.replace(env[name], '[redacted]')
            print(details,file=sys.stderr)
            raise
        finally:
            # Only this randomly named disposable test project is removed.
            compose('down', '--volumes', '--remove-orphans')
            fixtures.cleanup()


if __name__ == '__main__':
    main()
