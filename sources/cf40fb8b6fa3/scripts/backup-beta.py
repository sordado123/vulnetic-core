"""Operator-only beta backup and isolated restore check. Never restores over the live database."""
import argparse, datetime, hashlib, json, os, secrets, shutil, subprocess, time
from pathlib import Path

def run(args, data=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    if result.returncode:
        raise RuntimeError("Backup/restore command failed; inspect the service privately (exit %d)" % result.returncode)
    return result.stdout

def inspect(name):
    return json.loads(run(["docker", "inspect", name]))[0]

def sql(container, query):
    return run(["docker", "exec", container, "psql", "-U", "vulnetic", "-d", "vulnetic_beta", "-v", "ON_ERROR_STOP=1", "-tAc", query]).decode().strip()

def hashes(directory):
    return {str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.rglob("*") if p.is_file() and p != directory/"backup.json"}

def restore_check(backup, application_image, postgres_image):
    manifest=json.loads((backup/"backup.json").read_text())
    if hashes(backup) != manifest["sha256"]:
        raise RuntimeError("Backup integrity failed; restore refused")
    name="vulnetic-restore-"+secrets.token_hex(8)
    label="site.vulnetic.restore="+name
    state=name+"-state"
    created=[]
    try:
        run(["docker","volume","create","--label",label,state]);created.append(state)
        run(["docker","run","-d","--name",name,"--label",label,"--network","none","--memory","512m","--pids-limit","128","--security-opt","no-new-privileges:true","-e","POSTGRES_HOST_AUTH_METHOD=trust","-e","POSTGRES_USER=vulnetic","-e","POSTGRES_DB=vulnetic_beta",postgres_image])
        for _ in range(40):
            ready=subprocess.run(["docker","exec",name,"pg_isready","-U","vulnetic"],capture_output=True,timeout=10)
            if ready.returncode==0 and b"PostgreSQL init process complete" in run(["docker","logs",name]):break
            time.sleep(.5)
        else:raise RuntimeError("Isolated PostgreSQL did not become ready")
        sql(name,"CREATE ROLE vulnetic_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS")
        run(["docker","exec","-i",name,"pg_restore","-U","vulnetic","--single-transaction","--exit-on-error","-d","vulnetic_beta"],(backup/"database.dump").read_bytes())
        if sql(name,"SELECT count(*) FROM accounts") != str(manifest["accounts"]):
            raise RuntimeError("Restored database account count changed")
        if sql(name,"SELECT md5(coalesce(json_agg(row_to_json(x))::text,'[]')) FROM (SELECT e.*,s.agent_expires_at,s.host_key FROM execution_agents e JOIN ssh_targets s ON s.id=e.target_id ORDER BY e.target_id) x") != manifest["executor_fingerprint"]:
            raise RuntimeError("Restored executor identities or expiry changed")
        mounts=["--mount","type=volume,source="+state+",target=/state","--mount","type=bind,source="+str(backup)+",target=/backup,readonly"]
        for operation in ["-xzf","-dzf"]:
            run(["docker","run","--rm","--network","none","--read-only","--user","0","--security-opt","no-new-privileges:true","--entrypoint","tar",*mounts,application_image,"-C","/state",operation,"/backup/state.tar.gz"])
        return {"restore_verified":True,"executor_expiry_preserved":True,"network":"none","backup":str(backup)}
    finally:
        check=subprocess.run(["docker","inspect",name],capture_output=True,timeout=10)
        if check.returncode==0 and json.loads(check.stdout)[0]["Config"]["Labels"].get("site.vulnetic.restore")==name:
            run(["docker","rm","-fv",name])
        for volume in created:
            meta=json.loads(run(["docker","volume","inspect",volume]))[0]
            if meta["Labels"].get("site.vulnetic.restore")==name:run(["docker","volume","rm",volume])

def backup_beta(base, destination):
    if not base.is_dir() or not (base/".env.beta").is_file():raise RuntimeError("An installed beta directory is required")
    compose=["docker","compose","--env-file",str(base/".env.beta"),"-f",str(base/"docker-compose.beta.yml"),"-f",str(base/"docker-compose.protected.yml")]
    app_id=run(compose+["ps","-aq","app"]).decode().strip();pg_id=run(compose+["ps","-q","postgres"]).decode().strip()
    app,pg=inspect(app_id),inspect(pg_id)
    if sql(pg_id,"SELECT count(*) FROM tasks WHERE paused=false AND status NOT IN ('done','failed','timeout')")!="0":raise RuntimeError("Pause all tasks before backup")
    volume=next(m["Name"] for m in app["Mounts"] if m["Destination"]=="/var/lib/vulnetic" and m["Type"]=="volume")
    destination.mkdir(mode=0o700,parents=True,exist_ok=True)
    backup=destination/("beta-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+secrets.token_hex(3));backup.mkdir(mode=0o700)
    running=app["State"]["Running"]
    try:
        if running:run(compose+["stop","app"])
        (backup/"database.dump").write_bytes(run(["docker","exec",pg_id,"pg_dump","-U","vulnetic","-Fc","vulnetic_beta"]))
        run(["docker","run","--rm","--network","none","--user","0","--read-only","--security-opt","no-new-privileges:true","--entrypoint","tar","--mount","type=volume,source="+volume+",target=/state,readonly","--mount","type=bind,source="+str(backup)+",target=/backup",app["Image"],"-C","/state","-czf","/backup/state.tar.gz","."])
        for filename in [".env.beta","docker-compose.beta.yml","docker-compose.protected.yml","release-manifest.json"]:shutil.copy2(base/filename,backup/filename.lstrip("."))
        shutil.copytree(base/"secrets",backup/"secrets")
        manifest={"format":1,"application_image":app["Image"],"postgres_image":pg["Image"],"accounts":int(sql(pg_id,"SELECT count(*) FROM accounts")),"executor_fingerprint":sql(pg_id,"SELECT md5(coalesce(json_agg(row_to_json(x))::text,'[]')) FROM (SELECT e.*,s.agent_expires_at,s.host_key FROM execution_agents e JOIN ssh_targets s ON s.id=e.target_id ORDER BY e.target_id) x"),"sha256":hashes(backup)}
        (backup/"backup.json").write_text(json.dumps(manifest,indent=2))
        for path in backup.rglob("*"):path.chmod(0o700 if path.is_dir() else 0o600)
        result=restore_check(backup,app["Image"],pg["Image"])
        (backup/"restore-result.json").write_text(json.dumps(result,indent=2));(backup/"restore-result.json").chmod(0o600)
        # Keep the checksum index valid after adding the restore receipt.
        manifest["sha256"]=hashes(backup);(backup/"backup.json").write_text(json.dumps(manifest,indent=2));(backup/"backup.json").chmod(0o600)
        return result
    finally:
        if running:run(compose+["start","app"])

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--root",type=Path,default=Path("/opt/vulnetic"));parser.add_argument("--output-dir",type=Path,default=Path("/var/backups/vulnetic"));parser.add_argument("--restore-check",type=Path);args=parser.parse_args()
    os.umask(0o077)
    if args.restore_check:
        backup=args.restore_check.resolve();m=json.loads((backup/"backup.json").read_text());result=restore_check(backup,m["application_image"],m["postgres_image"])
    else:result=backup_beta(args.root.resolve(),args.output_dir.resolve())
    print(json.dumps(result))
if __name__=="__main__":main()
