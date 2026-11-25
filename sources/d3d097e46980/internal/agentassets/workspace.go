package agentassets

// Only the administrator's installer repairs legacy root-owned directory metadata.
// Creation happens after permanently dropping to the dedicated user's UID/GID.
const prepareWorkspacePython = `import os,pwd,sys
from contextlib import contextmanager
account,home=sys.argv[1:]
identity=pwd.getpwnam(account)
uid,gid=identity.pw_uid,identity.pw_gid
if os.geteuid()!=0 or uid<=0: raise SystemExit('Workspace preparation requires the administrator installer and a non-root agent user')
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
repaired=0
@contextmanager
def directory(parent,name,create=False):
 global repaired
 if create:
  try: os.mkdir(name,0o700,dir_fd=parent)
  except FileExistsError: pass
 try: fd=os.open(name,flags,dir_fd=parent)
 except FileNotFoundError:
  yield None
  return
 except OSError: raise SystemExit('Unsafe managed workspace directory: '+name)
 try:
  info=os.fstat(fd)
  if info.st_uid not in (0,uid): raise SystemExit('Managed workspace belongs to another user; administrator review required: '+name)
  if info.st_uid==0:
   if os.geteuid()!=0: raise SystemExit('Managed directory is still root-owned: '+name)
   os.fchown(fd,uid,gid)
   os.fchmod(fd,0o700)
   repaired+=1
  if os.geteuid()!=0 and not os.access('.',os.W_OK|os.X_OK,dir_fd=fd,effective_ids=True): raise SystemExit('Managed directory is not writable by the agent: '+name)
  yield fd
 finally: os.close(fd)
base=os.open(home,flags)
try:
 if os.fstat(base).st_uid!=uid: raise SystemExit('Workspace base ownership requires administrator review')
 with directory(base,'.vulnetic') as managed:
  if managed is not None:
   with directory(managed,'accounts') as accounts:
    if accounts is not None:
     for name in os.listdir(accounts):
      if not name.isdecimal() or int(name)<=0: continue
      with directory(accounts,name) as scope:
       if scope is None: continue
       for child in ('sessions','tasks','drafts','preflight','tool-tests','notifications','side-questions'):
        with directory(scope,child): pass
 os.setgroups([])
 os.setgid(gid)
 os.setuid(uid)
 with directory(base,'.vulnetic',True) as managed:
  with directory(managed,'accounts',True): pass
finally: os.close(base)
print('Workspace prepared as uid '+str(uid)+'; repaired '+str(repaired)+' managed directories; file contents unchanged')
`
