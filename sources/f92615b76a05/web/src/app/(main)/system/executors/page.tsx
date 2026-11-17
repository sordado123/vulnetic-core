"use client";

import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { executorState, executorTimeLeft } from "@/lib/executors";
import { useExecutors } from "@/components/executor-provider";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { SSHTarget } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";

type Installation = { target: SSHTarget; command: string };

const LIFETIMES = [{ value: "10800", label: "3 hours" }, { value: "86400", label: "24 hours" }, { value: "259200", label: "3 days" }, { value: "604800", label: "7 days" }];

function LifetimeSelect({ id, value, onChange }: { id: string; value: string; onChange: (value: string) => void }) {
  return <Select value={value} onValueChange={onChange}><SelectTrigger id={id} className="w-full"><SelectValue /></SelectTrigger><SelectContent>{LIFETIMES.map(item => <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>)}</SelectContent></Select>;
}

function PlatformSelect({ id, value, onChange }: {id:string;value:"linux"|"windows";onChange:(value:"linux"|"windows")=>void}) {
  return <Select value={value} onValueChange={(next)=>onChange(next as "linux"|"windows")}><SelectTrigger id={id} className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="linux">Linux</SelectItem><SelectItem value="windows">Windows (64-bit)</SelectItem></SelectContent></Select>;
}

export default function ExecutorsPage() {
  const { targets, refresh, error: loadError, now, selectedId, select } = useExecutors();
  const [name, setName] = useState("");
  const [lifetime, setLifetime] = useState("10800");
  const [platform,setPlatform]=useState<"linux"|"windows">("linux");
  const [busy, setBusy] = useState(false);
  const [install, setInstall] = useState<Installation | null>(null);
  const [renewing, setRenewing] = useState<SSHTarget | null>(null);
  const [renewLifetime, setRenewLifetime] = useState("10800");
  const [removing, setRemoving] = useState<SSHTarget | null>(null);
  const [deleting, setDeleting] = useState<SSHTarget | null>(null);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    try { await action(); await refresh(); }
    catch (error) { toast.error((error as Error).message); }
    finally { setBusy(false); }
  }

  return <div className="space-y-6 p-4 md:p-6">
    <div className="space-y-2"><h1 className="text-2xl font-semibold">VPS executors</h1><p className="max-w-2xl text-sm leading-relaxed text-muted-foreground">Connect your VPS to Vulnetic with a temporary executor. The connection starts from your VPS, without sharing an SSH password or opening an inbound port.</p></div>
    {loadError && <p role="alert" className="text-sm text-destructive">Could not refresh executors: {loadError}</p>}
    <Card><CardHeader><CardTitle>Add an executor</CardTitle></CardHeader><CardContent>
      <form className="grid gap-4 sm:grid-cols-2" onSubmit={(event) => { event.preventDefault(); void run(async () => {
        setInstall(await api.createExecutionAgent(name.trim(), Number(lifetime),platform)); setName("");
      }); }}>
        <div className="space-y-2"><Label htmlFor="vps-name">Executor name</Label><Input id="vps-name" required maxLength={120} value={name} onChange={(e) => setName(e.target.value)} placeholder="Security workspace" /></div>
        <div className="space-y-2"><Label htmlFor="agent-platform">Operating system</Label><PlatformSelect id="agent-platform" value={platform} onChange={setPlatform}/></div>
        <div className="space-y-2"><Label htmlFor="agent-lifetime">Access lifetime</Label><LifetimeSelect id="agent-lifetime" value={lifetime} onChange={setLifetime} /><p className="text-xs text-muted-foreground">Starts when the agent connects. Access ends automatically; reconnect with a new command after expiration.</p></div>
        {platform === "windows" ? <div className="space-y-2 text-sm leading-relaxed text-muted-foreground sm:col-span-2">
          <p>Run the command in a non-administrator PowerShell window on 64-bit Windows. No service, account or automatic startup is created. Keep the terminal open; Ctrl+C ends access.</p>
          <p>The executor reconnects after network or Vulnetic interruptions until the original deadline. After closing it or restarting Windows, generate and run a new command.</p>
          <p>Commands use your current Windows file and network permissions. Use a dedicated VM/VPS or an already restricted account. Native PowerShell is supported; Python tools require python3.exe on PATH. Task files are preserved.</p>
        </div> : <p className="text-sm leading-relaxed text-muted-foreground sm:col-span-2">Requires Linux, bash, Python 3, curl and systemd 250+ with encrypted credentials. Run installation as root; the service and its commands run as a locked dedicated user without sudo or capabilities. Reconnects after restart until the original deadline. Expiry or revocation clears private connection state; protected program files stay inactive and task files remain.</p>}
        <Button disabled={busy || !name.trim()} type="submit" className="w-fit">{platform === "windows" ? "Generate connection command" : "Generate installation command"}</Button>
      </form>
    </CardContent></Card>
    {install && <section className="space-y-3 rounded-xl border p-4" aria-label="Connect temporary executor">
      <h2 className="font-medium">{install.target.preflight?.os === "windows" ? "Connect" : "Install"} {install.target.name}</h2>
      <p className="text-sm text-muted-foreground">Run this command on your VPS within 5 minutes. This enrollment works once and is shown only here. Vulnetic checks the connection and required tools automatically.</p>
      {install.target.preflight?.os === "windows" && <p className="text-sm text-muted-foreground">Use a non-administrator PowerShell window and keep it open. This command starts a temporary terminal session.</p>}
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-muted p-3 text-xs" aria-label="Executor command">{install.command}</pre>
      <div className="flex flex-wrap gap-2"><Button onClick={() => void navigator.clipboard.writeText(install.command).then(() => toast.success("Command copied")).catch(() => toast.error("Could not copy; select the command manually"))}>Copy command</Button><Button variant="outline" onClick={() => setInstall(null)}>Hide command</Button></div>
    </section>}
    {targets.length === 0 && !loadError && <p className="text-sm text-muted-foreground">No executors yet. Generate a command above and run it on your VPS.</p>}
    {targets.map((target) => <Card key={target.id}><CardHeader><CardTitle className="flex flex-wrap items-center justify-between gap-2"><span className="break-words">{target.name}</span><Badge variant="outline">{executorState(target, true, now || Date.now())}</Badge></CardTitle></CardHeader><CardContent className="space-y-3">
      {target.transport === "agent" ? <>
        {target.agent_expires_at && <p className="text-sm text-muted-foreground">{target.preflight?.os==="windows"?"Windows terminal · ":""}{executorTimeLeft(target, now)} · Access deadline: {new Date(target.agent_expires_at).toLocaleString("en-US")}{target.username !== "pending" && target.preflight?.os !== "windows" ? ` · Installed as ${target.username}` : ""}</p>}
        {target.preflight?.os === "windows" && <p className="text-sm text-muted-foreground">Keep the terminal open on this executor. Closing it or restarting Windows ends the session; task history and files remain available.</p>}
        {target.username === "root" && <p role="status" className="text-sm text-amber-700 dark:text-amber-400">This legacy agent runs as root. Generate a new installation command and run it once as administrator to switch the service to its dedicated user. Use task Files to restore inputs into the new workspace.</p>}
        {target.preflight?.tools && <p className="text-sm text-muted-foreground">Required tools: {Object.entries(target.preflight.tools).map(([tool, ok]) => `${tool}: ${ok ? "ready" : "missing"}`).join(" · ")} · network capture: unavailable</p>}
        {target.last_error && <p role="alert" className="text-sm text-destructive">{target.last_error}</p>}
        <div className="flex flex-wrap gap-2"><Button variant="outline" disabled={busy} onClick={() => { setRenewLifetime("10800"); setRenewing(target); }}>{target.preflight?.os === "windows" ? "New connection command" : "New installation command"}</Button><Button variant="outline" disabled={busy || !target.agent_connected} onClick={() => void run(async () => { await api.validateSSHTarget(target.id); toast.success("Executor checks passed"); })}>Check connection</Button><Button variant="destructive" disabled={busy} onClick={() => setRemoving(target)}>Revoke access</Button><Button variant="outline" disabled={busy} onClick={() => setDeleting(target)}>Delete executor</Button></div>
      </> : <><p className="text-sm text-muted-foreground">This legacy record remains available for history. Add a temporary executor to start or resume SaaS tasks.</p><Button variant="outline" disabled={busy} onClick={() => setRemoving(target)}>Remove legacy record</Button></>}
    </CardContent></Card>)}
    <Button asChild variant="outline"><Link href="/function/tasks">Go to tasks</Link></Button>
    <Dialog open={renewing !== null} onOpenChange={(open) => { if (!open) setRenewing(null); }}><DialogContent><DialogHeader><DialogTitle>Generate a new executor command?</DialogTitle><DialogDescription>This stops existing sessions and creates a new authorization for the lifetime you select. Run the new command on your VPS to reconnect it. Task history and artifacts are preserved.</DialogDescription></DialogHeader>
      <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); if (renewing) void run(async () => { setInstall(await api.renewExecutionAgent(renewing.id, Number(renewLifetime))); setRenewing(null); }); }}><div className="space-y-2"><Label htmlFor="renew-lifetime">Access lifetime</Label><LifetimeSelect id="renew-lifetime" value={renewLifetime} onChange={setRenewLifetime} /></div><DialogFooter><Button type="submit" disabled={busy}>Generate new command</Button></DialogFooter></form>
    </DialogContent></Dialog>
    <Dialog open={removing !== null} onOpenChange={(open) => { if (!open) setRemoving(null); }}><DialogContent><DialogHeader><DialogTitle>{removing?.transport === "agent" ? "Revoke executor access?" : "Remove legacy executor?"}</DialogTitle><DialogDescription>{removing?.transport === "agent" ? "Active sessions will stop and this authorization will no longer work. Task history and files are preserved. Windows terminal sessions end; Linux service files may need manual removal." : "This removes the saved record. Also remove the old Vulnetic public key from authorized_keys on your VPS."}</DialogDescription></DialogHeader><DialogFooter><Button variant="destructive" disabled={busy} onClick={() => { if (removing) void run(async () => { if (removing.transport === "agent") await api.revokeExecutionAgent(removing.id); else await api.deleteSSHTarget(removing.id); setRemoving(null); }); }}>Confirm revocation</Button></DialogFooter></DialogContent></Dialog>
    <Dialog open={deleting !== null} onOpenChange={(open) => { if (!open && !busy) setDeleting(null); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete {deleting?.name}?</DialogTitle>
          <DialogDescription>This permanently removes the saved connection and revokes its access. Any active sessions will stop. Task history and evidence are kept; linked tasks cannot run without an executor. Your VPS and its task files are not deleted. To reconnect, add a new executor.</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={() => setDeleting(null)}>Cancel</Button>
          <Button variant="destructive" disabled={busy} onClick={() => {
            if (deleting) void run(async () => {
              await api.deleteSSHTarget(deleting.id);
              if (selectedId === deleting.id) select(null);
              if (install?.target.id === deleting.id) setInstall(null);
              setDeleting(null);
              toast.success("Executor deleted");
            });
          }}>{busy ? "Deleting…" : "Delete executor"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>;
}
