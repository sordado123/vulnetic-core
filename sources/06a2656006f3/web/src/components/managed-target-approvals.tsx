"use client";
import {useEffect,useState} from "react";
import {toast} from "sonner";
import {api} from "@/lib/api";
import {Switch} from "@/components/ui/switch";
export function ManagedTargetApprovals(){
 const [enabled,setEnabled]=useState(false),[busy,setBusy]=useState(true),[available,setAvailable]=useState(false);
 useEffect(()=>{let active=true;api.authStatus().then(async s=>{if(!s.saas_mode)return;const settings=await api.accountSettings();if(active){setEnabled(settings.managed_target_approvals===true);setAvailable(true)}}).catch(e=>toast.error((e as Error).message)).finally(()=>{if(active)setBusy(false)});return()=>{active=false}},[]);
 if(!available)return null;
 return <div className="flex items-start justify-between gap-4 rounded-lg border p-4"><div className="space-y-1"><label htmlFor="managed-target-approvals" className="text-sm font-medium">Approve managed network destinations</label><p className="max-w-3xl text-xs text-muted-foreground">Ask once per task or chat, executor, host, port and resolved IP set. DNS changes require approval again. Covers managed connections, including model/MCP HTTP; direct commands and external proxies need separate containment on your executor. Vulnetic targets remain blocked.</p></div><Switch id="managed-target-approvals" checked={enabled} disabled={busy} onCheckedChange={async value=>{setBusy(true);try{await api.setAccountSettings({managed_target_approvals:value});setEnabled(value)}catch(e){toast.error((e as Error).message)}finally{setBusy(false)}}}/></div>
}
