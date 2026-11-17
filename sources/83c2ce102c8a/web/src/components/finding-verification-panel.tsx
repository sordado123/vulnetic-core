"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { ExecutionProof } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";

export function FindingVerificationPanel({findingId,taskId,state,onVerified}:{findingId:string;taskId?:string;state?:string;onVerified:()=>void}) {
  const [proofs,setProofs]=useState<ExecutionProof[]>([]);
  const [selected,setSelected]=useState<number[]>([]);
  const [steps,setSteps]=useState("");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  useEffect(()=>{if(taskId) api.executionProofs(taskId).then(r=>setProofs(r.proofs)).catch(e=>setError((e as Error).message));},[taskId]);
  async function verify(){setBusy(true);try{await api.verifyFinding(findingId,selected,steps);toast.success("Execution evidence reviewed and linked");onVerified();}catch(e){toast.error((e as Error).message);}finally{setBusy(false);}}
  return <Card><CardHeader><CardTitle>Evidence verification · {state==="verified" ? "Verified" : "Candidate"}</CardTitle></CardHeader><CardContent className="space-y-3">
    <p className="text-sm text-muted-foreground">A candidate becomes verified after you review recorded execution results and document reproducible steps. Generated text alone does not confirm a vulnerability. Network capture is unavailable for this remote beta.</p>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {!proofs.length && <p className="text-sm">No remote execution evidence has been recorded for this task.</p>}
    {proofs.map(p=><details key={p.id} className="rounded border p-2"><summary className="cursor-pointer text-sm">Proof #{p.id} · {p.tool} · {new Date(p.created_at).toLocaleString()}</summary><div className="space-y-2 pt-2">
      <label className="flex gap-2 text-sm"><input type="checkbox" disabled={p.failed || p.capture_incomplete || (p.truncated && !p.full_artifact_id)} checked={selected.includes(p.id)} onChange={e=>setSelected(ids=>e.target.checked?[...ids,p.id]:ids.filter(id=>id!==p.id))}/>I reviewed this execution</label>
      {(p.failed || p.capture_incomplete || (p.truncated && !p.full_artifact_id)) && <p className="text-sm text-destructive">Failed or incomplete evidence cannot confirm a finding. Run a new check.</p>}
      {p.full_artifact_id && <Button size="sm" variant="outline" onClick={()=>void api.downloadProofArtifact(p.id).catch(e=>toast.error((e as Error).message))}>Download full proof (may contain secrets)</Button>}
      <p className="text-xs text-muted-foreground">Masked preview - {p.verification_run_id ? `controlled check #${p.verification_run_id}` : "manual execution; human review required"}</p>
      <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(p.input,null,2)}{"\n"}{p.output}</pre><p className="break-all text-xs">SHA256: {p.sha256}{p.truncated ? " · truncated evidence" : ""}</p>
    </div></details>)}
    <label className="block space-y-1 text-sm">Reproduction steps<Textarea value={steps} onChange={e=>setSteps(e.target.value)} maxLength={16000} placeholder="Describe the request, prerequisites, expected result and observed result."/></label>
    <Button disabled={busy || !selected.length || steps.trim().length<10} onClick={()=>void verify()}>Review and verify finding</Button>
  </CardContent></Card>;
}
