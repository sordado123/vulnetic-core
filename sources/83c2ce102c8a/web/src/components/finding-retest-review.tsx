"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { ExecutionProof, FindingRetest } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

export function FindingRetestReview({findingId,retest,onReviewed}:{findingId:string;retest:FindingRetest;onReviewed:()=>void}) {
  const [proofs,setProofs]=useState<ExecutionProof[]>([]);
  const [selected,setSelected]=useState<number[]>([]);
  const [steps,setSteps]=useState("");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  useEffect(()=>{
    let disposed=false;
    if(retest.conversation_id) api.conversationExecutionProofs(retest.conversation_id).then(r=>{if(!disposed)setProofs(r.proofs);}).catch(e=>{if(!disposed)setError((e as Error).message);});
    return ()=>{disposed=true;};
  },[retest.conversation_id]);
  async function review(){setBusy(true);try{await api.reviewFindingRetest(findingId,retest.id,selected,steps);toast.success("Retest evidence reviewed");onReviewed();}catch(e){toast.error((e as Error).message);}finally{setBusy(false);}}
  return <div className="space-y-3 rounded border p-3">
    <p className="text-sm">The agent proposed “{retest.verdict}”. Review this run’s command inputs and results, compare the original trigger with a working control, and document your conclusion. Only approving a fixed proposal changes the finding status.</p>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {!proofs.length && <p className="text-sm">No execution proofs are available for review.</p>}
    {proofs.map(p=><details key={p.id} className="rounded border p-2"><summary className="cursor-pointer text-sm">Retest proof #{p.id} · {p.tool}</summary>
      <label className="flex gap-2 py-2 text-sm"><input type="checkbox" checked={selected.includes(p.id)} onChange={e=>setSelected(ids=>e.target.checked?[...ids,p.id]:ids.filter(id=>id!==p.id))}/>I reviewed this retest execution</label>
      <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(p.input,null,2)}{"\n"}{p.output}</pre>
      <p className="break-all text-xs">SHA256: {p.sha256}{p.truncated ? " · truncated evidence" : ""}</p>
    </details>)}
    <label className="block space-y-1 text-sm">Review steps and comparison<Textarea maxLength={16000} value={steps} onChange={e=>setSteps(e.target.value)} placeholder="Explain the original trigger, the control, the observed result and why it supports this verdict."/></label>
    <Button disabled={busy || !selected.length || steps.trim().length<10} onClick={()=>void review()}>Approve retest evidence</Button>
  </div>;
}
