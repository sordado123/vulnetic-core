"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { ExecutionProof, FindingPlaybook, FindingEvidenceReview } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";

export function FindingVerificationPanel({findingId,taskId,state,onVerified}:{findingId:string;taskId?:string;state?:string;onVerified:()=>void}) {
  const router=useRouter();
  const [review,setReview]=useState<FindingEvidenceReview|null>(null);
  const [quotes,setQuotes]=useState<Record<number,string>>({});
  const [counterevidence,setCounterevidence]=useState("");
  const [rationale,setRationale]=useState("");
  const [reviewBusy,setReviewBusy]=useState(false);
  const [proofs,setProofs]=useState<ExecutionProof[]>([]);
  const [selected,setSelected]=useState<number[]>([]);
  const [steps,setSteps]=useState("");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [cursor,setCursor]=useState(0);
  const [nextCursor,setNextCursor]=useState(0);
  const [loading,setLoading]=useState(false);
  const [playbook,setPlaybook]=useState<FindingPlaybook|null>(null);
  const loadPlaybook=useCallback((signal?:AbortSignal)=>{api.findingVerification(findingId,signal).then(r=>{if(!signal?.aborted)setPlaybook(r.exists&&r.playbook?r.playbook:null)}).catch(()=>{if(!signal?.aborted)setPlaybook(null)})},[findingId]);
  useEffect(()=>{setSelected([]);setSteps("");setCursor(0);setProofs([]);setError("");},[findingId,taskId]);
  useEffect(()=>{const c=new AbortController();loadPlaybook(c.signal);return()=>c.abort();},[loadPlaybook]);
  useEffect(()=>{const controller=new AbortController();setProofs([]);setNextCursor(0);setError("");if(!taskId)return;setLoading(true);
   api.executionProofs(taskId,cursor,controller.signal).then(r=>{if(!controller.signal.aborted){setProofs(r.proofs);setNextCursor(r.next_cursor||0)}}).catch(e=>{if(!controller.signal.aborted)setError((e as Error).message)}).finally(()=>{if(!controller.signal.aborted)setLoading(false)});return()=>controller.abort();
  },[findingId,taskId,cursor]);
  useEffect(()=>{let active=true;setReview(null);setQuotes({});setCounterevidence("");setRationale("");api.findingEvidenceReview(findingId).then(r=>{if(active)setReview(r.review)}).catch(e=>{if(active)setError((e as Error).message)});return()=>{active=false}},[findingId]);
  async function reviewWithAgent(){setReviewBusy(true);try{const r=await api.startFindingAgentReview(findingId);await api.sendConversationMessage(r.conversation_id,r.message);router.push(`/chat?c=${r.conversation_id}`)}catch(e){toast.error((e as Error).message)}finally{setReviewBusy(false)}}
  async function saveReview(){setReviewBusy(true);try{const r=await api.saveFindingEvidenceReview(findingId,{counterevidence,confidence_rationale:rationale,quotes:Object.entries(quotes).filter(([,q])=>q.trim()).map(([id,quote])=>({proof_id:Number(id),quote}))});setReview(r.review);toast.success("Advisory evidence review recorded; human verification unchanged")}catch(e){toast.error((e as Error).message)}finally{setReviewBusy(false)}}
  async function verify(){setBusy(true);try{await api.verifyFinding(findingId,selected,steps);toast.success("Execution evidence reviewed and linked");setSteps("");setSelected([]);loadPlaybook();onVerified();}catch(e){toast.error((e as Error).message);}finally{setBusy(false);}}
  return <Card><CardHeader><CardTitle>Evidence verification · {state==="verified" ? "Verified" : "Candidate"}</CardTitle></CardHeader><CardContent className="space-y-3">
    <p className="text-sm text-muted-foreground">A candidate becomes verified after you review recorded execution results and document reproducible steps. Generated text alone does not confirm a vulnerability. Account browser captures can be attached separately when available; executor network capture is not assumed.</p>
    <div className="space-y-2 rounded border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm font-medium">Independent evidence review · advisory</p><Button size="sm" variant="outline" disabled={reviewBusy||!taskId} onClick={()=>void reviewWithAgent()}>Review with another agent</Button></div>
      <p className="text-xs text-muted-foreground">Uses your model profile when started. The reviewer cannot execute commands or confirm findings. Quote matching checks source text only.</p>
      {review&&<div className="space-y-1 text-sm"><p>{review.current?"Current evidence":"Evidence changed since this review"} · {review.actor}</p><p>Confidence rationale: {review.confidence_rationale}</p><p>Counterevidence: {review.counterevidence||"None recorded"}</p>{review.quotes.map((q,i)=><p key={i} className="break-words text-xs">{q.proof_id?`Proof #${q.proof_id}`:`Traffic binding #${q.traffic_binding_id}`} · {q.status}: “{q.quote}”</p>)}</div>}
    </div>
    {playbook && <div className="space-y-2 rounded border border-primary/30 bg-primary/5 p-3">
      <div className="flex items-center justify-between gap-2"><p className="text-sm font-medium">Reproduction playbook</p><span className="text-xs text-muted-foreground">verified {new Date(playbook.verified_at).toLocaleString()}</span></div>
      {!playbook.current && <p className="text-xs text-destructive">The finding&apos;s evidence changed after this verification — these steps may predate the current result. Re-verify below.</p>}
      <p className="text-sm"><span className="text-muted-foreground">Claim: </span>{playbook.summary}</p>
      <div><p className="text-xs text-muted-foreground">Steps to reproduce</p><pre className="mt-1 max-h-60 overflow-auto whitespace-pre-wrap break-words text-sm">{playbook.steps}</pre></div>
      <div className="space-y-1"><p className="text-xs text-muted-foreground">Evidence chain ({playbook.proofs.length})</p>
        {playbook.proofs.map(pr=><div key={pr.id} className="flex flex-wrap items-center gap-2 text-xs">
          <span className="font-mono">#{pr.id}</span><span>{pr.tool}</span><span className="text-muted-foreground">{new Date(pr.created_at).toLocaleString()}</span>{pr.truncated&&<span className="text-muted-foreground">· truncated</span>}
          {pr.full_artifact_id&&<Button size="sm" variant="outline" className="h-6 px-2" onClick={()=>void api.downloadProofArtifact(pr.id).catch(e=>toast.error((e as Error).message))}>Download proof</Button>}
        </div>)}
      </div>
    </div>}
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {!loading && !error && !proofs.length && <p className="text-sm">No remote execution evidence has been recorded for this task.</p>}
    {loading&&<p role="status" className="text-sm text-muted-foreground">Loading execution evidence…</p>}
    <div className="flex flex-wrap items-center gap-2"><Button size="sm" variant="outline" disabled={loading||cursor===0} onClick={()=>setCursor(0)}>Latest proofs</Button><Button size="sm" variant="outline" disabled={loading||!nextCursor} onClick={()=>setCursor(nextCursor)}>Older proofs</Button><span className="text-xs text-muted-foreground">{selected.length}/20 selected</span></div>
    {proofs.map(p=><details key={p.id} className="rounded border p-2"><summary className="cursor-pointer text-sm">Proof #{p.id} · {p.tool} · {new Date(p.created_at).toLocaleString()}</summary><div className="space-y-2 pt-2">
      <label className="flex gap-2 text-sm"><input type="checkbox" disabled={p.failed || p.capture_incomplete || (p.truncated && !p.full_artifact_id)} checked={selected.includes(p.id)} onChange={e=>setSelected(ids=>e.target.checked?ids.length<20?[...ids,p.id]:ids:ids.filter(id=>id!==p.id))}/>I reviewed this execution</label>
      {(p.failed || p.capture_incomplete || (p.truncated && !p.full_artifact_id)) && <p className="text-sm text-destructive">Failed or incomplete evidence cannot confirm a finding. Run a new check.</p>}
      {p.full_artifact_id && <Button size="sm" variant="outline" onClick={()=>void api.downloadProofArtifact(p.id).catch(e=>toast.error((e as Error).message))}>Download full proof (may contain secrets)</Button>}
      <p className="break-all text-xs text-muted-foreground">Origin: {p.conversation_id ? `chat #${p.conversation_id}` : `task #${p.task_id}`} · run {p.run_id}{p.executor_id ? ` · executor #${p.executor_id}` : ""}{!p.task_id && p.conversation_id ? " · explicitly linked to this task" : ""}</p>
      <p className="text-xs text-muted-foreground">Masked preview - {p.verification_run_id ? `controlled check #${p.verification_run_id}` : "manual execution; human review required"}</p>
      <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(p.input,null,2)}{"\n"}{p.output}</pre><label className="block space-y-1 text-sm">Evidence quote for advisory check<Textarea maxLength={8000} value={quotes[p.id]||""} onChange={e=>setQuotes(q=>({...q,[p.id]:e.target.value}))} placeholder="Paste an exact observed excerpt (at least 8 characters)."/></label><p className="break-all text-xs">SHA256: {p.sha256}{p.truncated ? " · truncated evidence" : ""}</p>
    </div></details>)}
    <details className="rounded border p-3"><summary className="cursor-pointer text-sm">Record an advisory quote check</summary><div className="space-y-2 pt-2"><label className="block text-sm">Counterevidence<Textarea maxLength={16000} value={counterevidence} onChange={e=>setCounterevidence(e.target.value)}/></label><label className="block text-sm">Confidence rationale<Textarea maxLength={16000} value={rationale} onChange={e=>setRationale(e.target.value)}/></label><Button size="sm" variant="outline" disabled={reviewBusy||rationale.trim().length<10||!Object.values(quotes).some(q=>q.trim().length>=8)} onClick={()=>void saveReview()}>Check quotes and save advisory review</Button></div></details>
    <label className="block space-y-1 text-sm">Reproduction steps<Textarea value={steps} onChange={e=>setSteps(e.target.value)} maxLength={16000} placeholder="Describe the request, prerequisites, expected result and observed result."/></label>
    <Button disabled={busy || !selected.length || steps.trim().length<10} onClick={()=>void verify()}>Review and verify finding</Button>
  </CardContent></Card>;
}
