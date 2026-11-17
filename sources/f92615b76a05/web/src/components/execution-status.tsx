"use client";

import * as React from "react";
import { AlertCircle, ChevronDown, Timer } from "lucide-react";
import { api } from "@/lib/api";
import { poll } from "@/lib/polling";
import { Button } from "@/components/ui/button";

type Run = {
  id: string; status: string; phase: string; phase_at: string; started_at: string;
  finished_at?: string; tokens: number; token_limit: number; duration_limit_seconds?: number;
  calls: number; tools: number; completed_tools: number; failed_tools: number; pending_tools: number;
  message?: string; recovery?: string; checkpoint?: string; code?: string; lane?: string;
};
export type ExecutionStatusResponse = {items: Run[]; token_limit: number; task_summary?: string; legacy_attribution?: string; interrupted_tool_calls?: number; attributed_tokens?: number};
const phases: Record<string,string> = {
  waiting_executor: "Waiting for executor reconnection", preflight: "Checking prerequisites", waiting_model: "Waiting for model", executing_tool: "Executing tool",
  waiting_approval: "Waiting for approval", processing_response: "Processing response", finalizing: "Finalizing", finished: "Finished",
};
const tokens = (n:number) => new Intl.NumberFormat("en", {notation:"compact",maximumFractionDigits:1}).format(n);
const elapsed = (from:string,to:number) => `${Math.max(0,Math.floor((to-Date.parse(from))/1000))}s`;

export function ExecutionStatus({kind,id,onStop}:{kind:"tasks"|"conversations";id:string|number;onStop?:()=>void}) {
  const [data,setData]=React.useState<ExecutionStatusResponse|null>(null);
  const [error,setError]=React.useState(false);
  const [now,setNow]=React.useState(Date.now());
  React.useEffect(()=>{setData(null);setError(false);return poll(async signal=>{
    try {const value=await api.executionRuns(kind,id,signal);if(!signal.aborted){setData(value);setError(false)}}
    catch {if(!signal.aborted)setError(true)}
  },5000)},[kind,id]);
  const active=data?.items.filter(run=>run.status==="running") ?? [];
  React.useEffect(()=>{if(!active.length)return;const timer=setInterval(()=>setNow(Date.now()),1000);return()=>clearInterval(timer)},[active.length]);
  if(error)return <div role="status" className="border-b px-4 py-2 text-sm text-destructive">Execution status is unavailable. Refreshing automatically; controls remain available.</div>;
  if(!data)return null;
  const shown=active.length ? active : data.items.slice(0,1);
  return <section aria-label="Execution status" className="border-b bg-muted/20 px-4 py-3 text-sm">
    {(data.interrupted_tool_calls ?? 0)>0 && <p className="mb-2 text-destructive">{data.interrupted_tool_calls} historical tool calls ended without a returned result. Their outcome is unknown; review before retrying. No commands were replayed.</p>}
    {data.attributed_tokens !== undefined && <p className="mb-2 text-xs text-muted-foreground">Conversation usage attributed since this update: {tokens(data.attributed_tokens)} tokens. Earlier unattributed calls remain in the account total.</p>}
    {data.task_summary && <p className="mb-2 text-muted-foreground">{data.task_summary}</p>}
    {!shown.length && <p className="text-muted-foreground">No attributed executions yet. {data.token_limit > 0 ? `New executions have a ${tokens(data.token_limit)} token budget.` : "New executions have no platform token cap."} Older history is preserved.</p>}
    {shown.map(run=>{
      const end=run.finished_at ? Date.parse(run.finished_at) : run.status==="running" ? now : Date.parse(run.phase_at);
      const warning=run.token_limit>0 && run.tokens>=run.token_limit*0.8;
      return <div key={run.id} className="space-y-2 py-1">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <span className="flex items-center gap-2 font-medium"><Timer className="size-4" aria-hidden="true"/>{run.status==="running" ? phases[run.phase] ?? run.phase : run.message ?? run.status}</span>
          <span className="text-muted-foreground tabular-nums">{elapsed(run.started_at,end)} elapsed{run.duration_limit_seconds ? ` / ${run.duration_limit_seconds}s limit` : ""}</span>
          {run.status==="running" && <span className="text-muted-foreground tabular-nums">Current phase: {elapsed(run.phase_at,now)}</span>}
          <span className={warning ? "font-medium text-destructive tabular-nums" : "text-muted-foreground tabular-nums"}>{tokens(run.tokens)}{run.token_limit>0 ? ` / ${tokens(run.token_limit)} tokens` : " tokens · no platform cap"}{warning ? " · budget warning" : ""}</span>
          {onStop && run.status==="running" && <Button variant="outline" size="sm" onClick={onStop}>Stop execution</Button>}
        </div>
        {run.recovery && run.status!=="completed" && <p className="flex items-start gap-2 text-muted-foreground"><AlertCircle className="mt-0.5 size-4 shrink-0" aria-hidden="true"/>{run.recovery}</p>}
        <details className="text-xs text-muted-foreground"><summary className="flex w-fit cursor-pointer list-none items-center gap-1 rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"><ChevronDown className="size-3" aria-hidden="true"/>Checkpoint and execution details</summary>
          <p className="mt-2 max-w-prose whitespace-pre-wrap">{run.checkpoint || `${run.completed_tools} tool calls returned (${run.failed_tools} errors); ${run.pending_tools} pending. ${run.calls} model calls.`}</p>
          <p className="mt-1 break-all">Run {run.id}{run.code ? ` · ${run.code}` : ""}</p>
          <p className="mt-1 max-w-prose">Tokens include cached input. {run.token_limit>0 ? "This historical execution had a token budget checked between calls; an in-flight response could exceed it." : "Usage is recorded without a platform token cap. Provider and per-response limits still apply."} History and evidence are preserved.</p>
        </details>
      </div>
    })}
  </section>;
}
