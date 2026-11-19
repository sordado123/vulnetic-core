"use client";

import { useEffect, useState } from "react";
import { poll } from "@/lib/polling";
import { api } from "@/lib/api";
import type { AttackChain } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

// AttackChains shows the agent-declared escalations for a task (#24): how separate
// findings compose into a larger impact. Renders nothing until a chain exists, so
// it stays out of the way on tasks that have none.
export function AttackChains({ taskId }: { taskId: string }) {
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [error,setError]=useState(false);
  useEffect(() => {
    setChains([]);setError(false);
    return poll(async signal=>{
      try {const r=await api.taskAttackChains(taskId,signal);if(!signal.aborted){setChains(r.chains||[]);setError(false)}}
      catch {if(!signal.aborted)setError(true)}
    },5000);
  }, [taskId]);
  if(error && !chains.length) return <p role="status" className="text-sm text-destructive">Attack chains are temporarily unavailable. Retrying automatically.</p>;
  if (!chains.length) return null;
  return <Card>
    <CardHeader><CardTitle>Attack chains</CardTitle>{error && <p role="status" className="text-sm text-muted-foreground">Refresh unavailable. Showing last loaded chains; retrying automatically.</p>}</CardHeader>
    <CardContent className="space-y-4">
      {chains.map(c => <div key={c.id} className="space-y-2 rounded border p-3">
        <div className="flex items-center gap-2"><Badge variant="outline" className="uppercase">{c.severity}</Badge><span className="text-sm font-medium">{c.title}</span></div>
        <p className="text-sm text-muted-foreground">{c.narrative}</p>
        <ol className="space-y-1">
          {c.steps.map(s => <li key={s.position} className="flex gap-2 text-sm">
            <span className="shrink-0 text-muted-foreground">{s.position + 1}.</span>
            <span><span className="font-medium">{s.name || s.summary || `Finding #${s.finding_id}`}</span>{s.severity && <span className="text-muted-foreground"> · {s.severity}</span>}{s.rationale && <span className="text-muted-foreground"> — {s.rationale}</span>}</span>
          </li>)}
        </ol>
      </div>)}
    </CardContent>
  </Card>;
}
