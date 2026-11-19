"use client";

import * as React from "react";

import { Card, CardContent } from "@/components/ui/card";
import { ExplorationGraph } from "@/components/exploration-graph";
import { Button } from "@/components/ui/button";
import { poll } from "@/lib/polling";
import { api } from "@/lib/api";
import type { Edge, TaskNode } from "@/lib/types";

export function GraphTab({ taskId }: { taskId: string }) {
  const [nodes, setNodes] = React.useState<TaskNode[]>([]);
  const [edges, setEdges] = React.useState<Edge[]>([]);
  // Signature of the previous graph data: polling skips setState on identical data to avoid
  // rebuilding the whole graph (so dragging is not jarred by the 20s poll). Only render-affecting fields count.
  const sigRef = React.useRef("");

  const [error,setError]=React.useState("");
  const [loaded,setLoaded]=React.useState(false);
  const [retry,setRetry]=React.useState(0);
  React.useEffect(() => {
    let cancelled = false;setNodes([]);setEdges([]);setLoaded(false);setError("");
    sigRef.current = ""; // task switch: force the next refresh
    const load = (signal:AbortSignal) => {
      return api
        .explorationGraph(taskId,signal)
        .then((g) => {
          if (cancelled) return;
          setError("");setLoaded(true);
          const ns = g.nodes ?? [];
          const es = g.edges ?? [];
          const sig = JSON.stringify([
            ns.map((n) => [n.id, n.type, n.state, n.priority, n.payload]),
            es.map((e) => [e.src, e.dst, e.rel]),
          ]);
          if (sig === sigRef.current) return; // unchanged → do not rebuild
          sigRef.current = sig;
          setNodes(ns);
          setEdges(es);
        })
        .catch(e => {if(!cancelled&&!signal.aborted)setError((e as Error).message)});
    };
    const timer = poll(load, 20000);
    return () => {
      cancelled = true;
      timer();
    };
  }, [taskId,retry]);

  return (
    <Card>
      <CardContent className="p-0">
        {error&&<div role="alert" className="flex flex-wrap items-center gap-2 p-4 text-sm text-destructive"><span>Graph refresh failed. {loaded?"Showing the last loaded snapshot.":"No snapshot loaded."} {error}</span><Button variant="outline" size="sm" onClick={()=>setRetry(v=>v+1)}>Retry</Button></div>}
        {!loaded&&!error&&<p role="status" className="p-4 text-sm text-muted-foreground">Loading exploration graph…</p>}
        <ExplorationGraph nodes={nodes} edges={edges} className="h-[72vh]" />
      </CardContent>
    </Card>
  );
}
