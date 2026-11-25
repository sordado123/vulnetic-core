"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import { BellRing } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { api, type OperatorRequest } from "@/lib/api";
import { OperatorRequestReply } from "@/components/operator-request-reply";
import { INPUT_LABELS } from "@/lib/operator-input";

const Context = createContext<{ items: OperatorRequest[]; error: boolean; refresh: () => void }>({ items: [], error: false, refresh: () => {} });
export const useOperatorRequests = () => useContext(Context);
export function operatorRequestURL(item: OperatorRequest) {
  return item.conversation_id ? `/chat/?c=${item.conversation_id}` : `/function/tasks/detail/?id=${item.task_id}&tab=sessions&intent=${item.intent_id}`;
}

export function OperatorRequestsProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<OperatorRequest[]>([]);
  const [error, setError] = useState(false);
  const seen = useRef(new Set<string>());
  const inFlight = useRef(false);
  const live = useRef(false);
  const refresh = useCallback(async () => {
    if (inFlight.current || !live.current) return;
    inFlight.current = true;
    try {
      const result = await api.operatorRequests();
      if (!live.current) return;
      setItems(result.items);
      setError(false);
      const added = result.items.filter((item) => !seen.current.has(`${item.conversation_id}:${item.task_id}:${item.seq}`));
      for (const item of result.items) seen.current.add(`${item.conversation_id}:${item.task_id}:${item.seq}`);
      if (added.length) {
        const first = added[0];
        toast.info(added.length > 1 ? `${added.length} requests need your input` : "Your input is needed", { description: first.conversation_id ? `Chat #${first.conversation_id}` : `Task #${first.task_id} · Worker #${first.intent_id}`, action: { label: "Open", onClick: () => { window.location.href = operatorRequestURL(first); } } });
      }
    } catch {
      if (live.current) setError(true);
    } finally { inFlight.current = false; }
  }, []);
  useEffect(() => {
    live.current = true;
    void refresh();
    let lastBackgroundPoll = 0;
    const tick = () => { if (!document.hidden || Date.now() - lastBackgroundPoll >= 15000) { lastBackgroundPoll = Date.now(); void refresh(); } };
    const timer = window.setInterval(tick, 5000);
    window.addEventListener("focus", tick);
    return () => { live.current = false; window.clearInterval(timer); window.removeEventListener("focus", tick); };
  }, [refresh]);
  useEffect(() => { const previous = document.title; const base = previous.replace(/^\(\d+\)\s*/, ""); const title = items.length ? `(${items.length}) ${base}` : base; document.title = title; return () => { if (document.title === title) document.title = base; }; }, [items.length]);
  return <Context.Provider value={{ items, error, refresh }}>{children}</Context.Provider>;
}

export function OperatorRequestsButton() {
  const { items, error, refresh } = useOperatorRequests();
  return <Popover>
    <PopoverTrigger asChild><Button variant="ghost" size="sm" aria-label={error ? "Input notifications unavailable" : `${items.length} requests need your input`} className="gap-1.5"><BellRing aria-hidden="true" className="size-4" />{(items.length > 0 || error) && <span className="rounded bg-amber-100 px-1.5 text-xs font-semibold text-amber-900 dark:bg-amber-950 dark:text-amber-200">{error ? "!" : items.length === 100 ? "100+" : items.length}</span>}</Button></PopoverTrigger>
    <PopoverContent align="end" className="max-h-96 w-80 max-w-[calc(100vw-2rem)] overflow-auto p-3">
      <h2 className="mb-2 text-sm font-semibold">Input requests</h2>
      {error && <div className="mb-2 text-sm text-destructive">Notifications could not be refreshed. <Button size="sm" variant="outline" onClick={refresh}>Retry</Button></div>}
      {!items.length && !error && <p className="text-sm text-muted-foreground">No questions waiting for your reply.</p>}
      <div className="space-y-3">{items.map((item) => <div key={`${item.conversation_id}:${item.task_id}:${item.seq}`} className="rounded-md border p-2 text-sm"><Link href={operatorRequestURL(item)} className="block rounded hover:underline focus-visible:outline-2 focus-visible:outline-ring"><span className="font-medium">{item.conversation_id ? `Chat #${item.conversation_id}` : `Task #${item.task_id} · Worker #${item.intent_id}`}</span><span className="mt-1 block line-clamp-2 text-muted-foreground">{item.question.replace(/^OPERATOR INPUT REQUESTED:\s*/, "")}</span></Link><div className="mt-2"><OperatorRequestReply item={item} onAnswered={refresh} /></div></div>)}</div>
    </PopoverContent>
  </Popover>;
}

export function PendingOperatorInput({ taskId, intentId, conversationId }: { taskId?: string; intentId?: string; conversationId?: number }) {
  const { items, refresh } = useOperatorRequests();
  const item = items.find((entry) => conversationId ? entry.conversation_id === conversationId : String(entry.task_id) === taskId && String(entry.intent_id) === intentId);
  if (!item) return null;
  return <div role="status" className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b bg-amber-50 px-3 py-2 text-sm text-amber-950 dark:bg-amber-950 dark:text-amber-100"><span>{INPUT_LABELS[item.input?.type ?? "text"]}{item.input?.destination_hint ? ` · ${item.input.destination_hint}` : ""}</span><OperatorRequestReply item={item} onAnswered={refresh} /></div>;
}
