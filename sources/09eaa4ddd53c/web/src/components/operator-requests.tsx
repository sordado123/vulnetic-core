"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import { BellRing } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { api, type OperatorRequest } from "@/lib/api";

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
    const tick = () => { if (!document.hidden) void refresh(); };
    const timer = window.setInterval(tick, 5000);
    window.addEventListener("focus", tick);
    return () => { live.current = false; window.clearInterval(timer); window.removeEventListener("focus", tick); };
  }, [refresh]);
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
      <div className="space-y-1">{items.map((item) => <Link key={`${item.conversation_id}:${item.task_id}:${item.seq}`} href={operatorRequestURL(item)} className="block rounded-md p-2 text-sm hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring"><span className="font-medium">{item.conversation_id ? `Chat #${item.conversation_id}` : `Task #${item.task_id} · Worker #${item.intent_id}`}</span><span className="mt-1 block line-clamp-2 text-muted-foreground">{item.question.replace(/^OPERATOR INPUT REQUESTED:\s*/, "")}</span></Link>)}</div>
    </PopoverContent>
  </Popover>;
}
