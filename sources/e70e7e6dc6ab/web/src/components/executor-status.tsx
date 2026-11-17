"use client";

import Link from "next/link";
import { useState } from "react";
import { AlertTriangleIcon, ServerIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ExecutorSelect, ExecutorNotice } from "@/components/executor-select";
import { useExecutors } from "@/components/executor-provider";
import { executorState, isExecutorReady } from "@/lib/executors";

export function ExecutorStatus({ targetId, onChange }: { targetId?: number | null; onChange?: () => void }) {
  const [open, setOpen] = useState(false);
  const { targets, selectedId, select, saas, loading, error, now, refresh } = useExecutors();
  if (!saas) return null;
  const pinned = targetId !== undefined;
  const id = pinned ? targetId : selectedId;
  const target = targets.find((t) => t.id === id);
  const ready = !!target && !error && isExecutorReady(target, saas, now || Date.now());
  const state = executorState(target, saas, now || Date.now());
  const label = loading
    ? "Checking VPS…"
    : error
      ? "VPS status unavailable"
      : target
        ? state
        : !targets.length
          ? "No VPS connected"
          : targets.some((t) => isExecutorReady(t, saas, now || Date.now()))
            ? "Select VPS"
            : targets.some((t) => executorState(t, saas, now || Date.now()) === "Expired")
              ? "VPS expired"
              : targets.some((t) => t.agent_expires_at)
                ? "VPS disconnected"
                : "Awaiting VPS install";
  const warning = !loading && (!ready || state === "Expiring soon");
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className={warning ? "max-w-48 text-amber-700 dark:text-amber-400" : "max-w-48"}
          aria-label={`${pinned ? "Task VPS" : "Execution VPS"}: ${label}`}
        >
          {warning ? <AlertTriangleIcon className="size-3.5 shrink-0" /> : <ServerIcon className="size-3.5 shrink-0" />}
          <span className="truncate">{label}</span>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 max-w-[calc(100vw-2rem)] space-y-3">
        <div className="space-y-1">
          <p className="text-sm font-medium">{pinned ? "Task VPS" : "Execution VPS"}</p>
          <p className="text-xs text-muted-foreground">
            {pinned
              ? "This task keeps its assigned VPS. Changing the default does not move an existing task."
              : "Choose a default for new tasks and connection tests in this session. Existing tasks keep their assigned VPS."}
          </p>
        </div>
        {pinned ? (
          <>
            <p className="break-words text-sm font-medium">{target?.name ?? "No assigned VPS"}</p>
            <ExecutorNotice value={id ?? null} />
            {onChange && <Button variant="outline" size="sm" className="w-full" onClick={() => {setOpen(false);onChange();}}>Change task VPS</Button>}
          </>
        ) : (
          <ExecutorSelect value={selectedId} onChange={select} className="space-y-2" />
        )}
        {error && (
          <Button variant="outline" size="sm" onClick={() => void refresh()}>
            Refresh status
          </Button>
        )}
        <Button asChild variant="outline" size="sm" className="w-full">
          <Link href="/system/executors">Manage VPS connections</Link>
        </Button>
      </PopoverContent>
    </Popover>
  );
}
