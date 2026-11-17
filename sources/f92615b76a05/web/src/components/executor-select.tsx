"use client";

import Link from "next/link";
import { useId } from "react";
import { useExecutors } from "@/components/executor-provider";
import { executorState, executorTimeLeft, isExecutorReady } from "@/lib/executors";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export function ExecutorNotice({
  value,
  optional = false,
  warningsOnly = false,
}: {
  value: number | null;
  optional?: boolean;
  warningsOnly?: boolean;
}) {
  const { targets, saas, loading, error, now } = useExecutors();
  if (!saas) return null;
  const target = targets.find((t) => t.id === value);
  const state = executorState(target, saas, now || Date.now());
  const ready = !!target && isExecutorReady(target, saas, now || Date.now());
  if (loading)
    return (
      <p className="text-xs text-muted-foreground" role="status">
        Checking VPS connection…
      </p>
    );
  if (error)
    return (
      <p className="text-xs text-destructive" role="alert">
        VPS status unavailable. Try refreshing or check{" "}
        <Link className="underline underline-offset-4" href="/system/executors">
          VPS executors
        </Link>
        .
      </p>
    );
  if (ready && state !== "Expiring soon")
    return warningsOnly ? null : target ? (
      <p className="text-xs text-muted-foreground">{executorTimeLeft(target, now)}.</p>
    ) : null;
  return (
    <p
      className={optional && !value ? "text-xs text-muted-foreground" : "text-xs text-amber-700 dark:text-amber-400"}
      role="status"
    >
      {ready
        ? `${target?.name}: ${executorTimeLeft(target!, now)}. Tasks stop when access expires. A new installation command is required to reconnect.`
        : target
          ? `${target.name}: ${state.toLowerCase()}. Reconnect it or choose a connected VPS before running.`
          : optional
            ? "You can save and activate this profile now. Select a VPS later to test the connection or run tasks."
            : "Select a connected VPS before running this action. Configuration can be saved without one."}{" "}
      <Link className="underline underline-offset-4" href="/system/executors">
        Manage VPS
      </Link>
    </p>
  );
}

export function ExecutorSelect({
  value,
  onChange,
  disabled,
  optional = false,
  className = "space-y-2 px-4 py-2",
}: {
  value: number | null;
  onChange: (id: number | null) => void;
  disabled?: boolean;
  optional?: boolean;
  className?: string;
}) {
  const { targets, saas, loading, error, now } = useExecutors();
  const id = useId();
  if (!saas && targets.length === 0) return null;
  return (
    <div className={className}>
      <label className="text-xs font-medium" htmlFor={id}>
        {optional ? "VPS for connection tests (optional now)" : "Execution VPS"}
      </label>
      <Select
        value={value ? String(value) : "none"}
        onValueChange={(v) => onChange(v === "none" ? null : Number(v))}
        disabled={disabled || loading || !!error}
      >
        <SelectTrigger id={id} className="w-full">
          <SelectValue placeholder="Select a connected VPS" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="none">Select later</SelectItem>
          {targets.map((t) => (
            <SelectItem key={t.id} value={String(t.id)} disabled={!isExecutorReady(t, saas, now || Date.now())}>
              {t.name} · {executorState(t, saas, now || Date.now())}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <ExecutorNotice value={value} optional={optional} />
    </div>
  );
}
