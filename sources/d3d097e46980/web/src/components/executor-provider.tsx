"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "@/lib/api";
import { executorState, isExecutorReady } from "@/lib/executors";
import type { SSHTarget } from "@/lib/types";

interface Executors {
  targets: SSHTarget[];
  saas: boolean;
  loading: boolean;
  error: string;
  now: number;
  selectedId: number | null;
  select: (id: number | null) => void;
  refresh: () => Promise<void>;
  ensureReady: (id: number | null) => void;
}
const Context = createContext<Executors | null>(null);

export function ExecutorProvider({ children }: { children: ReactNode }) {
  const [targets, setTargets] = useState<SSHTarget[]>([]);
  const [saas, setSaas] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [now, setNow] = useState(0);
  const [selectedId, select] = useState<number | null>(null);
  const live = useRef(false);
  const inFlight = useRef(false);
  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const [status, rows] = await Promise.all([api.authStatus(), api.sshTargets()]);
      if (live.current) {
        setSaas(status.saas_mode === true);
        setTargets(rows);
        setError("");
      }
    } catch (e) {
      if (live.current) setError((e as Error).message);
    } finally {
      inFlight.current = false;
      if (live.current) {
        setLoading(false);
        setNow(Date.now());
      }
    }
  }, []);
  useEffect(() => {
    live.current = true;
    void refresh();
    const tick = () => {
      setNow(Date.now());
      if (!document.hidden) void refresh();
    };
    const timer = window.setInterval(tick, 5000);
    window.addEventListener("focus", tick);
    return () => {
      live.current = false;
      window.clearInterval(timer);
      window.removeEventListener("focus", tick);
    };
  }, [refresh]);
  function ensureReady(id: number | null) {
    if (!saas) return;
    if (loading || error)
      throw new Error("VPS status is unavailable. Refresh the connection status before running this action.");
    const target = targets.find((t) => t.id === id);
    if (!target)
      throw new Error("Select a connected VPS before running this action. You can save configurations without one.");
    if (!isExecutorReady(target, saas))
      throw new Error(
        `${target.name}: ${executorState(target, saas)}. Reconnect it from VPS executors or select another connected VPS.`,
      );
  }
  return (
    <Context.Provider value={{ targets, saas, loading, error, now, selectedId, select, refresh, ensureReady }}>
      {children}
    </Context.Provider>
  );
}

export function useExecutors() {
  const context = useContext(Context);
  if (!context) throw new Error("ExecutorProvider is required");
  return context;
}

// A new action follows the session selection until the user explicitly picks its VPS.
export function useExecutionTarget() {
  const { selectedId } = useExecutors();
  const [value, setValue] = useState<number | null | undefined>(undefined);
  return [value === undefined ? selectedId : value, setValue] as const;
}
