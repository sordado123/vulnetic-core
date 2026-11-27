"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { CheckCircle2Icon, CircleIcon, LoaderIcon } from "lucide-react";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type Readiness = { llm_configured: boolean; executors: number; executors_verified: number; tasks: number; findings: number };

type Step = { done: boolean; pending?: boolean; title: string; why: string; href: string; cta: string };

// OnboardingChecklist guides a new account to its first finding. It hides once
// the account is fully activated (profile + verified executor + a task + a
// finding), so it only appears while setup is incomplete.
export function OnboardingChecklist() {
  const [r, setR] = useState<Readiness | null>(null);
  useEffect(() => {
    const c = new AbortController();
    const load = () => api.accountReadiness(c.signal).then(v => { if (!c.signal.aborted) setR(v); }).catch(() => {});
    void load();
    const t = setInterval(load, 10000);
    return () => { c.abort(); clearInterval(t); };
  }, []);
  if (!r) return null;
  if (r.llm_configured && r.executors_verified > 0 && r.tasks > 0 && r.findings > 0) return null;

  const steps: Step[] = [
    { done: r.llm_configured, title: "Configure an LLM profile", why: "The agent needs a model and API key to run.", href: "/system/llm", cta: "Open LLM settings" },
    { done: r.executors_verified > 0, pending: r.executors_verified === 0 && r.executors > 0, title: "Add an execution agent", why: "The agent runs on your leased VPS over SSH; add one and verify its host key.", href: "/system/executors", cta: "Add executor" },
    { done: r.tasks > 0, title: "Start your first task", why: "Point the agent at an authorized target to begin exploring.", href: "/function/tasks", cta: "Create a task" },
    { done: r.findings > 0, title: "Review your first finding", why: "Verified findings arrive with reproducible evidence.", href: "/function/findings", cta: "See findings" },
  ];
  const next = steps.find(s => !s.done);

  return <Card>
    <CardHeader><CardTitle>Get to your first finding</CardTitle></CardHeader>
    <CardContent className="space-y-2">
      {steps.map((s, i) => (
        <div key={i} className="flex items-start gap-2 text-sm">
          {s.done
            ? <CheckCircle2Icon className="mt-0.5 size-4 shrink-0 text-emerald-500" />
            : s.pending
              ? <LoaderIcon className="mt-0.5 size-4 shrink-0 text-amber-500" />
              : <CircleIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />}
          <div className="min-w-0 flex-1">
            <span className={s.done ? "text-muted-foreground line-through" : "font-medium"}>{s.title}</span>
            {s.pending && <span className="ml-2 text-xs text-amber-500">verifying…</span>}
            {!s.done && <p className="text-xs text-muted-foreground">{s.why}</p>}
          </div>
          {!s.done && s === next && (
            <Link href={s.href} className="shrink-0 text-xs font-medium text-primary hover:underline">{s.cta} →</Link>
          )}
        </div>
      ))}
    </CardContent>
  </Card>;
}
