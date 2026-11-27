"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Lesson } from "@/lib/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

// Per-kind label + color for an environment lesson (#11). positive = reuse,
// negative = don't repeat, caution = recheck before reporting.
const KIND: Record<string, { label: string; cls: string }> = {
  positive: { label: "works", cls: "text-emerald-500" },
  negative: { label: "avoid", cls: "text-red-500" },
  caution: { label: "recheck", cls: "text-amber-500" },
};

// AccountLearnings shows what the agent has learned about this account's own
// environment. Renders nothing until lessons exist (none in a fresh account, or
// when lesson extraction is off), so it stays out of the way.
export function AccountLearnings() {
  const [lessons, setLessons] = useState<Lesson[]>([]);
  useEffect(() => {
    const c = new AbortController();
    api.accountLessons(c.signal).then(r => { if (!c.signal.aborted) setLessons(r.lessons || []); }).catch(() => {});
    return () => c.abort();
  }, []);
  if (!lessons.length) return null;
  return <Card>
    <CardHeader><CardTitle>What the agent learned about your environment</CardTitle></CardHeader>
    <CardContent className="space-y-2">
      {lessons.map(l => {
        const k = KIND[l.kind] ?? { label: l.kind, cls: "text-muted-foreground" };
        return <div key={l.id} className="flex gap-2 text-sm">
          <span className={`shrink-0 text-xs font-semibold uppercase ${k.cls}`}>{k.label}</span>
          <span>
            <span className="font-medium">{l.cue}</span> → {l.action}
            {l.support > 1 && <span className="text-muted-foreground"> · seen {l.support}×</span>}
          </span>
        </div>;
      })}
    </CardContent>
  </Card>;
}
