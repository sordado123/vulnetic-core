"use client";

import * as React from "react";

import Link from "next/link";

import {
  ActivityIcon,
  ArrowUpRightIcon,
  BugIcon,
  ClockIcon,
  NetworkIcon,
  ShieldCheckIcon,
  TargetIcon,
  ZapIcon,
} from "lucide-react";
import { Bar, BarChart, CartesianGrid, Tooltip as RechartsTooltip, XAxis, YAxis } from "recharts";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { type ChartConfig, ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart";
import { Progress } from "@/components/ui/progress";
import { api } from "@/lib/api";
import type {
  Activity,
  Agent,
  Finding,
  FindingStats,
  InterceptPending,
  LLMProfile,
  MCPServer,
  Settings,
  SkillItem,
  Stats,
  Task,
  Tool,
  TrafficExchange,
  UsageStats,
} from "@/lib/types";
import { cn } from "@/lib/utils";
import { summarizeTokenUsage } from "@/lib/token-usage";

// ── chart constants ───────────────────────────────────────────────────────────

const dailyTrendConfig = {
  input: { label: "Input", color: "hsl(217 91% 60%)" },
  output: { label: "Output", color: "hsl(263 70% 60%)" },
  cacheRead: { label: "Cache read", color: "hsl(160 60% 45%)" },
} satisfies ChartConfig;

// ── helpers ──────────────────────────────────────────────────────────────────

function fmtRel(ts?: string | number): string {
  if (!ts) return "—";
  const ms = Date.now() - (typeof ts === "number" ? ts * 1000 : Date.parse(ts as string));
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function fmtTokens(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1000) return (n / 1000).toFixed(1) + "k";
  return String(n);
}

const ASSET_TYPE_LABELS: Record<string, string> = {
  root_domain: "Root domain",
  ip: "IP",
  subdomain: "Subdomain",
  app: "App",
  service: "Service",
  endpoint: "Endpoint",
};

const ASSET_COLORS: Record<string, string> = {
  root_domain: "bg-blue-500",
  ip: "bg-indigo-400",
  subdomain: "bg-violet-500",
  app: "bg-orange-400",
  service: "bg-cyan-500",
  endpoint: "bg-emerald-500",
};

function statusColor(code: number): string {
  if (code < 300) return "text-emerald-500";
  if (code < 400) return "text-blue-400";
  if (code < 500) return "text-amber-400";
  return "text-red-400";
}

function statusBg(code: number): string {
  if (code < 300) return "bg-emerald-500";
  if (code < 400) return "bg-blue-400";
  if (code < 500) return "bg-amber-400";
  return "bg-red-400";
}

// ── sub-components ────────────────────────────────────────────────────────────

function LiveDot({ className }: { className?: string }) {
  return <span className={cn("inline-block size-1.5 shrink-0 animate-pulse rounded-full bg-blue-400", className)} />;
}

function SectionTitle({
  icon: Icon,
  children,
  sub,
}: {
  icon: React.ElementType;
  children: React.ReactNode;
  sub?: React.ReactNode;
}) {
  return (
    <div className="mb-3 flex items-center justify-between">
      <div className="flex items-center gap-1.5 text-xs font-semibold">
        <Icon className="size-3.5 text-muted-foreground" />
        {children}
      </div>
      {sub && <span className="text-[10px] text-muted-foreground">{sub}</span>}
    </div>
  );
}

// ── page ─────────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  // data state
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [findingStats, setFindingStats] = React.useState<FindingStats | null>(null);
  const [findingsError, setFindingsError] = React.useState(false);
  const [stats, setStats] = React.useState<Stats | null>(null);
  const [settings, setSettings] = React.useState<Settings | null>(null);
  const [pending, setPending] = React.useState<InterceptPending[]>([]);
  const [activity, setActivity] = React.useState<Activity[]>([]);
  const [tokenDays, setTokenDays] = React.useState<7 | 30 | 90 | 180 | 365>(30);
  const [tokenTab, setTokenTab] = React.useState<string | null>(null);
  const [usageResult, setUsageResult] = React.useState<{ days: number; data: UsageStats } | null>(null);
  const [usageLoading, setUsageLoading] = React.useState(true);
  const [usageError, setUsageError] = React.useState(false);
  const [usageRetry, retryUsage] = React.useReducer((value: number) => value + 1, 0);
  const usageStats = usageResult?.days === tokenDays ? usageResult.data : null;
  const [assetCounts, setAssetCounts] = React.useState<Record<string, number> | null>(null);
  const [traffic, setTraffic] = React.useState<TrafficExchange[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [mcpServers, setMcpServers] = React.useState<MCPServer[]>([]);
  const [skills, setSkills] = React.useState<SkillItem[]>([]);
  const [tools, setTools] = React.useState<Tool[]>([]);
  const [llmProfiles, setLLMProfiles] = React.useState<LLMProfile[]>([]);

  const [saasMode, setSaasMode] = React.useState(true);
  const [fastErrors, setFastErrors] = React.useState("");
  const [slowErrors, setSlowErrors] = React.useState("");
  const [pendingLoaded, setPendingLoaded] = React.useState(false);
  const [activityLoaded, setActivityLoaded] = React.useState(false);
  const [trafficLoaded, setTrafficLoaded] = React.useState(false);
  const [taskCount,setTaskCount]=React.useState(0);
  const [statusCounts,setStatusCounts]=React.useState<Record<string,number>>({});
  const [tasksLoaded, setTasksLoaded] = React.useState(false);
  const [taskError, setTaskError] = React.useState(false);

  React.useEffect(() => {
    let alive = true;
    api.authStatus().then((result) => { if (alive) setSaasMode(!!result.saas_mode); }).catch(() => {});
    return () => { alive = false; };
  }, []);

  // The task list is the most expensive dashboard source. Poll it independently
  // so a large history cannot hold back every other dashboard panel.
  React.useEffect(() => {
    let alive = true;
    let loading = false;
    let signature = "";
    const load = async () => {
      if (loading) return;
      loading = true;
      try {
        const tr = await api.taskPage({summary:"true"});
        if(alive){setTaskCount(tr.account_total);setStatusCounts(tr.counts)}
        if (!alive) return;
        setTasksLoaded(true);
        setTaskError(false);
        const nextSignature = JSON.stringify(tr.tasks);
        if (nextSignature !== signature) {
          signature = nextSignature;
          setTasks(tr.tasks);
        }
      } catch {
        if (alive) setTaskError(true);
      } finally {
        loading = false;
      }
    };
    void load();
    const t = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  // A failed section must not discard successful account data.
  React.useEffect(() => {
    let alive = true;
    let loading = false;
    const load = async () => {
      if (loading) return;
      loading = true;
      const [status, preferences, approvals, feed] = await Promise.allSettled([
        api.stats(), saasMode ? Promise.resolve(null) : api.settings(),
        api.interceptPending(), api.activity(undefined, { limit: 30 }),
      ]);
      loading = false;
      if (!alive) return;
      if (status.status === "fulfilled") setStats(status.value);
      if (preferences.status === "fulfilled") setSettings(preferences.value);
      if (approvals.status === "fulfilled") { setPending(approvals.value); setPendingLoaded(true); }
      if (feed.status === "fulfilled") { setActivity(feed.value.items); setActivityLoaded(true); }
      setFastErrors([
        status.status === "rejected" && "account status", preferences.status === "rejected" && "settings",
        approvals.status === "rejected" && "approvals", feed.status === "rejected" && "activity",
      ].filter(Boolean).join(", "));
    };
    void load();
    const timer = setInterval(load, 5000);
    return () => { alive = false; clearInterval(timer); };
  }, [saasMode]);

  React.useEffect(() => {
    let alive = true;
    let loading = false;
    const load = async () => {
      if (loading) return;
      loading = true;
      try {
        const [items, counts] = await Promise.all([api.findings(), api.findingStats()]);
        if (!alive) return;
        setFindings(items);
        setFindingStats(counts);
        setFindingsError(false);
      } catch {
        if (alive) setFindingsError(true);
      } finally {
        loading = false;
      }
    };
    void load();
    const timer = setInterval(load, 5000);
    return () => { alive = false; clearInterval(timer); };
  }, []);

  // Infrastructure traffic/settings endpoints stay outside SaaS customer APIs.
  React.useEffect(() => {
    let alive = true;
    let loading = false;
    const load = async () => {
      if (loading) return;
      loading = true;
      const [traf, counts, agentList, mcpList, skillList, toolList, profileList] = await Promise.allSettled([
        saasMode ? Promise.resolve(null) : api.traffic(0, 50), api.assetCounts(),
        api.agents(), api.mcpServers(), api.skills(), api.tools(), api.llmProfiles(),
      ]);
      loading = false;
      if (!alive) return;
      if (traf.status === "fulfilled") { setTraffic(traf.value?.exchanges ?? []); setTrafficLoaded(true); }
      if (counts.status === "fulfilled") setAssetCounts(counts.value);
      if (agentList.status === "fulfilled") setAgents(agentList.value);
      if (mcpList.status === "fulfilled") setMcpServers(mcpList.value);
      if (skillList.status === "fulfilled") setSkills(skillList.value);
      if (toolList.status === "fulfilled") setTools(toolList.value);
      if (profileList.status === "fulfilled") setLLMProfiles(profileList.value);
      setSlowErrors([
        traf.status === "rejected" && "traffic", counts.status === "rejected" && "assets",
        agentList.status === "rejected" && "agents", mcpList.status === "rejected" && "MCP",
        skillList.status === "rejected" && "skills", toolList.status === "rejected" && "tools",
        profileList.status === "rejected" && "model profiles",
      ].filter(Boolean).join(", "));
    };
    void load();
    const timer = setInterval(load, 15000);
    return () => { alive = false; clearInterval(timer); };
  }, [saasMode]);

  // Isolate metering from unrelated dashboard requests; discard stale range responses.
  React.useEffect(() => {
    let alive = true;
    let inFlight = false;
    setUsageLoading(true);
    setUsageError(false);
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const data = await api.usageStats(tokenDays);
        if (!Array.isArray(data.daily) || !Array.isArray(data.by_profile)) throw new Error("Invalid usage response");
        if (alive) {
          setUsageResult({ days: tokenDays, data });
          setUsageError(false);
        }
      } catch {
        if (alive) setUsageError(true);
      } finally {
        inFlight = false;
        if (alive) setUsageLoading(false);
      }
    };
    void load();
    const timer = setInterval(load, 15000);
    return () => { alive = false; clearInterval(timer); };
  }, [tokenDays, usageRetry]);

  // ── derived ───────────────────────────────────────────────────────────────

  const tasksByStatus=statusCounts;

  const sortedTasks = React.useMemo(
    () =>
      [...tasks]
        .sort((a, b) => (b.last_activity_unix ?? b.created_unix ?? 0) - (a.last_activity_unix ?? a.created_unix ?? 0))
        .slice(0, 5),
    [tasks],
  );

  const recentFindings = React.useMemo(
    () => [...findings].sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts)).slice(0, 8),
    [findings],
  );

  const recentActivity = React.useMemo(
    () =>
      [...activity]
        .filter((a) => a.kind !== "usage")
        .sort((a, b) => b.seq - a.seq)
        .slice(0, 6),
    [activity],
  );

  const totalAssets = React.useMemo(() => assetCounts === null ? null : Object.values(assetCounts).reduce((a, b) => a + b, 0), [assetCounts]);

  // asset type breakdown
  const assetByType = React.useMemo(() => {
    return Object.entries(assetCounts ?? {})
      .filter(([, n]) => n > 0)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8);
  }, [assetCounts]);

  const assetMax = assetByType[0]?.[1] ?? 1;

  // traffic status code breakdown
  const trafficByCodes = React.useMemo(() => {
    const m: Record<number, number> = {};
    for (const e of traffic) {
      const bucket = Math.floor(e.status / 100) * 100;
      m[bucket] = (m[bucket] ?? 0) + 1;
    }
    return Object.entries(m)
      .sort(([a], [b]) => Number(a) - Number(b))
      .map(([code, n]) => ({ code: Number(code), n }));
  }, [traffic]);

  const trafficMax = Math.max(...trafficByCodes.map((x) => x.n), 1);
  const recentTraffic = [...traffic].sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts)).slice(0, 5);

  // system
  const activeProfile = llmProfiles.find((p) => p.is_default);
  const enabledTools = tools.filter((t) => t.enabled);
  const pendingCount = pending.length;

  const { total: displayedTokens, daily: dailyTokenData } = React.useMemo(
    () => summarizeTokenUsage(usageStats?.daily ?? [], tokenTab), [usageStats, tokenTab],
  );
  const usageUnavailable = !usageStats;
  const usagePending = usageLoading || (!usageStats && !usageError);
  const profileNames = [...new Set([...(usageStats?.by_profile ?? []), ...(usageStats?.daily ?? [])].map((profile) => profile.profile_name))];

  // activity kind label
  function kindLabel(a: Activity): string {
    if (a.kind === "tool_use") return a.tool ?? "tool_use";
    if (a.kind === "tool_result") return "tool_result";
    return a.kind;
  }

  function workerColor(w: string): string {
    if (w === "planner") return "text-violet-400";
    if (w === "mainagent") return "text-cyan-400";
    return "text-blue-400";
  }

  function workerBg(w: string): string {
    if (w === "planner") return "bg-violet-500/10 text-violet-400 border-violet-500/20";
    if (w === "mainagent") return "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
    return "bg-blue-500/10 text-blue-400 border-blue-500/20";
  }

  // ── render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-1 flex-col gap-4 pb-6">
      {(taskError || fastErrors || slowErrors) && <p role="status" className="text-xs text-muted-foreground">
        Some sections could not refresh: {[taskError && "tasks", fastErrors, slowErrors].filter(Boolean).join(", ")}. Retrying automatically; displayed data may be out of date.
      </p>}
      {/* ── Header ── */}
      <div>
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Overview</h1>
          <p className="text-xs text-muted-foreground">Account status · live refresh</p>
        </div>
      </div>

      {/* ── Row 1: 5 stat cards ── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {/* Active tasks */}
        <Card className="gap-1">
          <CardHeader className="pb-0">
            <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <TargetIcon className="size-3" /> Active tasks
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl font-semibold tabular-nums">{tasksByStatus.running ?? 0}</span>
              <span className="text-xs text-muted-foreground">/ {tasksLoaded ? taskCount : "—"}</span>
            </div>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-x-2.5 gap-y-0.5 text-[10px]">
            {(tasksByStatus.running ?? 0) > 0 && <span className="text-blue-400">Exploring {tasksByStatus.running}</span>}
            {(tasksByStatus.paused ?? 0) > 0 && <span className="text-amber-400">Paused {tasksByStatus.paused}</span>}
            {(tasksByStatus.done ?? 0) > 0 && <span className="text-emerald-400">Completed {tasksByStatus.done}</span>}
            {!tasksLoaded && <span className="text-muted-foreground">{taskError ? "Tasks unavailable" : "Loading tasks…"}</span>}
            {tasksLoaded && taskCount === 0 && <span className="text-muted-foreground">No tasks</span>}
          </CardContent>
        </Card>

        {/* Findings, including candidates awaiting review */}
        <Card className="gap-1">
          <CardHeader className="pb-0">
            <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <BugIcon className="size-3" /> Findings
            </div>
            <div className="text-2xl font-semibold tabular-nums">{findingStats?.total ?? "—"}</div>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-x-2.5 gap-y-1 text-[10px]">
            <Link href="/function/findings" className="basis-full font-medium text-foreground underline-offset-4 hover:underline">
              Pending review {findingStats?.pending ?? "—"}
            </Link>
            <span className="text-rose-500">Critical {findingStats?.critical ?? "—"}</span>
            <span className="text-red-400">High {findingStats?.high ?? "—"}</span>
            <span className="text-amber-400">Medium {findingStats?.medium ?? "—"}</span>
            <span className="text-slate-400">Low {findingStats?.low ?? "—"}</span>
          </CardContent>
        </Card>

        {/* Asset nodes */}
        <Card className="gap-1">
          <CardHeader className="pb-0">
            <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <NetworkIcon className="size-3" /> Asset nodes
            </div>
            <div className="text-2xl font-semibold tabular-nums">{totalAssets ?? "—"}</div>
          </CardHeader>
          <CardContent className="text-[10px] text-muted-foreground">Shared across tasks</CardContent>
        </Card>

        {/* Traffic exchanges */}
        <Card className="gap-1">
          <CardHeader className="pb-0">
            <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <ActivityIcon className="size-3" /> Traffic exchanges
            </div>
            <div className="text-2xl font-semibold tabular-nums">{trafficLoaded ? traffic.length : "—"}</div>
          </CardHeader>
          <CardContent className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
            {settings?.traffic_capture ? (
              <>
                <LiveDot />
                <span>Recording</span>
              </>
            ) : (
              <span>{saasMode ? "Capture unavailable" : settings ? "Capture is off" : "Checking capture…"}</span>
            )}
          </CardContent>
        </Card>

        {/* LLM usage */}
        <Card className="gap-1">
          <CardHeader className="pb-0">
            <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <ZapIcon className="size-3" /> Token usage
            </div>
            <div className="text-2xl font-semibold tabular-nums">
              {usageUnavailable ? "—" : fmtTokens(displayedTokens.input + displayedTokens.output)}
            </div>
          </CardHeader>
          <CardContent className="text-[10px] text-muted-foreground">
            {usageUnavailable ? (usagePending ? "Loading usage…" : "Usage unavailable") : <>In {fmtTokens(displayedTokens.input)} (incl. cache {fmtTokens(displayedTokens.cacheRead)}) · Out {fmtTokens(displayedTokens.output)}</>}
          </CardContent>
        </Card>
      </div>

      {usageStats?.metering_incomplete&&<p role="status" className="rounded border p-3 text-sm text-amber-700 dark:text-amber-300">Token totals are incomplete while {usageStats.pending_records||0} usage records await persistence. The ledger retries automatically; contact the operator if this persists.</p>}
      {/* ── Row 2: LLM token usage ── */}
      <Card className="p-4">
        {/* Header */}
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold">
            <ZapIcon className="size-3.5 text-muted-foreground" />
            LLM token usage

          </div>
          {/* Profile tabs */}
          <div className="flex flex-wrap items-center gap-1">
            <button
              type="button"
              onClick={() => setTokenTab(null)}
              aria-pressed={tokenTab === null}
              className={cn(
                "rounded-md px-2.5 py-1 text-[10px] font-medium transition-colors",
                tokenTab === null
                  ? "bg-foreground text-background"
                  : "bg-muted/30 text-muted-foreground hover:text-foreground",
              )}
            >
              All
            </button>
            {profileNames.map((name) => (
              <button
                type="button"
                key={name}
                onClick={() => setTokenTab(name)}
                aria-pressed={tokenTab === name}
                className={cn(
                  "rounded-md px-2.5 py-1 text-[10px] font-medium transition-colors",
                  tokenTab === name ? "bg-foreground text-background" : "bg-muted/30 text-muted-foreground hover:text-foreground",
                )}
              >
                {name || "Unassigned"}
              </button>
            ))}
          </div>
        </div>

        {usageError && (
          <div role="alert" className="mb-4 flex flex-wrap items-center gap-2 text-sm text-destructive">
            <span>{usageStats ? "Unable to refresh token usage. Showing the last recorded data." : "Unable to load token usage."}</span>
            <button type="button" className="underline underline-offset-4" onClick={retryUsage}>Retry</button>
          </div>
        )}
        <div aria-busy={usagePending}>
        {/* Body: metrics left + bar chart right */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[220px_1fr]">
          {/* Left: key metrics */}
          <div className="flex flex-col gap-4">
            {/* Total */}
            <div>
              <div className="text-[10px] text-muted-foreground">Total (input+output)</div>
              <div className="mt-0.5 text-3xl font-bold tabular-nums tracking-tight">
                {usageUnavailable ? "—" : fmtTokens(displayedTokens.input + displayedTokens.output)}
              </div>
              <div className="mt-0.5 text-[10px] text-muted-foreground">Last {tokenDays} days · UTC</div>
            </div>

            {/* Per-type bars */}
            <div className="space-y-3">
              {(() => {
                // input already includes cache; split into three non-overlapping segments: uncached input + cache hits + output = total.
                const total = displayedTokens.input + displayedTokens.output;
                return [
                  {
                    label: "Input (uncached)",
                    value: Math.max(0, displayedTokens.input - displayedTokens.cacheRead),
                    barColor: dailyTrendConfig.input.color!,
                    text: "text-blue-400",
                  },
                  {
                    label: "Cache hits",
                    value: displayedTokens.cacheRead,
                    barColor: dailyTrendConfig.cacheRead.color!,
                    text: "text-emerald-400",
                  },
                  {
                    label: "Output",
                    value: displayedTokens.output,
                    barColor: dailyTrendConfig.output.color!,
                    text: "text-violet-400",
                  },
                ].map(({ label, value, barColor, text }) => {
                  const pct = total > 0 ? (value / total) * 100 : 0;
                  return (
                    <div key={label}>
                      <div className="mb-1 flex items-center justify-between text-[10px]">
                        <span className="text-muted-foreground">{label}</span>
                        <span className={cn("font-mono font-semibold tabular-nums", text)}>{usageUnavailable ? "—" : fmtTokens(value)}</span>
                      </div>
                      <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{ width: `${pct}%`, background: barColor }}
                        />
                      </div>
                    </div>
                  );
                });
              })()}
            </div>

            {/* Cache hit rate */}
            {(() => {
              // input already includes cache → hit rate = cache hits / total input.
              const denominator = displayedTokens.input;
              const hitPct = denominator > 0 ? Math.round((displayedTokens.cacheRead / denominator) * 100) : 0;
              return (
                <div className="flex items-center justify-between rounded-lg border bg-muted/20 px-3 py-2 text-[10px]">
                  <span className="text-muted-foreground">Cache hit rate</span>
                  <span
                    className={cn("font-semibold tabular-nums", hitPct > 50 ? "text-emerald-400" : "text-amber-400")}
                  >
                    {usageUnavailable ? "—" : `${hitPct}%`}
                  </span>
                </div>
              );
            })()}
          </div>

          {/* Right: daily bar chart */}
          <div className="flex min-h-0 flex-col">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <div className="flex gap-3 text-[9px] text-muted-foreground">
                {(["input", "output", "cacheRead"] as const).map((k) => (
                  <span key={k} className="flex items-center gap-1">
                    <span
                      className="inline-block size-2 rounded-sm"
                      style={{ background: dailyTrendConfig[k].color }}
                    />
                    {dailyTrendConfig[k].label}
                  </span>
                ))}
              </div>
              <div className="flex gap-0.5 rounded-md border bg-muted/30 p-0.5">
                {(
                  [
                    { days: 7, label: "7d" },
                    { days: 30, label: "30d" },
                    { days: 90, label: "3mo" },
                    { days: 180, label: "6mo" },
                    { days: 365, label: "1y" },
                  ] as const
                ).map(({ days, label }) => (
                  <button
                    type="button"
                    key={days}
                    onClick={() => setTokenDays(days)}
                    aria-pressed={tokenDays === days}
                    title={`Last ${days} UTC calendar days, including today`}
                    className={cn(
                      "rounded px-2.5 py-0.5 text-[9px] font-medium transition-colors",
                      tokenDays === days
                        ? "bg-background text-foreground shadow-sm"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {dailyTokenData.length === 0 ? (
              <div
                className="flex flex-1 items-center justify-center rounded-lg border bg-muted/10 text-xs text-muted-foreground"
                style={{ minHeight: 180 }}
              >
                {usagePending ? "Loading token usage…" : usageError ? "Token usage unavailable" : "No recorded usage in this period"}
              </div>
            ) : (
              <ChartContainer config={dailyTrendConfig} className="h-[200px] w-full">
                <BarChart data={dailyTokenData} margin={{ top: 4, right: 4, bottom: 0, left: 0 }} maxBarSize={40}>
                  <CartesianGrid vertical={false} />
                  <XAxis
                    dataKey="date"
                    tickFormatter={(date: string) => date.slice(5)}
                    tickLine={false}
                    axisLine={false}
                    tick={{ fontSize: 10 }}
                    tickMargin={6}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    tickFormatter={(v) => fmtTokens(Number(v))}
                    tickLine={false}
                    axisLine={false}
                    tick={{ fontSize: 10 }}
                    width={44}
                  />
                  <ChartTooltip
                    cursor={false}
                    content={
                      <ChartTooltipContent
                        indicator="line"
                        formatter={(value, name) => (
                          <div className="flex w-full items-center justify-between gap-4">
                            <span>
                              {(dailyTrendConfig as Record<string, { label: string }>)[String(name)]?.label ??
                                String(name)}
                            </span>
                            <span className="font-mono font-semibold tabular-nums">{fmtTokens(Number(value))}</span>
                          </div>
                        )}
                      />
                    }
                  />
                  <Bar dataKey="input" stackId="1" fill="var(--color-input)" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="output" stackId="1" fill="var(--color-output)" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="cacheRead" stackId="1" fill="var(--color-cacheRead)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </div>
        </div>
        </div>
      </Card>

      {/* ── Row 3: Activity feed | Findings ── */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {/* Activity feed */}
        <Card className="p-4">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-xs font-semibold">
              <ActivityIcon className="size-3.5 text-muted-foreground" />
              Activity feed
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-muted-foreground">
                {activity.filter((a) => a.kind !== "usage").length} events
              </span>
              <Link
                href="/function/tasks"
                className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-foreground"
              >
                View tasks <ArrowUpRightIcon className="size-3" />
              </Link>
            </div>
          </div>

          <div className="mb-2.5 flex flex-wrap gap-1.5">
            {(["tool_use", "tool_result", "text", "thinking", "result"] as const).map((kind) => {
              const count = activity.filter((a) => a.kind === kind).length;
              if (count === 0) return null;
              return (
                <span key={kind} className="rounded border bg-muted/20 px-1.5 py-0.5 text-[9px] text-muted-foreground">
                  {kind} <strong className="text-foreground/70">{count}</strong>
                </span>
              );
            })}
          </div>

          <div className="divide-y">
            {recentActivity.length === 0 ? (
              <div className="py-4 text-center text-xs text-muted-foreground">{activityLoaded ? "No activity records" : fastErrors.includes("activity") ? "Activity unavailable" : "Loading activity…"}</div>
            ) : (
              recentActivity.map((a) => (
                <div key={a.seq} className="flex gap-2.5 py-2">
                  <span
                    className={cn(
                      "shrink-0 self-start rounded border px-1.5 py-0.5 font-mono text-[9px]",
                      workerBg(a.worker),
                    )}
                  >
                    {a.worker}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="text-[11px] font-medium">{kindLabel(a)}</div>
                    <div className="mt-0.5 truncate text-[10px] text-muted-foreground">{a.summary}</div>
                  </div>
                  <div className="shrink-0 text-right">
                    <Badge variant="outline" className="px-1.5 py-0 text-[9px] text-muted-foreground">
                      {a.kind}
                    </Badge>
                    <div className="mt-0.5 text-[9px] tabular-nums text-muted-foreground">{fmtRel(a.ts)}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>

        {/* Findings */}
        <Card className="p-4">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-xs font-semibold">
              <BugIcon className="size-3.5 text-muted-foreground" />
              Findings
            </div>
            <Link
              href="/function/findings"
              className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-foreground"
            >
              All <ArrowUpRightIcon className="size-3" />
            </Link>
          </div>

          {findingsError && <p role="status" className="mb-2 text-xs text-muted-foreground">Findings could not refresh. Retrying automatically.</p>}
          <div className="divide-y">
            {recentFindings.length === 0 ? (
              <div className="py-4 text-center text-xs text-muted-foreground">{findingStats ? "No findings" : findingsError ? "Findings unavailable" : "Loading findings…"}</div>
            ) : (
              recentFindings.map((f) => (
                <div key={f.id} className="flex items-start gap-2 py-2">
                  <StatusBadge
                    domain="severity"
                    value={f.severity}
                    className="mt-0.5 shrink-0 px-1.5 py-0 text-[10px]"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[11px] font-semibold">{f.name || f.vulnclass}</span>
                      <StatusBadge domain="finding" value={f.status} className="px-1.5 py-0 text-[10px]" />
                      {f.verification_state === "candidate" && <Badge variant="outline" className="px-1.5 py-0 text-[10px]">Candidate</Badge>}
                      {f.task_description && (
                        <span className="truncate text-[10px] text-muted-foreground">{f.task_description}</span>
                      )}
                    </div>
                    <div className="mt-0.5 line-clamp-2 text-[10px] leading-snug text-muted-foreground">
                      {f.summary}
                    </div>
                  </div>
                  <span className="shrink-0 text-[9px] tabular-nums text-muted-foreground">{fmtRel(f.ts)}</span>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      {/* ── Row 4: Task table ── */}
      <Card className="overflow-hidden p-0">
        <div className="flex items-center justify-between border-b px-4 py-3">
          <div className="flex items-center gap-1.5 text-xs font-semibold">
            <ClockIcon className="size-3.5 text-muted-foreground" />
            Tasks
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-muted-foreground">{tasksLoaded ? taskCount : "—"} tasks</span>
            <Link
              href="/function/tasks"
              className="flex items-center gap-0.5 text-[10px] text-muted-foreground hover:text-foreground"
            >
              All <ArrowUpRightIcon className="size-3" />
            </Link>
          </div>
        </div>
        <table className="w-full border-collapse text-xs">
          <thead>
            <tr className="border-b">
              {["Task", "Status", "Engine", "Goal progress", "In flight", "Last activity"].map((h) => (
                <th
                  key={h}
                  className="px-4 py-2 text-left text-[9px] font-semibold uppercase tracking-widest text-muted-foreground first:pl-4"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sortedTasks.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-xs text-muted-foreground">
                  No tasks
                </td>
              </tr>
            ) : (
              sortedTasks.map((t) => {
                const goalsPct = t.goals_total ? Math.round(((t.goals_met ?? 0) / t.goals_total) * 100) : null;
                return (
                  <tr key={t.id} className="border-b last:border-0 transition-colors hover:bg-muted/30">
                    <td className="max-w-xs px-4 py-3">
                      <Link href={`/function/tasks/detail?id=${t.id}`} className="group flex flex-col">
                        <span className="truncate font-medium group-hover:underline">{t.description}</span>
                        <span className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">{t.id}</span>
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge domain="task" value={t.status} dot className="px-1.5 py-0 text-[10px]" />
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge
                        domain="engine"
                        value={t.engine_mode ?? "idle"}
                        className="px-1.5 py-0 text-[10px]"
                      />
                    </td>
                    <td className="px-4 py-3">
                      {goalsPct !== null ? (
                        <div className="flex items-center gap-2">
                          <Progress value={goalsPct} className="h-1 w-14" />
                          <span className="tabular-nums text-muted-foreground">
                            {t.goals_met ?? 0}/{t.goals_total}
                          </span>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 tabular-nums">
                      {(t.in_flight ?? 0) > 0 ? (
                        <span className="font-semibold">{t.in_flight}</span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 tabular-nums text-muted-foreground">
                      {fmtRel(t.last_activity_unix ?? t.created_unix)}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </Card>

      {/* ── Row 5: Asset distribution | Traffic status codes | Interception & pending approvals ── */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        {/* Asset distribution */}
        <Card className="p-4">
          <SectionTitle icon={NetworkIcon} sub="By type">
            Asset distribution
          </SectionTitle>

          {assetByType.length === 0 ? (
            <div className="py-6 text-center text-xs text-muted-foreground">{assetCounts ? "No asset data" : slowErrors.includes("assets") ? "Assets unavailable" : "Loading assets…"}</div>
          ) : (
            <div className="flex flex-col gap-2">
              {assetByType.map(([type, count]) => (
                <div key={type} className="flex items-center gap-2 text-xs">
                  <span className="w-8 shrink-0 text-right text-[10px] text-muted-foreground">
                    {ASSET_TYPE_LABELS[type] ?? type}
                  </span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                    <div
                      className={cn("h-full rounded-full", ASSET_COLORS[type] ?? "bg-slate-400")}
                      style={{ width: `${(count / assetMax) * 100}%` }}
                    />
                  </div>
                  <span className="w-4 text-right tabular-nums">{count}</span>
                </div>
              ))}
            </div>
          )}

          <div className="mt-3 border-t pt-3 text-[10px] text-muted-foreground">{totalAssets ?? "—"} nodes in total</div>
        </Card>

        {/* Traffic status codes */}
        <Card className="p-4">
          <SectionTitle icon={ActivityIcon} sub={`${traffic.length} requests`}>
            Traffic status codes
          </SectionTitle>

          {/* bar chart */}
          {trafficByCodes.length === 0 ? (
            <div className="py-6 text-center text-xs text-muted-foreground">No traffic data</div>
          ) : (
            <>
              <div className="mb-3 flex items-end gap-2" style={{ height: 52 }}>
                {trafficByCodes.map(({ code, n }) => (
                  <div key={code} className="flex flex-1 flex-col items-center gap-1">
                    <span className="text-[9px] tabular-nums text-muted-foreground">{n}</span>
                    <div
                      className={cn("w-full min-h-1 rounded-sm", statusBg(code), "opacity-80")}
                      style={{ height: Math.max(4, (n / trafficMax) * 36) }}
                    />
                    <span className={cn("text-[9px] font-mono", statusColor(code))}>{code}</span>
                  </div>
                ))}
              </div>

              <div className="border-t pt-2.5">
                <div className="mb-1.5 text-[10px] text-muted-foreground">Recent requests</div>
                <div className="flex flex-col gap-1.5">
                  {recentTraffic.map((e) => (
                    <div key={e.id} className="flex items-center gap-1.5 text-[10px]">
                      <span
                        className={cn(
                          "shrink-0 rounded border px-1 py-0 font-mono text-[9px]",
                          e.method === "GET"
                            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                            : "border-blue-500/30 bg-blue-500/10 text-blue-400",
                        )}
                      >
                        {e.method}
                      </span>
                      <span className="min-w-0 flex-1 truncate text-muted-foreground">
                        {e.host}
                        {e.url.replace(/^https?:\/\/[^/]+/, "").substring(0, 30)}
                      </span>
                      <span className={cn("shrink-0 font-mono text-[9px]", statusColor(e.status))}>{e.status}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </Card>

        {/* System status & pending approvals */}
        <Card className="p-4">
          <SectionTitle icon={ShieldCheckIcon}>System status</SectionTitle>

          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between rounded-lg border bg-muted/20 px-3 py-2">
              <div className="text-[10px] text-muted-foreground">LLM config</div>
              <Badge
                variant="outline"
                className={cn(
                  "text-[10px]",
                  stats?.llm_configured
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                    : "border-red-500/30 bg-red-500/10 text-red-400",
                )}
              >
                {stats ? (stats.llm_configured ? "Configured" : "Not configured") : fastErrors.includes("account status") ? "Unavailable" : "Loading…"}
              </Badge>
            </div>

            <div className="flex items-center justify-between rounded-lg border bg-muted/20 px-3 py-2">
              <div className="text-[10px] text-muted-foreground">Traffic capture</div>
              <Badge
                variant="outline"
                className={cn(
                  "text-[10px]",
                  settings?.traffic_capture
                    ? "border-violet-500/30 bg-violet-500/10 text-violet-400"
                    : "text-muted-foreground",
                )}
              >
                {saasMode ? "Unavailable" : settings ? (settings.traffic_capture ? "On" : "Off") : "Loading…"}
              </Badge>
            </div>

            {activeProfile && (
              <div className="flex items-center justify-between rounded-lg border bg-muted/20 px-3 py-2">
                <div className="text-[10px] text-muted-foreground">Active model</div>
                <span className="font-mono text-[10px]">{activeProfile.model}</span>
              </div>
            )}
          </div>

          {/* pending approvals */}
          {pendingCount > 0 && (
            <div className="mt-3">
              <div className="mb-1.5 text-[10px] font-medium text-amber-400">Pending approvals ({pendingCount})</div>
              <div className="flex flex-col gap-1.5">
                {pending.slice(0, 3).map((p) => (
                  <Link
                    key={p.id}
                    href="/system/intercept/approvals"
                    className="flex items-center justify-between rounded-lg border border-amber-500/20 bg-amber-500/5 px-2.5 py-2 hover:bg-amber-500/10"
                  >
                    <div className="min-w-0">
                      <div className="text-[10px] font-medium">{p.tool_name}</div>
                      <div className="text-[9px] text-muted-foreground">{p.agent_name}</div>
                    </div>
                    <ArrowUpRightIcon className="size-3 shrink-0 text-amber-400" />
                  </Link>
                ))}
                {pendingCount > 3 && (
                  <Link
                    href="/system/intercept/approvals"
                    className="text-center text-[10px] text-muted-foreground hover:text-foreground"
                  >
                    {pendingCount - 3} more…
                  </Link>
                )}
              </div>
            </div>
          )}

          {pendingCount === 0 && pendingLoaded && (
            <div className="mt-3 rounded-lg border bg-muted/10 px-3 py-3 text-center text-[10px] text-muted-foreground">
              <ShieldCheckIcon className="mx-auto mb-1 size-4 text-emerald-500/50" />
              No pending interception approvals
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
