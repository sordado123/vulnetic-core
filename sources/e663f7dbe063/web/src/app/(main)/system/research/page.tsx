"use client";

import { type FormEvent, useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api, type AccountSearchSettings, type SearchBackend } from "@/lib/api";

const providers: { value: SearchBackend; name: string; hint: string }[] = [
  { value: "mwmbl", name: "Mwmbl", hint: "No API key. Independent search index; coverage and IP-based quotas may limit results." },
  { value: "ddgs", name: "DuckDuckGo", hint: "No API key. Uses the public HTML search endpoint; rate limits or challenges may temporarily block searches." },
  { value: "tavily", name: "Tavily", hint: "Uses your account API key with basic search. Your provider's credits and limits apply." },
  { value: "exa", name: "Exa", hint: "Uses your account API key. Your provider's credits and limits apply." },
  { value: "linkup", name: "Linkup", hint: "Uses your account API key with standard search. Your provider's credits and limits apply." },
];
type KeyProvider = "tavily" | "exa" | "linkup";
function needsKey(backend: SearchBackend): backend is KeyProvider {
  return backend === "tavily" || backend === "exa" || backend === "linkup";
}

export default function ResearchPage() {
  const [settings, setSettings] = useState<AccountSearchSettings | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [backend, setBackend] = useState<SearchBackend>("mwmbl");
  const [keys, setKeys] = useState<Partial<Record<KeyProvider, string>>>({});
  const [remove, setRemove] = useState<Partial<Record<KeyProvider, boolean>>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const current = await api.accountSearch();
      setSettings(current);
      setEnabled(current.enabled);
      setBackend(current.backend);
    } catch {
      setError("Research settings could not be loaded. Retry before making changes.");
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!settings || saving) return;
    if (enabled && needsKey(backend) && !keys[backend]?.trim() && (remove[backend] || !settings[`${backend}_key_set`])) {
      setError("Add an API key for this provider, or choose Mwmbl or DuckDuckGo.");
      return;
    }
    setSaving(true);
    setError("");
    try {
      const patch: Parameters<typeof api.setAccountSearch>[0] = { enabled, backend };
      for (const name of ["tavily", "exa", "linkup"] as const) {
        if (remove[name]) patch[`${name}_key`] = "";
        else if (keys[name]?.trim()) patch[`${name}_key`] = keys[name]!.trim();
      }
      setSettings(await api.setAccountSearch(patch));
      setKeys({});
      setRemove({});
      toast.success("Research settings saved");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Research settings could not be saved. Retry.");
    } finally { setSaving(false); }
  }

  const provider = providers.find((item) => item.value === backend)!;
  const keySaved = settings && needsKey(backend) && settings[`${backend}_key_set`];
  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Research</h1>
        <p className="max-w-prose text-sm text-muted-foreground">Give your agents public sources for CVEs, PoCs, advisories, affected versions and fixes.</p>
      </header>
      {error && <div role="alert" className="space-y-2 text-sm text-destructive"><p>{error}</p>{!settings && !loading && <Button variant="outline" onClick={() => void load()}>Retry loading</Button>}</div>}
      {loading ? <p role="status" className="text-sm text-muted-foreground">Loading research settings…</p> : settings && (
        <Card>
          <CardContent className="p-5 sm:p-6">
            <form onSubmit={save} className="space-y-6">
              <fieldset disabled={saving} className="min-w-0 space-y-6 disabled:opacity-60">
                <legend className="sr-only">Account research settings</legend>
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-1"><Label htmlFor="research-enabled">Enable web research</Label><p className="text-sm text-muted-foreground">Available to agents with the web_search tool enabled.</p></div>
                  <Switch id="research-enabled" checked={enabled} onCheckedChange={setEnabled} />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="research-provider">Search provider</Label>
                  <Select value={backend} onValueChange={(value) => setBackend(value as SearchBackend)}>
                    <SelectTrigger id="research-provider" aria-describedby="provider-hint" className="w-full"><SelectValue /></SelectTrigger>
                    <SelectContent>{providers.map((item) => <SelectItem key={item.value} value={item.value}>{item.name}{needsKey(item.value) ? " · Your API key" : " · No key"}</SelectItem>)}</SelectContent>
                  </Select>
                  <p id="provider-hint" className="text-sm text-muted-foreground">{provider.hint} Providers are never switched automatically.</p>
                </div>
                {needsKey(backend) && <div className="space-y-2">
                  <Label htmlFor="research-key">{provider.name} API key</Label>
                  <Input id="research-key" type="password" autoComplete="new-password" maxLength={4096} value={keys[backend] ?? ""} placeholder={keySaved && !remove[backend] ? "Saved securely · leave blank to keep" : "Enter your API key"} onChange={(event) => { setKeys({ ...keys, [backend]: event.target.value }); setRemove({ ...remove, [backend]: false }); }} aria-describedby="key-hint" />
                  <p id="key-hint" className="text-sm text-muted-foreground">Keys are encrypted for your account and never returned to the browser.</p>
                  {keySaved && <Button type="button" variant="ghost" size="sm" onClick={() => { setRemove({ ...remove, [backend]: !remove[backend] }); setKeys({ ...keys, [backend]: "" }); }}>{remove[backend] ? "Undo key removal" : "Remove saved key"}</Button>}
                  {remove[backend] && <p role="status" className="text-sm text-muted-foreground">The saved key will be removed when you save.</p>}
                </div>}
              </fieldset>
              <div className="border-t pt-4"><Button type="submit" disabled={saving}>{saving ? "Saving…" : "Save research settings"}</Button></div>
            </form>
          </CardContent>
        </Card>
      )}
      <div className="max-w-prose space-y-2 text-sm text-muted-foreground">
        <p>Queries leave from the executor selected in each chat or task. Save settings now; a connected VPS or Windows executor is required when searching.</p>
        <p>Search terms are sent to the selected provider. Research returns public references; a matching CVE or PoC does not verify a finding. Scope checks, execution protections and evidence review still apply.</p>
      </div>
    </div>
  );
}
