"use client";

import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api, type OperatorRequest } from "@/lib/api";
import { cookieExportHelper, INPUT_LABELS } from "@/lib/operator-input";

export function OperatorRequestReply({ item, onAnswered }: { item: OperatorRequest; onAnswered: () => void }) {
  const [open, setOpen] = useState(false);
  const [answer, setAnswer] = useState("");
  const [completed, setCompleted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [requestID, setRequestID] = useState("");
  const spec = item.input ?? { type: "text" };
  const sensitive = spec.type === "one_time_code" || spec.type === "session";
  const label = INPUT_LABELS[spec.type] ?? "Reply needed";
  const helper = spec.type === "session" && spec.target_url ? cookieExportHelper(spec.target_url) : "";

  function changeOpen(next: boolean) {
    setOpen(next);
    setError("");
    if (next) setRequestID(crypto.randomUUID());
    else { setAnswer(""); setCompleted(false); setRequestID(""); }
  }
  async function send(approved?: boolean) {
    if (saving) return;
    setSaving(true); setError("");
    try {
      await api.replyOperatorRequest({ task_id: item.task_id, intent_id: item.intent_id, conversation_id: item.conversation_id, seq: item.seq, request_id: requestID, answer, approved });
      changeOpen(false);
      onAnswered();
      toast.success("Reply delivered to this execution");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Reply could not be delivered. Retry."); }
    finally { setSaving(false); }
  }
  function submit(event: FormEvent) { event.preventDefault(); void send(spec.type === "action" ? completed : undefined); }

  return <Dialog open={open} onOpenChange={changeOpen}>
    <DialogTrigger asChild><Button type="button" size="sm" variant="outline">{spec.type === "one_time_code" ? "Enter code" : spec.type === "confirm_send_code" ? "Review request" : "Respond"}</Button></DialogTrigger>
    <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>{label}</DialogTitle>
        <DialogDescription>{item.conversation_id ? `Chat #${item.conversation_id}` : `Task #${item.task_id} · Worker #${item.intent_id}`} · Reply applies only to this request.</DialogDescription>
      </DialogHeader>
      {spec.target_url && <div className="space-y-1 text-sm"><span className="text-muted-foreground">Requested service</span><p className="break-all font-medium">{spec.target_url}</p>{(spec.delivery || spec.destination_hint) && <p className="text-muted-foreground">{[spec.delivery, spec.destination_hint].filter(Boolean).join(" · ")}</p>}</div>}
      <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{item.question.replace(/^OPERATOR INPUT REQUESTED:\s*/, "")}</p>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      {spec.type === "confirm_send_code" ? <div className="space-y-3">
        <p className="text-sm text-muted-foreground">Allow one code to be sent through the service above. This does not authorize repeated sends or confirm a login.</p>
        <div className="flex flex-wrap gap-2"><Button disabled={saving} onClick={() => void send(true)}>Allow one code</Button><Button variant="outline" disabled={saving} onClick={() => void send(false)}>Don&apos;t send</Button></div>
      </div> : <form onSubmit={submit} className="space-y-4">
        {spec.type === "action" ? <Label className="flex items-start gap-2 leading-relaxed"><Checkbox checked={completed} disabled={saving} onCheckedChange={(value) => setCompleted(value === true)} />I completed the requested action in my own browser or terminal.</Label> : <div className="space-y-2">
          <Label htmlFor={`operator-answer-${item.seq}`}>{spec.type === "one_time_code" ? "Current one-time code" : spec.type === "session" ? "Cookie export JSON or Cookie header" : "Your reply"}</Label>
          {spec.type === "one_time_code" ? <Input id={`operator-answer-${item.seq}`} type="password" autoComplete="off" value={answer} maxLength={128} disabled={saving} onChange={(event) => setAnswer(event.target.value)} placeholder="Enter the code you received" /> : <Textarea id={`operator-answer-${item.seq}`} autoComplete="off" value={answer} maxLength={spec.type === "session" ? 32768 : 4000} rows={spec.type === "session" ? 5 : 3} disabled={saving} onChange={(event) => setAnswer(event.target.value)} placeholder={spec.type === "session" ? "Paste only the session for the requested site" : "Reply to the question"} />}
          {spec.type === "session" && <div className="space-y-2">
            <Label htmlFor={`operator-file-${item.seq}`}>Or import a local cookie file · 32 KiB maximum</Label>
            <Input id={`operator-file-${item.seq}`} type="file" accept=".json,.txt,application/json,text/plain" disabled={saving} onChange={async (event) => {
              const file = event.target.files?.[0]; event.target.value = "";
              if (!file) return;
              if (file.size > 32768) { setError("Cookie input is limited to 32 KiB. Use the executor file upload for larger files."); return; }
              try { setAnswer(await file.text()); setError(""); } catch { setError("The cookie file could not be read."); }
            }} />
          </div>}
        </div>}
        {sensitive && <p className="text-sm text-muted-foreground">Held temporarily in memory and passed only to this execution&apos;s selected executor. The value is not saved in chat history or evidence. Its delivery reference lasts 15 minutes; a platform restart requires resubmission. A session may still be rejected or expire at the service.</p>}
        {spec.type === "text" && <p className="text-xs text-muted-foreground">Use the dedicated code or session request for sensitive authentication data.</p>}
        <Button type="submit" disabled={saving || (spec.type === "action" ? !completed : !answer.trim())}>{saving ? "Delivering…" : spec.type === "one_time_code" ? "Send code and continue" : spec.type === "session" ? "Share this session and continue" : "Send reply and continue"}</Button>
      </form>}
      {helper && <details className="space-y-2 border-t pt-3 text-sm">
        <summary className="cursor-pointer font-medium">Local cookie export helper</summary>
        <p className="mt-2 text-muted-foreground">Review the script before running it on the requested site. It downloads a local JSON file and sends nothing automatically. It only includes JavaScript-readable cookies. Use a browser export for HttpOnly cookies and original path, domain and expiry attributes. If DevTools blocks pasted scripts, use the browser export option.</p>
        <pre className="max-h-52 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs">{helper}</pre>
        <Button type="button" variant="outline" size="sm" onClick={async () => { try { await navigator.clipboard.writeText(helper); toast.success("Local export helper copied"); } catch { toast.error("Select the script and copy it manually."); } }}>Copy local export helper</Button>
        <p className="text-xs text-muted-foreground">Review the downloaded file and import it above only if you want this executor to use that session. Your session grants access to the account it represents.</p>
      </details>}
    </DialogContent>
  </Dialog>;
}
