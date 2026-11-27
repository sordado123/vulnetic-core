"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, FileTextIcon, DownloadIcon, PrinterIcon } from "lucide-react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { copyText } from "@/lib/utils";
import { reportOutline } from "@/lib/report-outline";

export function ReportTab({ taskId }: { taskId: string }) {
  const [report, setReport] = React.useState<string>("");
  const [loading, setLoading] = React.useState(true);
  const [copied, setCopied] = React.useState(false);
  const [error, setError] = React.useState("");
  const [reload, setReload] = React.useState(0);
  const reportRef = React.useRef<HTMLDivElement>(null);
  const outline = React.useMemo(() => reportOutline(report), [report]);

  function download() {
    const url = URL.createObjectURL(new Blob([report], {type:"text/markdown;charset=utf-8"}));
    const link = document.createElement("a"); link.href = url; link.download = `vulnetic-task-${taskId}-report.md`; link.click();
    setTimeout(() => URL.revokeObjectURL(url),1000);
  }

  function printReport() {
    if (!reportRef.current) return;
    const documentCopy = document.implementation.createHTMLDocument(`Vulnetic · Task ${taskId}`);
    const policy = documentCopy.createElement("meta"); policy.httpEquiv="Content-Security-Policy"; policy.content="default-src 'none'; style-src 'unsafe-inline'";documentCopy.head.append(policy);
    const style = documentCopy.createElement("style");style.textContent="body{font:14px/1.6 system-ui,sans-serif;color:#20242b;margin:24px}h1,h2,h3{break-after:avoid}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%}td,th{border:1px solid #667085;padding:6px;text-align:left}a{color:inherit;overflow-wrap:anywhere}@page{margin:18mm}";documentCopy.head.append(style);
    const content = reportRef.current.cloneNode(true) as HTMLElement;
    content.querySelectorAll("img,iframe,script,object,embed,link,style,form,input,textarea,button").forEach((node) => node.remove());documentCopy.body.append(content);
    const frame=document.createElement("iframe");frame.title="Print report";frame.setAttribute("sandbox","allow-modals allow-same-origin");frame.style.cssText="position:fixed;left:-10000px;width:800px;height:600px";
    frame.onload=()=>{try{frame.contentWindow?.addEventListener("afterprint",()=>frame.remove(),{once:true});frame.contentWindow?.print();}catch{frame.remove();toast.error("Print preview unavailable. Download Markdown instead.");}};
    frame.srcdoc=documentCopy.documentElement.outerHTML;document.body.append(frame);
    setTimeout(()=>frame.remove(),60000);
  }

  React.useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    api
      .report(taskId)
      .then((text) => {
        if (active) setReport(text);
      })
      .catch((e: Error) => {
        if (active) {
          setReport("");
          setError(e.message);
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [taskId, reload]);

  async function copy() {
    if (!report) return;
    const ok = await copyText(report);
    if (ok) {
      setCopied(true);
      toast.success("Markdown copied");
      setTimeout(() => setCopied(false), 1500);
    } else {
      toast.error("Copy failed; please select the text and copy it manually");
    }
  }

  let content: React.ReactNode;
  if (loading) {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        Loading…
      </div>
    );
  } else if (error) {
    content = (
      <div role="alert" className="space-y-3 rounded-md border p-4 text-sm">
        <p className="text-destructive">{error}</p>
        <Button size="sm" variant="outline" onClick={() => setReload((value) => value + 1)}>
          Retry report
        </Button>
      </div>
    );
  } else if (report) {
    content = (
      <div className="space-y-4">
        {outline.length > 1 && <nav aria-label="Report sections" className="max-h-40 overflow-auto border-b pb-3"><ul className="space-y-1 text-sm">{outline.map((heading)=><li key={heading.id} className={heading.level > 2 ? "pl-3" : undefined}><a href={`#${heading.id}`} className="text-muted-foreground underline-offset-2 hover:text-foreground hover:underline" onClick={(event)=>{event.preventDefault();document.getElementById(heading.id)?.scrollIntoView({block:"start"});}}>{heading.title}</a></li>)}</ul></nav>}
        <div ref={reportRef} className="max-h-[60vh] overflow-auto rounded-md border bg-muted/20 p-4">
          <Markdown text={report} navigable />
        </div>
      </div>
    );
  } else {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        No report yet
      </div>
    );
  }

  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <FileTextIcon className="size-4" /> Penetration test report (Markdown)
        </CardTitle>
        <div className="flex flex-wrap gap-2">
          {report && <><Button size="sm" variant="outline" onClick={download}><DownloadIcon /> Markdown</Button><Button size="sm" variant="outline" onClick={printReport}><PrinterIcon /> Print / Save PDF</Button></>}
          {report && (
            <Button size="sm" variant="outline" onClick={copy}>
              {copied ? <CheckIcon /> : <CopyIcon />} Copy
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>{content}</CardContent>
    </Card>
  );
}
