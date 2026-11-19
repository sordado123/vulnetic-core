"use client";
import { AttachmentDropzone } from "@/components/attachment-dropzone";

import * as React from "react";
import { DownloadIcon, FileIcon, RefreshCwIcon, UploadIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { ExecutorNotice } from "@/components/executor-select";
import { useExecutors } from "@/components/executor-provider";
import { api } from "@/lib/api";
import type { Task, TaskFile, RestoredTaskFile } from "@/lib/types";

export function FilesTab({ task, onReport }: { task: Task; onReport: () => void }) {
  const [files, setFiles] = React.useState<TaskFile[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState("");
  const [restored, setRestored] = React.useState<RestoredTaskFile[]>([]);
  const [restoredTarget, setRestoredTarget] = React.useState<number | null>(null);
  const [restoring, setRestoring] = React.useState(false);
  const input = React.useRef<HTMLInputElement | null>(null);
  const { ensureReady } = useExecutors();
  const idle = !task.queued && (task.paused || ["done", "failed", "timeout"].includes(task.status));
  const taskId = task.id;
  const load = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const result = await api.taskFiles(taskId);
      setFiles(result.files);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [taskId]);
  React.useEffect(() => {
    void load();
  }, [load]);
  React.useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function check() {
      try {
        const job = await api.taskFileRestoreStatus(taskId);
        if (!active) return;
        if (job.status === "restoring") {
          setRestoring(true);
          setBusy("restore");
          timer = setTimeout(() => void check(), 1000);
        } else {
          setRestoring(false);
          setBusy((previous) => (previous === "restore" ? "" : previous));
          if (job.status === "done") {
            setRestored(job.restored);
            setRestoredTarget(job.ssh_target_id);
          } else if (job.status === "failed") setError(job.error || "Restore stopped; saved files are intact.");
        }
      } catch (e) {
        if (active) {
          setError((e as Error).message);
          timer = setTimeout(() => void check(), 3000);
        }
      }
    }
    void check();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [taskId, restoring]);
  async function upload(selected: File[]) {
    if (!selected.length || busy) return;
    setBusy("upload");
    setError("");
    setRestored([]);
    let failure = "";
    try {
      ensureReady(task.ssh_target_id ?? null);
      await api.uploadTaskFiles(taskId, selected);
      toast.success("Files uploaded to the task executor. No file copy is stored in Vulnetic.");
    } catch (e) {
      failure = (e as Error).message;
    } finally {
      await load();
      if (failure) setError(failure);
      setBusy("");
      if (input.current) input.current.value = "";
    }
  }
  async function restore() {
    setError("");
    setRestored([]);
    setBusy("restore");
    try {
      ensureReady(task.ssh_target_id ?? null);
      await api.restoreTaskFiles(taskId);
      setRestoring(true);
    } catch (e) {
      setError((e as Error).message);
      setBusy("");
    }
  }
  async function stopRestore() {
    try {
      await api.cancelTaskFileRestore(taskId);
      toast.message("Stop requested. Waiting for the transfer to close.");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function download(file: TaskFile) {
    setBusy(file.id);
    setError("");
    try {
      await api.downloadTaskFile(taskId, file);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  return (
    <AttachmentDropzone className="space-y-5" onFiles={upload} disabled={!!busy}>
    <section className="space-y-5" aria-labelledby="task-files-title">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-2xl space-y-1">
          <h2 id="task-files-title" className="text-base font-semibold">
            Task files
          </h2>
          <p className="text-sm text-muted-foreground">
            New uploads go directly to temp/uploads on this task’s executor. Vulnetic keeps only their metadata.
            Previously saved files, reports and execution evidence remain available here.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <input
            ref={input}
            type="file"
            multiple
            className="sr-only"
            aria-label="Upload task files"
            disabled={!!busy}
            onChange={(e) => { const files = Array.from(e.target.files ?? []); e.target.value = ""; void upload(files); }}
          />
          <Button size="sm" variant="outline" disabled={!!busy} onClick={() => input.current?.click()}>
            <UploadIcon className="size-4" />
            {busy === "upload" ? "Saving files…" : "Upload files"}
          </Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button size="sm" disabled={!!busy || !idle || !task.ssh_target_id}>
                <RefreshCwIcon className="size-4" />
                {busy === "restore" ? "Restoring…" : "Restore task files"}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Restore to the task VPS?</AlertDialogTitle>
                <AlertDialogDescription>
                  Copy saved uploads, report versions and original execution evidence to uploads/ on the selected task
                  VPS. Identical files are kept; different existing files stop the restore. This does not resume the
                  task or install tools.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={() => void restore()}>Restore files</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
          {busy === "restore" && (
            <Button size="sm" variant="outline" onClick={() => void stopRestore()}>
              Stop restoration
            </Button>
          )}
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        20 MiB per file · A connected executor is required. New uploads cannot be restored to a replacement executor; upload them again.
      </p>
      <ExecutorNotice value={task.ssh_target_id ?? null} />
      {!idle && (
        <p className="text-sm text-amber-700 dark:text-amber-400">
          Pause this task and stop the main-agent turn before restoring files.
        </p>
      )}
      {error && (
        <div
          role="alert"
          className="flex flex-wrap items-center gap-3 rounded-md border border-destructive/30 p-3 text-sm text-destructive"
        >
          <p className="flex-1 break-words">{error}</p>
          <Button size="sm" variant="outline" disabled={!!busy || loading} onClick={() => void load()}>
            Reload files
          </Button>
        </div>
      )}
      {loading ? (
        <p role="status" className="py-5 text-sm text-muted-foreground">
          Loading saved files…
        </p>
      ) : files.length === 0 && !error ? (
        <div className="rounded-md border border-dashed p-6">
          <p className="text-sm font-medium">No files yet</p>
          <p className="mt-1 text-sm text-muted-foreground">
            Upload inputs here or attach files in the task chat. Files stored only on an unavailable VPS cannot be
            recovered.
          </p>
        </div>
      ) : (
        <ul className="divide-y rounded-md border">
          {files.map((file) => (
            <li key={file.id} className="flex items-center gap-3 p-3">
              <FileIcon className="size-4 shrink-0 text-muted-foreground" />
              <div className="min-w-0 flex-1">
                <p className="break-all text-sm font-medium">{file.name}</p>
                <p className="text-xs text-muted-foreground">
                  {(file.size / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} KiB ·{" "}
                  {file.kind === "remote-upload" ? `Executor #${file.executor_id} only` : file.kind === "report" ? "Report snapshot · Saved in Vulnetic" : "Previous upload · Saved in Vulnetic"}
                </p>
                {file.remote_path && <code className="mt-1 block break-all text-xs text-muted-foreground">{file.remote_path}</code>}
                {file.kind === "remote-upload" && file.executor_id !== task.ssh_target_id && <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">On a previous executor. Upload again to use on the current one.</p>}
              </div>
              {file.kind !== "remote-upload" && <Button
                size="icon"
                variant="ghost"
                aria-label={`Download ${file.name}`}
                disabled={!!busy}
                onClick={() => void download(file)}
              >
                <DownloadIcon className="size-4" />
              </Button>}
            </li>
          ))}
        </ul>
      )}
      <p className="text-sm text-muted-foreground">
        Report versions are saved when viewed or restored. Execution evidence stays in Vulnetic. Restored evidence
        retains its original task and execution IDs.{" "}
        <button type="button" className="font-medium text-foreground underline underline-offset-4" onClick={onReport}>
          View report
        </button>
      </p>
      {restored.length > 0 && restoredTarget === task.ssh_target_id && (
        <div role="status" className="space-y-3 rounded-md border p-4">
          <div>
            <h3 className="text-sm font-medium">Files restored</h3>
            <p className="mt-1 text-sm text-muted-foreground">
              Use these paths on the current task VPS. Prepare required tools, then resume when ready.
            </p>
          </div>
          <ul className="space-y-2">
            {restored.map((file) => (
              <li key={file.path} className="text-sm">
                <span className="font-medium">{file.name}</span>
                <code className="mt-0.5 block break-all text-xs text-muted-foreground">{file.path}</code>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
    </AttachmentDropzone>
  );
}
