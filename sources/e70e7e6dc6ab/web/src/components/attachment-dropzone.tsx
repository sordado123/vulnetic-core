"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

export function AttachmentDropzone({ children, onFiles, disabled, className }: {
  children: React.ReactNode;
  onFiles?: (files: File[]) => void;
  disabled?: boolean;
  className?: string;
}) {
  const [dragging, setDragging] = React.useState(false);
  const depth = React.useRef(0);
  return (
    <div
      className={cn(className, dragging && !disabled && "bg-accent outline-2 -outline-offset-2 outline-primary")}
      onDragEnter={(e) => {
        if (!e.dataTransfer.types.includes("Files")) return;
        e.preventDefault();
        depth.current++;
        setDragging(true);
      }}
      onDragOver={(e) => {
        if (!e.dataTransfer.types.includes("Files")) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = disabled ? "none" : "copy";
      }}
      onDragLeave={() => {
        depth.current = Math.max(0, depth.current - 1);
        if (!depth.current) setDragging(false);
      }}
      onDrop={(e) => {
        if (!e.dataTransfer.types.includes("Files")) return;
        e.preventDefault();
        depth.current = 0;
        setDragging(false);
        const files = Array.from(e.dataTransfer.files);
        if (!disabled && files.length) onFiles?.(files);
      }}
      onPaste={(e) => {
        const files = Array.from(e.clipboardData.files);
        if (!files.length) return;
        e.preventDefault();
        if (!disabled) onFiles?.(files);
      }}
    >
      {children}
      {onFiles && (
        <p role="status" className="mt-2 text-xs text-muted-foreground">
          {dragging && !disabled ? "Drop files to upload" : "Attach, drop or paste files · 20 MiB each · Stored only on your executor"}
        </p>
      )}
    </div>
  );
}
