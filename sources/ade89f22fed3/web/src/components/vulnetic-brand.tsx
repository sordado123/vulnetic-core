import { cn } from "@/lib/utils";

export function VulneticBrand({ compact = false, className }: { compact?: boolean; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2.5 text-[22px] font-semibold tracking-tight", className)}>
      <svg aria-hidden="true" viewBox="0 0 32 32" className="size-8 shrink-0">
        <rect width="32" height="32" rx="8" fill="currentColor" />
        <path d="m9 10 7 13 7-13M12 10h8" fill="none" stroke="var(--card)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {!compact && <span>Vulnetic</span>}
    </span>
  );
}
