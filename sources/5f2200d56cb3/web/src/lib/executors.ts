import type { SSHTarget } from "@/lib/types";

export function isExecutorReady(target: SSHTarget, saas = true, now = Date.now()): boolean {
  if (target.status !== "verified" || !target.host_key) return false;
  return (
    !saas ||
    (target.transport === "agent" &&
      !!target.agent_connected &&
      !!target.agent_expires_at &&
      Date.parse(target.agent_expires_at) > now)
  );
}

export function executorState(target?: SSHTarget, saas = true, now = Date.now()): string {
  if (!target) return "No VPS selected";
  if (saas && target.transport !== "agent") return "Legacy SSH";
  const expires = Date.parse(target.agent_expires_at ?? "");
  if (expires <= now) return "Expired";
  if (isExecutorReady(target, saas, now)) return expires - now <= 30 * 60_000 ? "Expiring soon" : "Connected";
  if (target.agent_connected) return target.status === "failed" ? "Needs attention" : "Checking VPS";
  return target.agent_expires_at ? "Disconnected" : "Awaiting installation";
}

export function executorTimeLeft(target: SSHTarget, now = Date.now()): string {
  const remaining = Date.parse(target.agent_expires_at ?? "") - now;
  if (!Number.isFinite(remaining)) return "";
  if (remaining <= 0) return "Access expired";
  const minutes = Math.ceil(remaining / 60_000);
  if (minutes < 60) return `Expires in ${minutes} min`;
  const hours = Math.ceil(minutes / 60);
  return hours < 48 ? `Expires in ${hours} h` : `Expires in ${Math.ceil(hours / 24)} days`;
}
