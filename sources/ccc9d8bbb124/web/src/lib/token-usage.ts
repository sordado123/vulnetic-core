import type { ProfileDayUsage } from "./types";

// Both the total and chart use the same date-filtered ledger rows from the API.
export function summarizeTokenUsage(rows: ProfileDayUsage[], profile: string | null) {
  const total = { input: 0, output: 0, cacheRead: 0 };
  const days = new Map<string, { date: string; input: number; output: number; cacheRead: number }>();
  for (const row of rows) {
    if (profile !== null && row.profile_name !== profile) continue;
    total.input += row.input_tokens;
    total.output += row.output_tokens;
    total.cacheRead += row.cache_read_tokens;
    const day = days.get(row.date) ?? { date: row.date, input: 0, output: 0, cacheRead: 0 };
    day.input += Math.max(0, row.input_tokens - row.cache_read_tokens);
    day.output += row.output_tokens;
    day.cacheRead += row.cache_read_tokens;
    days.set(row.date, day);
  }
  return { total, daily: [...days.values()].sort((a, b) => a.date.localeCompare(b.date)) };
}
