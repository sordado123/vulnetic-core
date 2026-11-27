export const INPUT_LABELS: Record<string, string> = {
  text: "Reply needed", action: "Action needed", confirm_send_code: "Allow code delivery?", one_time_code: "Login code needed", session: "Session needed",
};

// This helper downloads a local file; it never uploads cookies or reads other browser storage.
export function cookieExportHelper(targetURL: string): string {
  let origin: string;
  try {
    const target = new URL(targetURL);
    if (!["https:", "http:"].includes(target.protocol) || target.username || target.password) return "";
    origin = target.origin;
  } catch { return ""; }
  return `(() => {
  const expectedOrigin = ${JSON.stringify(origin)};
  if (location.origin !== expectedOrigin) throw new Error("Open the requested site before exporting.");
  const cookies = document.cookie.split(";").filter(part => part.trim()).map(part => {
    const index = part.indexOf("=");
    return {name: part.slice(0, index).trim(), value: part.slice(index + 1), domain: location.hostname, path: "/", secure: location.protocol === "https:", httpOnly: false};
  });
  if (!cookies.length) throw new Error("No JavaScript-readable cookies. Use a browser cookie export for HttpOnly cookies.");
  const data = {origin: location.origin, cookies, note: "JavaScript-readable cookies only; HttpOnly cookies are not included. Original path, domain and expiry attributes are unavailable through document.cookie; use a browser export to preserve them."};
  const objectURL = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type: "application/json"}));
  const link = document.createElement("a");
  link.href = objectURL; link.download = "vulnetic-cookies.json"; link.click();
  setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
})();`;
}
