export function reportOutline(markdown: string) {
  const headings: { id: string; title: string; level: number }[] = [];
  let offset = 0;
  let fence = "";
  for (const line of markdown.split("\n")) {
    const marker = /^\s*(`{3,}|~{3,})(.*)$/.exec(line);
    if (marker) { if (!fence) fence = marker[1]; else if (fence[0] === marker[1][0] && marker[1].length >= fence.length && !marker[2].trim()) fence = ""; }
    if (!fence && !marker) {
      const heading = /^(#{1,3})\s+(.+?)\s*#*\s*$/.exec(line);
      if (heading) headings.push({id:`report-heading-${offset}`, title:heading[2].replace(/[*_`]/g,""), level:heading[1].length});
    }
    offset += line.length + 1;
  }
  return headings;
}
