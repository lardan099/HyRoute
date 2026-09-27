// Display-side masking for Privacy mode. The Go side (logx.Sanitize) uses
// the same rules for exported logs and diagnostics.

const v4 = /(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])/g;
// Candidate IPv6: hex groups with colons. Timestamps (12:34:56) have no
// "::" and fewer than 7 colons, so they are left alone.
const v6 = /(?<![\w:.])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])/g;

function privateV4(a: number, b: number): boolean {
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

function maskV6(s: string): string {
  const colons = (s.match(/:/g) ?? []).length;
  if (!s.includes('::') && colons < 7) return s;
  if (!/[0-9a-fA-F]/.test(s)) return s;
  const low = s.toLowerCase();
  if (low === '::1' || low === '::' || /^fe[89ab]/.test(low) || /^f[cd]/.test(low)) return s;
  const first = low.split(':')[0];
  return first ? `${first}:xxxx::xxxx` : 'xxxx::xxxx';
}

export function maskIPs(s: string): string {
  if (!s) return s;
  s = s.replace(v4, (m, a, b, c, d) => {
    const n = [a, b, c, d].map(Number);
    if (n.some((x) => x > 255)) return m;
    return privateV4(n[0], n[1]) ? m : `${a}.xxx.xxx.${d}`;
  });
  return s.replace(v6, (m) => maskV6(m));
}

// maskURLs hides subscription-like URLs completely: https://***/…
export function maskURLs(s: string): string {
  return s.replace(/\bhttps?:\/\/[^\s"'<>]+/g, (m) => m.replace(/^(https?:\/\/)[^\s"'<>]*/, '$1***/…'));
}

export function maskHosts(s: string, hosts: string[]): string {
  for (const h of hosts) {
    if (h && h.length >= 4 && !/^[\d.:]+$/.test(h)) s = s.split(h).join('***');
  }
  return s;
}

// maskDomains keeps only the top-level domain (***.com): visited sites and
// SNI give away as much as addresses. File names are left alone.
const fileExt = new Set(['exe', 'dll', 'sys', 'dat', 'json', 'yaml', 'yml', 'log', 'txt', 'zip', 'ps1', 'md', 'go', 'tmp', 'old', 'new', 'part', 'ini', 'conf', 'html', 'js', 'css', 'png', 'svg']);
const domRe = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})\b/gi;

export function maskDomains(s: string): string {
  return s.replace(domRe, (m) => {
    const tld = m.slice(m.lastIndexOf('.') + 1);
    return fileExt.has(tld.toLowerCase()) ? m : `***.${tld}`;
  });
}
