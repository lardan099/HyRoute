// Display-side masking for Privacy mode. The Go side (logx.Sanitize) uses
// the same rules for exported logs and diagnostics.

// Word boundaries, as Go's v4re: an address before a full stop is masked
// too (internal/logx/testdata/sanitize.json holds the shared cases).
const v4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
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
// SNI give away as much as addresses. Labels may be Unicode
// (мой-магазин.рф): rule sites are kept as typed, not punycode. File names
// are left alone. Some extensions are real top-level domains too (999.md,
// example.zip): such a name counts as a file only right after another
// extension (geosite.dat.new, not go.md). logx.MaskDomains does the same.
const fileExt = new Set(['exe', 'dll', 'sys', 'dat', 'json', 'yaml', 'yml', 'log', 'txt', 'zip', 'ps1', 'md', 'go', 'tmp', 'old', 'new', 'part', 'ini', 'conf', 'html', 'js', 'css', 'png', 'svg']);
// tldExt are the extensions in fileExt that are top-level domains too.
const tldExt = new Set(['md', 'zip', 'new']);
const domRe = /(?<![\p{L}\p{N}_])(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+(?:xn--[a-z0-9-]{2,59}|\p{L}{2,63})(?![\p{L}\p{N}_])/giu;

// fileName reports whether the name m is a file name.
function fileName(m: string): boolean {
  const dot = m.lastIndexOf('.');
  const tld = m.slice(dot + 1).toLowerCase();
  if (!fileExt.has(tld)) return false;
  if (!tldExt.has(tld)) return true;
  const rest = m.slice(0, dot);
  const j = rest.lastIndexOf('.');
  return j >= 0 && fileExt.has(rest.slice(j + 1).toLowerCase());
}

export function maskDomains(s: string): string {
  return s.replace(domRe, (m: string) => (fileName(m) ? m : `***.${m.slice(m.lastIndexOf('.') + 1)}`));
}
