// HyRoute extension: remembers, per tab, the names the page loaded and the
// ones that failed, for the popup. Only in session storage (memory): gone
// when the browser closes, never written to disk, never sent anywhere but
// to HyRoute when the popup asks how those names go.

const MAX_HOSTS = 300;
// Errors that are not the network's: the page or an ad blocker stopped
// the request, or a cache-only lookup missed.
const IGNORED = /^net::ERR_(ABORTED|BLOCKED_BY_\w+|CACHE_MISS|INSUFFICIENT_RESOURCES)$/;

const tabs = new Map(); // tabId -> {top, hosts: {host: {n, err}}}
const dirty = new Set();
let flushTimer = 0;

function hostOf(url) {
  try {
    const u = new URL(url);
    if (!/^(https?|wss?):$/.test(u.protocol) || !u.hostname) return '';
    return u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    return '';
  }
}

async function load(tabId) {
  let t = tabs.get(tabId);
  if (t) return t;
  const key = 't' + tabId;
  try {
    t = (await chrome.storage.session.get(key))[key];
  } catch {
    t = undefined;
  }
  if (!tabs.has(tabId)) tabs.set(tabId, t || { top: '', hosts: {} });
  return tabs.get(tabId);
}

function touch(tabId) {
  dirty.add(tabId);
  if (!flushTimer) flushTimer = setTimeout(flush, 500);
}

function flush() {
  flushTimer = 0;
  const items = {};
  for (const id of dirty) {
    const t = tabs.get(id);
    if (t) items['t' + id] = t;
  }
  dirty.clear();
  chrome.storage.session.set(items).catch(() => {});
}

function badge(tabId, t) {
  const n = Object.values(t.hosts).filter((h) => h.err).length;
  chrome.action.setBadgeText({ tabId, text: n ? String(n) : '' }).catch(() => {});
  if (n) chrome.action.setBadgeBackgroundColor({ tabId, color: '#dc2626' }).catch(() => {});
}

chrome.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.tabId < 0) return;
    const host = hostOf(d.url);
    if (!host) return;
    load(d.tabId).then((t) => {
      if (d.type === 'main_frame') {
        t.top = host;
        t.hosts = {};
        badge(d.tabId, t);
      }
      const h = t.hosts[host];
      if (h) h.n++;
      else if (Object.keys(t.hosts).length < MAX_HOSTS) t.hosts[host] = { n: 1, err: '' };
      touch(d.tabId);
    });
  },
  { urls: ['<all_urls>'] },
);

chrome.webRequest.onErrorOccurred.addListener(
  (d) => {
    if (d.tabId < 0 || IGNORED.test(d.error)) return;
    const host = hostOf(d.url);
    if (!host) return;
    load(d.tabId).then((t) => {
      const h = t.hosts[host] || (t.hosts[host] = { n: 1, err: '' });
      h.err = d.error;
      touch(d.tabId);
      badge(d.tabId, t);
    });
  },
  { urls: ['<all_urls>'] },
);

chrome.tabs.onRemoved.addListener((tabId) => {
  tabs.delete(tabId);
  dirty.delete(tabId);
  chrome.storage.session.remove('t' + tabId).catch(() => {});
});

// The popup asks for a tab's names; it may also clear the failures once
// the user has sent them somewhere.
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id || typeof msg?.tabId !== 'number') return false;
  load(msg.tabId).then((t) => {
    if (msg.type === 'clear-errors') {
      for (const h of Object.values(t.hosts)) h.err = '';
      touch(msg.tabId);
      badge(msg.tabId, t);
    }
    reply({ top: t.top, hosts: t.hosts });
  });
  return true;
});
