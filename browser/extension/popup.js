// HyRoute popup: the names of the current tab, how HyRoute sends each of
// them now, and buttons to change that: the whole page at once or the
// checked names. What is sent from a page is kept in HyRoute as the rules
// of that page's site. HyRoute is reached through its native messaging
// host (hyroutectl.exe), installed from HyRoute's settings.

const HOST = 'com.hyroute.browser';

const $ = (id) => document.getElementById(id);

const state = {
  tabId: -1,
  top: '', // the tab's host
  hosts: {}, // host -> {n, err} from the background worker
  info: null, // HyRoute's answer
  whole: true, // rows are whole sites
  onlyErr: false, // only the rows that failed are shown
  shown: [], // keys of the rows shown
  master: null, // the «all» checkbox
  checked: new Set(), // row keys
  touched: false, // the user changed the selection
  busy: false,
};

// ---- HyRoute ----

class HostError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

let seq = 0;
function hy(cmd, args) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(HOST, { id: ++seq, cmd, args }, (r) => {
      const le = chrome.runtime.lastError;
      if (le) return reject(new HostError('host', le.message || String(le)));
      if (!r) return reject(new HostError('host', 'empty reply'));
      if (!r.ok) return reject(new HostError(r.code || 'failed', r.error || 'Ошибка HyRoute'));
      resolve(r.result);
    });
  });
}

// ---- texts ----

function errWord(e) {
  const code = String(e || '').replace(/^net::ERR_/, '');
  if (/TIMED_OUT/.test(code)) return 'таймаут';
  if (/CONNECTION_RESET/.test(code)) return 'соединение сброшено';
  if (/CONNECTION_REFUSED/.test(code)) return 'отказ в соединении';
  if (/CONNECTION_CLOSED|EMPTY_RESPONSE/.test(code)) return 'соединение закрыто';
  if (/NAME_NOT_RESOLVED|NAME_RESOLUTION/.test(code)) return 'адрес не найден (DNS)';
  if (/^(SSL|CERT)_/.test(code)) return 'ошибка TLS';
  if (/QUIC/.test(code)) return 'ошибка QUIC';
  if (/HTTP2/.test(code)) return 'ошибка HTTP/2';
  if (/ADDRESS_UNREACHABLE|NETWORK_|INTERNET_DISCONNECTED/.test(code)) return 'сеть недоступна';
  return code.toLowerCase().replace(/_/g, ' ');
}

// dnsErr: a name that does not resolve is most often an ad blocker's DNS:
// not picked by default.
const dnsErr = (e) => /NAME_NOT_RESOLVED|NAME_RESOLUTION/.test(String(e || ''));

function routeText(r) {
  if (!r) return '';
  if (r.to === 'direct') return 'напрямую';
  if (r.to === 'block') return 'блок';
  return 'через ' + (r.server || 'VPN');
}

function routeClass(r) {
  if (!r) return 'mixed';
  return r.to === 'direct' ? 'direct' : r.to === 'block' ? 'block' : 'tunnel';
}

function plural(n, one, few, many) {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}

// ---- rows ----

// rows groups HyRoute's answer: by whole site, or one row per name. The
// tab's own site first, then the ones that failed, then by use.
function rows() {
  const out = new Map();
  for (const s of state.info?.sites || []) {
    const whole = state.whole && s.site;
    const key = whole ? '.' + s.site : s.host;
    let row = out.get(key);
    if (!row) {
      row = { key, label: whole ? s.siteLabel : s.label, hosts: [], n: 0, err: '', routes: new Map(), rules: new Set(), top: false, pattern: '' };
      out.set(key, row);
    }
    const seen = state.hosts[s.host] || { n: 0, err: '' };
    row.hosts.push(s.label);
    row.n += seen.n;
    if (seen.err && !row.err) row.err = seen.err;
    row.routes.set(s.route.to + '|' + (s.route.server || ''), s.route);
    row.rules.add(s.route.rule || '');
    if (s.host === state.top) {
      row.top = true;
      if (s.route.pattern) row.pattern = s.route.pattern;
      row.rule = s.route.rule;
      row.browser = s.route.browser;
    }
  }
  return [...out.values()].sort((a, b) => b.top - a.top || !!b.err - !!a.err || b.n - a.n || a.label.localeCompare(b.label));
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids) if (k != null) e.append(k);
  return e;
}

function rowEl(row) {
  const only = row.routes.size === 1 ? [...row.routes.values()][0] : null;
  const why = row.rules.size > 1 ? 'Снимите «Целиком сайты», чтобы увидеть правило для каждого адреса.' :
    only?.rule ? 'Правило «' + only.rule + '»' : only ? 'Всё остальное' : '';
  const box = el('input', { type: 'checkbox', checked: state.checked.has(row.key) });
  box.checked = state.checked.has(row.key);
  box.addEventListener('change', () => {
    state.touched = true;
    if (box.checked) state.checked.add(row.key);
    else state.checked.delete(row.key);
    renderSelection();
  });
  const sub = [];
  if (row.err) sub.push(el('span', { class: 'err' }, 'не загрузилось: ' + errWord(row.err)));
  if (row.hosts.length > 1 || (row.hosts[0] && row.hosts[0] !== row.label)) {
    const names = row.hosts.slice(0, 3).join(', ') + (row.hosts.length > 3 ? ` и ещё ${row.hosts.length - 3}` : '');
    sub.push(el('span', {}, (row.err ? ' · ' : '') + names));
  }
  const label = el('label', { class: 'row' + (row.top ? ' top' : '') },
    box,
    el('span', { class: 'name' }, row.label, sub.length ? el('span', { class: 'sub' }, ...sub) : null),
    el('span', { class: 'route ' + routeClass(only), title: why },
      only ? routeText(only) : 'по-разному'),
  );
  const out = [label];
  const page = state.info?.page;
  if (row.top && page?.items) {
    out.push(el('div', { class: 'mine' }, `В правилах сайта: ${page.items} ${plural(page.items, 'адрес', 'адреса', 'адресов')}`,
      el('button', { class: 'linkbtn', type: 'button', title: 'Удалить правила «Из браузера: ' + page.label + '» со всеми адресами', onclick: () => removeSite() }, 'убрать сайт целиком')));
  } else if (row.top && row.pattern) {
    out.push(el('div', { class: 'mine' }, 'Есть в правилах из браузера',
      el('button', { class: 'linkbtn', type: 'button', onclick: () => remove(row.pattern) }, 'убрать')));
  } else if (row.top && row.rule && !row.browser) {
    out.push(el('div', { class: 'mine' }, 'Решает правило «' + row.rule + '»'));
  }
  return out;
}

// ---- render ----

function render() {
  const info = state.info;
  const main = $('main');
  main.replaceChildren();
  if (!state.top) {
    main.append(el('p', { class: 'muted center' }, 'Откройте сайт: здесь появятся его адреса и то, как HyRoute их отправляет.'));
    $('actions').hidden = true;
    return;
  }
  const all = rows();
  const failed = all.filter((r) => r.err).length;
  // The page's own site stays in sight: the rest is hidden, not unchecked
  // behind the user's back (the selection starts over with the filter).
  const list = state.onlyErr ? all.filter((r) => r.top || r.err) : all;
  state.shown = list.map((r) => r.key);
  if (!state.touched) {
    state.checked = new Set(list.filter((r) => r.top || (r.err && !dnsErr(r.err))).map((r) => r.key));
  } else {
    const keys = new Set(state.shown);
    state.checked = new Set([...state.checked].filter((k) => keys.has(k)));
  }
  const master = el('input', { type: 'checkbox', title: 'Отметить все или снять все' });
  master.addEventListener('change', () => {
    state.touched = true;
    state.checked = new Set(master.checked ? state.shown : []);
    render();
  });
  state.master = master;
  const only = el('input', { type: 'checkbox' });
  only.checked = state.onlyErr;
  only.addEventListener('change', () => {
    state.onlyErr = only.checked;
    state.touched = false;
    render();
  });
  const whole = el('input', { type: 'checkbox' });
  whole.checked = state.whole;
  whole.addEventListener('change', () => {
    state.whole = whole.checked;
    state.touched = false;
    chrome.storage.local.set({ whole: state.whole });
    render();
  });
  main.append(el('div', { class: 'listhead' },
    el('label', { class: 'check all' }, master, el('h2', {}, `Адреса: ${all.length}`)),
    el('span', { class: 'checks' },
      el('label', { class: 'check', title: 'Показать только адреса, которые не загрузились' }, only, `с ошибкой: ${failed}`),
      el('label', { class: 'check', title: 'Отправлять сайт вместе с поддоменами (www, cdn, api…)' }, whole, 'целиком сайты'))));
  for (const row of list) main.append(...rowEl(row));
  if (state.onlyErr && !failed) main.append(el('p', { class: 'muted center small' }, 'Все адреса страницы загрузились.'));
  $('to-all').textContent = `Весь сайт через VPN · ${all.length} ${plural(all.length, 'адрес', 'адреса', 'адресов')}`;
  $('to-all').title = 'Отправить через VPN сайт и всё, что загружает его страница, одним правилом «Из браузера: ' + (info.page?.label || state.top) + '»';

  const sel = $('server');
  const keep = sel.value || state.server || 'vpn';
  sel.replaceChildren(el('option', { value: 'vpn' }, info.main ? `основной (${info.main})` : 'основной'));
  for (const t of info.targets) sel.append(el('option', { value: t.to }, (t.group ? 'группа ' : '') + t.name));
  sel.value = [...sel.options].some((o) => o.value === keep) ? keep : 'vpn';
  $('actions').hidden = false;
  renderSelection();
}

function renderSelection() {
  const n = state.checked.size;
  $('selcount').textContent = n ? `Или только отмеченные (${n}):` : 'Или отметьте адреса и выберите, куда их отправить:';
  const stop = state.busy || !!state.info?.problem;
  for (const id of ['to-vpn', 'to-direct', 'to-block']) $(id).disabled = !n || stop;
  $('to-all').disabled = stop || !state.info?.sites?.length;
  if (state.master) {
    state.master.checked = n > 0 && n === state.shown.length;
    state.master.indeterminate = n > 0 && n < state.shown.length;
  }
}

function showProblem(text, steps) {
  $('problem-text').textContent = text;
  const ol = $('problem-steps');
  ol.replaceChildren(...(steps || []).map((s) => el('li', {}, s)));
  ol.hidden = !steps?.length;
  $('problem').hidden = false;
}

function problemOf(err) {
  const m = String(err?.message || err);
  if (err?.code === 'host') {
    if (/not found/i.test(m)) {
      return ['Браузер не связан с HyRoute.', [
        'Откройте HyRoute → «Настройки» → «Расширение для браузера».',
        'Нажмите «Установить в браузер».',
        'Откройте это окно снова.',
      ]];
    }
    if (/forbidden/i.test(m)) {
      return ['HyRoute не узнал это расширение. Удалите его на странице расширений и установите заново из HyRoute.'];
    }
    return ['Не удалось запустить hyroutectl.exe из папки HyRoute (' + m + ').', [
      'Проверьте, что HyRoute на месте и запущен.',
      'В HyRoute → «Настройки» → «Расширение для браузера» нажмите «Установить в браузер» ещё раз.',
    ]];
  }
  if (err?.code === 'not-running') return ['HyRoute не запущен. Запустите его и откройте это окно снова.'];
  if (err?.code === 'browser-off') return ['Расширение выключено в HyRoute: «Настройки» → «Расширение для браузера».'];
  return [m];
}

// ---- actions ----

async function refresh() {
  $('problem').hidden = true;
  const hosts = [state.top, ...Object.keys(state.hosts).filter((h) => h !== state.top)]
    .filter(Boolean)
    .sort((a, b) => (a === state.top ? -1 : b === state.top ? 1 : !!state.hosts[b]?.err - !!state.hosts[a]?.err || (state.hosts[b]?.n || 0) - (state.hosts[a]?.n || 0)))
    .slice(0, 200);
  try {
    state.info = await hy('browser-info', { hosts, page: state.top });
  } catch (e) {
    $('loading')?.remove();
    $('actions').hidden = true;
    const [text, steps] = problemOf(e);
    showProblem(text, steps);
    return;
  }
  const st = $('state');
  st.hidden = false;
  st.textContent = state.info.state === 'connected' ? 'подключён' : 'не подключён';
  st.className = 'pill' + (state.info.state === 'connected' ? ' on' : '');
  $('ruleset').textContent = state.info.ruleset;
  $('ruleset').title = 'Профиль правил: ' + state.info.ruleset;
  $('browser-scope').textContent = state.info.app ? 'Новые правила только для ' + state.info.app : '';
  $('browser-scope').hidden = !state.info.app;
  render();
  if (state.info.problem) showProblem(state.info.problem);
}

// send: the checked rows, or every row of the page (all).
async function send(to, word, all) {
  const sites = all ? rows().map((r) => r.key) : [...state.checked];
  if (!sites.length) return;
  state.busy = true;
  renderSelection();
  try {
    const res = await hy('browser-add', { sites, to, page: state.top });
    const n = res.added + res.moved;
    let text = n ? `Готово: ${n} ${plural(n, 'адрес', 'адреса', 'адресов')} → ${word}, правило «${res.rule}».` : `Уже ${word}: ничего не изменилось.`;
    if (all && n) text = `Готово: весь сайт (${sites.length}) → ${word}, правило «${res.rule}».`;
    if (res.raised) text += ` Правила из браузера подняты наверх: выше стояло правило «${res.raised}», оно решало сайт.`;
    $('done-text').textContent = text;
    $('done-lost').replaceChildren(...res.lost.map((l) =>
      el('li', {}, `${l.pattern.replace(/^\./, '')}: всё ещё решает правило «${l.rule}» выше. Поднимите правила «Из браузера» в HyRoute.`)));
    $('done').hidden = false;
    chrome.runtime.sendMessage({ type: 'clear-errors', tabId: state.tabId }).then((t) => { if (t) state.hosts = t.hosts; }).catch(() => {});
    state.touched = false;
    await refresh();
  } catch (e) {
    const [text, steps] = problemOf(e);
    showProblem(text, steps);
  } finally {
    state.busy = false;
    renderSelection();
  }
}

async function remove(pattern) {
  state.busy = true;
  renderSelection();
  try {
    await hy('browser-remove', { sites: [pattern] });
    $('done-text').textContent = `«${pattern.replace(/^\./, '')}» убран из правил браузера: дальше решают остальные правила.`;
    $('done-lost').replaceChildren();
    $('done').hidden = false;
    await refresh();
  } catch (e) {
    const [text, steps] = problemOf(e);
    showProblem(text, steps);
  } finally {
    state.busy = false;
    renderSelection();
  }
}

// removeSite takes the page's site out whole: its rules with everything
// sent from its pages.
async function removeSite() {
  state.busy = true;
  renderSelection();
  try {
    const res = await hy('browser-remove', { sites: [], page: state.top });
    $('done-text').textContent = `Сайт «${state.info.page?.label || state.top}» убран из правил браузера целиком (${res.removed} ${plural(res.removed, 'адрес', 'адреса', 'адресов')}): дальше решают остальные правила.`;
    $('done-lost').replaceChildren();
    $('done').hidden = false;
    state.touched = false;
    await refresh();
  } catch (e) {
    const [text, steps] = problemOf(e);
    showProblem(text, steps);
  } finally {
    state.busy = false;
    renderSelection();
  }
}

function vpnWord() {
  const sel = $('server');
  return 'через ' + (sel.value === 'vpn' ? state.info.main || 'VPN' : sel.selectedOptions[0].textContent.replace(/^группа /, ''));
}
$('to-all').addEventListener('click', () => send($('server').value, vpnWord(), true));
$('to-vpn').addEventListener('click', () => send($('server').value, vpnWord()));
$('to-direct').addEventListener('click', () => send('direct', 'напрямую'));
$('to-block').addEventListener('click', () => send('block', 'в блок'));
$('server').addEventListener('change', () => chrome.storage.local.set({ server: $('server').value }));
$('retry').addEventListener('click', () => refresh());
$('reload').addEventListener('click', () => {
  chrome.tabs.reload(state.tabId);
  window.close();
});

// ---- start ----

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const saved = await chrome.storage.local.get(['whole', 'server']);
  state.whole = saved.whole !== false;
  state.server = saved.server || 'vpn';
  if (tab) {
    state.tabId = tab.id;
    try {
      const u = new URL(tab.url || '');
      if (/^https?:$/.test(u.protocol)) state.top = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    } catch {}
    const t = await chrome.runtime.sendMessage({ type: 'tab', tabId: tab.id }).catch(() => null);
    if (t) state.hosts = t.hosts || {};
  }
  if (!state.top) {
    $('loading')?.remove();
    render();
    return;
  }
  await refresh();
})();
