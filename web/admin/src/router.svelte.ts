// A minimal history router: the controller answers every non-API path with
// index.html, so pages have real URLs (/servers, /deployments…).

export type Page = 'overview' | 'servers' | 'cascades' | 'rules' | 'presets' | 'deployments' | 'logs' | 'settings';

export const pages: Page[] = ['overview', 'servers', 'cascades', 'rules', 'presets', 'deployments', 'logs', 'settings'];

function fromPath(path: string): Page {
  const first = path.split('/').filter(Boolean)[0] ?? '';
  return (pages as string[]).includes(first) ? (first as Page) : 'overview';
}

export const route = $state({ page: fromPath(location.pathname) });

export function go(page: Page) {
  const path = page === 'overview' ? '/' : '/' + page;
  if (location.pathname !== path) history.pushState(null, '', path);
  route.page = page;
}

addEventListener('popstate', () => {
  route.page = fromPath(location.pathname);
});
