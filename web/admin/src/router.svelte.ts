// A minimal history router: the controller answers every non-API path with
// index.html, so pages have real URLs (/servers, /deployments…).

export type Page = 'overview' | 'servers' | 'cascades' | 'rules' | 'presets' | 'deployments' | 'logs' | 'settings';

export const pages: Page[] = ['overview', 'servers', 'cascades', 'rules', 'presets', 'deployments', 'logs', 'settings'];

// fromPath reads "/deployments/42" as page deployments, id 42.
function fromPath(path: string): { page: Page; id: number | null } {
  const [first = '', second] = path.split('/').filter(Boolean);
  const page = (pages as string[]).includes(first) ? (first as Page) : 'overview';
  const id = second && /^\d+$/.test(second) ? Number(second) : null;
  return { page, id };
}

export const route = $state(fromPath(location.pathname));

export function go(page: Page, id: number | null = null) {
  const path = (page === 'overview' ? '/' : '/' + page) + (id ? '/' + id : '');
  if (location.pathname !== path) history.pushState(null, '', path);
  route.page = page;
  route.id = id;
}

addEventListener('popstate', () => {
  Object.assign(route, fromPath(location.pathname));
});
