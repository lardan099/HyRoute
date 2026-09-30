// Client of the controller API (/api/v1). Every failure is an ApiError with
// the structured error of the server: message for people, details for the
// technical cause.

import { t } from './i18n';

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details = '',
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let res: Response;
  try {
    res = await fetch('/api/v1' + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    });
  } catch (e) {
    throw new ApiError(0, 'network', t('error.network'), String(e));
  }
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = data?.error;
    throw new ApiError(res.status, err?.code ?? 'unknown', err?.message ?? t('error.unknown'), err?.details ?? '');
  }
  return data as T;
}

export interface Health {
  status: string;
  version: string;
  schemaVersion: number;
}

export const api = {
  health: () => request<Health>('GET', '/health'),
};
