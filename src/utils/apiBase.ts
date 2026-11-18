// Resolves API endpoint URLs cleanly for both full-stack (same-origin) and static (GitHub Pages -> Cloud Run) deployments
const RAW_API_BASE = (import.meta as any).env?.VITE_API_BASE_URL || '';
const NORMALIZED_API_BASE =
  typeof RAW_API_BASE === 'string' ? RAW_API_BASE.trim().replace(/\/+$/, '') : '';

export function apiUrl(path: string): string {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  return NORMALIZED_API_BASE ? `${NORMALIZED_API_BASE}${cleanPath}` : cleanPath;
}

export function getConfiguredApiBase(): string {
  return NORMALIZED_API_BASE;
}

export async function safeReadJsonResponse<T = any>(
  res: Response
): Promise<{ ok: boolean; status: number; data: T | null; rawText: string; isJson: boolean }> {
  let rawText = '';
  try {
    rawText = await res.text();
  } catch {
    return { ok: res.ok, status: res.status, data: null, rawText: '', isJson: false };
  }
  const trimmed = rawText.trim();
  if (!trimmed) {
    return { ok: res.ok, status: res.status, data: null, rawText: '', isJson: false };
  }
  try {
    const parsed = JSON.parse(trimmed) as T;
    return { ok: res.ok, status: res.status, data: parsed, rawText, isJson: true };
  } catch {
    return { ok: res.ok, status: res.status, data: null, rawText, isJson: false };
  }
}

