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
