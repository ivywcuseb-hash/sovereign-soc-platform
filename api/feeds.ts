import syncHandler from './live-feeds/sync.js';
import catalogHandler from './live-feeds/catalog.js';

export default async function handler(req: any, res: any) {
  const url = req.url || '';
  if (url.includes('catalog')) return catalogHandler(req, res);
  return syncHandler(req, res);
}
