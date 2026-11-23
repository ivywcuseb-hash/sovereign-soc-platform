import {
  malwareHashHandler,
  urlTraceHandler,
  analyzeBinaryHandler,
  analyzeBrowserHistoryHandler,
} from '../server/handlers/forensic.js';

export default async function handler(req: any, res: any) {
  const url = req.url || '';
  if (url.includes('malware-hash')) return malwareHashHandler(req, res);
  if (url.includes('url-trace')) return urlTraceHandler(req, res);
  if (url.includes('analyze-binary')) return analyzeBinaryHandler(req, res);
  if (url.includes('analyze-browser-history')) return analyzeBrowserHistoryHandler(req, res);
  return res.status(404).json({ error: 'Forensic API route not found' });
}
