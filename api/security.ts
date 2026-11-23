import {
  breachLookupHandler,
  sslInspectHandler,
  ipGeoThreatHandler,
  dnsIpLookupHandler,
  socKevEpssHandler,
  threatIntelHandler,
} from '../server/handlers/security.js';

export default async function handler(req: any, res: any) {
  const url = req.url || '';
  if (url.includes('breach-lookup')) return breachLookupHandler(req, res);
  if (url.includes('ssl-inspect')) return sslInspectHandler(req, res);
  if (url.includes('ip-geo-threat')) return ipGeoThreatHandler(req, res);
  if (url.includes('dns-ip-lookup')) return dnsIpLookupHandler(req, res);
  if (url.includes('soc-kev-epss')) return socKevEpssHandler(req, res);
  if (url.includes('threat-intel')) return threatIntelHandler(req, res);
  return res.status(404).json({ error: 'Security API route not found' });
}
