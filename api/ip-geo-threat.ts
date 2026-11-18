import * as dns from 'node:dns/promises';
import * as net from 'node:net';

function isPrivateOrReservedIp(ip: string): boolean {
  const clean = ip.replace(/^::ffff:/i, '');
  if (!net.isIP(clean)) return true;
  if (clean === '::1' || clean === '::' || clean.startsWith('fe80:') || clean.startsWith('fc') || clean.startsWith('fd')) {
    return true;
  }
  const parts = clean.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

async function fetchJsonSafe(url: string, options?: RequestInit, timeoutMs = 4500): Promise<any | null> {
  try {
    const res = await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(timeoutMs),
      headers: { Accept: 'application/json', 'User-Agent': 'SovereignForensicEngine/2.5.2', ...(options?.headers || {}) },
    });
    if (!res.ok) return null;
    const text = await res.text();
    return text.trim() ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const bodyObj = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const rawIp = String(bodyObj.ip || '').trim();
    if (!net.isIP(rawIp)) {
      return res.status(400).json({ error: 'يرجى إدخال عنوان IPv4 أو IPv6 صالح.' });
    }
    if (isPrivateOrReservedIp(rawIp)) {
      return res.status(400).json({ error: 'عناوين IP الخاصة والمحلية محظورة أمنياً (SSRF Protection).' });
    }

    const [ipWho, rdap, ptrs, feodoList, threatFox] = await Promise.all([
      fetchJsonSafe(`https://ipwho.is/${encodeURIComponent(rawIp)}`),
      fetchJsonSafe(`https://rdap.org/ip/${encodeURIComponent(rawIp)}`),
      dns.reverse(rawIp).catch(() => [] as string[]),
      fetchJsonSafe('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json', undefined, 5000),
      fetchJsonSafe(
        'https://threatfox-api.abuse.ch/api/v1/',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: 'search_ioc', search_term: rawIp }),
        },
        4500
      ),
    ]);

    const blocklistHits: Array<{ source: string; detail: string; severity: 'critical' | 'high' }> = [];

    if (Array.isArray(feodoList)) {
      const feodoMatch = feodoList.find((e: any) => String(e?.ip_address || '').trim() === rawIp);
      if (feodoMatch) {
        blocklistHits.push({
          source: 'Abuse.ch Feodo Tracker',
          detail: `خادم C2 نشط (${feodoMatch.malware || 'Botnet'}) • الحالة: ${feodoMatch.status || 'online'}`,
          severity: 'critical',
        });
      }
    }

    if (threatFox?.query_status === 'ok' && Array.isArray(threatFox?.data) && threatFox.data.length > 0) {
      const first = threatFox.data[0];
      blocklistHits.push({
        source: 'Abuse.ch ThreatFox',
        detail: `${first.threat_type_desc || first.threat_type || 'Malicious IOC'} • ${first.malware_printable || first.malware || 'Malware'}`,
        severity: 'critical',
      });
    }

    // Check Spamhaus ZEN via DNS over IPv4 reverse lookup
    if (net.isIPv4(rawIp)) {
      const rev = rawIp.split('.').reverse().join('.');
      const spamhausRes = await fetchJsonSafe(`https://dns.google/resolve?name=${rev}.zen.spamhaus.org&type=A`);
      const ans = Array.isArray(spamhausRes?.Answer) ? spamhausRes.Answer : [];
      if (ans.some((a: any) => /^127\.0\.0\./.test(String(a.data)))) {
        blocklistHits.push({
          source: 'Spamhaus ZEN DNSBL',
          detail: `مدرج في قوائم الحظر (${ans.map((a: any) => a.data).join(', ')})`,
          severity: 'high',
        });
      }
    }

    return res.status(200).json({
      success: true,
      geoThreat: {
        ip: rawIp,
        country: ipWho?.country || rdap?.country || 'غير محدد',
        countryCode: ipWho?.country_code || '',
        flagEmoji: ipWho?.flag?.emoji || '',
        region: ipWho?.region || '—',
        city: ipWho?.city || '—',
        timezone: ipWho?.timezone?.id || 'UTC',
        latitude: typeof ipWho?.latitude === 'number' ? ipWho.latitude : null,
        longitude: typeof ipWho?.longitude === 'number' ? ipWho.longitude : null,
        asn: ipWho?.connection?.asn ? `AS${ipWho.connection.asn}` : '—',
        isp: ipWho?.connection?.isp || rdap?.name || '—',
        org: ipWho?.connection?.org || rdap?.name || '—',
        domain: ipWho?.connection?.domain || '',
        reverseDns: ptrs.slice(0, 5),
        cidr: Array.isArray(rdap?.cidr0_cidrs) && rdap.cidr0_cidrs[0]
          ? `${rdap.cidr0_cidrs[0].v4prefix || rdap.cidr0_cidrs[0].v6prefix}/${rdap.cidr0_cidrs[0].length}`
          : null,
        blocklisted: blocklistHits.length > 0,
        blocklistHits,
        sourcesChecked: [
          'IPWhois Live GeoIP',
          'RDAP Network Registry',
          'Abuse.ch Feodo C2',
          'Abuse.ch ThreatFox',
          'Spamhaus ZEN DNSBL',
        ],
        checkedAt: new Date().toISOString(),
      },
    });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'تعذر جلب البيانات الجغرافية والتهديدات للـ IP.' });
  }
}
