import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import * as tls from 'node:tls';

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

export function classifyTarget(rawInput: string): {
  indicator: string;
  originalInput: string;
  indicatorType: 'ipv4' | 'ipv6' | 'domain';
} {
  const originalInput = rawInput.trim();
  if (!originalInput) {
    throw new Error('يرجى إدخال عنوان IP أو نطاق (Domain) صالح للفحص.');
  }
  let candidate = originalInput;
  if (/^https?:\/\//i.test(candidate)) {
    candidate = new URL(candidate).hostname;
  } else if (candidate.includes('/') && !net.isIP(candidate)) {
    candidate = candidate.split('/')[0];
  }
  candidate = candidate.replace(/:\d+$/, '').trim();

  if (net.isIPv4(candidate)) {
    if (isPrivateOrReservedIp(candidate)) {
      throw new Error('عنوان IP الخاص أو الداخلي مرفوض أمنياً (SSRF Protection).');
    }
    return { indicator: candidate, originalInput, indicatorType: 'ipv4' };
  }
  if (net.isIPv6(candidate)) {
    if (isPrivateOrReservedIp(candidate)) {
      throw new Error('عنوان IPv6 الخاص أو المحلي مرفوض أمنياً (SSRF Protection).');
    }
    return { indicator: candidate, originalInput, indicatorType: 'ipv6' };
  }
  const domain = candidate.toLowerCase().replace(/^\.+|\.+$/g, '');
  if (
    domain === 'localhost' ||
    domain.endsWith('.local') ||
    domain.endsWith('.internal') ||
    domain.endsWith('.localhost')
  ) {
    throw new Error('النطاقات المحلية والداخلية محظورة أمنياً (SSRF Protection).');
  }
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) {
    throw new Error('صيغة عنوان IP أو النطاق غير صالحة.');
  }
  return { indicator: domain, originalInput, indicatorType: 'domain' };
}

async function fetchJson(url: string, timeoutMs = 4500): Promise<any> {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: { Accept: 'application/json', 'User-Agent': 'SovereignForensicEngine/2.5.2' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

async function fetchIpGeo(ip: string) {
  if (isPrivateOrReservedIp(ip)) return null;
  try {
    const d = await fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (d && d.success) {
      return {
        primaryIp: d.ip || ip,
        country: d.country || null,
        countryCode: d.country_code || null,
        region: d.region || null,
        city: d.city || null,
        isp: d.connection?.isp || null,
        org: d.connection?.org || null,
        asn: d.connection?.asn ? `AS${d.connection.asn}` : null,
        isProxyOrVpn: null,
        isHosting: null,
        coordinates:
          typeof d.latitude === 'number' && typeof d.longitude === 'number'
            ? { lat: d.latitude, lon: d.longitude }
            : null,
      };
    }
  } catch {
    // try ipapi.co
  }
  try {
    const d = await fetchJson(`https://ipapi.co/${encodeURIComponent(ip)}/json/`);
    if (d && !d.error) {
      return {
        primaryIp: d.ip || ip,
        country: d.country_name || null,
        countryCode: d.country_code || null,
        region: d.region || null,
        city: d.city || null,
        isp: d.org || null,
        org: d.org || null,
        asn: d.asn || null,
        isProxyOrVpn: null,
        isHosting: null,
        coordinates:
          typeof d.latitude === 'number' && typeof d.longitude === 'number'
            ? { lat: d.latitude, lon: d.longitude }
            : null,
      };
    }
  } catch {
    // unavailable
  }
  return null;
}

async function fetchRdap(type: 'ip' | 'domain', target: string) {
  try {
    const d = await fetchJson(`https://rdap.org/${type}/${encodeURIComponent(target)}`, 5000);
    const events: any[] = Array.isArray(d.events) ? d.events : [];
    const findEvent = (act: string) => events.find((e) => e.eventAction === act)?.eventDate || null;
    const entities: any[] = Array.isArray(d.entities) ? d.entities : [];
    let registrar: string | null = null;
    const abuseContacts: string[] = [];
    for (const ent of entities) {
      const roles: string[] = Array.isArray(ent.roles) ? ent.roles : [];
      const vcard = Array.isArray(ent.vcardArray?.[1]) ? ent.vcardArray[1] : [];
      const fn = vcard.find((v: any) => v[0] === 'fn')?.[3] || null;
      const email = vcard.find((v: any) => v[0] === 'email')?.[3] || null;
      if (roles.includes('registrar') && fn) registrar = String(fn);
      if (roles.includes('abuse') && email) abuseContacts.push(String(email));
    }
    return {
      handle: d.handle || null,
      networkName: d.name || null,
      registrar,
      country: d.country || null,
      registrationDate: findEvent('registration'),
      lastChangedDate: findEvent('last changed'),
      expirationDate: findEvent('expiration'),
      status: Array.isArray(d.status) ? d.status.slice(0, 6).map(String) : [],
      cidr: Array.isArray(d.cidr0_cidrs) && d.cidr0_cidrs[0]
        ? `${d.cidr0_cidrs[0].v4prefix || d.cidr0_cidrs[0].v6prefix}/${d.cidr0_cidrs[0].length}`
        : null,
      abuseContacts: Array.from(new Set(abuseContacts)).slice(0, 4),
    };
  } catch {
    return null;
  }
}

async function fetchTlsCert(domain: string, resolvedIp: string) {
  if (isPrivateOrReservedIp(resolvedIp)) return null;
  return await new Promise<any>((resolve) => {
    let settled = false;
    const done = (v: any) => {
      if (!settled) {
        settled = true;
        resolve(v);
      }
    };
    try {
      const socket = tls.connect(
        { host: resolvedIp, port: 443, servername: domain, rejectUnauthorized: false },
        () => {
          try {
            const cert = socket.getPeerCertificate(false);
            socket.end();
            if (!cert || !Object.keys(cert).length) return done(null);
            done({
              subjectCN: cert.subject?.CN ? String(cert.subject.CN) : null,
              issuerO: cert.issuer?.O ? String(cert.issuer.O) : null,
              issuerCN: cert.issuer?.CN ? String(cert.issuer.CN) : null,
              validFrom: cert.valid_from || null,
              validTo: cert.valid_to || null,
              fingerprint256: cert.fingerprint256 || null,
            });
          } catch {
            done(null);
          }
        }
      );
      socket.setTimeout(3000, () => {
        socket.destroy();
        done(null);
      });
      socket.on('error', () => done(null));
    } catch {
      done(null);
    }
  });
}

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }
  try {
    const bodyObj = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const { target } = bodyObj;
    if (!target || typeof target !== 'string' || target.trim().length > 256) {
      return res.status(400).json({ error: 'يرجى إدخال عنوان IP أو نطاق (Domain) صالح للفحص.' });
    }
    const { indicator, originalInput, indicatorType } = classifyTarget(target);
    const sourcesChecked: { name: string; status: 'ok' | 'not_found' | 'unavailable'; detail?: string }[] = [];

    if (indicatorType === 'ipv4' || indicatorType === 'ipv6') {
      const [geo, ptrs, rdap] = await Promise.all([
        fetchIpGeo(indicator),
        dns.reverse(indicator).catch(() => [] as string[]),
        fetchRdap('ip', indicator),
      ]);
      sourcesChecked.push({ name: 'IP Geolocation / ASN', status: geo ? 'ok' : 'unavailable' });
      sourcesChecked.push({ name: 'Reverse DNS (PTR)', status: ptrs.length ? 'ok' : 'not_found' });
      sourcesChecked.push({ name: 'RDAP Network Registry', status: rdap ? 'ok' : 'unavailable' });

      return res.status(200).json({
        success: true,
        telemetry: {
          indicator,
          originalInput,
          indicatorType,
          serverInfo: geo
            ? { ...geo, reverseDns: ptrs.slice(0, 5) }
            : {
                primaryIp: indicator,
                reverseDns: ptrs.slice(0, 5),
                country: rdap?.country || null,
                countryCode: null,
                region: null,
                city: null,
                isp: rdap?.networkName || null,
                org: rdap?.networkName || null,
                asn: null,
                isProxyOrVpn: null,
                isHosting: null,
                coordinates: null,
              },
          dnsRecords: null,
          rdapInfo: rdap,
          tlsCertificate: null,
          hashTelemetry: null,
          sourcesChecked,
          collectedAt: new Date().toISOString(),
        },
        analyzedAt: new Date().toISOString(),
        engine: 'Sovereign Live DNS & IP Engine v3.5',
      });
    }

    const [a, aaaa, mx, ns, txt, cname, soa] = await Promise.all([
      dns.resolve4(indicator).catch(() => [] as string[]),
      dns.resolve6(indicator).catch(() => [] as string[]),
      dns.resolveMx(indicator).catch(() => [] as { exchange: string; priority: number }[]),
      dns.resolveNs(indicator).catch(() => [] as string[]),
      dns.resolveTxt(indicator).catch(() => [] as string[][]),
      dns.resolveCname(indicator).catch(() => [] as string[]),
      dns.resolveSoa(indicator).catch(() => null),
    ]);

    const safeIps = [...a, ...aaaa].filter((ip) => !isPrivateOrReservedIp(ip));
    const primaryIp = safeIps[0] || null;
    const [geo, ptrs, rdap, tlsCert] = await Promise.all([
      primaryIp ? fetchIpGeo(primaryIp) : Promise.resolve(null),
      primaryIp ? dns.reverse(primaryIp).catch(() => [] as string[]) : Promise.resolve([] as string[]),
      fetchRdap('domain', indicator),
      primaryIp ? fetchTlsCert(indicator, primaryIp) : Promise.resolve(null),
    ]);

    sourcesChecked.push({ name: 'Live DNS Records', status: a.length || mx.length || ns.length ? 'ok' : 'not_found' });
    sourcesChecked.push({ name: 'IP Geolocation / ASN', status: geo ? 'ok' : 'unavailable' });
    sourcesChecked.push({ name: 'RDAP Domain Registry', status: rdap ? 'ok' : 'unavailable' });
    sourcesChecked.push({ name: 'TLS/SSL Live Probe', status: tlsCert ? 'ok' : 'unavailable' });

    return res.status(200).json({
      success: true,
      telemetry: {
        indicator,
        originalInput,
        indicatorType: 'domain',
        serverInfo: geo ? { ...geo, reverseDns: ptrs.slice(0, 5) } : null,
        dnsRecords: {
          a: a.slice(0, 8),
          aaaa: aaaa.slice(0, 6),
          mx: mx.slice(0, 6),
          ns: ns.slice(0, 6),
          txt: txt.map((t) => t.join('')).slice(0, 8),
          cname: cname.slice(0, 5),
          soa: soa ? `${soa.nsname} (${soa.hostmaster})` : null,
        },
        rdapInfo: rdap,
        tlsCertificate: tlsCert,
        hashTelemetry: null,
        sourcesChecked,
        collectedAt: new Date().toISOString(),
      },
      analyzedAt: new Date().toISOString(),
      engine: 'Sovereign Live DNS & IP Engine v3.5',
    });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'تعذر استخراج بيانات DNS والشبكة للمؤشر.' });
  }
}
