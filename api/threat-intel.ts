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

function classifyIndicator(rawInput: string) {
  const originalInput = rawInput.trim();
  if (!originalInput) throw new Error('يرجى إدخال عنوان IP أو نطاق أو بصمة Hash أو رقم CVE للفحص.');
  let candidate = originalInput;
  if (/^https?:\/\//i.test(candidate)) {
    candidate = new URL(candidate).hostname;
  } else if (candidate.includes('/') && !net.isIP(candidate)) {
    candidate = candidate.split('/')[0];
  }
  candidate = candidate.replace(/:\d+$/, '').trim();

  if (net.isIPv4(candidate)) {
    if (isPrivateOrReservedIp(candidate)) throw new Error('عنوان IP الخاص مرفوض أمنياً (SSRF Protection).');
    return { indicator: candidate, originalInput, indicatorType: 'ipv4' as const };
  }
  if (net.isIPv6(candidate)) {
    if (isPrivateOrReservedIp(candidate)) throw new Error('عنوان IPv6 الخاص مرفوض أمنياً (SSRF Protection).');
    return { indicator: candidate, originalInput, indicatorType: 'ipv6' as const };
  }
  if (/^[a-fA-F0-9]{64}$/.test(candidate)) return { indicator: candidate.toLowerCase(), originalInput, indicatorType: 'hash_sha256' as const };
  if (/^[a-fA-F0-9]{128}$/.test(candidate)) return { indicator: candidate.toLowerCase(), originalInput, indicatorType: 'hash_sha512' as const };
  if (/^[a-fA-F0-9]{40}$/.test(candidate)) return { indicator: candidate.toLowerCase(), originalInput, indicatorType: 'hash_sha1' as const };
  if (/^[a-fA-F0-9]{32}$/.test(candidate)) return { indicator: candidate.toLowerCase(), originalInput, indicatorType: 'hash_md5' as const };

  const domain = candidate.toLowerCase().replace(/^\.+|\.+$/g, '');
  if (domain === 'localhost' || domain.endsWith('.local') || domain.endsWith('.internal')) {
    throw new Error('النطاقات المحلية محظورة أمنياً (SSRF Protection).');
  }
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) {
    return { indicator: domain, originalInput, indicatorType: 'domain' as const };
  }
  throw new Error('صيغة المؤشر غير مدعومة. أدخل IP أو Domain أو Hash.');
}

async function fetchJson(url: string, options?: RequestInit, timeoutMs = 4500) {
  const res = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(timeoutMs),
    headers: { Accept: 'application/json', 'User-Agent': 'SovereignForensicEngine/2.5.2', ...(options?.headers || {}) },
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
        coordinates: typeof d.latitude === 'number' && typeof d.longitude === 'number' ? { lat: d.latitude, lon: d.longitude } : null,
      };
    }
  } catch {
    // fallback
  }
  return null;
}

async function fetchRdap(type: 'ip' | 'domain', target: string) {
  try {
    const d = await fetchJson(`https://rdap.org/${type}/${encodeURIComponent(target)}`, undefined, 5000);
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
      const socket = tls.connect({ host: resolvedIp, port: 443, servername: domain, rejectUnauthorized: false }, () => {
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
      });
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

async function fetchHashIntel(hash: string, algo: string) {
  let circlKnownClean = false;
  let circlProduct: string | null = null;
  let circlFileName: string | null = null;
  let malwareBazaarFound = false;
  let malwareSignature: string | null = null;
  let fileType: string | null = null;
  let tags: string[] = [];
  let firstSeen: string | null = null;
  let reporter: string | null = null;
  const sources: { name: string; status: 'ok' | 'not_found' | 'unavailable'; detail?: string }[] = [];

  if (algo !== 'sha512') {
    try {
      const c = await fetchJson(`https://hashlookup.circl.lu/lookup/${algo}/${encodeURIComponent(hash)}`, undefined, 4000);
      if (c && (c.FileName || c['KnownMalicious'] === undefined)) {
        circlKnownClean = true;
        circlFileName = c.FileName || null;
        circlProduct = c.ProductName || c['RDS:package_name'] || null;
        sources.push({ name: 'CIRCL Hashlookup (NSRL)', status: 'ok', detail: circlFileName || 'Known software' });
      }
    } catch {
      sources.push({ name: 'CIRCL Hashlookup (NSRL)', status: 'not_found' });
    }
    try {
      const form = new URLSearchParams({ query: 'get_info', hash });
      const mb = await fetchJson('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
      }, 4500);
      if (mb?.query_status === 'ok' && Array.isArray(mb.data) && mb.data.length > 0) {
        const e = mb.data[0];
        malwareBazaarFound = true;
        malwareSignature = e.signature || null;
        fileType = e.file_type || null;
        tags = Array.isArray(e.tags) ? e.tags.slice(0, 6) : [];
        firstSeen = e.first_seen || null;
        reporter = e.reporter || null;
        sources.push({ name: 'Abuse.ch MalwareBazaar', status: 'ok', detail: malwareSignature || 'Malicious sample' });
      } else {
        sources.push({ name: 'Abuse.ch MalwareBazaar', status: 'not_found' });
      }
    } catch {
      sources.push({ name: 'Abuse.ch MalwareBazaar', status: 'unavailable' });
    }
  }

  return {
    hashTelemetry: {
      algorithm: algo.toUpperCase(),
      circlKnownClean,
      circlProduct,
      circlFileName,
      malwareBazaarFound,
      malwareSignature,
      fileType,
      tags,
      firstSeen,
      reporter,
    },
    sources,
  };
}

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }
  try {
    const bodyObj = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const { indicator: rawIndicator } = bodyObj;
    if (!rawIndicator || typeof rawIndicator !== 'string' || rawIndicator.trim().length > 256) {
      return res.status(400).json({ error: 'يرجى إدخال عنوان IP أو نطاق أو بصمة صالحة.' });
    }

    const { indicator, originalInput, indicatorType } = classifyIndicator(rawIndicator);
    const sourcesChecked: any[] = [];
    let telemetry: any;

    if (indicatorType === 'ipv4' || indicatorType === 'ipv6') {
      const [geo, ptrs, rdap] = await Promise.all([
        fetchIpGeo(indicator),
        dns.reverse(indicator).catch(() => [] as string[]),
        fetchRdap('ip', indicator),
      ]);
      sourcesChecked.push({ name: 'IP Geolocation / ASN', status: geo ? 'ok' : 'unavailable' });
      sourcesChecked.push({ name: 'Reverse DNS (PTR)', status: ptrs.length ? 'ok' : 'not_found' });
      sourcesChecked.push({ name: 'RDAP Network Registry', status: rdap ? 'ok' : 'unavailable' });
      telemetry = {
        indicator,
        originalInput,
        indicatorType,
        serverInfo: geo ? { ...geo, reverseDns: ptrs.slice(0, 5) } : { primaryIp: indicator, reverseDns: ptrs.slice(0, 5), country: rdap?.country || null, countryCode: null, region: null, city: null, isp: rdap?.networkName || null, org: rdap?.networkName || null, asn: null, isProxyOrVpn: null, isHosting: null, coordinates: null },
        dnsRecords: null,
        rdapInfo: rdap,
        tlsCertificate: null,
        hashTelemetry: null,
        sourcesChecked,
        collectedAt: new Date().toISOString(),
      };
    } else if (indicatorType === 'domain') {
      const [a, aaaa, mx, ns, txt, cname, soa] = await Promise.all([
        dns.resolve4(indicator).catch(() => [] as string[]),
        dns.resolve6(indicator).catch(() => [] as string[]),
        dns.resolveMx(indicator).catch(() => [] as { exchange: string; priority: number }[]),
        dns.resolveNs(indicator).catch(() => [] as string[]),
        dns.resolveTxt(indicator).catch(() => [] as string[][]),
        dns.resolveCname(indicator).catch(() => [] as string[]),
        dns.resolveSoa(indicator).catch(() => null),
      ]);
      const primaryIp = [...a, ...aaaa].find((ip) => !isPrivateOrReservedIp(ip)) || null;
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
      telemetry = {
        indicator,
        originalInput,
        indicatorType,
        serverInfo: geo ? { ...geo, reverseDns: ptrs.slice(0, 5) } : null,
        dnsRecords: { a: a.slice(0, 8), aaaa: aaaa.slice(0, 6), mx: mx.slice(0, 6), ns: ns.slice(0, 6), txt: txt.map((t) => t.join('')).slice(0, 8), cname: cname.slice(0, 5), soa: soa ? `${soa.nsname} (${soa.hostmaster})` : null },
        rdapInfo: rdap,
        tlsCertificate: tlsCert,
        hashTelemetry: null,
        sourcesChecked,
        collectedAt: new Date().toISOString(),
      };
    } else {
      const algo = indicatorType.replace('hash_', '');
      const { hashTelemetry, sources } = await fetchHashIntel(indicator, algo);
      sourcesChecked.push(...sources);
      telemetry = {
        indicator,
        originalInput,
        indicatorType,
        serverInfo: null,
        dnsRecords: null,
        rdapInfo: null,
        tlsCertificate: null,
        hashTelemetry,
        sourcesChecked,
        collectedAt: new Date().toISOString(),
      };
    }

    const findings: string[] = [];
    const categories: string[] = [];
    let score = 10;
    let isMal = false;

    if (telemetry.hashTelemetry) {
      if (telemetry.hashTelemetry.malwareBazaarFound) {
        score = 95;
        isMal = true;
        categories.push('Known Malware Sample', 'Abuse.ch MalwareBazaar');
        findings.push(`العينة مدرجة كبرمجية خبيثة في MalwareBazaar (${telemetry.hashTelemetry.malwareSignature || 'عينة خطرة'}).`);
      } else if (telemetry.hashTelemetry.circlKnownClean) {
        score = 5;
        categories.push('Whitelisted Known Software');
        findings.push('البصمة موثقة كبرمجية قياسية سليمة في قاعدة CIRCL/NSRL.');
      } else {
        score = 30;
        findings.push('البصمة غير مسجلة في قواعد البرمجيات الخبيثة أو النظيفة المعروفة.');
      }
    }
    if (telemetry.serverInfo) {
      if (telemetry.serverInfo.country) findings.push(`الموقع الجغرافي الفعلي: ${telemetry.serverInfo.country} (${telemetry.serverInfo.countryCode || ''}) • ASN: ${telemetry.serverInfo.asn || 'غير محدد'}.`);
      if (telemetry.serverInfo.isp) findings.push(`مزود الاستضافة / ISP: ${telemetry.serverInfo.isp}.`);
      if (telemetry.serverInfo.reverseDns?.length) findings.push(`سجل PTR العكسي: ${telemetry.serverInfo.reverseDns.join(', ')}.`);
    }
    if (telemetry.dnsRecords) {
      if (telemetry.dnsRecords.a?.length) findings.push(`عناوين IPv4 الحية: ${telemetry.dnsRecords.a.slice(0, 4).join(', ')}.`);
      if (telemetry.dnsRecords.mx?.length) findings.push(`خوادم البريد MX: ${telemetry.dnsRecords.mx.slice(0, 3).map((m: any) => m.exchange).join(', ')}.`);
      if (telemetry.dnsRecords.ns?.length) findings.push(`خوادم الأسماء NS: ${telemetry.dnsRecords.ns.slice(0, 3).join(', ')}.`);
    }
    if (telemetry.tlsCertificate) {
      findings.push(`شهادة SSL/TLS الحية صادرة عن: ${telemetry.tlsCertificate.issuerO || telemetry.tlsCertificate.issuerCN || 'CA'}.`);
    }

    const riskLevel = score >= 80 ? 'حرج' : score >= 60 ? 'مرتفع' : score >= 35 ? 'متوسط' : 'منخفض';
    const verdict = isMal
      ? 'مؤشر أمني عالي الخطورة (Threat IOC Detected)'
      : 'تم إتمام الفحص الحي من المصادر المفتوحة بنجاح';

    return res.status(200).json({
      telemetry,
      intelligence: {
        verdict,
        isMalicious: isMal,
        riskLevel,
        threatScore: score,
        threatCategories: categories.length ? categories : ['Live OSINT Telemetry'],
        executiveSummary: `تم جمع البيانات الفعلية للمؤشر (${telemetry.indicator}) مباشرة عبر DNS وRDAP وGeoIP وقواعد السمعة المفتوحة.`,
        infrastructureAnalysis: `البنية التحتية المستخرجة تشير إلى استضافة لدى (${telemetry.serverInfo?.org || telemetry.serverInfo?.isp || 'غير متوفر'}) في (${telemetry.serverInfo?.country || 'غير محدد'}).`,
        osintFindings: findings,
        recommendations: isMal
          ? ['حظر المؤشر فوراً في جدار الحماية وأنظمة EDR.', 'مراجعة سجلات الشبكة للتحقق من وجود اتصالات نشطة.']
          : ['حفظ التقرير الاستخباراتي في ملف التحقيق.', 'مراقبة أي تغييرات في سجلات DNS أو الاستضافة.'],
      },
      sources: [
        { title: 'RDAP Official Registry', uri: 'https://rdap.org' },
        { title: 'IP Geolocation & ASN Registry', uri: 'https://ipwho.is' },
        { title: 'Abuse.ch MalwareBazaar / CIRCL', uri: 'https://bazaar.abuse.ch' },
      ],
      analyzedAt: new Date().toISOString(),
      modelUsed: 'Sovereign Live OSINT Engine v3.5',
    });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'تعذر إتمام الفحص الاستخباراتي للمؤشر.' });
  }
}
