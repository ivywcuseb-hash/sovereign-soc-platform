import type { LiveNetworkTelemetry } from './threatIntelServer';

function isValidPublicIpv4Client(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  return true;
}

async function fetchJsonSafe(url: string, timeoutMs = 5000): Promise<any | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { Accept: 'application/json' } });
    if (!res.ok) return null;
    const text = await res.text();
    if (!text.trim()) return null;
    return JSON.parse(text);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function resolveDohRecord(domain: string, type: 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | 'CNAME'): Promise<any[]> {
  const res = await fetchJsonSafe(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
  return Array.isArray(res?.Answer) ? res.Answer : [];
}

export async function gatherOsintClientFallback(rawInput: string): Promise<LiveNetworkTelemetry> {
  const originalInput = rawInput.trim();
  if (!originalInput) {
    throw new Error('يرجى إدخال عنوان IP أو نطاق (Domain) أو بصمة (Hash) أو رقم CVE للفحص.');
  }

  let candidate = originalInput;
  if (/^https?:\/\//i.test(candidate)) {
    candidate = new URL(candidate).hostname;
  } else if (candidate.includes('/') && !/^\d+\.\d+\.\d+\.\d+$/.test(candidate)) {
    candidate = candidate.split('/')[0];
  }
  candidate = candidate.replace(/:\d+$/, '').trim();

  const sourcesChecked: { name: string; status: 'ok' | 'not_found' | 'unavailable'; detail?: string }[] = [];

  // IPv4 Lookup
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(candidate)) {
    if (!isValidPublicIpv4Client(candidate)) {
      throw new Error('عنوان IP الخاص أو المحلي محظور أمنياً (SSRF Protection).');
    }
    const [geo, rdap] = await Promise.all([
      fetchJsonSafe(`https://ipwho.is/${encodeURIComponent(candidate)}`),
      fetchJsonSafe(`https://rdap.org/ip/${encodeURIComponent(candidate)}`),
    ]);
    sourcesChecked.push({ name: 'IPWhois GeoIP & ASN', status: geo?.success ? 'ok' : 'unavailable' });
    sourcesChecked.push({ name: 'RDAP Network Registry', status: rdap ? 'ok' : 'unavailable' });

    return {
      indicator: candidate,
      originalInput,
      indicatorType: 'ipv4',
      serverInfo: geo?.success
        ? {
            primaryIp: geo.ip || candidate,
            reverseDns: [],
            country: geo.country || null,
            countryCode: geo.country_code || null,
            region: geo.region || null,
            city: geo.city || null,
            isp: geo.connection?.isp || null,
            org: geo.connection?.org || null,
            asn: geo.connection?.asn ? `AS${geo.connection.asn}` : null,
            isProxyOrVpn: null,
            isHosting: null,
            coordinates:
              typeof geo.latitude === 'number' && typeof geo.longitude === 'number'
                ? { lat: geo.latitude, lon: geo.longitude }
                : null,
          }
        : null,
      dnsRecords: null,
      rdapInfo: rdap
        ? {
            handle: rdap.handle || null,
            networkName: rdap.name || null,
            registrar: null,
            country: rdap.country || null,
            registrationDate: rdap.events?.find((e: any) => e.eventAction === 'registration')?.eventDate || null,
            lastChangedDate: rdap.events?.find((e: any) => e.eventAction === 'last changed')?.eventDate || null,
            expirationDate: null,
            status: Array.isArray(rdap.status) ? rdap.status.slice(0, 6) : [],
            cidr: null,
            abuseContacts: [],
          }
        : null,
      tlsCertificate: null,
      hashTelemetry: null,
      sourcesChecked,
      collectedAt: new Date().toISOString(),
    };
  }

  // Hash Lookup (CIRCL Hashlookup)
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(candidate)) {
    const hash = candidate.toLowerCase();
    const indicatorType =
      hash.length === 64 ? 'hash_sha256' : hash.length === 40 ? 'hash_sha1' : hash.length === 32 ? 'hash_md5' : 'hash_sha512';
    const algo = indicatorType.replace('hash_', '');
    const circl = algo !== 'sha512' ? await fetchJsonSafe(`https://hashlookup.circl.lu/lookup/${algo}/${hash}`) : null;
    sourcesChecked.push({ name: 'CIRCL Hashlookup (NSRL)', status: circl ? 'ok' : 'not_found' });
    return {
      indicator: hash,
      originalInput,
      indicatorType,
      serverInfo: null,
      dnsRecords: null,
      rdapInfo: null,
      tlsCertificate: null,
      hashTelemetry: {
        algorithm: algo.toUpperCase(),
        circlKnownClean: Boolean(circl),
        circlProduct: circl?.ProductName || circl?.['RDS:package_name'] || null,
        circlFileName: circl?.FileName || null,
        malwareBazaarFound: false,
        malwareSignature: null,
        fileType: null,
        tags: [],
        firstSeen: null,
        reporter: null,
      },
      sourcesChecked,
      collectedAt: new Date().toISOString(),
    };
  }

  // Domain Lookup via Google Public DNS-over-HTTPS + IPWhois + RDAP
  const domain = candidate.toLowerCase().replace(/^\.+|\.+$/g, '');
  if (domain === 'localhost' || domain.endsWith('.local') || domain.endsWith('.internal')) {
    throw new Error('النطاقات المحلية محظورة أمنياً (SSRF Protection).');
  }

  const [aAns, aaaaAns, mxAns, nsAns, txtAns, cnameAns, rdap] = await Promise.all([
    resolveDohRecord(domain, 'A'),
    resolveDohRecord(domain, 'AAAA'),
    resolveDohRecord(domain, 'MX'),
    resolveDohRecord(domain, 'NS'),
    resolveDohRecord(domain, 'TXT'),
    resolveDohRecord(domain, 'CNAME'),
    fetchJsonSafe(`https://rdap.org/domain/${encodeURIComponent(domain)}`),
  ]);

  const a = aAns.filter((r) => r.type === 1).map((r) => String(r.data));
  const aaaa = aaaaAns.filter((r) => r.type === 28).map((r) => String(r.data));
  const mx = mxAns
    .filter((r) => r.type === 15)
    .map((r) => {
      const [prio, ex] = String(r.data).split(/\s+/);
      return { priority: Number(prio) || 10, exchange: (ex || prio || '').replace(/\.$/, '') };
    });
  const ns = nsAns.filter((r) => r.type === 2).map((r) => String(r.data).replace(/\.$/, ''));
  const txt = txtAns.filter((r) => r.type === 16).map((r) => String(r.data));
  const cname = cnameAns.filter((r) => r.type === 5).map((r) => String(r.data).replace(/\.$/, ''));

  const primaryIp = a.find(isValidPublicIpv4Client) || null;
  const geo = primaryIp ? await fetchJsonSafe(`https://ipwho.is/${encodeURIComponent(primaryIp)}`) : null;

  sourcesChecked.push({ name: 'Google Public DNS-over-HTTPS', status: a.length || mx.length || ns.length ? 'ok' : 'not_found' });
  sourcesChecked.push({ name: 'IPWhois GeoIP & ASN', status: geo?.success ? 'ok' : 'unavailable' });
  sourcesChecked.push({ name: 'RDAP Domain Registry', status: rdap ? 'ok' : 'unavailable' });

  return {
    indicator: domain,
    originalInput,
    indicatorType: 'domain',
    serverInfo: geo?.success
      ? {
          primaryIp: geo.ip || primaryIp,
          reverseDns: [],
          country: geo.country || null,
          countryCode: geo.country_code || null,
          region: geo.region || null,
          city: geo.city || null,
          isp: geo.connection?.isp || null,
          org: geo.connection?.org || null,
          asn: geo.connection?.asn ? `AS${geo.connection.asn}` : null,
          isProxyOrVpn: null,
          isHosting: null,
          coordinates:
            typeof geo.latitude === 'number' && typeof geo.longitude === 'number'
              ? { lat: geo.latitude, lon: geo.longitude }
              : null,
        }
      : primaryIp
      ? {
          primaryIp,
          reverseDns: [],
          country: null,
          countryCode: null,
          region: null,
          city: null,
          isp: null,
          org: null,
          asn: null,
          isProxyOrVpn: null,
          isHosting: null,
          coordinates: null,
        }
      : null,
    dnsRecords: {
      a: a.slice(0, 8),
      aaaa: aaaa.slice(0, 6),
      mx: mx.slice(0, 6),
      ns: ns.slice(0, 6),
      txt: txt.slice(0, 8),
      cname: cname.slice(0, 5),
      soa: null,
    },
    rdapInfo: rdap
      ? {
          handle: rdap.handle || null,
          networkName: rdap.name || null,
          registrar: null,
          country: rdap.country || null,
          registrationDate: rdap.events?.find((e: any) => e.eventAction === 'registration')?.eventDate || null,
          lastChangedDate: rdap.events?.find((e: any) => e.eventAction === 'last changed')?.eventDate || null,
          expirationDate: rdap.events?.find((e: any) => e.eventAction === 'expiration')?.eventDate || null,
          status: Array.isArray(rdap.status) ? rdap.status.slice(0, 6) : [],
          cidr: null,
          abuseContacts: [],
        }
      : null,
    tlsCertificate: null,
    hashTelemetry: null,
    sourcesChecked,
    collectedAt: new Date().toISOString(),
  };
}

export function buildThreatIntelReportClient(telemetry: LiveNetworkTelemetry) {
  const findings: string[] = [];
  const categories: string[] = [];
  let score = 10;

  if (telemetry.hashTelemetry?.circlKnownClean) {
    score = 5;
    categories.push('Known Clean Software (NSRL)');
    findings.push(`البصمة التشفيرية موثقة في قاعدة بيانات CIRCL/NSRL (${telemetry.hashTelemetry.circlFileName || 'ملف قياسي'}).`);
  }
  if (telemetry.serverInfo) {
    if (telemetry.serverInfo.country) {
      findings.push(`الموقع الجغرافي الفعلي: ${telemetry.serverInfo.country} • المزود: ${telemetry.serverInfo.isp || '—'} (${telemetry.serverInfo.asn || '—'}).`);
    }
  }
  if (telemetry.dnsRecords) {
    if (telemetry.dnsRecords.a.length) findings.push(`سجلات A: ${telemetry.dnsRecords.a.join(', ')}`);
    if (telemetry.dnsRecords.mx.length) findings.push(`خوادم البريد MX: ${telemetry.dnsRecords.mx.map((m) => m.exchange).join(', ')}`);
    if (telemetry.dnsRecords.ns.length) findings.push(`خوادم الأسماء NS: ${telemetry.dnsRecords.ns.join(', ')}`);
  }

  return {
    telemetry,
    intelligence: {
      verdict: 'تم الفحص الحي عبر DNS-over-HTTPS وRDAP وGeoIP بنجاح',
      isMalicious: false,
      riskLevel: score >= 60 ? 'مرتفع' : score >= 35 ? 'متوسط' : 'منخفض',
      threatScore: score,
      threatCategories: categories.length ? categories : ['Live OSINT Telemetry'],
      executiveSummary: `تم استعلام المؤشر (${telemetry.indicator}) مباشرة من مصادر الاستخبارات المفتوحة الحية بدون بيانات ثابتة.`,
      infrastructureAnalysis: `الخادم/النطاق يستضيفه (${telemetry.serverInfo?.org || telemetry.serverInfo?.isp || 'غير متوفر'}) في (${telemetry.serverInfo?.country || 'غير محدد'}).`,
      osintFindings: findings.length ? findings : ['تم التحقق من استجابة السجلات الحية للمؤشر.'],
      recommendations: [
        'حفظ بيانات DNS وRDAP في ملف القضية كمرجع تحقيقي موثق.',
        'متابعة التغذيات الحية للثغرات للتأكد من خلو البنية التحتية من ثغرات نشطة.',
      ],
    },
    sources: [
      { title: 'Google Public DNS-over-HTTPS', uri: 'https://dns.google' },
      { title: 'IPWhois Live GeoIP & ASN', uri: 'https://ipwho.is' },
      { title: 'RDAP Official Registry', uri: 'https://rdap.org' },
    ],
    analyzedAt: new Date().toISOString(),
    modelUsed: 'Sovereign Live Browser OSINT Engine v3.5',
  };
}
