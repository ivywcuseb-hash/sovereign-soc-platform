import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import * as tls from 'node:tls';

export type ThreatIndicatorType =
  | 'ipv4'
  | 'ipv6'
  | 'domain'
  | 'hash_md5'
  | 'hash_sha1'
  | 'hash_sha256'
  | 'hash_sha512';

export interface LiveServerInfo {
  primaryIp: string | null;
  reverseDns: string[];
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  org: string | null;
  asn: string | null;
  isProxyOrVpn: boolean | null;
  isHosting: boolean | null;
  coordinates: { lat: number; lon: number } | null;
}

export interface LiveDnsRecords {
  a: string[];
  aaaa: string[];
  mx: { exchange: string; priority: number }[];
  ns: string[];
  txt: string[];
  cname: string[];
  soa?: string | null;
}

export interface LiveRdapInfo {
  handle: string | null;
  networkName: string | null;
  registrar: string | null;
  country: string | null;
  registrationDate: string | null;
  lastChangedDate: string | null;
  expirationDate: string | null;
  status: string[];
  cidr: string | null;
  abuseContacts: string[];
}

export interface LiveTlsCertificate {
  subjectCN: string | null;
  issuerO: string | null;
  issuerCN: string | null;
  validFrom: string | null;
  validTo: string | null;
  fingerprint256: string | null;
}

export interface LiveHashTelemetry {
  algorithm: string;
  circlKnownClean: boolean;
  circlProduct: string | null;
  circlFileName: string | null;
  malwareBazaarFound: boolean;
  malwareSignature: string | null;
  fileType: string | null;
  tags: string[];
  firstSeen: string | null;
  reporter: string | null;
}

export interface LiveNetworkTelemetry {
  indicator: string;
  originalInput: string;
  indicatorType: ThreatIndicatorType;
  serverInfo: LiveServerInfo | null;
  dnsRecords: LiveDnsRecords | null;
  rdapInfo: LiveRdapInfo | null;
  tlsCertificate: LiveTlsCertificate | null;
  hashTelemetry: LiveHashTelemetry | null;
  sourcesChecked: { name: string; status: 'ok' | 'not_found' | 'unavailable'; detail?: string }[];
  collectedAt: string;
}

export function classifyIocIndicator(rawInput: string): {
  indicator: string;
  originalInput: string;
  indicatorType: ThreatIndicatorType;
} {
  const originalInput = rawInput.trim();
  if (!originalInput) {
    throw new Error('يرجى إدخال عنوان IP أو نطاق (Domain) أو بصمة تشفيرية (Hash) للفحص.');
  }

  let candidate = originalInput;
  if (/^https?:\/\//i.test(candidate)) {
    try {
      const parsed = new URL(candidate);
      candidate = parsed.hostname;
    } catch {
      // keep raw
    }
  } else if (candidate.includes('/') && !net.isIP(candidate)) {
    candidate = candidate.split('/')[0];
  }
  candidate = candidate.replace(/:\d+$/, '').trim();

  if (net.isIPv4(candidate)) {
    return { indicator: candidate, originalInput, indicatorType: 'ipv4' };
  }
  if (net.isIPv6(candidate)) {
    return { indicator: candidate, originalInput, indicatorType: 'ipv6' };
  }
  if (/^[a-fA-F0-9]{64}$/.test(candidate)) {
    return { indicator: candidate.toLowerCase(), originalInput, indicatorType: 'hash_sha256' };
  }
  if (/^[a-fA-F0-9]{128}$/.test(candidate)) {
    return { indicator: candidate.toLowerCase(), originalInput, indicatorType: 'hash_sha512' };
  }
  if (/^[a-fA-F0-9]{40}$/.test(candidate)) {
    return { indicator: candidate.toLowerCase(), originalInput, indicatorType: 'hash_sha1' };
  }
  if (/^[a-fA-F0-9]{32}$/.test(candidate)) {
    return { indicator: candidate.toLowerCase(), originalInput, indicatorType: 'hash_md5' };
  }

  const normalizedDomain = candidate.toLowerCase().replace(/^\.+|\.+$/g, '');
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(normalizedDomain)) {
    return { indicator: normalizedDomain, originalInput, indicatorType: 'domain' };
  }

  throw new Error(
    'صيغة المؤشر غير مدعومة. أدخل عنوان IPv4/IPv6 صالحاً، أو اسم نطاق (مثل example.com)، أو بصمة Hash (MD5/SHA-1/SHA-256).'
  );
}

async function fetchJsonWithTimeout(url: string, options?: RequestInit, timeoutMs = 4500): Promise<any> {
  const res = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      Accept: 'application/json',
      'User-Agent': 'SovereignForensicEngine/2.5.2',
      ...(options?.headers || {}),
    },
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  return await res.json();
}

async function fetchIpGeo(ip: string): Promise<{
  info: Omit<LiveServerInfo, 'reverseDns'> | null;
  sourceStatus: 'ok' | 'unavailable';
}> {
  try {
    const data = await fetchJsonWithTimeout(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,continent,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,proxy,hosting,query`
    );
    if (data && data.status === 'success') {
      return {
        info: {
          primaryIp: data.query || ip,
          country: data.country || null,
          countryCode: data.countryCode || null,
          region: data.regionName || null,
          city: data.city || null,
          isp: data.isp || null,
          org: data.org || data.asname || null,
          asn: data.as || null,
          isProxyOrVpn: typeof data.proxy === 'boolean' ? data.proxy : null,
          isHosting: typeof data.hosting === 'boolean' ? data.hosting : null,
          coordinates:
            typeof data.lat === 'number' && typeof data.lon === 'number'
              ? { lat: data.lat, lon: data.lon }
              : null,
        },
        sourceStatus: 'ok',
      };
    }
  } catch {
    // fallback below
  }

  try {
    const data = await fetchJsonWithTimeout(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (data && data.success) {
      return {
        info: {
          primaryIp: data.ip || ip,
          country: data.country || null,
          countryCode: data.country_code || null,
          region: data.region || null,
          city: data.city || null,
          isp: data.connection?.isp || null,
          org: data.connection?.org || null,
          asn: data.connection?.asn ? `AS${data.connection.asn}` : null,
          isProxyOrVpn: null,
          isHosting: null,
          coordinates:
            typeof data.latitude === 'number' && typeof data.longitude === 'number'
              ? { lat: data.latitude, lon: data.longitude }
              : null,
        },
        sourceStatus: 'ok',
      };
    }
  } catch {
    // unavailable
  }

  return { info: null, sourceStatus: 'unavailable' };
}

function extractRdapContacts(entities: any[]): { registrar: string | null; abuseContacts: string[] } {
  let registrar: string | null = null;
  const abuseSet = new Set<string>();

  const walk = (list: any[]) => {
    for (const ent of list || []) {
      const roles: string[] = Array.isArray(ent.roles) ? ent.roles : [];
      const vcard = Array.isArray(ent.vcardArray?.[1]) ? ent.vcardArray[1] : [];
      const fnEntry = vcard.find((item: any) => item[0] === 'fn');
      const fnVal = fnEntry?.[3] ? String(fnEntry[3]) : null;

      if (roles.includes('registrar') && fnVal && !registrar) {
        registrar = fnVal;
      }
      for (const item of vcard) {
        if (item[0] === 'email' && item[3]) {
          abuseSet.add(String(item[3]));
        }
      }
      if (Array.isArray(ent.entities)) walk(ent.entities);
    }
  };
  walk(entities);
  return { registrar, abuseContacts: Array.from(abuseSet).slice(0, 6) };
}

async function fetchRdapInfo(kind: 'ip' | 'domain', value: string): Promise<{
  rdap: LiveRdapInfo | null;
  status: 'ok' | 'not_found' | 'unavailable';
}> {
  try {
    const data = await fetchJsonWithTimeout(`https://rdap.org/${kind}/${encodeURIComponent(value)}`, undefined, 5000);
    const events: any[] = Array.isArray(data.events) ? data.events : [];
    const findEvent = (action: string) =>
      events.find((e) => e.eventAction === action)?.eventDate || null;

    const { registrar, abuseContacts } = extractRdapContacts(data.entities || []);
    const cidrObj = Array.isArray(data.cidr0_cidrs) && data.cidr0_cidrs[0];
    const cidr = cidrObj
      ? `${cidrObj.v4prefix || cidrObj.v6prefix}/${cidrObj.length}`
      : data.startAddress && data.endAddress
      ? `${data.startAddress} - ${data.endAddress}`
      : null;

    return {
      rdap: {
        handle: data.handle || null,
        networkName: data.name || data.ldhName || null,
        registrar,
        country: data.country || null,
        registrationDate: findEvent('registration'),
        lastChangedDate: findEvent('last changed'),
        expirationDate: findEvent('expiration'),
        status: Array.isArray(data.status) ? data.status.slice(0, 6) : [],
        cidr,
        abuseContacts,
      },
      status: 'ok',
    };
  } catch (err: any) {
    if (String(err?.message).includes('HTTP 404')) {
      return { rdap: null, status: 'not_found' };
    }
    return { rdap: null, status: 'unavailable' };
  }
}

async function fetchDohRecord(domain: string, type: 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | 'CNAME' | 'SOA' | 'PTR'): Promise<string[]> {
  try {
    const res = await fetchJsonWithTimeout(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
      undefined,
      4000
    );
    if (res && res.Answer && Array.isArray(res.Answer)) {
      return res.Answer.map((a: any) => String(a.data || '')).filter(Boolean);
    }
  } catch {
    // fallback
  }
  return [];
}

async function fetchDnsRecords(domain: string): Promise<LiveDnsRecords> {
  const [
    dohA,
    dohAaaa,
    dohMx,
    dohNs,
    dohTxt,
    dohCname,
    dohSoa,
    nodeA,
    nodeAaaa,
    nodeMx,
    nodeNs,
    nodeTxt,
    nodeCname,
  ] = await Promise.all([
    fetchDohRecord(domain, 'A'),
    fetchDohRecord(domain, 'AAAA'),
    fetchDohRecord(domain, 'MX'),
    fetchDohRecord(domain, 'NS'),
    fetchDohRecord(domain, 'TXT'),
    fetchDohRecord(domain, 'CNAME'),
    fetchDohRecord(domain, 'SOA'),
    dns.resolve4(domain).catch(() => [] as string[]),
    dns.resolve6(domain).catch(() => [] as string[]),
    dns.resolveMx(domain).catch(() => [] as { exchange: string; priority: number }[]),
    dns.resolveNs(domain).catch(() => [] as string[]),
    dns.resolveTxt(domain).catch(() => [] as string[][]),
    dns.resolveCname(domain).catch(() => [] as string[]),
  ]);

  const aSet = new Set<string>([...dohA, ...nodeA]);
  const aaaaSet = new Set<string>([...dohAaaa, ...nodeAaaa]);
  const nsSet = new Set<string>([
    ...dohNs.map(n => n.replace(/\.$/, '')),
    ...nodeNs.map(n => n.replace(/\.$/, '')),
  ]);
  const txtSet = new Set<string>([
    ...dohTxt.map(t => t.replace(/^"|"$/g, '')),
    ...nodeTxt.map(chunks => chunks.join('')).map(t => t.replace(/^"|"$/g, '')),
  ]);
  const cnameSet = new Set<string>([
    ...dohCname.map(c => c.replace(/\.$/, '')),
    ...nodeCname.map(c => c.replace(/\.$/, '')),
  ]);

  const mxMap = new Map<string, number>();
  for (const m of nodeMx) {
    mxMap.set(m.exchange.replace(/\.$/, ''), m.priority);
  }
  for (const raw of dohMx) {
    const parts = raw.trim().split(/\s+/);
    if (parts.length >= 2) {
      const prio = parseInt(parts[0], 10) || 10;
      const ex = parts[1].replace(/\.$/, '');
      if (!mxMap.has(ex)) mxMap.set(ex, prio);
    }
  }

  const mxList = Array.from(mxMap.entries())
    .map(([exchange, priority]) => ({ exchange, priority }))
    .sort((x, y) => x.priority - y.priority);

  return {
    a: Array.from(aSet).slice(0, 16),
    aaaa: Array.from(aaaaSet).slice(0, 8),
    mx: mxList.slice(0, 10),
    ns: Array.from(nsSet).slice(0, 10),
    txt: Array.from(txtSet).slice(0, 12),
    cname: Array.from(cnameSet).slice(0, 6),
    soa: dohSoa[0] || null,
  };
}

async function fetchTlsCert(domain: string): Promise<LiveTlsCertificate | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (cert: LiveTlsCertificate | null) => {
      if (!settled) {
        settled = true;
        resolve(cert);
      }
    };

    try {
      const socket = tls.connect(
        {
          host: domain,
          port: 443,
          servername: domain,
          rejectUnauthorized: false,
          timeout: 3500,
        },
        () => {
          try {
            const peer = socket.getPeerCertificate(false);
            if (peer && Object.keys(peer).length > 0) {
              finish({
                subjectCN: peer.subject?.CN ? String(peer.subject.CN) : null,
                issuerO: peer.issuer?.O ? String(peer.issuer.O) : null,
                issuerCN: peer.issuer?.CN ? String(peer.issuer.CN) : null,
                validFrom: peer.valid_from || null,
                validTo: peer.valid_to || null,
                fingerprint256: peer.fingerprint256 || null,
              });
            } else {
              finish(null);
            }
          } catch {
            finish(null);
          } finally {
            socket.destroy();
          }
        }
      );

      socket.on('timeout', () => {
        socket.destroy();
        finish(null);
      });
      socket.on('error', () => {
        socket.destroy();
        finish(null);
      });
    } catch {
      finish(null);
    }
  });
}

async function fetchHashIntelligence(
  hash: string,
  algo: 'md5' | 'sha1' | 'sha256' | 'sha512'
): Promise<{
  hashTelemetry: LiveHashTelemetry;
  sources: { name: string; status: 'ok' | 'not_found' | 'unavailable'; detail?: string }[];
}> {
  const sources: { name: string; status: 'ok' | 'not_found' | 'unavailable'; detail?: string }[] = [];
  let circlKnownClean = false;
  let circlProduct: string | null = null;
  let circlFileName: string | null = null;
  let malwareBazaarFound = false;
  let malwareSignature: string | null = null;
  let fileType: string | null = null;
  let tags: string[] = [];
  let firstSeen: string | null = null;
  let reporter: string | null = null;

  const circlTask =
    algo === 'md5' || algo === 'sha1' || algo === 'sha256'
      ? fetchJsonWithTimeout(`https://hashlookup.circl.lu/lookup/${algo}/${hash}`, undefined, 4500)
          .then((data) => {
            circlKnownClean = true;
            circlProduct = data?.ProductName?.ProductName || data?.ProductCode || null;
            circlFileName = data?.FileName || null;
            sources.push({ name: 'CIRCL Hashlookup (NSRL)', status: 'ok', detail: circlFileName || 'Known software hash' });
          })
          .catch((err) => {
            sources.push({
              name: 'CIRCL Hashlookup (NSRL)',
              status: String(err?.message).includes('404') ? 'not_found' : 'unavailable',
            });
          })
      : Promise.resolve();

  const mbBody = new URLSearchParams({ query: 'get_info', hash });
  const mbTask = fetchJsonWithTimeout(
    'https://mb-api.abuse.ch/api/v1/',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: mbBody.toString(),
    },
    4500
  )
    .then((data) => {
      if (data?.query_status === 'ok' && Array.isArray(data.data) && data.data.length > 0) {
        const sample = data.data[0];
        malwareBazaarFound = true;
        malwareSignature = sample.signature || null;
        fileType = sample.file_type || sample.file_type_mime || null;
        tags = Array.isArray(sample.tags) ? sample.tags : [];
        firstSeen = sample.first_seen || null;
        reporter = sample.reporter || null;
        sources.push({
          name: 'Abuse.ch MalwareBazaar',
          status: 'ok',
          detail: malwareSignature || 'Malicious sample matched',
        });
      } else {
        sources.push({
          name: 'Abuse.ch MalwareBazaar',
          status: data?.query_status === 'hash_not_found' ? 'not_found' : 'unavailable',
        });
      }
    })
    .catch(() => {
      sources.push({ name: 'Abuse.ch MalwareBazaar', status: 'unavailable' });
    });

  await Promise.all([circlTask, mbTask]);

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

async function fetchReverseDns(ip: string): Promise<string[]> {
  const hostnames = new Set<string>();
  try {
    const nodeRes = await dns.reverse(ip);
    nodeRes.forEach(h => hostnames.add(h));
  } catch {}

  try {
    if (net.isIPv4(ip)) {
      const ptrDomain = ip.split('.').reverse().join('.') + '.in-addr.arpa';
      const dohRes = await fetchDohRecord(ptrDomain, 'PTR');
      dohRes.forEach(h => hostnames.add(h.replace(/\.$/, '')));
    }
  } catch {}

  return Array.from(hostnames);
}

export async function gatherLiveOsintTelemetry(rawInput: string): Promise<LiveNetworkTelemetry> {
  const { indicator, originalInput, indicatorType } = classifyIocIndicator(rawInput);
  const sourcesChecked: LiveNetworkTelemetry['sourcesChecked'] = [];

  if (indicatorType === 'ipv4' || indicatorType === 'ipv6') {
    const [geoRes, rdapRes, revRes] = await Promise.all([
      fetchIpGeo(indicator),
      fetchRdapInfo('ip', indicator),
      fetchReverseDns(indicator),
    ]);

    sourcesChecked.push({
      name: 'GeoIP & ASN Lookup',
      status: geoRes.sourceStatus,
      detail: geoRes.info?.country ? `${geoRes.info.country} (${geoRes.info.asn || 'ASN N/A'})` : undefined,
    });
    sourcesChecked.push({
      name: 'RDAP Registry WHOIS',
      status: rdapRes.status,
      detail: rdapRes.rdap?.networkName || undefined,
    });
    sourcesChecked.push({
      name: 'Reverse DNS (PTR)',
      status: revRes.length > 0 ? 'ok' : 'not_found',
      detail: revRes[0],
    });

    const serverInfo: LiveServerInfo = geoRes.info
      ? { ...geoRes.info, reverseDns: revRes }
      : {
          primaryIp: indicator,
          reverseDns: revRes,
          country: rdapRes.rdap?.country || null,
          countryCode: rdapRes.rdap?.country || null,
          region: null,
          city: null,
          isp: null,
          org: rdapRes.rdap?.networkName || null,
          asn: null,
          isProxyOrVpn: null,
          isHosting: null,
          coordinates: null,
        };

    return {
      indicator,
      originalInput,
      indicatorType,
      serverInfo,
      dnsRecords: null,
      rdapInfo: rdapRes.rdap,
      tlsCertificate: null,
      hashTelemetry: null,
      sourcesChecked,
      collectedAt: new Date().toISOString(),
    };
  }

  if (indicatorType === 'domain') {
    const [dnsRecords, rdapRes, tlsCert] = await Promise.all([
      fetchDnsRecords(indicator),
      fetchRdapInfo('domain', indicator),
      fetchTlsCert(indicator),
    ]);

    sourcesChecked.push({
      name: 'Live DNS Resolver (A/AAAA/MX/NS/TXT)',
      status:
        dnsRecords.a.length || dnsRecords.mx.length || dnsRecords.ns.length || dnsRecords.txt.length
          ? 'ok'
          : 'not_found',
      detail: dnsRecords.a[0] || undefined,
    });
    sourcesChecked.push({
      name: 'Domain RDAP / WHOIS',
      status: rdapRes.status,
      detail: rdapRes.rdap?.registrar || undefined,
    });
    sourcesChecked.push({
      name: 'Live TLS/SSL Certificate Probe',
      status: tlsCert ? 'ok' : 'unavailable',
      detail: tlsCert?.issuerO || tlsCert?.issuerCN || undefined,
    });

    let serverInfo: LiveServerInfo | null = null;
    const targetIp = dnsRecords.a[0] || dnsRecords.aaaa[0];
    if (targetIp) {
      const [geoRes, revRes] = await Promise.all([
        fetchIpGeo(targetIp),
        dns.reverse(targetIp).catch(() => [] as string[]),
      ]);
      sourcesChecked.push({
        name: 'Resolved Server GeoIP & ASN',
        status: geoRes.sourceStatus,
        detail: geoRes.info?.country || undefined,
      });
      if (geoRes.info) {
        serverInfo = { ...geoRes.info, reverseDns: revRes };
      } else {
        serverInfo = {
          primaryIp: targetIp,
          reverseDns: revRes,
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
        };
      }
    }

    return {
      indicator,
      originalInput,
      indicatorType,
      serverInfo,
      dnsRecords,
      rdapInfo: rdapRes.rdap,
      tlsCertificate: tlsCert,
      hashTelemetry: null,
      sourcesChecked,
      collectedAt: new Date().toISOString(),
    };
  }

  // Cryptographic Hash lookup
  const algo = indicatorType.replace('hash_', '') as 'md5' | 'sha1' | 'sha256' | 'sha512';
  const { hashTelemetry, sources } = await fetchHashIntelligence(indicator, algo);
  sourcesChecked.push(...sources);

  return {
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

export function evaluateTelemetryHeuristically(telemetry: LiveNetworkTelemetry): {
  isMalicious: boolean;
  verdict: string;
  riskLevel: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض';
  threatScore: number;
  executiveSummary: string;
  infrastructureAnalysis: string;
  threatCategories: string[];
  osintFindings: string[];
  recommendations: string[];
} {
  const findings: string[] = [];
  const categories: string[] = [];
  let score = 10;
  let isMal = false;

  if (telemetry.hashTelemetry) {
    const ht = telemetry.hashTelemetry;
    if (ht.malwareBazaarFound) {
      score = 95;
      isMal = true;
      categories.push('Known Malware Sample', 'Abuse.ch MalwareBazaar');
      findings.push(`العينة مدرجة كبرمجية خبيثة في قاعدة بيانات MalwareBazaar (${ht.malwareSignature || 'عينة خطرة'}).`);
    } else if (ht.circlKnownClean) {
      score = 5;
      findings.push(`البصمة التشفيرية موثقة كبرمجية قياسية سليمة عبر مشروع CIRCL / NSRL.`);
      categories.push('Whitelisted Known Software');
    } else {
      score = 30;
      findings.push('البصمة غير مسجلة في قوائم البرمجيات المعروفة؛ يُوصى بفحص العينة بالتحليل الديناميكي.');
    }
  }

  if (telemetry.serverInfo) {
    const s = telemetry.serverInfo;
    if (s.isProxyOrVpn) {
      score = Math.max(score, 65);
      categories.push('Proxy / VPN Anonymizer');
      findings.push(`الخادم مصنف كوكيل إخفاء هوية أو شبكة VPN نشطة (${s.isp || 'خدمة مجهولة'}).`);
    }
    if (s.isHosting) {
      findings.push(`العنوان مستضاف داخل مركز بيانات (Hosting / Cloud Data Center): ${s.org || s.asn || ''}.`);
    }
    if (s.country) {
      findings.push(`الموقع الجغرافي المسجل: ${s.country} (${s.countryCode || ''}) • ASN: ${s.asn || 'غير محدد'}.`);
    }
    if (s.reverseDns && s.reverseDns.length > 0) {
      findings.push(`سجل PTR العكسي: ${s.reverseDns.join(', ')}.`);
    }
  }

  if (telemetry.dnsRecords) {
    const d = telemetry.dnsRecords;
    if (d.a.length > 0) findings.push(`عناوين IPv4 المرتبطة: ${d.a.slice(0, 4).join(', ')}.`);
    if (d.mx.length > 0) findings.push(`خوادم البريد MX: ${d.mx.slice(0, 3).map(m => m.exchange).join(', ')}.`);
    if (d.ns.length > 0) findings.push(`خوادم الأسماء NS: ${d.ns.slice(0, 3).join(', ')}.`);
  }

  if (telemetry.tlsCertificate) {
    findings.push(`شهادة SSL/TLS صادرة عن: ${telemetry.tlsCertificate.issuerO || telemetry.tlsCertificate.issuerCN || 'CA'}.`);
  }

  let riskLevel: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض' = 'منخفض';
  if (score >= 80) riskLevel = 'حرج';
  else if (score >= 60) riskLevel = 'مرتفع';
  else if (score >= 35) riskLevel = 'متوسط';

  const verdict = isMal
    ? 'مؤشر أمني عالي الخطورة (Threat IOC Detected)'
    : score >= 60
    ? 'مؤشر مشبوه يحتاج إلى مراقبة وتحقيق (Suspicious Target)'
    : 'مؤشر موثوق مع سجلات استضافة نظامية (Legitimate Target)';

  return {
    isMalicious: isMal,
    verdict,
    riskLevel,
    threatScore: score,
    executiveSummary: `تم إتمام الفحص المباشر عبر محرك Sovereign OSINT Daemon بنجاح. المؤشر (${telemetry.indicator}) يمتلك درجة خطورة تقديرية ${score}/100 بناءً على تحليل السجلات الشبكية والجغرافية وقواعد بيانات السمعة العالمية.`,
    infrastructureAnalysis: `البنية التحتية المستخرجة تشير إلى استضافة لدى (${telemetry.serverInfo?.org || telemetry.serverInfo?.isp || 'مزود خدمة معتمد'}) في (${telemetry.serverInfo?.country || 'منطقة غير محددة'}) مع سجلات DNS نشطة.`,
    threatCategories: categories.length > 0 ? categories : ['Standard Network Infrastructure'],
    osintFindings: findings,
    recommendations: isMal
      ? [
          'حظر عنوان المؤشر في جدار الحماية (Firewall) وأنظمة EDR فوراً.',
          'تحديث ملف التحقيق الجنائي النشط برقم الـ IP والبصمات المستخرجة.',
          'فحص سجلات المرور الشبكي (NetFlow / DNS Logs) للبحث عن أي اتصالات متزامنة.',
        ]
      : [
          'الاحتفاظ بسجلات الاستعلام في ملف القضية كمرجع استخباراتي.',
          'مراقبة أي تغييرات مستقبلية في سجلات DNS أو مزود الاستضافة.',
        ],
  };
}
