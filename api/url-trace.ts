import dns from 'node:dns/promises';
import net from 'node:net';

function isPrivateOrReservedIp(ip: string): boolean {
  if (!ip) return true;
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) {
      return true;
    }
    if (lower.startsWith('::ffff:')) {
      return isPrivateOrReservedIp(lower.replace('::ffff:', ''));
    }
    return false;
  }
  return true;
}

async function resolvePublicIp(hostname: string): Promise<string> {
  const cleanHost = hostname.replace(/^\[|\]$/g, '');
  if (cleanHost === 'localhost' || cleanHost.endsWith('.local') || cleanHost.endsWith('.internal')) {
    throw new Error(`تم حظر النطاق المحلي (${cleanHost}) لأغراض الحماية من SSRF.`);
  }
  if (net.isIP(cleanHost)) {
    if (isPrivateOrReservedIp(cleanHost)) {
      throw new Error(`تم حظر عنوان IP الداخلي (${cleanHost}) لأغراض الحماية الأمنية.`);
    }
    return cleanHost;
  }
  const lookedUp = await dns.lookup(cleanHost, { all: true });
  if (!lookedUp || lookedUp.length === 0) {
    throw new Error(`تعذر حل النطاق ${cleanHost} عبر DNS.`);
  }
  for (const rec of lookedUp) {
    if (isPrivateOrReservedIp(rec.address)) {
      throw new Error(`تم حظر الوصول لأن النطاق ${cleanHost} يشير إلى عنوان داخلي (${rec.address}).`);
    }
  }
  return lookedUp[0].address;
}

function extractHtmlRedirect(html: string, baseUrl: string): { target: string; type: string } | null {
  const metaMatch =
    html.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url=([^"'>\s]+)["']/i) ||
    html.match(/<meta[^>]+content=["'][^"']*url=([^"'>\s]+)["'][^>]+http-equiv=["']?refresh["']?/i);
  if (metaMatch && metaMatch[1]) {
    try {
      const cleaned = metaMatch[1].replace(/['"]/g, '').trim();
      return {
        target: new URL(cleaned, baseUrl).toString(),
        type: 'HTML Meta-Refresh',
      };
    } catch {
      // ignore invalid meta url
    }
  }

  const jsMatch =
    html.match(/window\.location(?:\.href)?\s*=\s*["'](https?:\/\/[^"']+)["']/i) ||
    html.match(/location\.replace\(\s*["'](https?:\/\/[^"']+)["']\s*\)/i);
  if (jsMatch && jsMatch[1]) {
    try {
      return {
        target: new URL(jsMatch[1], baseUrl).toString(),
        type: 'JavaScript Redirect',
      };
    } catch {
      // ignore
    }
  }
  return null;
}

const KNOWN_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rb.gy',
  'cutt.ly',
  'rebrand.ly',
  'shorturl.at',
  'tiny.cc',
  'lnkd.in',
  'youtu.be',
  'clk.sh',
  's.id',
]);

const TRACKING_PARAM_NAMES = new Set([
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'fbclid',
  'gclid',
  'mc_cid',
  'mc_eid',
  'ref',
  'si',
]);

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const bodyObj = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    let inputUrl = String(bodyObj.url || '').trim();
    if (!inputUrl || inputUrl.length > 2048) {
      return res.status(400).json({ error: 'يرجى إدخال رابط URL صالح للفحص والتتبع.' });
    }
    if (!/^https?:\/\//i.test(inputUrl)) {
      inputUrl = `https://${inputUrl}`;
    }

    let currentParsed: URL;
    try {
      currentParsed = new URL(inputUrl);
    } catch {
      return res.status(400).json({ error: 'صيغة الرابط المدخل غير صحيحة.' });
    }
    if (currentParsed.protocol !== 'http:' && currentParsed.protocol !== 'https:') {
      return res.status(400).json({ error: 'يُسمح فقط بتتبع روابط HTTP و HTTPS.' });
    }

    const hops: any[] = [];
    const visited = new Set<string>();
    const MAX_HOPS = 15;
    let currentUrl = currentParsed.toString();
    let finalIp = '';
    let loopDetected = false;

    for (let step = 1; step <= MAX_HOPS; step++) {
      if (visited.has(currentUrl)) {
        loopDetected = true;
        break;
      }
      visited.add(currentUrl);

      const parsed = new URL(currentUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        break;
      }

      const resolvedIp = await resolvePublicIp(parsed.hostname);
      finalIp = resolvedIp;

      const t0 = Date.now();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 6000);

      let response: Response;
      try {
        response = await fetch(currentUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; SovereignForensicTracer/2.5; +https://sovqs.vercel.app)',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          },
        });
      } finally {
        clearTimeout(timer);
      }

      const latencyMs = Date.now() - t0;
      const status = response.status;
      const locationHeader = response.headers.get('location');
      const serverHeader = response.headers.get('server') || response.headers.get('via') || '—';
      const contentType = response.headers.get('content-type') || '';

      let nextUrl: string | null = null;
      let redirectType = 'Final Destination';

      if (status >= 300 && status < 400 && locationHeader) {
        try {
          nextUrl = new URL(locationHeader, currentUrl).toString();
          redirectType = `HTTP ${status} Redirect`;
        } catch {
          nextUrl = null;
        }
      } else if (status >= 200 && status < 300 && /html/i.test(contentType)) {
        try {
          const textChunk = (await response.text()).slice(0, 48000);
          const embedded = extractHtmlRedirect(textChunk, currentUrl);
          if (embedded) {
            nextUrl = embedded.target;
            redirectType = embedded.type;
          }
        } catch {
          // ignore body read error
        }
      } else {
        try {
          await response.body?.cancel();
        } catch {
          // ignore
        }
      }

      const prevHop = hops[hops.length - 1];
      const httpsDowngrade = Boolean(prevHop && prevHop.protocol === 'https:' && parsed.protocol === 'http:');

      hops.push({
        step,
        url: currentUrl,
        hostname: parsed.hostname.toLowerCase(),
        resolvedIp,
        protocol: parsed.protocol,
        status,
        statusText: response.statusText || '',
        redirectType,
        locationHeader: locationHeader || nextUrl || null,
        serverHeader,
        latencyMs,
        httpsDowngrade,
      });

      if (!nextUrl) break;
      currentUrl = nextUrl;
    }

    if (hops.length === 0) {
      return res.status(400).json({ error: 'تعذر الوصول إلى الرابط أو تحليل المسار.' });
    }

    const firstHop = hops[0];
    const lastHop = hops[hops.length - 1];
    const finalParsed = new URL(lastHop.url);
    const trackingParams: string[] = [];
    finalParsed.searchParams.forEach((_val, key) => {
      if (TRACKING_PARAM_NAMES.has(key.toLowerCase())) {
        trackingParams.push(key);
      }
    });

    const redirectCount = Math.max(0, hops.length - 1);
    const changedDomain = firstHop.hostname !== lastHop.hostname;
    const shortenerDetected = hops.some((h) => KNOWN_SHORTENERS.has(h.hostname));
    const hasHttpsDowngrade = hops.some((h) => h.httpsDowngrade) || finalParsed.protocol === 'http:';
    const isIpLiteralFinal = net.isIP(finalParsed.hostname) !== 0;

    return res.status(200).json({
      success: true,
      trace: {
        initialUrl: firstHop.url,
        finalUrl: lastHop.url,
        initialDomain: firstHop.hostname,
        finalDomain: finalParsed.hostname.toLowerCase(),
        finalIp,
        finalProtocol: finalParsed.protocol.replace(':', '').toUpperCase(),
        finalStatus: lastHop.status,
        redirectCount,
        totalHops: hops.length,
        changedDomain,
        shortenerDetected,
        hasHttpsDowngrade,
        isIpLiteralFinal,
        loopDetected,
        trackingParams,
        totalLatencyMs: hops.reduce((acc, h) => acc + (h.latencyMs || 0), 0),
        hops,
        tracedAt: new Date().toISOString(),
      },
    });
  } catch (err: any) {
    return res.status(400).json({
      error: err?.message || 'تعذر تتبع الرابط أو فحص التحويلات.',
    });
  }
}
