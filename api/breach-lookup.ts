import crypto from 'node:crypto';

async function fetchJsonWithTimeout(url: string, options?: RequestInit, timeoutMs = 6000): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'SovereignForensicEngine/2.5.2 (BreachLookup)',
        ...(options?.headers || {}),
      },
    });
    const text = await res.text();
    if (!text.trim()) return { status: res.status, data: null };
    try {
      return { status: res.status, data: JSON.parse(text) };
    } catch {
      return { status: res.status, data: null, raw: text };
    }
  } finally {
    clearTimeout(timer);
  }
}

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const bodyObj = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const query = String(bodyObj.query || '').trim().slice(0, 160);
    const mode = String(bodyObj.mode || 'auto');

    if (!query) {
      return res.status(400).json({ error: 'يرجى إدخال بريد إلكتروني أو اسم مستخدم للفحص.' });
    }

    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(query);

    if (isEmail || mode === 'email') {
      const email = query.toLowerCase();
      const domain = email.split('@')[1] || '';

      const [xonBasic, xonAnalytics, mxDns, gravatarCheck] = await Promise.all([
        fetchJsonWithTimeout(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`),
        fetchJsonWithTimeout(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`),
        domain
          ? fetchJsonWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`)
          : Promise.resolve({ status: 200, data: null }),
        fetch(
          `https://www.gravatar.com/avatar/${crypto.createHash('md5').update(email).digest('hex')}?d=404`,
          { method: 'HEAD', signal: AbortSignal.timeout(4000) }
        )
          .then((r) => r.ok)
          .catch(() => false),
      ]);

      const rawBreaches: string[] = [];
      if (Array.isArray(xonBasic?.data?.breaches?.[0])) {
        rawBreaches.push(...xonBasic.data.breaches[0].map(String));
      } else if (Array.isArray(xonBasic?.data?.breaches)) {
        rawBreaches.push(...xonBasic.data.breaches.flat().map(String));
      }

      const exposedDetails: Array<{
        breach: string;
        domain: string;
        breachDate: string;
        exposedData: string;
        recordsCount: string;
        industry: string;
        passwordRisk: string;
      }> = [];

      const analyticsBreaches = xonAnalytics?.data?.ExposedBreaches?.breaches_details;
      if (Array.isArray(analyticsBreaches)) {
        for (const b of analyticsBreaches) {
          exposedDetails.push({
            breach: String(b.breach || 'Unknown Breach'),
            domain: String(b.domain || '—'),
            breachDate: String(b.xposed_date || '—'),
            exposedData: String(b.xposed_data || 'Email'),
            recordsCount: b.xposed_records ? Number(b.xposed_records).toLocaleString('en-US') : '—',
            industry: String(b.industry || '—'),
            passwordRisk: String(b.password_risk || 'unknown'),
          });
        }
      }

      for (const name of rawBreaches) {
        if (!exposedDetails.some((d) => d.breach.toLowerCase() === name.toLowerCase())) {
          exposedDetails.push({
            breach: name,
            domain: '—',
            breachDate: '—',
            exposedData: 'Email / Credentials',
            recordsCount: '—',
            industry: '—',
            passwordRisk: 'unknown',
          });
        }
      }

      const mxAnswers = Array.isArray(mxDns?.data?.Answer) ? mxDns.data.Answer : [];
      const mxServers = mxAnswers.map((a: any) => String(a.data)).filter(Boolean);

      return res.status(200).json({
        success: true,
        queryType: 'email',
        target: email,
        breached: exposedDetails.length > 0,
        breachCount: exposedDetails.length,
        breaches: exposedDetails,
        riskSummary: xonAnalytics?.data?.BreachMetrics?.risk?.[0] || null,
        gravatarExposed: Boolean(gravatarCheck),
        domainMxActive: mxServers.length > 0,
        mxServers: mxServers.slice(0, 5),
        sources: ['XposedOrNot Breach Database', 'Google DNS-over-HTTPS', 'Gravatar Public Identity'],
        checkedAt: new Date().toISOString(),
      });
    }

    // Username public OSINT & breach exposure probe
    const username = query.replace(/^@/, '');
    const [githubRes, npmRes] = await Promise.all([
      fetchJsonWithTimeout(`https://api.github.com/users/${encodeURIComponent(username)}`),
      fetchJsonWithTimeout(`https://registry.npmjs.org/-/v1/search?text=maintainer:${encodeURIComponent(username)}&size=3`),
    ]);

    const platforms: Array<{ platform: string; found: boolean; url: string; detail: string }> = [];
    if (githubRes?.status === 200 && githubRes?.data?.login) {
      platforms.push({
        platform: 'GitHub',
        found: true,
        url: String(githubRes.data.html_url),
        detail: `${githubRes.data.name || githubRes.data.login} • Public Repos: ${githubRes.data.public_repos ?? 0}`,
      });
    } else {
      platforms.push({ platform: 'GitHub', found: false, url: '', detail: 'غير مسجل أو خاص' });
    }

    const npmHits = Array.isArray(npmRes?.data?.objects) ? npmRes.data.objects.length : 0;
    platforms.push({
      platform: 'npm Registry',
      found: npmHits > 0,
      url: npmHits > 0 ? `https://www.npmjs.com/~${encodeURIComponent(username)}` : '',
      detail: npmHits > 0 ? `تم العثور على ${npmHits} حزم عامة مرتبطة بالمعرف` : 'لا توجد حزم منشورة',
    });

    return res.status(200).json({
      success: true,
      queryType: 'username',
      target: username,
      breached: false,
      breachCount: 0,
      breaches: [],
      usernameExposures: platforms,
      sources: ['GitHub Public Users API', 'npm Registry Maintainer Search'],
      checkedAt: new Date().toISOString(),
    });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'تعذر إتمام فحص التسريبات.' });
  }
}
