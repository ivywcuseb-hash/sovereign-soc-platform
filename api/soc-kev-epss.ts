async function fetchJsonTimeout(url: string, timeoutMs = 8000): Promise<{ ok: boolean; status: number; data: any }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'SovereignForensicEngine/2.5.2 (SOC-KEV-EPSS)',
      },
    });
    const text = await res.text();
    if (!text.trim()) return { ok: res.ok, status: res.status, data: null };
    return { ok: res.ok, status: res.status, data: JSON.parse(text) };
  } catch {
    return { ok: false, status: 0, data: null };
  } finally {
    clearTimeout(timer);
  }
}

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'GET' && req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const bodyObj =
      req.method === 'POST'
        ? typeof req.body === 'string'
          ? JSON.parse(req.body || '{}')
          : req.body || {}
        : req.query || {};

    const specificCve = String(bodyObj.cve || '').trim().toUpperCase();

    // Direct single-CVE lookup mode (CIRCL CVE + FIRST EPSS)
    if (/^CVE-\d{4}-\d{4,}$/.test(specificCve)) {
      const [circlRes, epssRes] = await Promise.all([
        fetchJsonTimeout(`https://cve.circl.lu/api/cve/${encodeURIComponent(specificCve)}`),
        fetchJsonTimeout(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(specificCve)}`),
      ]);
      const epssRow = Array.isArray(epssRes.data?.data) ? epssRes.data.data[0] : null;
      const cvss = circlRes.data?.cvss ?? circlRes.data?.cvss3 ?? null;
      return res.status(200).json({
        success: true,
        mode: 'single',
        cveDetail: {
          cveId: specificCve,
          summary: circlRes.data?.summary || 'لم يتم العثور على وصف موسع في CIRCL، تم جلب بيانات EPSS الحية.',
          cvss: typeof cvss === 'number' ? cvss : null,
          published: circlRes.data?.Published || null,
          modified: circlRes.data?.Modified || null,
          cwe: circlRes.data?.cwe || null,
          references: Array.isArray(circlRes.data?.references) ? circlRes.data.references.slice(0, 8) : [],
          epss: epssRow ? Number.parseFloat(epssRow.epss) : null,
          percentile: epssRow ? Number.parseFloat(epssRow.percentile) : null,
          epssDate: epssRow?.date || null,
        },
      });
    }

    // Full CISA KEV + FIRST EPSS live aggregation
    const kevRes = await fetchJsonTimeout(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      9000
    );

    const rawCatalog = kevRes.data;
    const allVulns: any[] = Array.isArray(rawCatalog?.vulnerabilities) ? rawCatalog.vulnerabilities : [];
    if (!allVulns.length) {
      return res.status(502).json({
        error: 'تعذر جلب كتالوج الثغرات المستغلة (CISA KEV) في الوقت الحالي.',
      });
    }

    // Sort newest by dateAdded descending and take top 45 for EPSS enrichment
    const sorted = [...allVulns].sort((a, b) =>
      String(b.dateAdded || '').localeCompare(String(a.dateAdded || ''))
    );
    const recentSlice = sorted.slice(0, 45);
    const cveIds = recentSlice.map((v) => String(v.cveID)).filter(Boolean);

    // Query FIRST.org EPSS batch API for those exact real CVEs
    const epssRes = cveIds.length
      ? await fetchJsonTimeout(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveIds.join(','))}`, 8000)
      : { ok: false, status: 0, data: null };

    const epssMap = new Map<string, { epss: number; percentile: number; date: string }>();
    if (Array.isArray(epssRes.data?.data)) {
      for (const row of epssRes.data.data) {
        if (row?.cve) {
          epssMap.set(String(row.cve).toUpperCase(), {
            epss: Number.parseFloat(row.epss || '0') || 0,
            percentile: Number.parseFloat(row.percentile || '0') || 0,
            date: String(row.date || ''),
          });
        }
      }
    }

    // Global CISA KEV Statistics across ALL entries
    let totalRansomware = 0;
    const vendorCounts = new Map<string, number>();
    const recent30Cutoff = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    let addedLast30Days = 0;

    for (const v of allVulns) {
      if (String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known') {
        totalRansomware++;
      }
      if (String(v.dateAdded || '') >= recent30Cutoff) {
        addedLast30Days++;
      }
      const vendor = String(v.vendorProject || 'Unknown').trim();
      vendorCounts.set(vendor, (vendorCounts.get(vendor) || 0) + 1);
    }

    const topVendors = Array.from(vendorCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([vendor, count]) => ({ vendor, count }));

    // Enrich recent 45 CVEs with live EPSS & compute real EPSS distribution
    const items = recentSlice.map((v) => {
      const cveId = String(v.cveID || '').toUpperCase();
      const epssInfo = epssMap.get(cveId);
      const epssPct = epssInfo ? Number((epssInfo.epss * 100).toFixed(2)) : null;
      const percentilePct = epssInfo ? Number((epssInfo.percentile * 100).toFixed(1)) : null;
      const isRansomware = String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known';

      let priority: 'critical' | 'high' | 'medium' | 'low' = 'medium';
      if (isRansomware || (epssPct !== null && epssPct >= 70)) priority = 'critical';
      else if (epssPct !== null && epssPct >= 35) priority = 'high';
      else if (epssPct !== null && epssPct < 10) priority = 'low';

      return {
        cveId,
        vendorProject: String(v.vendorProject || '—'),
        product: String(v.product || '—'),
        vulnerabilityName: String(v.vulnerabilityName || ''),
        shortDescription: String(v.shortDescription || ''),
        dateAdded: String(v.dateAdded || ''),
        dueDate: String(v.dueDate || ''),
        requiredAction: String(v.requiredAction || ''),
        knownRansomware: isRansomware,
        cwes: Array.isArray(v.cwes) ? v.cwes : [],
        epssPct,
        percentilePct,
        priority,
      };
    });

    // Compute real EPSS distribution buckets from fetched items
    const epssBuckets = {
      critical70Plus: items.filter((i) => (i.epssPct ?? 0) >= 70).length,
      high40To69: items.filter((i) => (i.epssPct ?? 0) >= 40 && (i.epssPct ?? 0) < 70).length,
      medium10To39: items.filter((i) => (i.epssPct ?? 0) >= 10 && (i.epssPct ?? 0) < 40).length,
      lowUnder10: items.filter((i) => i.epssPct !== null && i.epssPct < 10).length,
    };

    const avgEpssPct = items.filter((i) => i.epssPct !== null).length
      ? Number(
          (
            items.reduce((sum, i) => sum + (i.epssPct ?? 0), 0) /
            items.filter((i) => i.epssPct !== null).length
          ).toFixed(2)
        )
      : 0;

    return res.status(200).json({
      success: true,
      mode: 'catalog',
      catalogVersion: rawCatalog.catalogVersion || '',
      dateReleased: rawCatalog.dateReleased || '',
      summary: {
        totalKevCount: allVulns.length,
        totalRansomware,
        addedLast30Days,
        enrichedCount: items.length,
        epssCoverageCount: epssMap.size,
        avgEpssPct,
        epssBuckets,
        topVendors,
      },
      items,
      fetchedAt: new Date().toISOString(),
    });
  } catch (err: any) {
    return res.status(500).json({
      error: err?.message || 'حدث خطأ أثناء جلب بيانات الثغرات و EPSS.',
    });
  }
}
