const BUILTIN_THREAT_FEEDS = [
  {
    id: 'cisa_kev',
    name: 'CISA Known Exploited Vulnerabilities (KEV)',
    provider: 'U.S. CISA',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    format: 'json',
    category: 'CVE / Vulnerability',
    description: 'الكتالوج الرسمي للثغرات الأمنية المستغلة فعلياً في الهجمات النشطة',
  },
  {
    id: 'feodo_c2',
    name: 'Abuse.ch Feodo Tracker Botnet C2',
    provider: 'Abuse.ch',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
    format: 'json',
    category: 'Botnet C2 IP',
    description: 'قائمة عناوين IP النشطة لخوادم التحكم والسيطرة (Botnet C2)',
  },
  {
    id: 'circl_cve',
    name: 'CIRCL Latest CVE & Advisories API',
    provider: 'CIRCL.lu',
    url: 'https://cve.circl.lu/api/last/15',
    format: 'json',
    category: 'CVE / Vulnerability',
    description: 'أحدث الثغرات الأمنية المنشورة عالمياً مع التوصيف والدرجات',
  },
  {
    id: 'cisa_advisories',
    name: 'CISA Cybersecurity Advisories RSS',
    provider: 'U.S. CISA',
    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    format: 'rss',
    category: 'Security Advisory',
    description: 'التنبيهات والتحذيرات السيبرانية الرسمية الصادرة عن وكالة CISA',
  },
  {
    id: 'sans_isc',
    name: 'SANS Internet Storm Center Diary RSS',
    provider: 'SANS ISC',
    url: 'https://isc.sans.edu/rssfeed_full.xml',
    format: 'rss',
    category: 'Threat Intel RSS',
    description: 'تقارير الرصد اليومي للحوادث والهجمات من مركز عواصف الإنترنت',
  },
  {
    id: 'hacker_news',
    name: 'The Hacker News Threat Feed RSS',
    provider: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    format: 'rss',
    category: 'Threat Intel RSS',
    description: 'تغذية الأخبار والتحليلات الأمنية الفورية لأحدث الثغرات والاختراقات',
  },
];

export default function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=300');
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }
  return res.status(200).json({ feeds: BUILTIN_THREAT_FEEDS });
}
