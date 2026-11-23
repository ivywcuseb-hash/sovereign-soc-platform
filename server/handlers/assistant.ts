export async function siteAssistantHandler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });
  const { prompt } = req.body || {};
  return res.json({
    reply: `أهلاً بك! لقد استلمت استفسارك "${prompt || ''}". المنصة تعمل بكامل فعاليتها الجنائية والأمنية.`,
    suggestedActions: ['فحص بصمة', 'تحقيق رقمي', 'فحص سجل التصفح'],
    sources: [],
    timestamp: new Date().toISOString(),
  });
}

export async function liveVoiceTurnHandler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });
  const { text } = req.body || {};
  return res.json({
    ok: true,
    response: `مرحباً بك، المساعد الصوتي يستجيب لرسالتك: "${text || 'أهلاً'}". النظام جاهز للتحقيق الرقمي.`,
    audioBase64: null,
    timestamp: new Date().toISOString(),
  });
}
