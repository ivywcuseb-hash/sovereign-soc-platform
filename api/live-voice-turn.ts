import { GoogleGenAI, Modality } from '@google/genai';

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === 'dummy-key') {
      return res.status(400).json({
        error: 'مفتاح Gemini API غير مهيأ في إعدادات الخادم (Settings > Secrets).',
      });
    }

    const bodyObj = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const audioBase64 = typeof bodyObj.audioBase64 === 'string' ? bodyObj.audioBase64 : '';
    const audioMimeType = typeof bodyObj.audioMimeType === 'string' ? bodyObj.audioMimeType : 'audio/webm';
    const textPrompt = typeof bodyObj.text === 'string' ? bodyObj.text.trim().slice(0, 2000) : '';
    const voiceName = ['Zephyr', 'Puck', 'Charon', 'Kore', 'Fenrir'].includes(bodyObj.voiceName)
      ? bodyObj.voiceName
      : 'Zephyr';
    const forensicContext = typeof bodyObj.forensicContext === 'string' ? bodyObj.forensicContext.slice(0, 2500) : '';

    if (!audioBase64 && !textPrompt) {
      return res.status(400).json({ error: 'يرجى إرسال مقطع صوتي أو رسالة نصية.' });
    }

    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    const systemInstruction = `أنت المساعد الصوتي الجنائي الذكي لمنصة SOVEREIGN FORENSIC ENGINE.
تتحدث العربية بطلاقة واحترافية (ويمكنك الرد بالإنجليزية إذا خاطبك المستخدم بها).
قدّم إجابات دقيقة، واضحة، وموجزة مناسبة للمحادثة الصوتية في مجالات التحقيق الجنائي الرقمي، الأمن السيبراني، تحليل البرمجيات الخبيثة، وثغرات CVE.
${forensicContext ? `ملخص سياق المنصة الحالي: ${forensicContext}` : ''}`;

    const parts: any[] = [];
    if (audioBase64) {
      parts.push({
        inlineData: {
          mimeType: audioMimeType,
          data: audioBase64,
        },
      });
    }
    parts.push({
      text: textPrompt || 'استمع إلى رسالة المستخدم الصوتية وأجب عليها مباشرة بوضوح وإيجاز.',
    });

    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: { parts },
      config: { systemInstruction },
    });

    const replyText = (response.text || '').trim();
    if (!replyText) {
      return res.status(502).json({ error: 'لم يُرجع النموذج استجابة نصية صالحة.' });
    }

    // Synthesize natural speech via Gemini TTS (24kHz PCM)
    let audioPcmBase64: string | null = null;
    try {
      const ttsResponse = await ai.models.generateContent({
        model: 'gemini-3.8-flash-lite-tts',
        contents: replyText,
        config: {
          responseModalities: [Modality.AUDIO],
          speechConfig: {
            voiceConfig: {
              prebuiltVoiceConfig: { voiceName },
            },
          },
        },
      });
      const audioPart = ttsResponse.candidates?.[0]?.content?.parts?.find((p: any) => p.inlineData?.data);
      if (audioPart?.inlineData?.data) {
        audioPcmBase64 = audioPart.inlineData.data;
      }
    } catch {
      // Return text reply gracefully even if TTS synthesis fails
    }

    return res.status(200).json({
      success: true,
      replyText,
      audioPcmBase64,
      sampleRate: 24000,
    });
  } catch (err: any) {
    return res.status(500).json({
      error: err?.message || 'تعذر معالجة جولة المحادثة الصوتية.',
    });
  }
}
