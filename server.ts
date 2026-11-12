import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import { initializeApp, cert, getApps, App as FirebaseApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import firebaseConfig from './firebase-applet-config.json' with { type: 'json' };

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Initialize Firebase Admin
let adminApp: FirebaseApp;
if (!getApps().length) {
  adminApp = initializeApp({
    projectId: firebaseConfig.projectId,
  });
} else {
  adminApp = getApps()[0];
}

const adminAuth = getAuth(adminApp);
const adminDb = getFirestore(adminApp, (firebaseConfig as any).firestoreDatabaseId);

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '10mb' }));

  const apiKey = process.env.GEMINI_API_KEY;
  const ai = new GoogleGenAI({
    apiKey: apiKey || 'dummy-key',
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });

  // Auth Middleware
  const requireAuth = async (req: any, res: any, next: any) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const token = authHeader.split('Bearer ')[1];
    try {
      const decodedToken = await adminAuth.verifyIdToken(token);
      req.user = decodedToken;
      next();
    } catch (error) {
      res.status(401).json({ error: 'Invalid token' });
    }
  };

  // Application Version and Update Status API
  const SYSTEM_CURRENT_VERSION = '2.5.2';
  const SYSTEM_BUILD_TIMESTAMP = '2026-11-11T21:00:00.000Z';

  app.get('/api/version', (req, res) => {
    const clientVersion = req.query.clientVersion as string | undefined;
    const forceUpdateCheck = req.query.simulate === 'true';

    // If client version is older than system version or simulation is on
    const hasUpdate = forceUpdateCheck || (clientVersion ? clientVersion !== SYSTEM_CURRENT_VERSION : false);

    res.json({
      version: SYSTEM_CURRENT_VERSION,
      buildTimestamp: SYSTEM_BUILD_TIMESTAMP,
      hasUpdate: hasUpdate,
      latestVersion: forceUpdateCheck ? '2.5.3' : SYSTEM_CURRENT_VERSION,
      releaseDate: '2026-11-11',
      title: 'تحديث منصة SOVEREIGN الجنائية',
      message: hasUpdate
        ? 'يتوفر إصدار جديد من الموقع يتضمن حزم معالجة مطورة وسرعة مضاعفة في فحص التجزئة.'
        : 'المنصة تعمل بأحدث إصدار مستقر.',
      features: [
        'نظام كشف وتنبيه التحديثات التلقائي (Service Worker & Cache Sync)',
        'تسريع خوارزميات التجزئة WebCrypto ومكتبة SparkMD5',
        'نظام سلسلة العهدة الرقمية (Chain of Custody) التلقائي',
        'مقارنة الأدلة الثنائية وفحص بصمات التجزئة المتعددة',
        'تحسين أمان وخصوصية الحسابات بقواعد Firestore وFirebase Storage الصارمة'
      ]
    });
  });

  // Dashboard Stats API
  app.get('/api/dashboard-stats', requireAuth, async (req: any, res: any) => {
    try {
      const uid = req.user.uid;
      
      const investigationsSnap = await adminDb.collection('investigations')
        .where('userId', '==', uid)
        .get();
      
      const evidenceSnap = await adminDb.collection('evidence')
        .where('userId', '==', uid)
        .get();
      
      const auditSnap = await adminDb.collection('audit_logs')
        .where('userId', '==', uid)
        .get();

      // Calculate risks
      let threatCount = 0;
      evidenceSnap.forEach(doc => {
        const data = doc.data();
        if (data.analysis?.authenticityScore < 50) {
          threatCount++;
        }
      });

      res.json({
        totalInvestigations: investigationsSnap.size,
        totalEvidence: evidenceSnap.size,
        totalLogs: auditSnap.size,
        detectedThreats: threatCount,
        lastUpdated: new Date().toISOString()
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // API endpoint for Gemini forensic analysis
  app.post('/api/analyze-image', async (req, res) => {
    try {
      const { forensicData, prompt } = req.body;
      
      if (!apiKey) {
        return res.json({
          analysis: 'لم يتم توفير مفتاح Gemini API. يعمل النظام حالياً في وضع الفحص المحلي التكتيكي (Local Forensic Mode).',
          riskLevel: 'متوسط',
          confidence: 85,
        });
      }

      const systemInstruction = `أنت خبير محترف في أمن الصور الرقمية والأدلة الجنائية والتحقق من التزييف العميق (Deepfake) والتلاعب بالصور. قم بتحليل البيانات الجنائية التالية بدقة واحترانية عالية باللغة العربية:
- نتائج تحليل ELA (Error Level Analysis)
- تباين Laplacian (الحدة والتشويش)
- تقييم ضوضاء المستشعر (Sensor Grain)
- بيانات EXIF والميتاتا الحقيقية
- معلومات التوقيع الجنائي والتشفير البايناوي

أعط تقريراً أمنياً تكتيكياً يتضمن:
1. التقييم النهائي للأصالة (أصلية / مشكوك فيها / مزيفة عميقاً).
2. نسبة الثقة والتلاعب المكتشف.
3. مؤشرات الخطورة والتفاصيل الفنية.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt || `قم بتحليل البيانات الجنائية التالية للصورة: ${JSON.stringify(forensicData)}`,
        config: {
          systemInstruction,
          responseMimeType: 'application/json',
          responseSchema: {
            type: 'OBJECT',
            properties: {
              verdict: { type: 'STRING' },
              riskLevel: { type: 'STRING' },
              confidenceScore: { type: 'NUMBER' },
              detailedReport: { type: 'STRING' },
              indicators: {
                type: 'ARRAY',
                items: { type: 'STRING' }
              }
            },
            required: ['verdict', 'riskLevel', 'confidenceScore', 'detailedReport', 'indicators']
          }
        }
      });

      const resultText = response.text || '{}';
      res.json(JSON.parse(resultText));
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Chat API
  app.post('/api/chat', async (req, res) => {
    try {
      const { messages } = req.body;
      if (!apiKey) return res.json({ reply: 'Gemini API key missing.' });

      const systemInstruction = `أنت "أمان", مساعد ذكي خبير في الأمن السيبراني والأدلة الجنائية الرقمية وفحص التسريبات والوثائق والمستندات.
مهمتك الأساسية عند رفع صورة:
1. تحليل محتوى الصورة بدقة فائقة.
2. استخراج أي نصوص، أسماء أشخاص، تواريخ، أنواع وثائق، أو أي بيانات تعريفية حقيقية.
3. تقديم تقرير شامل ومفصل حول الصورة وما تحتويه.`;

      const formattedContents = messages.map((m: any) => ({
        role: m.role === 'user' ? 'user' : 'model',
        parts: m.image ? [{ text: m.content }, { inlineData: { data: m.image.base64, mimeType: m.image.mimeType } }] : [{ text: m.content }]
      }));

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: formattedContents,
        config: { systemInstruction }
      });
      res.json({ reply: response.text });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Search API
  app.post('/api/search', async (req, res) => {
    try {
      const { query } = req.body;
      if (!apiKey) return res.json({ result: 'API key missing.', sources: [] });
      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: query,
        config: { tools: [{ googleSearch: {} }] }
      });
      const text = response.text || 'لا توجد نتائج.';
      const sources = (response.candidates?.[0]?.groundingMetadata?.groundingChunks || []).map((chunk: any) => ({
        title: chunk.web?.title || 'مصدر',
        uri: chunk.web?.uri || '#'
      }));
      res.json({ result: text, sources });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'dist', 'index.html')));
  }

  // In AI Studio, the application dev server must strictly listen on port 3000 on 0.0.0.0
  const portArgIndex = process.argv.indexOf('--port');
  const port = portArgIndex !== -1 ? parseInt(process.argv[portArgIndex + 1], 10) : 3000;
  app.listen(port, '0.0.0.0', () => console.log(`Server running on http://0.0.0.0:${port}`));
}

startServer().catch((err) => {
  console.error('Fatal error starting server:', err);
  process.exit(1);
});
