import React, { useState } from 'react';

interface ChatMessage {
  role: 'user' | 'model';
  content: string;
}

export const CybersecurityAssistantChat: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'model',
      content: 'أهلاً بك يا محققنا العريق. أنا "مساعد أمان الذكي" (Gemini 1.5 Pro). كيف يمكنني مساعدتك في التحقيقات الجنائية الرقمية، فحص الملفات، أو تحليل مؤشرات الاختراق اليوم؟'
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMessage = input.trim();
    setInput('');
    setErrorMsg(null);

    const newMessages: ChatMessage[] = [...messages, { role: 'user', content: userMessage }];
    setMessages(newMessages);
    setLoading(true);

    try {
      // API call to backend handler
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: newMessages })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'حدث خطأ أثناء معالجة الطلب');
      }

      setMessages([...newMessages, { role: 'model', content: data.reply }]);
    } catch (err: any) {
      console.error('Frontend Chat Error:', err);
      setErrorMsg(err.message || 'حدث خطأ في الاتصال بالخادم');
      setMessages([
        ...newMessages,
        {
          role: 'model',
          content: `عذراً، حدث خطأ أثناء الاتصال: ${err.message}. يرجى التحقق من إعدادات المفتاح والاتصال.`
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-6 bg-slate-900 text-slate-100 rounded-xl border border-slate-700 shadow-2xl">
      <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
        <h2 className="text-xl font-bold text-cyan-400 flex items-center gap-2">
          <span>🛡️</span> مساعد أمان الذكي (Gemini 1.5 Pro)
        </h2>
        <span className="text-xs bg-cyan-950 text-cyan-300 px-3 py-1 rounded-full border border-cyan-800">
          محرك التحقيق الجنائي النشط
        </span>
      </div>

      <div className="h-[450px] overflow-y-auto space-y-4 mb-4 pr-2">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`p-4 rounded-lg leading-relaxed ${
              m.role === 'user'
                ? 'bg-slate-800 ml-12 border border-slate-700 text-slate-200'
                : 'bg-cyan-950/40 mr-12 border border-cyan-900/60 text-cyan-100 shadow-inner'
            }`}
          >
            <div className="text-xs font-semibold mb-1 opacity-70">
              {m.role === 'user' ? 'محقق الأمن السيبراني' : 'مساعد أمان الذكي'}
            </div>
            <div className="whitespace-pre-wrap">{m.content}</div>
          </div>
        ))}
        {loading && (
          <div className="p-4 rounded-lg bg-cyan-950/20 mr-12 border border-cyan-900/40 text-cyan-300 animate-pulse flex items-center gap-2">
            <span>⏳</span> جاري تحليل الأدلة وسجلات النظام عبر نموذج Gemini 1.5 Pro...
          </div>
        )}
      </div>

      {errorMsg && (
        <div className="mb-4 p-3 bg-red-950/80 border border-red-700 text-red-200 rounded-lg text-sm">
          <strong>تنبيه خطأ:</strong> {errorMsg}
        </div>
      )}

      <form onSubmit={handleSend} className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="اكتب استفسارك الجنائي أو الأمني هنا..."
          className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 text-slate-100 focus:outline-none focus:border-cyan-500 transition"
        />
        <button
          type="submit"
          disabled={loading}
          className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white px-6 py-3 rounded-lg font-medium transition shadow-lg flex items-center gap-2"
        >
          <span>إرسال</span>
          <span>🚀</span>
        </button>
      </form>
    </div>
  );
};
