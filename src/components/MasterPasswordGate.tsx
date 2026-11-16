import React, { useEffect, useState } from 'react';
import { Shield, Lock, KeyRound, Eye, EyeOff, AlertTriangle } from 'lucide-react';
import {
  verifyMasterPasswordSha256,
  getPinLockoutRemainingSec,
  recordFailedPinAttempt,
  clearPinFailureCounter,
  reportClientSecurityEvent,
} from '../utils/clientSecurity';

interface MasterPasswordGateProps {
  onUnlock: () => void;
}

const GATE_LOCKOUT_SCOPE = 'master-gate';

export const MasterPasswordGate: React.FC<MasterPasswordGateProps> = ({ onUnlock }) => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lockoutSeconds, setLockoutSeconds] = useState<number>(() =>
    getPinLockoutRemainingSec(GATE_LOCKOUT_SCOPE)
  );

  useEffect(() => {
    if (lockoutSeconds <= 0) return;
    const timer = window.setInterval(() => {
      const remaining = getPinLockoutRemainingSec(GATE_LOCKOUT_SCOPE);
      setLockoutSeconds(remaining);
      if (remaining <= 0) {
        setErrorMessage(null);
      }
    }, 1000);
    return () => window.clearInterval(timer);
  }, [lockoutSeconds]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const remaining = getPinLockoutRemainingSec(GATE_LOCKOUT_SCOPE);
    if (remaining > 0) {
      setLockoutSeconds(remaining);
      setErrorMessage(`تم إيقاف المحاولات مؤقتاً لحماية النظام. يرجى الانتظار ${remaining} ثانية.`);
      return;
    }

    if (!password) {
      setErrorMessage('يرجى إدخال كلمة المرور الرئيسية للمتابعة.');
      return;
    }

    setIsVerifying(true);
    setErrorMessage(null);

    try {
      const isValid = await verifyMasterPasswordSha256(password);
      if (isValid) {
        clearPinFailureCounter(GATE_LOCKOUT_SCOPE);
        setPassword('');
        onUnlock();
        return;
      }

      const failState = recordFailedPinAttempt(GATE_LOCKOUT_SCOPE);
      if (failState.lockedSeconds > 0) {
        setLockoutSeconds(failState.lockedSeconds);
        setErrorMessage(
          `تم تجاوز الحد المسموح للمحاولات (${failState.failedAttempts}). تم قفل البوابة مؤقتاً لمدة ${failState.lockedSeconds} ثانية.`
        );
        void reportClientSecurityEvent({
          eventType: 'AUTH_FAILURE',
          detail: `Master Password Gate cooldown activated after ${failState.failedAttempts} failed attempts`,
        });
      } else {
        setErrorMessage('كلمة المرور غير صحيحة. تم رفض الدخول إلى النظام.');
      }
      setPassword('');
    } catch {
      setErrorMessage('تعذر التحقق التشفيري في المتصفح. تأكد من دعم WebCrypto SHA-256.');
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div
      dir="rtl"
      className="fixed inset-0 z-[200] min-h-screen w-full overflow-y-auto bg-[#070b14] text-slate-100 flex flex-col justify-center items-center px-4 py-8 selection:bg-[#D4AF37]/30 selection:text-white"
    >
      {/* Subtle Sovereign Cyber/Forensic Atmospheric Background */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-0 overflow-hidden"
      >
        <div className="absolute -top-40 right-1/4 w-[420px] h-[420px] rounded-full bg-[#D4AF37]/8 blur-[120px]" />
        <div className="absolute -bottom-40 left-1/4 w-[420px] h-[420px] rounded-full bg-[#10B981]/6 blur-[120px]" />
        <div
          className="absolute inset-0 opacity-[0.035]"
          style={{
            backgroundImage:
              'linear-gradient(to right, #D4AF37 1px, transparent 1px), linear-gradient(to bottom, #D4AF37 1px, transparent 1px)',
            backgroundSize: '48px 48px',
          }}
        />
      </div>

      <main className="relative w-full max-w-md bg-[#0b0f19]/95 border border-gray-800 rounded-2xl shadow-2xl shadow-black/70 overflow-hidden">
        <div className="h-1 w-full bg-gradient-to-r from-[#D4AF37]/40 via-[#D4AF37] to-[#10B981]/70" />

        <div className="p-7 sm:p-9 space-y-7">
          {/* Sovereign Brand Header */}
          <div className="text-center space-y-3">
            <div className="w-16 h-16 mx-auto rounded-xl bg-gradient-to-br from-[#D4AF37] to-[#10B981] flex items-center justify-center shadow-lg shadow-[#D4AF37]/20">
              <Shield className="w-8 h-8 text-[#030712]" strokeWidth={2.2} />
            </div>

            <div className="space-y-1.5">
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
                SOVEREIGN FORENSIC ENGINE
              </h1>
              <p className="text-sm font-semibold text-[#D4AF37]">
                شاشة القفل السيادية الرئيسية
              </p>
              <p className="text-xs text-slate-400 leading-relaxed max-w-sm mx-auto">
                الوصول إلى منصة التحقيق الجنائي والأدلة الرقمية مقيد. أدخل كلمة المرور الرئيسية للمتابعة.
              </p>
            </div>
          </div>

          <div className="border-t border-gray-800/80" />

          {/* Master Password Form */}
          <form onSubmit={handleSubmit} className="space-y-5" noValidate>
            <div className="space-y-2">
              <label
                htmlFor="master-password-input"
                className="flex items-center justify-between text-xs font-bold text-slate-300"
              >
                <span className="flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5 text-[#D4AF37]" />
                  كلمة المرور الرئيسية
                </span>
                <span className="text-[11px] font-mono text-slate-500">SHA-256</span>
              </label>

              <div className="relative">
                <input
                  id="master-password-input"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  placeholder="أدخل كلمة المرور..."
                  autoComplete="current-password"
                  autoFocus
                  disabled={isVerifying || lockoutSeconds > 0}
                  className="w-full min-h-[48px] px-4 pl-12 bg-[#030712] border border-gray-800 hover:border-gray-700 focus:border-[#D4AF37] focus:ring-2 focus:ring-[#D4AF37]/25 rounded-xl text-sm text-white placeholder:text-slate-600 outline-none transition disabled:opacity-50"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور'}
                  className="absolute inset-y-0 left-0 px-3.5 flex items-center justify-center text-slate-400 hover:text-[#D4AF37] transition cursor-pointer focus-visible:outline-none focus-visible:text-[#D4AF37]"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {errorMessage && (
              <div
                role="alert"
                className="flex items-start gap-2.5 p-3.5 rounded-xl bg-red-950/50 border border-red-500/40 text-xs text-red-200 leading-relaxed"
              >
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{errorMessage}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={isVerifying || lockoutSeconds > 0}
              className="w-full min-h-[48px] px-6 py-3 bg-[#D4AF37] hover:bg-[#c59f2c] active:bg-[#b59125] text-[#030712] font-bold text-sm rounded-xl shadow-lg shadow-[#D4AF37]/15 transition flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#D4AF37] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0b0f19]"
            >
              <Lock className="w-4 h-4" />
              <span>
                {isVerifying
                  ? 'جاري التحقق من التشفير...'
                  : lockoutSeconds > 0
                  ? `الانتظار (${lockoutSeconds}ث)`
                  : 'فتح النظام'}
              </span>
            </button>
          </form>

          {/* Session Boundary Notice */}
          <div className="pt-2 border-t border-gray-800/80 text-center">
            <p className="text-[11px] text-slate-500 leading-relaxed">
              تبقى الجلسة مفتوحة خلال فتح هذا التبويب فقط، ويُعاد قفل النظام تلقائياً فور إغلاق المتصفح أو التطبيق.
            </p>
          </div>
        </div>
      </main>
    </div>
  );
};
