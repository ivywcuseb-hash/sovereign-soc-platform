import React from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

// Auto-unregister stale service workers and clear caches if chunk load error occurs
if (typeof window !== 'undefined' && 'serviceWorker' in navigator) {
  window.addEventListener('error', (event) => {
    const msg = event?.message || '';
    if (msg.includes('Failed to fetch dynamically imported module') || msg.includes('Importing a module script failed') || msg.includes('Loading chunk')) {
      navigator.serviceWorker.getRegistrations().then((registrations) => {
        for (const reg of registrations) {
          reg.unregister();
        }
      });
      if (typeof caches !== 'undefined') {
        caches.keys().then((keys) => {
          for (const key of keys) {
            caches.delete(key);
          }
        });
      }
      // Reload once to fetch fresh assets
      if (!sessionStorage.getItem('sov_reloaded_for_update')) {
        sessionStorage.setItem('sov_reloaded_for_update', '1');
        window.location.reload();
      }
    }
  });
}

interface ErrorBoundaryState {
  hasError: boolean;
  message: string;
}

class SovereignErrorBoundary extends React.Component<
  {children: React.ReactNode},
  ErrorBoundaryState
> {
  constructor(props: {children: React.ReactNode}) {
    super(props);
    this.state = {hasError: false, message: ''};
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      message: error?.message || 'حدث خطأ غير متوقع أثناء تحميل الواجهة.',
    };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          dir="rtl"
          className="min-h-screen bg-[#070b14] text-slate-100 flex items-center justify-center p-6 selection:bg-[#D4AF37]/30 selection:text-white"
        >
          <div className="max-w-md w-full bg-[#0b0f19] border border-gray-800 rounded-2xl p-6 text-center space-y-4 shadow-2xl">
            <h1 className="text-lg font-bold text-[#D4AF37]">
              تعذر عرض واجهة النظام
            </h1>
            <p className="text-xs text-slate-300 leading-relaxed break-words">
              {this.state.message}
            </p>
            <button
              type="button"
              onClick={() => {
                if (typeof caches !== 'undefined') {
                  caches.keys().then((keys) => keys.forEach((k) => caches.delete(k)));
                }
                if ('serviceWorker' in navigator) {
                  navigator.serviceWorker.getRegistrations().then((regs) => regs.forEach((r) => r.unregister()));
                }
                window.location.reload();
              }}
              className="w-full py-3 px-5 rounded-xl bg-[#D4AF37] text-[#030712] font-bold text-sm cursor-pointer hover:bg-[#c29f30] transition"
            >
              إعادة تحميل وتحديث النظام
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById('root')!).render(
  <SovereignErrorBoundary>
    <App />
  </SovereignErrorBoundary>
);
