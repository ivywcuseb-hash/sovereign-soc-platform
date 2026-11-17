import React from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

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
          className="min-h-screen bg-[#070b14] text-slate-100 flex items-center justify-center p-6"
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
              onClick={() => window.location.reload()}
              className="w-full py-3 px-5 rounded-xl bg-[#D4AF37] text-[#030712] font-bold text-sm cursor-pointer"
            >
              إعادة تحميل النظام
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
