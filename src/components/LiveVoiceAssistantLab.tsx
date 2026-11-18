import React, { useEffect, useRef, useState } from 'react';
import {
  AudioLines,
  Mic,
  MicOff,
  PhoneCall,
  PhoneOff,
  Send,
  Volume2,
  ShieldCheck,
  Sparkles,
  Trash2,
  Activity,
  Radio,
  AlertTriangle,
  Wifi,
} from 'lucide-react';
import { apiUrl, safeReadJsonResponse } from '../utils/apiBase';

export type LiveVoiceName = 'Zephyr' | 'Puck' | 'Charon' | 'Kore' | 'Fenrir';

interface VoiceOption {
  id: LiveVoiceName;
  label: string;
  tone: string;
}

const VOICE_OPTIONS: VoiceOption[] = [
  { id: 'Zephyr', label: 'Zephyr — زيفير', tone: 'واضح ومتزن (قياسي)' },
  { id: 'Kore', label: 'Kore — كوري', tone: 'هادئ واحترافي' },
  { id: 'Puck', label: 'Puck — باك', tone: 'حيوي وسريع الاستجابة' },
  { id: 'Charon', label: 'Charon — شارون', tone: 'عميق وتحليلي (SOC)' },
  { id: 'Fenrir', label: 'Fenrir — فنرير', tone: 'حازم ومباشر' },
];

export interface VoiceTranscriptEntry {
  id: string;
  role: 'user' | 'assistant' | 'system';
  text: string;
  timestamp: string;
  partial?: boolean;
}

interface LiveVoiceAssistantLabProps {
  forensicSummaryContext: string;
  onNotify: (msg: string, type?: 'success' | 'error' | 'warning') => void;
  onRecordAudit: (payload: {
    id: string;
    fileName: string;
    fileSize: string;
    verdict: string;
    score: number;
    risk: string;
    sha256: string;
  }) => void;
}

function encodeInt16PcmToBase64(float32: Float32Array): string {
  const int16 = new Int16Array(float32.length);
  for (let i = 0; i < float32.length; i++) {
    const s = Math.max(-1, Math.min(1, float32[i]));
    int16[i] = s < 0 ? s * 0x8000 : s * 0x7fff;
  }
  const bytes = new Uint8Array(int16.buffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function decodeBase64Pcm24k(base64: string): Float32Array<ArrayBuffer> {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  const sampleCount = Math.floor(bytes.byteLength / 2);
  const view = new DataView(bytes.buffer, bytes.byteOffset, sampleCount * 2);
  const outBuf = new ArrayBuffer(sampleCount * 4);
  const float32 = new Float32Array(outBuf);
  for (let i = 0; i < sampleCount; i++) {
    float32[i] = view.getInt16(i * 2, true) / 32768;
  }
  return float32;
}

export const LiveVoiceAssistantLab: React.FC<LiveVoiceAssistantLabProps> = ({
  forensicSummaryContext,
  onNotify,
  onRecordAudit,
}) => {
  const [connectionState, setConnectionState] = useState<
    'idle' | 'connecting' | 'live' | 'fallback_ptt' | 'error'
  >('idle');
  const [selectedVoice, setSelectedVoice] = useState<LiveVoiceName>('Zephyr');
  const [includeContext, setIncludeContext] = useState(true);
  const [isMuted, setIsMuted] = useState(false);
  const [isModelSpeaking, setIsModelSpeaking] = useState(false);
  const [isPttRecording, setIsPttRecording] = useState(false);
  const [isFallbackBusy, setIsFallbackBusy] = useState(false);
  const [textInput, setTextInput] = useState('');
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [transcripts, setTranscripts] = useState<VoiceTranscriptEntry[]>([]);

  // Mutable refs for real-time audio callbacks (avoids stale closures)
  const wsRef = useRef<WebSocket | null>(null);
  const isStreamingRef = useRef(false);
  const isMutedRef = useRef(false);
  const inputCtxRef = useRef<AudioContext | null>(null);
  const outputCtxRef = useRef<AudioContext | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const processorRef = useRef<ScriptProcessorNode | null>(null);
  const muteGainRef = useRef<GainNode | null>(null);
  const nextStartTimeRef = useRef<number>(0);
  const activeSourcesRef = useRef<AudioBufferSourceNode[]>([]);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recordedChunksRef = useRef<Blob[]>([]);

  // Live visualizer refs
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const micLevelRef = useRef<number>(0);
  const speakerLevelRef = useRef<number>(0);
  const animFrameRef = useRef<number>(0);
  const transcriptEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    isMutedRef.current = isMuted;
  }, [isMuted]);

  useEffect(() => {
    transcriptEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [transcripts]);

  // Waveform animation loop
  useEffect(() => {
    let phase = 0;
    const renderWave = () => {
      const canvas = canvasRef.current;
      if (canvas) {
        const ctx = canvas.getContext('2d');
        if (ctx) {
          const w = canvas.width;
          const h = canvas.height;
          ctx.clearRect(0, 0, w, h);

          // Grid lines
          ctx.strokeStyle = 'rgba(148, 163, 184, 0.08)';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(0, h / 2);
          ctx.lineTo(w, h / 2);
          ctx.stroke();

          // Decay levels smoothly
          micLevelRef.current *= 0.88;
          speakerLevelRef.current *= 0.9;

          const activeAmp = Math.max(micLevelRef.current, speakerLevelRef.current);
          const isSpeaking = speakerLevelRef.current > micLevelRef.current && speakerLevelRef.current > 0.02;
          const baseAmp =
            connectionState === 'live' || isPttRecording
              ? Math.max(0.06, Math.min(1, activeAmp * 3.2))
              : 0.015;

          const drawRibbon = (
            color: string,
            freq: number,
            speed: number,
            ampScale: number,
            lineWidth: number
          ) => {
            ctx.beginPath();
            ctx.strokeStyle = color;
            ctx.lineWidth = lineWidth;
            for (let x = 0; x <= w; x += 3) {
              const norm = x / w;
              const envelope = Math.sin(norm * Math.PI);
              const y =
                h / 2 +
                Math.sin(norm * Math.PI * freq + phase * speed) *
                  (h * 0.38) *
                  baseAmp *
                  ampScale *
                  envelope;
              if (x === 0) ctx.moveTo(x, y);
              else ctx.lineTo(x, y);
            }
            ctx.stroke();
          };

          if (isSpeaking) {
            drawRibbon('#D4AF37', 5, 1.8, 1.0, 2.5);
            drawRibbon('rgba(16, 185, 129, 0.55)', 8, 2.4, 0.65, 1.5);
          } else {
            drawRibbon(
              connectionState === 'live' || isPttRecording ? '#10B981' : '#475569',
              4.5,
              1.4,
              1.0,
              2.5
            );
            drawRibbon('rgba(212, 175, 55, 0.45)', 7, 2.0, 0.6, 1.4);
          }

          phase += 0.06;
        }
      }
      animFrameRef.current = requestAnimationFrame(renderWave);
    };

    animFrameRef.current = requestAnimationFrame(renderWave);
    return () => cancelAnimationFrame(animFrameRef.current);
  }, [connectionState, isPttRecording]);

  const stopQueuedOutputAudio = () => {
    for (const src of activeSourcesRef.current) {
      try {
        src.stop();
      } catch {
        // ignore already-stopped sources
      }
    }
    activeSourcesRef.current = [];
    if (outputCtxRef.current) {
      nextStartTimeRef.current = outputCtxRef.current.currentTime;
    } else {
      nextStartTimeRef.current = 0;
    }
    speakerLevelRef.current = 0;
    setIsModelSpeaking(false);
  };

  const ensureOutputAudioContext = async (): Promise<AudioContext> => {
    if (!outputCtxRef.current || outputCtxRef.current.state === 'closed') {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      outputCtxRef.current = new AudioCtx({ sampleRate: 24000 });
      nextStartTimeRef.current = outputCtxRef.current.currentTime;
    }
    if (outputCtxRef.current.state === 'suspended') {
      await outputCtxRef.current.resume();
    }
    return outputCtxRef.current;
  };

  const schedulePcm24kPlayback = async (base64Pcm: string) => {
    try {
      const ctx = await ensureOutputAudioContext();
      const floatSamples = decodeBase64Pcm24k(base64Pcm);
      if (floatSamples.length === 0) return;

      // Compute peak for visualizer
      let peak = 0;
      for (let i = 0; i < floatSamples.length; i += 8) {
        const abs = Math.abs(floatSamples[i]);
        if (abs > peak) peak = abs;
      }
      speakerLevelRef.current = Math.max(speakerLevelRef.current, peak);

      const audioBuffer = ctx.createBuffer(1, floatSamples.length, 24000);
      audioBuffer.copyToChannel(floatSamples, 0);

      const source = ctx.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(ctx.destination);

      const startAt = Math.max(ctx.currentTime + 0.01, nextStartTimeRef.current);
      source.start(startAt);
      nextStartTimeRef.current = startAt + audioBuffer.duration;

      activeSourcesRef.current.push(source);
      setIsModelSpeaking(true);

      source.onended = () => {
        activeSourcesRef.current = activeSourcesRef.current.filter((s) => s !== source);
        if (activeSourcesRef.current.length === 0) {
          setIsModelSpeaking(false);
        }
      };
    } catch {
      // Ignore transient playback decode glitches
    }
  };

  const appendOrMergeTranscript = (role: 'user' | 'assistant' | 'system', textChunk: string) => {
    if (!textChunk) return;
    setTranscripts((prev) => {
      const last = prev[prev.length - 1];
      if (last && last.role === role && last.partial && role !== 'system') {
        const updated = [...prev];
        updated[updated.length - 1] = {
          ...last,
          text: `${last.text}${textChunk}`,
        };
        return updated;
      }
      return [
        ...prev,
        {
          id: `${role}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          role,
          text: textChunk,
          timestamp: new Date().toLocaleTimeString('ar-EG', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          }),
          partial: role !== 'system',
        },
      ];
    });
  };

  const finalizeCurrentPartialTranscripts = () => {
    setTranscripts((prev) =>
      prev.map((entry) => (entry.partial ? { ...entry, partial: false } : entry))
    );
  };

  const cleanupLiveResources = () => {
    isStreamingRef.current = false;

    if (processorRef.current) {
      try {
        processorRef.current.disconnect();
      } catch {}
      processorRef.current.onaudioprocess = null;
      processorRef.current = null;
    }

    if (muteGainRef.current) {
      try {
        muteGainRef.current.disconnect();
      } catch {}
      muteGainRef.current = null;
    }

    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }

    if (inputCtxRef.current) {
      try {
        void inputCtxRef.current.close();
      } catch {}
      inputCtxRef.current = null;
    }

    stopQueuedOutputAudio();

    if (wsRef.current) {
      try {
        if (wsRef.current.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({ type: 'stop' }));
        }
        wsRef.current.close();
      } catch {}
      wsRef.current = null;
    }

    micLevelRef.current = 0;
  };

  useEffect(() => {
    return () => {
      cleanupLiveResources();
      if (outputCtxRef.current && outputCtxRef.current.state !== 'closed') {
        try {
          void outputCtxRef.current.close();
        } catch {}
      }
    };
  }, []);

  const startLiveVoiceSession = async () => {
    if (connectionState === 'connecting' || connectionState === 'live') return;
    setErrorBanner(null);
    setConnectionState('connecting');

    if (!navigator.mediaDevices?.getUserMedia) {
      setErrorBanner('المتصفح لا يدعم واجهة التقاط الميكروفون (getUserMedia) في هذا السياق.');
      setConnectionState('error');
      return;
    }

    let openedLive = false;

    try {
      await ensureOutputAudioContext();

      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          channelCount: 1,
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
        },
      });
      streamRef.current = stream;

      const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProto}//${window.location.host}/api/live-voice`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      // Build 16kHz PCM capture pipeline
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      const inputCtx = new AudioCtx({ sampleRate: 16000 });
      inputCtxRef.current = inputCtx;
      if (inputCtx.state === 'suspended') {
        await inputCtx.resume();
      }

      const source = inputCtx.createMediaStreamSource(stream);
      const processor = inputCtx.createScriptProcessor(4096, 1, 1);
      const silentGain = inputCtx.createGain();
      silentGain.gain.value = 0;

      processorRef.current = processor;
      muteGainRef.current = silentGain;

      processor.onaudioprocess = (ev) => {
        if (!isStreamingRef.current || isMutedRef.current) return;
        const activeWs = wsRef.current;
        if (!activeWs || activeWs.readyState !== WebSocket.OPEN) return;

        const inputData = ev.inputBuffer.getChannelData(0);
        let rmsSum = 0;
        for (let i = 0; i < inputData.length; i += 4) {
          rmsSum += inputData[i] * inputData[i];
        }
        const rms = Math.sqrt(rmsSum / Math.max(1, inputData.length / 4));
        micLevelRef.current = Math.max(micLevelRef.current, rms);

        const base64Pcm = encodeInt16PcmToBase64(inputData);
        activeWs.send(JSON.stringify({ type: 'audio', data: base64Pcm }));
      };

      source.connect(processor);
      processor.connect(silentGain);
      silentGain.connect(inputCtx.destination);

      ws.onopen = () => {
        ws.send(
          JSON.stringify({
            type: 'start',
            voiceName: selectedVoice,
            forensicContext: includeContext ? forensicSummaryContext : '',
          })
        );
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'ready') {
            openedLive = true;
            isStreamingRef.current = true;
            setConnectionState('live');
            appendOrMergeTranscript(
              'system',
              `تم تأسيس قناة الصوت الحية (${msg.model || 'gemini-3.8-live'} • الصوت: ${msg.voiceName || selectedVoice})`
            );
            onNotify('تم تفعيل المحادثة الصوتية الحية بنجاح.', 'success');
            onRecordAudit({
              id: `voice-${Date.now()}`,
              fileName: `Live Voice Session (${selectedVoice})`,
              fileSize: 'Live Stream',
              verdict: 'جلسة محادثة صوتية حية (gemini-3.8-live)',
              score: 100,
              risk: 'آمن',
              sha256: 'LIVE-STREAM-AUDIO',
            });
          } else if (msg.type === 'audio' && typeof msg.data === 'string') {
            void schedulePcm24kPlayback(msg.data);
          } else if (msg.type === 'input_transcript' && typeof msg.text === 'string') {
            appendOrMergeTranscript('user', msg.text);
          } else if (msg.type === 'output_transcript' && typeof msg.text === 'string') {
            appendOrMergeTranscript('assistant', msg.text);
          } else if (msg.type === 'interrupted') {
            stopQueuedOutputAudio();
            finalizeCurrentPartialTranscripts();
          } else if (msg.type === 'turn_complete') {
            finalizeCurrentPartialTranscripts();
          } else if (msg.type === 'error') {
            setErrorBanner(msg.message || 'حدث خطأ في قناة الصوت الحية.');
            onNotify(msg.message || 'خطأ في الجلسة الصوتية الحية', 'error');
          } else if (msg.type === 'closed') {
            finalizeCurrentPartialTranscripts();
            cleanupLiveResources();
            setConnectionState('idle');
          }
        } catch {
          // Ignore invalid JSON frames
        }
      };

      ws.onerror = () => {
        // Fallback smoothly if WebSocket upgrade isn't supported on stateless serverless hosting
        if (!openedLive) {
          cleanupLiveResources();
          setConnectionState('fallback_ptt');
          setErrorBanner(
            'الخادم يعمل بوضع Serverless لا يدعم WebSocket مستمراً؛ تم التفعيل التلقائي لوضع الجولات الصوتية الحية عبر HTTP.'
          );
          appendOrMergeTranscript(
            'system',
            'تم التبديل تلقائياً إلى وضع التحدث بالضغط (HTTP Voice Turn) المتوافق مع Vercel.'
          );
        } else {
          cleanupLiveResources();
          setConnectionState('error');
          setErrorBanner('انقطع اتصال WebSocket الصوتي بشكل مفاجئ.');
        }
      };

      ws.onclose = () => {
        if (!openedLive) {
          cleanupLiveResources();
          setConnectionState('fallback_ptt');
          setErrorBanner(
            'قناة WebSocket غير متاحة في هذه البيئة؛ يمكنك التحدث فوراً باستخدام زر اضغط للتحدث (HTTP Live Turn).'
          );
        } else if (isStreamingRef.current) {
          finalizeCurrentPartialTranscripts();
          cleanupLiveResources();
          setConnectionState('idle');
        }
      };
    } catch (err: any) {
      cleanupLiveResources();
      setConnectionState('error');
      const msg =
        err?.name === 'NotAllowedError'
          ? 'تم رفض إذن الميكروفون. يرجى السماح للمتصفح بالوصول إلى الميكروفون ثم إعادة المحاولة.'
          : err?.message || 'تعذر بدء جلسة المحادثة الصوتية.';
      setErrorBanner(msg);
      onNotify(msg, 'error');
    }
  };

  const stopLiveVoiceSession = () => {
    finalizeCurrentPartialTranscripts();
    cleanupLiveResources();
    setConnectionState('idle');
    appendOrMergeTranscript('system', 'تم إنهاء جلسة المحادثة الصوتية.');
  };

  // HTTP Push-to-Talk fallback for serverless Vercel deployments
  const startPttTurn = async () => {
    if (isPttRecording || isFallbackBusy) return;
    setErrorBanner(null);
    try {
      await ensureOutputAudioContext();
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
        ? 'audio/webm;codecs=opus'
        : 'audio/webm';
      const recorder = new MediaRecorder(stream, { mimeType });
      recordedChunksRef.current = [];
      mediaRecorderRef.current = recorder;

      recorder.ondataavailable = (ev) => {
        if (ev.data.size > 0) recordedChunksRef.current.push(ev.data);
      };

      recorder.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        setIsPttRecording(false);
        const blob = new Blob(recordedChunksRef.current, { type: mimeType });
        if (blob.size < 400) return;

        setIsFallbackBusy(true);
        try {
          const base64Audio = await new Promise<string>((resolve, reject) => {
            const reader = new FileReader();
            reader.onloadend = () => {
              const result = String(reader.result || '');
              resolve(result.split(',')[1] || '');
            };
            reader.onerror = reject;
            reader.readAsDataURL(blob);
          });

          appendOrMergeTranscript('user', '🎙️ [رسالة صوتية مرسلة للتحليل الفوري]');
          finalizeCurrentPartialTranscripts();

          const res = await fetch(apiUrl('/api/live-voice-turn'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              audioBase64: base64Audio,
              audioMimeType: mimeType.split(';')[0],
              voiceName: selectedVoice,
              forensicContext: includeContext ? forensicSummaryContext : '',
            }),
          });
          const parsed = await safeReadJsonResponse<any>(res);
          const payload = parsed.data || {};
          if (!res.ok || payload.error) {
            throw new Error(payload.error || 'فشل تنفيذ الجولة الصوتية.');
          }
          appendOrMergeTranscript('assistant', payload.replyText || '');
          finalizeCurrentPartialTranscripts();
          if (payload.audioPcmBase64) {
            await schedulePcm24kPlayback(payload.audioPcmBase64);
          }
        } catch (err: any) {
          setErrorBanner(err?.message || 'تعذر معالجة الرسالة الصوتية.');
          onNotify(err?.message || 'فشل الرد الصوتي', 'error');
        } finally {
          setIsFallbackBusy(false);
        }
      };

      recorder.start();
      setIsPttRecording(true);
      micLevelRef.current = 0.65;
    } catch (err: any) {
      setErrorBanner(err?.message || 'تعذر الوصول إلى الميكروفون.');
    }
  };

  const stopPttTurn = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
    }
  };

  const handleSendTextTurn = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = textInput.trim();
    if (!clean) return;
    setTextInput('');
    setErrorBanner(null);

    if (connectionState === 'live' && wsRef.current?.readyState === WebSocket.OPEN) {
      appendOrMergeTranscript('user', clean);
      finalizeCurrentPartialTranscripts();
      wsRef.current.send(JSON.stringify({ type: 'text', text: clean }));
      return;
    }

    // Text turn via HTTP fallback when not in active WS stream
    setIsFallbackBusy(true);
    try {
      await ensureOutputAudioContext();
      appendOrMergeTranscript('user', clean);
      finalizeCurrentPartialTranscripts();

      const res = await fetch(apiUrl('/api/live-voice-turn'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: clean,
          voiceName: selectedVoice,
          forensicContext: includeContext ? forensicSummaryContext : '',
        }),
      });
      const parsed = await safeReadJsonResponse<any>(res);
      const payload = parsed.data || {};
      if (!res.ok || payload.error) {
        throw new Error(payload.error || 'فشل إرسال الرسالة الصوتية.');
      }
      appendOrMergeTranscript('assistant', payload.replyText || '');
      finalizeCurrentPartialTranscripts();
      if (payload.audioPcmBase64) {
        await schedulePcm24kPlayback(payload.audioPcmBase64);
      }
    } catch (err: any) {
      setErrorBanner(err?.message || 'تعذر الحصول على رد صوتي.');
      onNotify(err?.message || 'تعذر الإرسال', 'error');
    } finally {
      setIsFallbackBusy(false);
    }
  };

  return (
    <div className="space-y-6" dir="rtl">
      {/* Header Banner */}
      <div className="rounded-3xl bg-gray-900/95 border border-[#D4AF37]/30 p-6 shadow-2xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[11px] font-mono text-[#D4AF37]">
              <AudioLines className="w-3.5 h-3.5" />
              <span>GEMINI LIVE REAL-TIME VOICE • 16kHz IN / 24kHz PCM OUT</span>
            </div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2.5">
              <span>المحادثة الصوتية الحية (Sovereign Live Voice Core)</span>
            </h2>
            <p className="text-xs text-gray-400 leading-relaxed max-w-2xl">
              محادثة صوتية ثنائية الاتجاه بالزمن الحقيقي عبر <span className="font-mono text-gray-300">gemini-3.8-live</span>، مع التقاط صوتي حي 16kHz وبث صوتي مستمر 24kHz ودعم المقاطعة الفورية (Barge-In) وتفريغ النص لحظياً.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div
              className={`px-3.5 py-2 rounded-xl border text-xs font-bold flex items-center gap-2 ${
                connectionState === 'live'
                  ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                  : connectionState === 'connecting'
                  ? 'bg-amber-500/15 border-amber-500/40 text-amber-300'
                  : connectionState === 'fallback_ptt'
                  ? 'bg-sky-500/15 border-sky-500/40 text-sky-300'
                  : connectionState === 'error'
                  ? 'bg-red-500/15 border-red-500/40 text-red-300'
                  : 'bg-gray-950 border-gray-800 text-gray-400'
              }`}
            >
              <Radio className={`w-3.5 h-3.5 ${connectionState === 'live' ? 'animate-pulse' : ''}`} />
              <span>
                {connectionState === 'live'
                  ? 'قناة الصوت الحية متصلة'
                  : connectionState === 'connecting'
                  ? 'جاري تأسيس القناة...'
                  : connectionState === 'fallback_ptt'
                  ? 'وضع HTTP الصوتي (Serverless)'
                  : connectionState === 'error'
                  ? 'تعذر الاتصال'
                  : 'جاهز للاتصال'}
              </span>
            </div>

            {connectionState === 'live' ? (
              <button
                type="button"
                onClick={stopLiveVoiceSession}
                className="px-4 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg transition cursor-pointer"
              >
                <PhoneOff className="w-4 h-4" />
                <span>إنهاء المكالمة</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={() => void startLiveVoiceSession()}
                disabled={connectionState === 'connecting'}
                className="px-5 py-2.5 rounded-xl bg-[#D4AF37] hover:opacity-90 disabled:opacity-60 text-gray-950 font-bold text-xs flex items-center gap-2 shadow-lg transition cursor-pointer"
              >
                <PhoneCall className="w-4 h-4" />
                <span>{connectionState === 'connecting' ? 'جاري الاتصال...' : 'بدء محادثة صوتية حية'}</span>
              </button>
            )}
          </div>
        </div>

        {errorBanner && (
          <div className="mt-4 p-3.5 rounded-2xl bg-amber-950/40 border border-amber-500/40 text-amber-200 text-xs flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <span>{errorBanner}</span>
          </div>
        )}
      </div>

      {/* Main Split Workspace: Controls + Waveform / Live Transcript */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Control & Audio Visualizer Panel */}
        <div className="lg:col-span-5 space-y-4">
          <div className="rounded-3xl bg-gray-900 border border-gray-800 p-5 space-y-5 shadow-xl">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                <Activity className="w-4 h-4 text-[#D4AF37]" />
                <span>المرسم الطيفي الصوتي (Live Waveform)</span>
              </div>
              <span className="text-[10px] font-mono text-gray-400">
                {isModelSpeaking ? 'AI SPEAKING • 24kHz' : connectionState === 'live' ? 'LISTENING • 16kHz' : 'STANDBY'}
              </span>
            </div>

            <div className="rounded-2xl bg-gray-950 border border-gray-800/90 p-3 relative overflow-hidden">
              <canvas ref={canvasRef} width={440} height={110} className="w-full h-28 block" />
              <div className="mt-2 flex items-center justify-between text-[11px] text-gray-400 font-mono">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  صوتك (Mic)
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-[#D4AF37]" />
                  المساعد الصوتي
                </span>
              </div>
            </div>

            {/* Live Action Controls */}
            <div className="grid grid-cols-2 gap-2.5">
              <button
                type="button"
                onClick={() => setIsMuted((m) => !m)}
                disabled={connectionState !== 'live'}
                className={`px-3.5 py-2.5 rounded-xl border text-xs font-bold flex items-center justify-center gap-2 transition cursor-pointer disabled:opacity-40 ${
                  isMuted
                    ? 'bg-red-500/15 border-red-500/40 text-red-300'
                    : 'bg-gray-950 border-gray-700 hover:border-gray-500 text-gray-200'
                }`}
              >
                {isMuted ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4 text-emerald-400" />}
                <span>{isMuted ? 'الميكروفون مكتوم' : 'كتم الميكروفون'}</span>
              </button>

              <button
                type="button"
                onClick={stopQueuedOutputAudio}
                disabled={!isModelSpeaking}
                className="px-3.5 py-2.5 rounded-xl border border-gray-700 hover:border-[#D4AF37] bg-gray-950 text-xs font-bold text-gray-200 flex items-center justify-center gap-2 transition cursor-pointer disabled:opacity-40"
              >
                <Volume2 className="w-4 h-4 text-[#D4AF37]" />
                <span>إيقاف/مقاطعة الصوت</span>
              </button>
            </div>

            {/* Serverless HTTP Push-to-Talk Fallback Control */}
            {connectionState === 'fallback_ptt' && (
              <div className="p-3.5 rounded-2xl bg-sky-950/30 border border-sky-500/30 space-y-2.5">
                <div className="text-[11px] text-sky-200 font-bold flex items-center gap-2">
                  <Wifi className="w-3.5 h-3.5 text-sky-400" />
                  <span>التحدث بالضغط (وضع Serverless HTTP)</span>
                </div>
                <button
                  type="button"
                  onClick={() => (isPttRecording ? stopPttTurn() : void startPttTurn())}
                  disabled={isFallbackBusy}
                  className={`w-full py-3 rounded-xl font-bold text-xs flex items-center justify-center gap-2 transition cursor-pointer ${
                    isPttRecording
                      ? 'bg-red-600 hover:bg-red-500 text-white animate-pulse'
                      : 'bg-sky-500 hover:bg-sky-400 text-gray-950'
                  }`}
                >
                  <Mic className="w-4 h-4" />
                  <span>
                    {isFallbackBusy
                      ? 'جاري تحليل الصوت وتوليد الرد...'
                      : isPttRecording
                      ? 'اضغط للإيقاف وإرسال الصوت'
                      : 'اضغط للتحدث وتسجيل جولة صوتية'}
                  </span>
                </button>
              </div>
            )}

            {/* Voice Selection */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-gray-300 flex items-center gap-2">
                <Sparkles className="w-3.5 h-3.5 text-[#D4AF37]" />
                <span>نبرة الصوت المختارة (Gemini Prebuilt Voice)</span>
              </label>
              <div className="grid grid-cols-1 gap-1.5">
                {VOICE_OPTIONS.map((voice) => {
                  const active = selectedVoice === voice.id;
                  return (
                    <button
                      key={voice.id}
                      type="button"
                      disabled={connectionState === 'live'}
                      onClick={() => setSelectedVoice(voice.id)}
                      className={`px-3 py-2 rounded-xl border text-right flex items-center justify-between transition cursor-pointer disabled:opacity-60 ${
                        active
                          ? 'bg-[#D4AF37]/15 border-[#D4AF37] text-white'
                          : 'bg-gray-950 border-gray-800 text-gray-300 hover:border-gray-700'
                      }`}
                    >
                      <span className="text-xs font-bold">{voice.label}</span>
                      <span className="text-[10px] text-gray-400">{voice.tone}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Forensic Context Injection Toggle */}
            <label className="flex items-center justify-between p-3 rounded-xl bg-gray-950 border border-gray-800 cursor-pointer">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <div>
                  <div className="text-xs font-bold text-white">تضمين سياق المنصة الجنائي</div>
                  <div className="text-[10px] text-gray-400">تزويد المحادثة بملخص الأدلة والسجلات النشطة</div>
                </div>
              </div>
              <input
                type="checkbox"
                checked={includeContext}
                onChange={(e) => setIncludeContext(e.target.checked)}
                className="w-4 h-4 accent-[#D4AF37]"
              />
            </label>
          </div>
        </div>

        {/* Right Live Transcript & Hybrid Prompt Panel */}
        <div className="lg:col-span-7 flex flex-col rounded-3xl bg-gray-900 border border-gray-800 shadow-xl overflow-hidden min-h-[520px]">
          <div className="px-5 py-3.5 border-b border-gray-800 bg-gray-950/60 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-white">
              <AudioLines className="w-4 h-4 text-[#D4AF37]" />
              <span>سجل التفريغ الصوتي الفوري (Live Audio Transcript)</span>
            </div>
            <button
              type="button"
              onClick={() => setTranscripts([])}
              className="px-2.5 py-1 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-[11px] text-gray-300 flex items-center gap-1 cursor-pointer"
            >
              <Trash2 className="w-3 h-3" />
              <span>مسح السجل</span>
            </button>
          </div>

          <div className="flex-1 p-5 overflow-y-auto space-y-3 max-h-[440px]">
            {transcripts.length === 0 ? (
              <div className="h-full min-h-[280px] flex flex-col items-center justify-center text-center space-y-3 text-gray-400">
                <div className="w-14 h-14 rounded-2xl bg-[#D4AF37]/10 border border-[#D4AF37]/30 flex items-center justify-center text-[#D4AF37]">
                  <AudioLines className="w-7 h-7" />
                </div>
                <div className="text-sm font-bold text-white">ابدأ المحادثة الصوتية الحية</div>
                <p className="text-xs max-w-md leading-relaxed">
                  اضغط على <span className="text-[#D4AF37] font-bold">«بدء محادثة صوتية حية»</span> وتحدث مباشرة بالعربية أو الإنجليزية عن أي دليل رقمي، حزمة APK، ثغرة CVE، أو مؤشر تهديد؛ أو اكتب سؤالاً أدناه للحصول على رد صوتي منطوق.
                </p>
              </div>
            ) : (
              transcripts.map((entry) => (
                <div
                  key={entry.id}
                  className={`flex flex-col ${
                    entry.role === 'user'
                      ? 'items-start'
                      : entry.role === 'assistant'
                      ? 'items-end'
                      : 'items-center'
                  }`}
                >
                  {entry.role === 'system' ? (
                    <div className="px-3 py-1 rounded-lg bg-gray-950 border border-gray-800 text-[11px] text-gray-400 font-mono">
                      {entry.text}
                    </div>
                  ) : (
                    <div
                      className={`max-w-[85%] rounded-2xl px-4 py-3 text-xs leading-relaxed border ${
                        entry.role === 'user'
                          ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-100'
                          : 'bg-gray-950 border-[#D4AF37]/35 text-gray-100'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-4 mb-1 text-[10px] font-mono text-gray-400">
                        <span className={entry.role === 'user' ? 'text-emerald-400' : 'text-[#D4AF37]'}>
                          {entry.role === 'user' ? 'أنت (صوت/نص)' : 'Sovereign Voice Core'}
                        </span>
                        <span>{entry.timestamp}</span>
                      </div>
                      <div className="whitespace-pre-wrap">{entry.text}</div>
                    </div>
                  )}
                </div>
              ))
            )}
            <div ref={transcriptEndRef} />
          </div>

          {/* Hybrid Text-to-Voice Turn Bar */}
          <form
            onSubmit={handleSendTextTurn}
            className="p-4 border-t border-gray-800 bg-gray-950/80 flex items-center gap-2.5"
          >
            <input
              type="text"
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
              placeholder={
                connectionState === 'live'
                  ? 'أرسل توجيهاً نصياً فورياً داخل المكالمة الحية...'
                  : 'اكتب سؤالاً ليتم الرد عليه صوتياً فوراً...'
              }
              className="flex-1 px-4 py-2.5 rounded-xl bg-gray-900 border border-gray-800 focus:border-[#D4AF37] text-xs text-white placeholder-gray-500 outline-none transition"
            />
            <button
              type="submit"
              disabled={!textInput.trim() || isFallbackBusy}
              className="px-4 py-2.5 rounded-xl bg-[#D4AF37] hover:opacity-90 disabled:opacity-50 text-gray-950 font-bold text-xs flex items-center gap-1.5 transition cursor-pointer shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{isFallbackBusy ? 'جاري التوليد...' : 'إرسال'}</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
