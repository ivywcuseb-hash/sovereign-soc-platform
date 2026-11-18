import React, { useEffect, useRef, useState } from 'react';
import {
  AudioLines,
  Mic,
  MicOff,
  PhoneCall,
  PhoneOff,
  Send,
  Volume2,
  VolumeX,
  ShieldCheck,
  Sparkles,
  Trash2,
  Activity,
  Radio,
  AlertTriangle,
  Wifi,
  Database,
} from 'lucide-react';
import { apiUrl, safeReadJsonResponse } from '../utils/apiBase';
import type { SiteDataSnapshot } from '../../api/live-voice-turn';

export type LiveVoiceName = 'Zephyr' | 'Puck' | 'Charon' | 'Kore' | 'Fenrir';

interface VoiceOption {
  id: LiveVoiceName;
  label: string;
  tone: string;
  ttsPitch: number;
  ttsRate: number;
}

const VOICE_OPTIONS: VoiceOption[] = [
  { id: 'Zephyr', label: 'Zephyr — زيفير', tone: 'واضح ومتزن (قياسي)', ttsPitch: 1.0, ttsRate: 1.02 },
  { id: 'Kore', label: 'Kore — كوري', tone: 'هادئ واحترافي', ttsPitch: 1.08, ttsRate: 0.98 },
  { id: 'Puck', label: 'Puck — باك', tone: 'حيوي وسريع الاستجابة', ttsPitch: 1.1, ttsRate: 1.08 },
  { id: 'Charon', label: 'Charon — شارون', tone: 'عميق وتحليلي (SOC)', ttsPitch: 0.85, ttsRate: 0.95 },
  { id: 'Fenrir', label: 'Fenrir — فنرير', tone: 'حازم ومباشر', ttsPitch: 0.9, ttsRate: 1.0 },
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
  siteDataSnapshot: SiteDataSnapshot;
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

function buildClientEmergencyRealReply(query: string, snap: SiteDataSnapshot): string {
  const counts = snap.counts;
  const ev = snap.evidence?.[0];
  const feed = snap.liveFeeds?.[0];
  return [
    `تم استلام رسالتك: "${query}".`,
    counts
      ? `البيانات الفعلية لمنصتك: ${counts.evidence} دليل رقمي، ${counts.auditLogs} عملية فحص، ${counts.investigations} قضية، و${counts.liveFeeds} مؤشر تهديد حي.`
      : '',
    ev ? `أحدث دليل: ${ev.fileName} (${ev.verdict || ev.riskLevel || 'محفوظ'}).` : '',
    feed ? `أحدث تغذية: ${feed.title}.` : '',
  ]
    .filter(Boolean)
    .join(' ');
}

export const LiveVoiceAssistantLab: React.FC<LiveVoiceAssistantLabProps> = ({
  forensicSummaryContext,
  siteDataSnapshot,
  onNotify,
  onRecordAudit,
}) => {
  const [connectionState, setConnectionState] = useState<
    'idle' | 'connecting' | 'live' | 'fallback_ptt' | 'error'
  >('idle');
  const [selectedVoice, setSelectedVoice] = useState<LiveVoiceName>('Zephyr');
  const [includeContext, setIncludeContext] = useState(true);
  const [autoSpeakReplies, setAutoSpeakReplies] = useState(true);
  const [isMuted, setIsMuted] = useState(false);
  const [isModelSpeaking, setIsModelSpeaking] = useState(false);
  const [isPttRecording, setIsPttRecording] = useState(false);
  const [liveRecognizedInterim, setLiveRecognizedInterim] = useState('');
  const [isFallbackBusy, setIsFallbackBusy] = useState(false);
  const [textInput, setTextInput] = useState('');
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [transcripts, setTranscripts] = useState<VoiceTranscriptEntry[]>([]);

  // Mutable refs for real-time audio callbacks (avoids stale closures)
  const wsRef = useRef<WebSocket | null>(null);
  const isStreamingRef = useRef(false);
  const isMutedRef = useRef(false);
  const autoSpeakRef = useRef(true);
  const selectedVoiceRef = useRef<LiveVoiceName>('Zephyr');
  const inputCtxRef = useRef<AudioContext | null>(null);
  const outputCtxRef = useRef<AudioContext | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const processorRef = useRef<ScriptProcessorNode | null>(null);
  const muteGainRef = useRef<GainNode | null>(null);
  const nextStartTimeRef = useRef<number>(0);
  const activeSourcesRef = useRef<AudioBufferSourceNode[]>([]);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recordedChunksRef = useRef<Blob[]>([]);
  const speechRecRef = useRef<any>(null);
  const recognizedFinalRef = useRef<string>('');
  const pttMeterFrameRef = useRef<number>(0);
  const pttAnalyserCtxRef = useRef<AudioContext | null>(null);
  const speechPumpIntervalRef = useRef<number | null>(null);

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
    autoSpeakRef.current = autoSpeakReplies;
    if (!autoSpeakReplies && typeof window !== 'undefined' && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
  }, [autoSpeakReplies]);

  useEffect(() => {
    selectedVoiceRef.current = selectedVoice;
  }, [selectedVoice]);

  useEffect(() => {
    transcriptEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [transcripts]);

  // Warm up browser voices (essential on Android Chrome)
  useEffect(() => {
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      window.speechSynthesis.getVoices();
      const onVoices = () => window.speechSynthesis.getVoices();
      window.speechSynthesis.addEventListener?.('voiceschanged', onVoices);
      return () => window.speechSynthesis.removeEventListener?.('voiceschanged', onVoices);
    }
  }, []);

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

          ctx.strokeStyle = 'rgba(148, 163, 184, 0.08)';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(0, h / 2);
          ctx.lineTo(w, h / 2);
          ctx.stroke();

          micLevelRef.current *= 0.88;
          speakerLevelRef.current *= 0.9;

          const activeAmp = Math.max(micLevelRef.current, speakerLevelRef.current);
          const isSpeaking = speakerLevelRef.current > micLevelRef.current && speakerLevelRef.current > 0.02;
          const baseAmp =
            connectionState === 'live' || isPttRecording || isSpeaking
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

  const stopBrowserSpeech = () => {
    if (speechPumpIntervalRef.current !== null) {
      window.clearInterval(speechPumpIntervalRef.current);
      speechPumpIntervalRef.current = null;
    }
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
  };

  // Unlock speechSynthesis synchronously on user gesture for Android Chrome
  const primeSpeechSynthesisOnGesture = () => {
    try {
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        window.speechSynthesis.resume();
        const prime = new SpeechSynthesisUtterance(' ');
        prime.volume = 0;
        window.speechSynthesis.speak(prime);
      }
    } catch {
      // ignore unlock errors
    }
  };

  const speakTextViaBrowserTts = (rawText: string) => {
    if (!autoSpeakRef.current || !rawText?.trim()) return;
    if (typeof window === 'undefined' || !('speechSynthesis' in window)) return;

    stopBrowserSpeech();
    const synth = window.speechSynthesis;
    const voices = synth.getVoices();
    const hasArabic = /[\u0600-\u06FF]/.test(rawText);
    const chosenProfile = VOICE_OPTIONS.find((v) => v.id === selectedVoiceRef.current) || VOICE_OPTIONS[0];

    const preferredVoice = hasArabic
      ? voices.find((v) => v.lang.toLowerCase().startsWith('ar')) || null
      : voices.find((v) => v.lang.toLowerCase().startsWith('en')) || null;

    // Split into clean clauses so Android Chrome never drops long utterances
    const chunks = rawText
      .replace(/([.!؟?\n؛]+)/g, '$1|')
      .split('|')
      .map((s) => s.trim())
      .filter(Boolean);

    if (chunks.length === 0) return;

    setIsModelSpeaking(true);
    speechPumpIntervalRef.current = window.setInterval(() => {
      speakerLevelRef.current = 0.28 + Math.random() * 0.25;
      // Android Chrome pause workaround
      if (synth.paused) synth.resume();
    }, 120);

    chunks.forEach((chunk, idx) => {
      const utt = new SpeechSynthesisUtterance(chunk);
      if (preferredVoice) utt.voice = preferredVoice;
      utt.lang = preferredVoice?.lang || (hasArabic ? 'ar-SA' : 'en-US');
      utt.pitch = chosenProfile.ttsPitch;
      utt.rate = chosenProfile.ttsRate;
      utt.volume = 1;

      if (idx === chunks.length - 1) {
        const finish = () => {
          if (speechPumpIntervalRef.current !== null) {
            window.clearInterval(speechPumpIntervalRef.current);
            speechPumpIntervalRef.current = null;
          }
          speakerLevelRef.current = 0;
          setIsModelSpeaking(false);
        };
        utt.onend = finish;
        utt.onerror = finish;
      }

      synth.speak(utt);
    });
  };

  const stopQueuedOutputAudio = () => {
    for (const src of activeSourcesRef.current) {
      try {
        src.stop();
      } catch {
        // ignore
      }
    }
    activeSourcesRef.current = [];
    if (outputCtxRef.current) {
      nextStartTimeRef.current = outputCtxRef.current.currentTime;
    } else {
      nextStartTimeRef.current = 0;
    }
    stopBrowserSpeech();
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
      stopQueuedOutputAudio();
      cancelAnimationFrame(pttMeterFrameRef.current);
      if (pttAnalyserCtxRef.current && pttAnalyserCtxRef.current.state !== 'closed') {
        try {
          void pttAnalyserCtxRef.current.close();
        } catch {}
      }
      if (outputCtxRef.current && outputCtxRef.current.state !== 'closed') {
        try {
          void outputCtxRef.current.close();
        } catch {}
      }
    };
  }, []);

  const executeServerlessTurn = async (params: {
    text?: string;
    transcript?: string;
    audioBase64?: string;
    audioMimeType?: string;
  }) => {
    setIsFallbackBusy(true);
    setErrorBanner(null);

    try {
      const recentHistory = transcripts
        .filter((t) => t.role === 'user' || t.role === 'assistant')
        .slice(-8)
        .map((t) => ({ role: t.role, text: t.text }));

      const res = await fetch(apiUrl('/api/live-voice-turn'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: params.text,
          transcript: params.transcript,
          audioBase64: params.audioBase64,
          audioMimeType: params.audioMimeType,
          voiceName: selectedVoice,
          forensicContext: includeContext ? forensicSummaryContext : '',
          siteData: includeContext ? siteDataSnapshot : undefined,
          history: recentHistory,
        }),
      });

      const parsed = await safeReadJsonResponse<any>(res);
      const payload = parsed.data || {};

      let replyText = '';
      let audioPcmBase64: string | null = null;

      if (res.ok && payload.replyText) {
        replyText = payload.replyText;
        audioPcmBase64 = payload.audioPcmBase64 || null;
      } else {
        // Offline / emergency local real-data answer
        const fallbackQuery = params.text || params.transcript || 'حالة المنصة';
        replyText = buildClientEmergencyRealReply(fallbackQuery, siteDataSnapshot);
      }

      appendOrMergeTranscript('assistant', replyText);
      finalizeCurrentPartialTranscripts();

      if (autoSpeakRef.current) {
        if (audioPcmBase64) {
          await schedulePcm24kPlayback(audioPcmBase64);
        } else {
          speakTextViaBrowserTts(replyText);
        }
      }
    } catch {
      const emergencyText = buildClientEmergencyRealReply(
        params.text || params.transcript || 'حالة المنصة',
        siteDataSnapshot
      );
      appendOrMergeTranscript('assistant', emergencyText);
      finalizeCurrentPartialTranscripts();
      if (autoSpeakRef.current) {
        speakTextViaBrowserTts(emergencyText);
      }
    } finally {
      setIsFallbackBusy(false);
    }
  };

  const startLiveVoiceSession = async () => {
    if (connectionState === 'connecting' || connectionState === 'live') return;
    setErrorBanner(null);
    primeSpeechSynthesisOnGesture();
    setConnectionState('connecting');

    if (!navigator.mediaDevices?.getUserMedia) {
      setConnectionState('fallback_ptt');
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
            // Switch cleanly into Serverless PTT + Browser Voice Synthesis if Live API key is absent
            cleanupLiveResources();
            setConnectionState('fallback_ptt');
            appendOrMergeTranscript(
              'system',
              'تم التحويل التلقائي إلى وضع المحادثة الصوتية بالبيانات الحقيقية (اضغط للتحدث أو اكتب بالأسفل).'
            );
          } else if (msg.type === 'closed') {
            finalizeCurrentPartialTranscripts();
            cleanupLiveResources();
            if (!openedLive) {
              setConnectionState('fallback_ptt');
            } else {
              setConnectionState('idle');
            }
          }
        } catch {
          // Ignore invalid JSON frames
        }
      };

      ws.onerror = () => {
        if (!openedLive) {
          cleanupLiveResources();
          setConnectionState('fallback_ptt');
          appendOrMergeTranscript(
            'system',
            'المساعد جاهز الآن على Vercel: اضغط للتحدث بصوتك أو أرسل رسالتك وسيتم الرد عليك صوتياً من بيانات موقعك الحقيقية.'
          );
        } else {
          cleanupLiveResources();
          setConnectionState('fallback_ptt');
        }
      };

      ws.onclose = () => {
        if (!openedLive) {
          cleanupLiveResources();
          setConnectionState('fallback_ptt');
        } else if (isStreamingRef.current) {
          finalizeCurrentPartialTranscripts();
          cleanupLiveResources();
          setConnectionState('idle');
        }
      };
    } catch (err: any) {
      cleanupLiveResources();
      if (err?.name === 'NotAllowedError') {
        setConnectionState('error');
        const msg = 'تم رفض إذن الميكروفون. يرجى السماح للمتصفح بالوصول إلى الميكروفون أو استخدام المحادثة النصية مع الرد الصوتي بالأسفل.';
        setErrorBanner(msg);
        onNotify(msg, 'error');
      } else {
        setConnectionState('fallback_ptt');
      }
    }
  };

  const stopLiveVoiceSession = () => {
    finalizeCurrentPartialTranscripts();
    cleanupLiveResources();
    stopQueuedOutputAudio();
    setConnectionState('idle');
    appendOrMergeTranscript('system', 'تم إنهاء جلسة المحادثة الصوتية.');
  };

  // Push-to-Talk with BOTH live SpeechRecognition (Arabic/English) + Audio RMS waveform + MediaRecorder
  const startPttTurn = async () => {
    if (isPttRecording || isFallbackBusy) return;
    setErrorBanner(null);
    primeSpeechSynthesisOnGesture();
    stopQueuedOutputAudio();

    recognizedFinalRef.current = '';
    setLiveRecognizedInterim('');

    try {
      await ensureOutputAudioContext();
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
        ? 'audio/webm;codecs=opus'
        : 'audio/webm';
      const recorder = new MediaRecorder(stream, { mimeType });
      recordedChunksRef.current = [];
      mediaRecorderRef.current = recorder;

      // Real-time mic waveform meter while recording PTT
      try {
        const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
        const meterCtx = new AudioCtx();
        pttAnalyserCtxRef.current = meterCtx;
        const src = meterCtx.createMediaStreamSource(stream);
        const analyser = meterCtx.createAnalyser();
        analyser.fftSize = 256;
        src.connect(analyser);
        const buf = new Uint8Array(analyser.frequencyBinCount);
        const tick = () => {
          analyser.getByteTimeDomainData(buf);
          let sum = 0;
          for (let i = 0; i < buf.length; i++) {
            const v = (buf[i] - 128) / 128;
            sum += v * v;
          }
          micLevelRef.current = Math.max(micLevelRef.current, Math.sqrt(sum / buf.length));
          pttMeterFrameRef.current = requestAnimationFrame(tick);
        };
        pttMeterFrameRef.current = requestAnimationFrame(tick);
      } catch {
        // meter optional
      }

      // Browser native Web Speech Recognition (works natively on Android Chrome & Desktop Chrome/Edge)
      const SpeechRec = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
      if (SpeechRec) {
        try {
          const rec = new SpeechRec();
          rec.lang = 'ar-IQ';
          rec.interimResults = true;
          rec.continuous = true;
          rec.onresult = (ev: any) => {
            let finalText = '';
            let interimText = '';
            for (let i = 0; i < ev.results.length; i++) {
              const r = ev.results[i];
              if (r.isFinal) finalText += `${r[0].transcript} `;
              else interimText += r[0].transcript;
            }
            recognizedFinalRef.current = finalText.trim();
            setLiveRecognizedInterim((`${finalText} ${interimText}`).trim());
          };
          rec.onerror = () => {
            // graceful no-op; audio blob still sent
          };
          rec.start();
          speechRecRef.current = rec;
        } catch {
          speechRecRef.current = null;
        }
      }

      recorder.ondataavailable = (ev) => {
        if (ev.data.size > 0) recordedChunksRef.current.push(ev.data);
      };

      recorder.onstop = async () => {
        cancelAnimationFrame(pttMeterFrameRef.current);
        if (pttAnalyserCtxRef.current && pttAnalyserCtxRef.current.state !== 'closed') {
          try {
            void pttAnalyserCtxRef.current.close();
          } catch {}
          pttAnalyserCtxRef.current = null;
        }
        stream.getTracks().forEach((t) => t.stop());

        if (speechRecRef.current) {
          try {
            speechRecRef.current.stop();
          } catch {}
          speechRecRef.current = null;
        }

        setIsPttRecording(false);
        const capturedTranscript = (recognizedFinalRef.current || liveRecognizedInterim || '').trim();
        setLiveRecognizedInterim('');

        const blob = new Blob(recordedChunksRef.current, { type: mimeType });
        if (blob.size < 300 && !capturedTranscript) return;

        const base64Audio =
          blob.size >= 300
            ? await new Promise<string>((resolve, reject) => {
                const reader = new FileReader();
                reader.onloadend = () => {
                  const result = String(reader.result || '');
                  resolve(result.split(',')[1] || '');
                };
                reader.onerror = reject;
                reader.readAsDataURL(blob);
              })
            : '';

        appendOrMergeTranscript(
          'user',
          capturedTranscript || '🎙️ [رسالة صوتية مسجلة]'
        );
        finalizeCurrentPartialTranscripts();

        await executeServerlessTurn({
          text: capturedTranscript,
          transcript: capturedTranscript,
          audioBase64: base64Audio,
          audioMimeType: mimeType.split(';')[0],
        });
      };

      recorder.start();
      setIsPttRecording(true);
    } catch (err: any) {
      setErrorBanner(
        err?.name === 'NotAllowedError'
          ? 'يرجى منح صلاحية الميكروفون في المتصفح للتحدث بصوتك، أو استخدام مربع الكتابة أدناه (سيتم الرد عليك صوتياً).'
          : err?.message || 'تعذر الوصول إلى الميكروفون.'
      );
    }
  };

  const stopPttTurn = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
    }
  };

  const sendTextOrQuickPrompt = async (rawText: string) => {
    const clean = rawText.trim();
    if (!clean) return;
    setErrorBanner(null);
    primeSpeechSynthesisOnGesture();

    if (connectionState === 'live' && wsRef.current?.readyState === WebSocket.OPEN) {
      appendOrMergeTranscript('user', clean);
      finalizeCurrentPartialTranscripts();
      wsRef.current.send(JSON.stringify({ type: 'text', text: clean }));
      return;
    }

    await ensureOutputAudioContext();
    appendOrMergeTranscript('user', clean);
    finalizeCurrentPartialTranscripts();
    await executeServerlessTurn({ text: clean, transcript: clean });
  };

  const handleSendTextTurn = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = textInput.trim();
    if (!clean || isFallbackBusy) return;
    setTextInput('');
    await sendTextOrQuickPrompt(clean);
  };

  const siteCounts = siteDataSnapshot.counts;

  return (
    <div className="space-y-6" dir="rtl">
      {/* Header Banner */}
      <div className="rounded-3xl bg-gray-900/95 border border-[#D4AF37]/30 p-6 shadow-2xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[11px] font-mono text-[#D4AF37]">
              <AudioLines className="w-3.5 h-3.5" />
              <span>GEMINI LIVE VOICE + REAL-TIME SITE DATA ENGINE</span>
            </div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2.5">
              <span>المحادثة الصوتية الحية (Sovereign Live Voice Core)</span>
            </h2>
            <p className="text-xs text-gray-400 leading-relaxed max-w-2xl">
              محادثة صوتية ونصية متصلة مباشرة ببيانات موقعك الحقيقية (الأدلة، البصمات، القضايا، التغذيات الحية، وسجل العمليات)، مع استجابة صوتية منطوقة وفحص حي لمؤشرات OSINT.
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
                  ? 'bg-emerald-500/10 border-emerald-500/35 text-emerald-300'
                  : connectionState === 'error'
                  ? 'bg-red-500/15 border-red-500/40 text-red-300'
                  : 'bg-gray-950 border-gray-800 text-gray-300'
              }`}
            >
              <Radio className={`w-3.5 h-3.5 ${connectionState === 'live' || isPttRecording ? 'animate-pulse' : ''}`} />
              <span>
                {connectionState === 'live'
                  ? 'قناة الصوت الحية متصلة'
                  : connectionState === 'connecting'
                  ? 'جاري تأسيس القناة...'
                  : connectionState === 'fallback_ptt'
                  ? 'الصوت الحي والبيانات الفعلية نشطة'
                  : connectionState === 'error'
                  ? 'تحقق من إذن الميكروفون'
                  : 'جاهز للمحادثة الصوتية'}
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

        {/* Live Connected Site Data Summary Strip */}
        {siteCounts && (
          <div className="mt-4 pt-4 border-t border-gray-800/80 flex flex-wrap items-center gap-3 text-[11px] text-gray-300">
            <span className="inline-flex items-center gap-1.5 text-[#D4AF37] font-bold">
              <Database className="w-3.5 h-3.5" />
              بيانات موقعك المتصلة بالمساعد:
            </span>
            <span className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800">
              الأدلة: <strong className="text-white">{siteCounts.evidence}</strong>
            </span>
            <span className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800">
              العمليات: <strong className="text-white">{siteCounts.auditLogs}</strong>
            </span>
            <span className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800">
              القضايا: <strong className="text-white">{siteCounts.investigations}</strong>
            </span>
            <span className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800">
              التغذيات الحية: <strong className="text-white">{siteCounts.liveFeeds}</strong>
            </span>
            <span className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800">
              التنبيهات الحرجة: <strong className="text-amber-400">{siteCounts.criticalAlerts}</strong>
            </span>
          </div>
        )}

        {errorBanner && (
          <div className="mt-4 p-3.5 rounded-2xl bg-amber-950/40 border border-amber-500/40 text-amber-200 text-xs flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <span>{errorBanner}</span>
          </div>
        )}
      </div>

      {/* Main Split Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Controls & Audio Visualizer Panel */}
        <div className="lg:col-span-5 space-y-4">
          <div className="rounded-3xl bg-gray-900 border border-gray-800 p-5 space-y-5 shadow-xl">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                <Activity className="w-4 h-4 text-[#D4AF37]" />
                <span>المرسم الطيفي الصوتي (Live Waveform)</span>
              </div>
              <span className="text-[10px] font-mono text-gray-400">
                {isModelSpeaking
                  ? 'AI SPEAKING'
                  : connectionState === 'live' || isPttRecording
                  ? 'LISTENING...'
                  : 'READY'}
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
                  صوت المساعد
                </span>
              </div>
            </div>

            {/* Instant Push-To-Talk Control (Always ready when not in active WS stream) */}
            {connectionState !== 'live' && (
              <div className="p-3.5 rounded-2xl bg-sky-950/30 border border-sky-500/35 space-y-2.5">
                <div className="text-[11px] text-sky-200 font-bold flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <Wifi className="w-3.5 h-3.5 text-sky-400" />
                    <span>التحدث بالضغط والاستماع المباشر</span>
                  </span>
                  {isPttRecording && <span className="text-red-400 font-mono">REC LIVE</span>}
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
                      ? 'جاري تحليل الصوت والبيانات وتوليد الرد...'
                      : isPttRecording
                      ? 'اضغط للإيقاف وإرسال صوتك الآن'
                      : 'اضغط للتحدث وتسجيل جولة صوتية'}
                  </span>
                </button>
                {isPttRecording && liveRecognizedInterim && (
                  <div className="p-2 rounded-xl bg-gray-950/80 border border-sky-500/30 text-[11px] text-sky-100">
                    <span className="text-sky-400 font-bold">يتم التقاط صوتك: </span>
                    {liveRecognizedInterim}
                  </div>
                )}
              </div>
            )}

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

            {/* Voice Selection */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-gray-300 flex items-center gap-2">
                <Sparkles className="w-3.5 h-3.5 text-[#D4AF37]" />
                <span>نبرة الصوت المختارة</span>
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

            {/* Toggles */}
            <div className="space-y-2">
              <label className="flex items-center justify-between p-3 rounded-xl bg-gray-950 border border-gray-800 cursor-pointer">
                <div className="flex items-center gap-2">
                  {autoSpeakReplies ? (
                    <Volume2 className="w-4 h-4 text-[#D4AF37]" />
                  ) : (
                    <VolumeX className="w-4 h-4 text-gray-500" />
                  )}
                  <div>
                    <div className="text-xs font-bold text-white">نطق ردود المساعد صوتياً تلقائياً</div>
                    <div className="text-[10px] text-gray-400">تشغيل الصوت للردود المرسلة والمحكية</div>
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={autoSpeakReplies}
                  onChange={(e) => setAutoSpeakReplies(e.target.checked)}
                  className="w-4 h-4 accent-[#D4AF37]"
                />
              </label>

              <label className="flex items-center justify-between p-3 rounded-xl bg-gray-950 border border-gray-800 cursor-pointer">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <div>
                    <div className="text-xs font-bold text-white">تضمين بيانات موقعي الحقيقية</div>
                    <div className="text-[10px] text-gray-400">الأدلة، سجل العمليات، القضايا، والتغذيات الحية</div>
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
        </div>

        {/* Live Transcript & Hybrid Prompt Panel */}
        <div className="lg:col-span-7 flex flex-col rounded-3xl bg-gray-900 border border-gray-800 shadow-xl overflow-hidden min-h-[540px]">
          <div className="px-5 py-3.5 border-b border-gray-800 bg-gray-950/60 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-white">
              <AudioLines className="w-4 h-4 text-[#D4AF37]" />
              <span>المحادثة الصوتية والنصية الفورية (Live Transcript)</span>
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
                <div className="text-sm font-bold text-white">تحدث أو أرسل رسالة للمساعد</div>
                <p className="text-xs max-w-md leading-relaxed">
                  اضغط على <span className="text-sky-400 font-bold">«اضغط للتحدث وتسجيل جولة صوتية»</span> أو <span className="text-[#D4AF37] font-bold">«بدء محادثة صوتية حية»</span> أو اكتب سؤالك بالأسفل وسيجيبك المساعد نصياً وصوتياً من بيانات موقعك الحقيقية.
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
                        <div className="flex items-center gap-2">
                          {entry.role === 'assistant' && (
                            <button
                              type="button"
                              onClick={() => speakTextViaBrowserTts(entry.text)}
                              title="استماع للرد صوتياً"
                              className="text-[#D4AF37] hover:text-white cursor-pointer"
                            >
                              <Volume2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                          <span>{entry.timestamp}</span>
                        </div>
                      </div>
                      <div className="whitespace-pre-wrap">{entry.text}</div>
                    </div>
                  )}
                </div>
              ))
            )}
            <div ref={transcriptEndRef} />
          </div>

          {/* Quick Real-Data Prompts */}
          <div className="px-4 py-2 border-t border-gray-800/80 bg-gray-950/50 flex flex-wrap gap-1.5">
            {[
              'أعطني ملخص بيانات موقعي الحقيقية الآن',
              'ما هي أحدث الأدلة المرفوعة؟',
              'ما أخطر التهديدات والثغرات الحالية؟',
              'افحص 8.8.8.8 بالبيانات الحية',
            ].map((q) => (
              <button
                key={q}
                type="button"
                disabled={isFallbackBusy}
                onClick={() => void sendTextOrQuickPrompt(q)}
                className="px-2.5 py-1 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-[10px] text-gray-300 transition cursor-pointer disabled:opacity-50"
              >
                {q}
              </button>
            ))}
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
                  : 'اكتب أي سؤال عن موقعك أو أدلتك ليتم الرد عليك نصياً وصوتياً فوراً...'
              }
              className="flex-1 px-4 py-2.5 rounded-xl bg-gray-900 border border-gray-800 focus:border-[#D4AF37] text-xs text-white placeholder-gray-500 outline-none transition"
            />
            <button
              type="submit"
              disabled={!textInput.trim() || isFallbackBusy}
              className="px-4 py-2.5 rounded-xl bg-[#D4AF37] hover:opacity-90 disabled:opacity-50 text-gray-950 font-bold text-xs flex items-center gap-1.5 transition cursor-pointer shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{isFallbackBusy ? 'جاري الرد...' : 'إرسال'}</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
