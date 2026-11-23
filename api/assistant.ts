import {
  siteAssistantHandler,
  liveVoiceTurnHandler,
} from '../server/handlers/assistant.js';

export default async function handler(req: any, res: any) {
  const url = req.url || '';
  if (url.includes('site-assistant')) return siteAssistantHandler(req, res);
  if (url.includes('live-voice-turn')) return liveVoiceTurnHandler(req, res);
  return res.status(404).json({ error: 'Assistant API route not found' });
}
