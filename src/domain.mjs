import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const STEP_COUNT = 5;
export const DEFAULT_STEPS = [
  { position: 1, title: 'Step 1', label: 'Continue to destination', instruction: 'Open the Monetag ad in a new tab, stay there for 10 seconds, then return.', destination_url: '' },
  { position: 2, title: 'Step 2', label: 'Visit sponsor', instruction: 'Open the Monetag ad in a new tab, stay there for 10 seconds, then return.', destination_url: '' },
  { position: 3, title: 'Step 3', label: 'Continue', instruction: 'Open the Monetag ad in a new tab, stay there for 10 seconds, then return.', destination_url: '' },
  { position: 4, title: 'Step 4', label: 'Visit partner', instruction: 'Open the Monetag ad in a new tab, stay there for 10 seconds, then return.', destination_url: '' },
  { position: 5, title: 'Step 5', label: 'Final step', instruction: 'Open the Monetag ad in a new tab, stay there for 10 seconds, then return.', destination_url: '' },
].map(step => ({ ...step, enabled: 1, destination_url: step.destination_url, policy: 'clickthrough', retry_limit: 3, timeout_seconds: 0 }));

export function normalizeEmail(value) {
  return String(value ?? '').trim().toLowerCase();
}

export function validateEmail(value) {
  const email = normalizeEmail(value);
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function validatePassword(value) {
  return typeof value === 'string' && value.length >= 10 && value.length <= 128 && /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value);
}

export function validateDestination(value) {
  try {
    const url = new URL(String(value));
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    return url.href;
  } catch { return null; }
}

export function validateAdDestination(value) {
  if (/^demo:\/\/step\/[1-5]$/.test(String(value ?? ''))) return String(value);
  if (!value) return '';
  const urlString = String(value).replaceAll('{event_id}', 'event-id');
  try {
    const url = new URL(urlString);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    return String(value);
  } catch { return null; }
}

export function safeAlias(value) {
  const alias = String(value ?? '').trim();
  if (!alias) return null;
  return /^[A-Za-z0-9_-]{3,32}$/.test(alias) ? alias : undefined;
}

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

export function hashToken(token) {
  return createHash('sha256').update(String(token)).digest('hex');
}

export function safeEqualHex(left, right) {
  if (!/^[a-f0-9]+$/i.test(left) || !/^[a-f0-9]+$/i.test(right) || left.length !== right.length) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

export function passwordLooksCompromised(password) {
  return /^(password|qwerty|letmein|admin|welcome|123456|changeme)/i.test(password);
}

export function cleanText(value, max = 240) {
  return String(value ?? '').trim().replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max);
}

export function deviceCategory(userAgent = '') {
  const ua = userAgent.toLowerCase();
  if (/bot|crawler|spider|headless|preview|facebookexternalhit|whatsapp|slackbot|discordbot/.test(ua)) return 'bot';
  if (/ipad|tablet/.test(ua)) return 'tablet';
  if (/mobile|android|iphone/.test(ua)) return 'mobile';
  return 'desktop';
}

export function calculateEarning(ratePaisePerThousand, eligibleEvents = 1) {
  const rate = Number(ratePaisePerThousand);
  const events = Number(eligibleEvents);
  if (!Number.isSafeInteger(rate) || rate < 0 || !Number.isSafeInteger(events) || events < 0) throw new TypeError('Rate and event count must be non-negative integers');
  return Math.floor((rate * events) / 1000);
}

export function nextStepPosition(steps, completedPositions) {
  const completed = new Set(completedPositions);
  for (const step of [...steps].filter(s => s.enabled).sort((a, b) => a.position - b.position)) {
    if (!completed.has(step.position)) return step.position;
  }
  return null;
}

export function publicStepState(steps, completedPositions, activePosition) {
  const completed = new Set(completedPositions);
  const enabled = [...steps].filter(s => s.enabled).sort((a, b) => a.position - b.position);
  const total = enabled.length;
  const done = enabled.filter(s => completed.has(s.position)).length;
  return {
    currentStep: activePosition,
    completed: done,
    total,
    progress: total ? Math.round((done / total) * 100) : 100,
    steps: enabled.map(s => ({
      position: s.position,
      title: s.title,
      label: s.label,
      instruction: s.instruction,
      policy: s.policy,
      status: completed.has(s.position) ? 'completed' : s.position === activePosition ? 'current' : 'locked',
    })),
  };
}
