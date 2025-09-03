import { nanoid } from 'nanoid';

/**
 * Basic rule-based signals + optional AI hook placeholder.
 * Return { verdict: 'clean'|'suspicious'|'malicious', score: 0..1, reasons: string[] }
 */
export async function scanEmail({ headers = {}, subject = '', body = '' }, { aiFn } = {}) {
  let score = 0;
  const reasons = [];

  const lower = (subject + ' ' + body).toLowerCase();
  const flags = [
    /reset your password/i,
    /wire transfer|bank|routing number/i,
    /gift card/i,
    /urgent|immediately|asap/i,
    /verify your account/i,
    /invoice attached/i,
    /click (here|link)/i
  ];
  flags.forEach(rx => {
    if (rx.test(subject) || rx.test(body)) {
      score += 0.15;
      reasons.push(`Matched rule: ${rx}`);
    }
  });

  // Spoofing heuristic: display name mismatch
  const from = headers['from'] || '';
  if (/@(gmail|outlook|yahoo)\.com/i.test(from) && /CEO|CFO|Finance|HR/i.test(from)) {
    score += 0.2;
    reasons.push('Possible spoofed executive sender');
  }

  // Attachment heuristic
  if (/attachment/i.test(body) || /content-disposition: attachment/i.test(body)) {
    score += 0.1;
    reasons.push('Mentions attachment');
  }

  // Optional AI hook (LLM)
  if (aiFn) {
    try {
      const ai = await aiFn({ headers, subject, body });
      if (ai && typeof ai.score === 'number') {
        score = Math.max(score, ai.score);
        if (ai.reason) reasons.push(`AI: ${ai.reason}`);
      }
    } catch (e) {
      reasons.push('AI hook failed (ignored)');
    }
  }

  score = Math.min(1, score);
  const verdict = score >= 0.75 ? 'malicious' : score >= 0.35 ? 'suspicious' : 'clean';
  return { verdict, score, reasons };
}

export function annotate(raw) {
  return {
    id: nanoid(),
    source: raw.source || 'upload',
    from_addr: raw.from || '',
    to_addr: raw.to || '',
    subject: raw.subject || '',
    received_at: raw.received_at || Date.now(),
    raw
  };
}
