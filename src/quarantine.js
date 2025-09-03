import { insertMessage, insertAudit, updateQuarantine } from './db.js';
import { notifyQuarantine } from './alerts.js';
import { nanoid } from 'nanoid';

export async function quarantineMessage(msg, { actor = 'system', note = '' } = {}) {
  insertMessage({ ...msg, quarantine: true, verdict: msg.verdict, score: msg.score });
  await notifyQuarantine(msg);
  insertAudit({ id: nanoid(), message_id: msg.id, action: 'quarantine', actor, note });
}

export function releaseMessage(id, { actor = 'admin', note = '' } = {}) {
  updateQuarantine(id, false);
  insertAudit({ id: nanoid(), message_id: id, action: 'release', actor, note });
}

export function deleteMessage(id, { actor = 'admin', note = '' } = {}) {
  updateQuarantine(id, false);
  insertAudit({ id: nanoid(), message_id: id, action: 'delete', actor, note });
}
