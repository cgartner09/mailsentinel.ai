/**
 * Very light RFC822-ish parser for demo; for production consider 'mailparser'.
 */
export function parseRawEmail(raw) {
  const [headerPart, ...rest] = raw.split(/\r?\n\r?\n/);
  const body = rest.join('\n\n');
  const headers = {};
  for (const line of headerPart.split(/\r?\n/)) {
    const m = line.match(/^([^:]+):\s*(.*)$/);
    if (m) headers[m[1].toLowerCase()] = m[2];
  }
  return {
    headers,
    subject: headers['subject'] || '',
    from: headers['from'] || '',
    to: headers['to'] || '',
    text: body || ''
  };
}
