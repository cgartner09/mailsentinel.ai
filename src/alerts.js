import axios from 'axios';
import nodemailer from 'nodemailer';

const slackWebhook = process.env.SLACK_WEBHOOK_URL || '';

export async function sendSlack(text) {
  if (!slackWebhook) return;
  try {
    await axios.post(slackWebhook, { text });
  } catch (e) {
    console.error('Slack error', e.message);
  }
}

export async function sendEmail({ to, from, subject, text }) {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) return;

  const transporter = nodemailer.createTransport({ host, port, auth: { user, pass } });
  await transporter.sendMail({ to, from, subject, text });
}

export async function notifyQuarantine(message) {
  const subject = `Quarantined: ${message.subject}`;
  const text = `From: ${message.from_addr}\nTo: ${message.to_addr}\nVerdict: ${message.verdict} (${message.score})\nID: ${message.id}`;
  await sendSlack(`:rotating_light: ${subject}\n${text}`);
  await sendEmail({
    to: process.env.ALERTS_TO || '',
    from: process.env.ALERTS_FROM || 'notify@mailsentinel.ai',
    subject,
    text
  });
}
