import { connect } from 'cloudflare:sockets';
import type { Bindings } from '../types/env';
import { utf8 } from './encoding';

type Mail = { to: string; subject: string; text: string };

const domainName = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const mailbox = /^[a-z0-9!#$%&'*+/=?^`{|}~_-]+(?:\.[a-z0-9!#$%&'*+/=?^`{|}~_-]+)*@([a-z0-9.-]+)$/i;

function validMailbox(value: string) {
  const match = mailbox.exec(value);
  return value.length <= 254 && match?.[1] && domainName.test(match[1]);
}

function base64(text: string) {
  let binary = '';
  for (const byte of utf8(text)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function headerWord(value: string) {
  // Fold UTF-8 into RFC 2047 encoded words without splitting a code point.
  const words: string[] = [];
  let group = '';
  for (const character of value) {
    if (utf8(group + character).length > 42) {
      words.push(group);
      group = '';
    }
    group += character;
  }
  words.push(group);
  return words.map(word => '=?UTF-8?B?' + base64(word) + '?=').join('\r\n ');
}

export async function sendMail(env: Bindings, mail: Mail): Promise<void> {
  const host = env.SMTP_HOST ?? 'smtpout.secureserver.net';
  const port = Number(env.SMTP_PORT ?? '465');
  const security = (env.SMTP_SECURITY ?? 'tls').toLowerCase();
  const ehlo = env.SMTP_EHLO_DOMAIN ?? 'osmcreations.com';
  const from = env.SMTP_FROM_EMAIL ?? 'support@osmcreations.com';
  const fromName = env.SMTP_FROM_NAME ?? 'Incoming';
  const username = env.SMTP_USERNAME;
  const password = env.SMTP_PASSWORD;
  const method = (env.SMTP_AUTH_METHOD ?? 'auto').toLowerCase();
  if (!username || !password || /[\r\n\0]/.test(username + password)
      || !domainName.test(host) || !domainName.test(ehlo) || !Number.isInteger(port) || port < 1 || port > 65535
      || security !== 'tls' || !['auto', 'login', 'plain'].includes(method)
      || !validMailbox(from) || !validMailbox(mail.to) || /[\x00-\x1f\x7f]/.test(fromName + mail.subject)
      || (env.SMTP_ALLOW_DIFFERENT_FROM !== 'true' && username.toLowerCase() !== from.toLowerCase())) {
    throw new Error('Invalid SMTP configuration or message address');
  }

  // No plaintext fallback. The Workers runtime negotiates and verifies TLS for this host.
  const socket = connect({ hostname: host, port }, { secureTransport: 'on', allowHalfOpen: false });
  void socket.closed.catch(() => {});
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  const decoder = new TextDecoder();
  let buffered = '';
  let timer: ReturnType<typeof setTimeout> | undefined;
  let accepted = false;

  async function response(...allowed: number[]) {
    const lines: string[] = [];
    let total = 0;
    for (;;) {
      while (!buffered.includes('\r\n')) {
        const part = await reader.read();
        if (part.done) throw new Error('SMTP connection closed');
        buffered += decoder.decode(part.value, { stream: true });
        if (buffered.length > 32768) throw new Error('Invalid SMTP response');
      }
      const boundary = buffered.indexOf('\r\n');
      const line = buffered.slice(0, boundary);
      buffered = buffered.slice(boundary + 2);
      const match = /^(\d{3})(?:([- ])(.*))?$/.exec(line);
      const code = Number(match?.[1]);
      total += line.length + 2;
      if (!match || !allowed.includes(code) || total > 32768) throw new Error('SMTP command refused');
      lines.push(match[3] ?? '');
      if (match[2] !== '-') return lines;
    }
  }

  async function command(line: string, ...codes: number[]) {
    await writer.write(utf8(line + '\r\n'));
    return response(...codes);
  }

  async function deliver() {
    await socket.opened;
    await response(220);
    const capabilities = await command('EHLO ' + ehlo, 250);
    const methods = new Set(capabilities
      .filter(line => /^AUTH[ =]/i.test(line))
      .flatMap(line => line.toLowerCase().slice(5).trim().split(/\s+/)));
    if (method !== 'login' && methods.has('plain')) {
      // Challenge form keeps the initial SMTP command within its protocol length.
      await command('AUTH PLAIN', 334);
      await command(base64('\0' + username + '\0' + password), 235);
    } else if (method !== 'plain' && methods.has('login')) {
      await command('AUTH LOGIN', 334);
      await command(base64(username!), 334);
      await command(base64(password!), 235);
    } else {
      throw new Error('SMTP authentication unavailable');
    }
    await command('MAIL FROM:<' + from + '>', 250);
    await command('RCPT TO:<' + mail.to + '>', 250, 251);
    await command('DATA', 354);
    const body = base64(mail.text.replace(/\r\n|\r|\n/g, '\r\n')).match(/.{1,76}/g) ?? [];
    const message = [
      'Date: ' + new Date().toUTCString().replace(/ GMT$/, ' +0000'),
      'Message-ID: <' + crypto.randomUUID() + '@' + ehlo + '>',
      'From: ' + headerWord(fromName) + ' <' + from + '>',
      'To: <' + mail.to + '>',
      'Subject: ' + headerWord(mail.subject),
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '', ...body, '.'
    ];
    await command(message.join('\r\n'), 250);
    // The final 250 is the delivery acknowledgement. A disconnect during QUIT
    // must not turn an accepted message into a reported failure or a retry.
    accepted = true;
    await writer.write(utf8('QUIT\r\n'));
  }

  try {
    await Promise.race([
      deliver(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('SMTP timeout')), 20000);
      })
    ]);
  } catch {
    // Provider replies can echo addresses, credentials, or message body text.
    if (!accepted) throw new Error('SMTP delivery was not confirmed');
  } finally {
    clearTimeout(timer);
    void socket.close().catch(() => {});
  }
}
