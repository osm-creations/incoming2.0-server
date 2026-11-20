import { afterEach, expect, test, vi } from 'vitest';
import { Buffer } from 'node:buffer';

const connect = vi.hoisted(() => vi.fn());
vi.mock('cloudflare:sockets', () => ({ connect }));
import { sendMail } from '../src/lib/smtp.ts';

const config = { SMTP_USERNAME: 'support@osmcreations.com', SMTP_PASSWORD: 'Test-only 🔑' };
const message = { to: 'person+test@example.org', subject: 'Incoming — sample', text: 'Temporary example\n.\n🔐\r\n' };
const decode64 = value => Buffer.from(value, 'base64').toString('utf8');

function mockServer(replies) {
  let stream;
  const commands = [];
  const encoder = new TextEncoder();
  function reply(lines) {
    if (lines == null) return;
    const bytes = encoder.encode(lines.replaceAll('\n', '\r\n') + '\r\n');
    stream.enqueue(bytes.slice(0, 2));
    stream.enqueue(bytes.slice(2));
  }
  const close = vi.fn(() => {
    stream.close();
    return Promise.resolve();
  });
  connect.mockReturnValue({
    opened: Promise.resolve(), closed: Promise.resolve(), close,
    readable: new ReadableStream({ start(controller) { stream = controller; reply('220 Mail server ready'); } }),
    writable: new WritableStream({
      write(chunk) {
        commands.push(new TextDecoder().decode(chunk));
        reply(replies.shift());
      }
    })
  });
  return { commands, close };
}

afterEach(() => { vi.useRealTimers(); connect.mockReset(); });

test('sends one UTF-8 plain-text message through authenticated implicit TLS', async () => {
  const server = mockServer(['250-relay\n250-SIZE 80000\n250 AUTH LOGIN PLAIN', '334 ', '235 OK', '250 OK', '250 OK', '354 Continue', '250 Accepted']);
  await sendMail(config, message);
  expect(connect).toHaveBeenCalledWith({ hostname: 'smtpout.secureserver.net', port: 465 }, { secureTransport: 'on', allowHalfOpen: false });
  expect(server.commands[0]).toBe('EHLO osmcreations.com\r\n');
  expect(server.commands[1]).toBe('AUTH PLAIN\r\n');
  expect(decode64(server.commands[2])).toBe('\0' + config.SMTP_USERNAME + '\0' + config.SMTP_PASSWORD);
  expect(server.commands.slice(3, 6)).toEqual(['MAIL FROM:<support@osmcreations.com>\r\n', 'RCPT TO:<person+test@example.org>\r\n', 'DATA\r\n']);
  const [headers, body] = server.commands[6].split('\r\n\r\n');
  expect(headers).toContain('Content-Transfer-Encoding: base64');
  expect(headers).toMatch(/Message-ID: <[a-f0-9-]+@osmcreations.com>/);
  expect(decode64(headers.match(/Subject: =\?UTF-8\?B\?(.*?)\?=/)[1])).toBe(message.subject);
  expect(body.endsWith('\r\n.\r\n')).toBe(true);
  expect(decode64(body.slice(0, -5))).toBe('Temporary example\r\n.\r\n🔐\r\n');
  expect(server.close).toHaveBeenCalledOnce();
});

test('uses LOGIN when advertised and reports only acknowledged mail as sent', async () => {
  const server = mockServer(['250-relay\n250 AUTH=LOGIN', '334 Username', '334 Password', '235 OK', '250 OK', '251 Forward', '354 Continue', '550 private details here']);
  await expect(sendMail(config, message)).rejects.toThrow(/^SMTP delivery was not confirmed$/);
  expect(server.commands[1]).toBe('AUTH LOGIN\r\n');
  expect(decode64(server.commands[2])).toBe(config.SMTP_USERNAME);
  expect(decode64(server.commands[3])).toBe(config.SMTP_PASSWORD);
  expect(server.close).toHaveBeenCalledOnce();
});

test('fails closed for invalid headers, missing secrets, insecure config and mismatched sender', async () => {
  for (const changes of [{ SMTP_PASSWORD: '' }, { SMTP_SECURITY: 'none' }, { SMTP_FROM_EMAIL: 'unrelated@example.com' }, { SMTP_EHLO_DOMAIN: 'test\r\nNOOP' }]) {
    await expect(sendMail({ ...config, ...changes }, message)).rejects.toThrow();
  }
  await expect(sendMail(config, { ...message, to: 'ok@example.org\r\nBCC: other@example.org' })).rejects.toThrow();
  await expect(sendMail(config, { ...message, subject: 'Reset\r\nBcc: somebody' })).rejects.toThrow();
  expect(connect).not.toHaveBeenCalled();
});

test('requires a supported authenticated mechanism and bounds a stalled exchange', async () => {
  let server = mockServer(['250-relay\n250 SIZE 1000']);
  await expect(sendMail(config, message)).rejects.toThrow();
  expect(server.commands).toEqual(['EHLO osmcreations.com\r\n']);
  vi.useFakeTimers();
  server = mockServer([]);
  const pending = expect(sendMail(config, message)).rejects.toThrow('SMTP delivery was not confirmed');
  await vi.advanceTimersByTimeAsync(20001);
  await pending;
  expect(server.close).toHaveBeenCalledOnce();
});
