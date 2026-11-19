const defaultTemplate = 'https://11z.co/_w/{userId}/selection';

export function injectSelectionUrl(configuredTemplate: string | undefined, userId: string): URL {
  const template = (configuredTemplate ?? defaultTemplate).trim();
  const parts = template.split('{userId}');
  const [prefix, suffix] = parts;
  // Require the origin to be complete before the placeholder. An ID may only
  // fill part of a path or query, never a host, port or credentials.
  if (parts.length !== 2 || !prefix || suffix === undefined ||
      !/^https:\/\/[^/?#\\{}]+[/?]/i.test(prefix) || /[{}#\\\s]/u.test(prefix + suffix)) {
    throw new Error('Invalid Inject URL template');
  }
  const url = new URL(prefix + encodeURIComponent(userId) + suffix);
  if (url.username || url.password) throw new Error('Invalid Inject URL credentials');
  return url;
}
