import type { Bindings } from '../types/env';

export function resetSite(env: Bindings): URL | undefined {
  const address = env.RESET_PUBLIC_URL ?? 'https://incoming-2-0-password-reset.incoming-osmcreations.workers.dev/';
  if (!URL.canParse(address)) return;
  const site = new URL(address);
  if (site.protocol === 'https:' && !site.username && !site.password) return site;
}
