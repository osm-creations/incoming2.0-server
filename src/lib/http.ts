import type { Context } from 'hono';
import { z, type ZodType } from 'zod';
import type { Bindings, Variables } from '../types/env';

export function ok<T>(c: Context<{ Bindings: Bindings; Variables: Variables }>, data: T, status: 200 | 201 = 200) {
  return c.json({ data }, status);
}

export function apiError(c: Context<{ Bindings: Bindings; Variables: Variables }>, status: 400 | 401 | 403 | 404 | 409 | 422 | 429 | 500, code: string, message: string) {
  return c.json({ error: { code, message, requestId: c.get('requestId') } }, status);
}

export async function jsonBody<S extends ZodType>(c: Context, schema: S): Promise<{ data: z.infer<S> } | { error: Response }> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    return { error: c.json({ error: { code: 'INVALID_JSON', message: 'Invalid JSON body.' } }, 400) };
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map(issue => ({
      field: issue.path.length ? issue.path.join('.') : 'request',
      message: issue.message
    }));
    return {
      error: c.json({
        error: {
          code: 'VALIDATION_ERROR',
          message: issues[0]?.message ?? 'Request validation failed.',
          details: issues
        }
      }, 422)
    };
  }
  return { data: parsed.data as z.infer<S> };
}
