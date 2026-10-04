import { Hono } from 'hono';
import { z } from 'zod';
import type { Bindings, Variables } from '../types/env';
import { authMiddleware, magicianOnly } from '../middleware/core';
import { apiError, jsonBody, ok } from '../lib/http';
import { audit } from '../lib/db';
import { issueCapability } from '../lib/security';
import { randomPublicId } from '../lib/encoding';

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();
app.use('*', authMiddleware, magicianOnly);

const configSchema = z.object({
  name: z.string().trim().min(1).max(60),
  mode: z.enum(['MENU','STATIC','DIRECT_NOTES']),
  staticText: z.string().max(500).nullable().optional(),
  openOverflowInitially: z.boolean().default(false),
  enabled: z.boolean().default(true)
});

async function ownedConfig(c: any, id: string) {
  return c.env.DB.prepare(`SELECT * FROM clip_configs WHERE id=?1 AND owner_user_id=?2`).bind(id, c.get('authUser').id).first();
}

async function invocationUrl(c: any, row: any) {
  const cap = await issueCapability({ publicUserId: c.get('authUser').publicUserId, publicConfigId: row.public_config_id, version: row.capability_version }, c.env);
  const base = c.env.PUBLIC_BASE_URL.replace(/\/$/, '');
  return `${base}/c/${encodeURIComponent(c.get('authUser').publicUserId)}/${encodeURIComponent(row.public_config_id)}?t=${encodeURIComponent(cap)}`;
}

app.get('/', async c => {
  const result = await c.env.DB.prepare(`SELECT id, public_config_id, name, mode, enabled, static_text, open_overflow_initially, capability_version, created_at, updated_at FROM clip_configs WHERE owner_user_id=?1 ORDER BY created_at DESC`).bind(c.get('authUser')!.id).all<any>();
  const configs = await Promise.all(result.results.map(async row => ({ ...row, invocation_url: await invocationUrl(c, row) })));
  return ok(c, { configs });
});

app.post('/', async c => {
  const body = await jsonBody(c, configSchema);
  if ('error' in body) return body.error;
  const id = crypto.randomUUID();
  const publicConfigId = randomPublicId('clip', 7);
  const now = new Date().toISOString();
  await c.env.DB.prepare(`INSERT INTO clip_configs (id, owner_user_id, public_config_id, name, mode, enabled, static_text, open_overflow_initially, capability_version, created_at, updated_at)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?9)`)
    .bind(id, c.get('authUser')!.id, publicConfigId, body.data.name, body.data.mode, body.data.enabled ? 1 : 0, body.data.staticText ?? null, body.data.openOverflowInitially ? 1 : 0, now).run();
  const row = await ownedConfig(c, id);
  await audit(c.env.DB, { actorUserId: c.get('authUser')!.id, action: 'CLIP_CONFIG_CREATED', targetType: 'CLIP_CONFIG', targetId: id, requestId: c.get('requestId') });
  return ok(c, { config: row, invocationUrl: await invocationUrl(c, row) }, 201);
});

app.get('/:id', async c => {
  const row = await ownedConfig(c, c.req.param('id'));
  if (!row) return apiError(c, 404, 'NOT_FOUND', 'Configuration not found.');
  const options = await c.env.DB.prepare(`SELECT id, value, display_order, enabled FROM clip_menu_options WHERE config_id=?1 ORDER BY display_order`).bind(row.id).all();
  return ok(c, { config: row, options: options.results, invocationUrl: await invocationUrl(c, row) });
});

const patchSchema = configSchema.partial();
app.patch('/:id', async c => {
  const row = await ownedConfig(c, c.req.param('id'));
  if (!row) return apiError(c, 404, 'NOT_FOUND', 'Configuration not found.');
  const body = await jsonBody(c, patchSchema);
  if ('error' in body) return body.error;
  const v = body.data;
  await c.env.DB.prepare(`UPDATE clip_configs SET
    name=COALESCE(?2,name), mode=COALESCE(?3,mode), enabled=COALESCE(?4,enabled), static_text=CASE WHEN ?5=1 THEN ?6 ELSE static_text END,
    open_overflow_initially=COALESCE(?7,open_overflow_initially), updated_at=?8 WHERE id=?1`)
    .bind(row.id, v.name ?? null, v.mode ?? null, v.enabled === undefined ? null : (v.enabled ? 1 : 0), Object.prototype.hasOwnProperty.call(v, 'staticText') ? 1 : 0, v.staticText ?? null, v.openOverflowInitially === undefined ? null : (v.openOverflowInitially ? 1 : 0), new Date().toISOString()).run();
  await audit(c.env.DB, { actorUserId: c.get('authUser')!.id, action: 'CLIP_CONFIG_UPDATED', targetType: 'CLIP_CONFIG', targetId: row.id, requestId: c.get('requestId') });
  return ok(c, { updated: true });
});

app.delete('/:id', async c => {
  const row = await ownedConfig(c, c.req.param('id'));
  if (!row) return apiError(c, 404, 'NOT_FOUND', 'Configuration not found.');
  await c.env.DB.prepare(`DELETE FROM clip_configs WHERE id=?1`).bind(row.id).run();
  await audit(c.env.DB, { actorUserId: c.get('authUser')!.id, action: 'CLIP_CONFIG_DELETED', targetType: 'CLIP_CONFIG', targetId: row.id, requestId: c.get('requestId') });
  return ok(c, { deleted: true });
});

app.post('/:id/rotate-link', async c => {
  const row = await ownedConfig(c, c.req.param('id'));
  if (!row) return apiError(c, 404, 'NOT_FOUND', 'Configuration not found.');
  await c.env.DB.prepare(`UPDATE clip_configs SET capability_version=capability_version+1, updated_at=?2 WHERE id=?1`).bind(row.id, new Date().toISOString()).run();
  const updated = await ownedConfig(c, row.id);
  await audit(c.env.DB, { actorUserId: c.get('authUser')!.id, action: 'CLIP_LINK_ROTATED', targetType: 'CLIP_CONFIG', targetId: row.id, requestId: c.get('requestId') });
  return ok(c, { invocationUrl: await invocationUrl(c, updated) });
});

const optionSchema = z.object({ value: z.string().trim().min(1).max(120), displayOrder: z.number().int().min(0).max(1000).default(0), enabled: z.boolean().default(true) });
app.post('/:id/options', async c => {
  const config = await ownedConfig(c, c.req.param('id'));
  if (!config) return apiError(c, 404, 'NOT_FOUND', 'Configuration not found.');
  const body = await jsonBody(c, optionSchema);
  if ('error' in body) return body.error;
  const id = crypto.randomUUID(), now = new Date().toISOString();
  await c.env.DB.prepare(`INSERT INTO clip_menu_options (id, config_id, value, display_order, enabled, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)`)
    .bind(id, config.id, body.data.value, body.data.displayOrder, body.data.enabled ? 1 : 0, now).run();
  return ok(c, { id }, 201);
});

app.patch('/:id/options/:optionId', async c => {
  const config = await ownedConfig(c, c.req.param('id'));
  if (!config) return apiError(c, 404, 'NOT_FOUND', 'Configuration not found.');
  const body = await jsonBody(c, optionSchema.partial());
  if ('error' in body) return body.error;
  const opt = await c.env.DB.prepare(`SELECT id FROM clip_menu_options WHERE id=?1 AND config_id=?2`).bind(c.req.param('optionId'), config.id).first();
  if (!opt) return apiError(c, 404, 'NOT_FOUND', 'Option not found.');
  await c.env.DB.prepare(`UPDATE clip_menu_options SET value=COALESCE(?2,value), display_order=COALESCE(?3,display_order), enabled=COALESCE(?4,enabled), updated_at=?5 WHERE id=?1`)
    .bind(c.req.param('optionId'), body.data.value ?? null, body.data.displayOrder ?? null, body.data.enabled === undefined ? null : (body.data.enabled ? 1 : 0), new Date().toISOString()).run();
  return ok(c, { updated: true });
});

app.delete('/:id/options/:optionId', async c => {
  const config = await ownedConfig(c, c.req.param('id'));
  if (!config) return apiError(c, 404, 'NOT_FOUND', 'Configuration not found.');
  const result = await c.env.DB.prepare(`DELETE FROM clip_menu_options WHERE id=?1 AND config_id=?2`).bind(c.req.param('optionId'), config.id).run();
  if (!result.meta.changes) return apiError(c, 404, 'NOT_FOUND', 'Option not found.');
  return ok(c, { deleted: true });
});

export default app;
