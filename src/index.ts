import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import auth from './routes/auth';
import admin from './routes/admin';
import setup from './routes/setup';
import clipConfigs from './routes/clipConfigs';
import appClip from './routes/appClip';
import performance from './routes/performance';
import { requestIdMiddleware } from './middleware/core';
import type { Bindings, Variables } from './types/env';

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

app.use('*', requestIdMiddleware);
app.use('*', secureHeaders({ contentSecurityPolicy: false }));
app.use('*', async (c, next) => {
  const allowed = new Set((c.env.ALLOWED_ORIGINS ?? '').split(',').map(v => v.trim()).filter(Boolean));
  return cors({
    origin: origin => allowed.has(origin) ? origin : '',
    credentials: true,
    allowHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Setup-Secret'],
    allowMethods: ['GET','POST','PATCH','DELETE','OPTIONS']
  })(c, next);
});

app.get('/health', c => c.json({ ok: true, service: 'incoming2-api' }));
app.get('/.well-known/apple-app-site-association', c => {
  c.header('Content-Type', 'application/json');
  c.header('Cache-Control', 'public, max-age=3600');
  return c.json({
    appclips: { apps: [c.env.APP_CLIP_APP_ID] },
    applinks: {
      details: [
        { appIDs: [c.env.PARENT_APP_ID], components: [{ '/': '/c/*' }] }
      ]
    }
  });
});

app.get('/c/:publicUserId/:publicConfigId', c => {
  c.header('Content-Type', 'text/html; charset=utf-8');
  return c.html(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Incoming</title></head><body style="margin:0;background:#05070d;color:#eef4ff;font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:grid;place-items:center;min-height:100vh"><main style="text-align:center;padding:32px"><div style="font-size:64px">↘</div><h1>Incoming</h1><p style="color:#9aa9c0">Open this experience on a supported iPhone.</p></main></body></html>`);
});

app.route('/api/v1/auth', auth);
app.route('/api/v1/setup', setup);
app.route('/api/v1/admin', admin);
app.route('/api/v1/clip-configs', clipConfigs);
app.route('/api/v1/app-clip', appClip);
app.route('/api/v1/performance', performance);

app.notFound(c => c.json({ error: { code: 'NOT_FOUND', message: 'Not found.', requestId: c.get('requestId') } }, 404));
app.onError((err, c) => {
  console.error(JSON.stringify({ level: 'error', requestId: c.get('requestId'), message: err.message }));
  return c.json({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong.', requestId: c.get('requestId') } }, 500);
});

export default app;
