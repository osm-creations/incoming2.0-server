export type Bindings = {
  DB: D1Database;
  PUBLIC_BASE_URL: string;
  INJECT_SELECTION_URL_TEMPLATE?: string;
  PLAIN_PRESENTATION_ACCOUNT?: string;
  ALLOWED_ORIGINS: string;
  CORS_ALLOWED_ORIGINS?: string;
  RESET_PUBLIC_URL: string;
  SMTP_HOST?: string;
  SMTP_PORT?: string;
  SMTP_SECURITY?: string;
  SMTP_FROM_EMAIL?: string;
  SMTP_FROM_NAME?: string;
  SMTP_EHLO_DOMAIN?: string;
  SMTP_AUTH_METHOD?: string;
  SMTP_ALLOW_DIFFERENT_FROM?: string;
  SMTP_USERNAME?: string;
  SMTP_PASSWORD?: string;
  ACCESS_TOKEN_TTL_SECONDS: string;
  REFRESH_TOKEN_TTL_SECONDS: string;
  APP_CLIP_SESSION_TTL_SECONDS: string;
  APP_CLIP_APP_ID: string;
  PARENT_APP_ID: string;
  JWT_SECRET: string;
  TOKEN_PEPPER: string;
  CAPABILITY_SIGNING_SECRET: string;
  SETUP_SECRET: string;
};

export type AuthUser = {
  id: string;
  publicUserId: string;
  email: string;
  role: 'ADMIN' | 'MAGICIAN';
  status: 'ACTIVE' | 'DISABLED';
};

export type Variables = {
  requestId: string;
  authUser?: AuthUser;
};
