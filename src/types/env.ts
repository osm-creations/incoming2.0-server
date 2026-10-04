export type Bindings = {
  DB: D1Database;
  PUBLIC_BASE_URL: string;
  ALLOWED_ORIGINS: string;
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
