const COOKIE_NAMES = {
  production: {
    access: '__Host-vn_access_token',
    refresh: '__Host-vn_refresh_token',
    blocker: '__Host-vn_sso_block',
  },
  development: {
    access: 'vn_access_token_dev',
    refresh: 'vn_refresh_token_dev',
    blocker: 'vn_sso_block_dev',
  },
};

const defaultMaxAge = {
  access: 86400,
  refresh: 604800,
};

const configuredMaxAge = (kind) => {
  const envName = kind === 'refresh' ? 'COOKIE_REFRESH_MAX_AGE' : 'COOKIE_ACCESS_MAX_AGE';
  const parsed = Number(process.env[envName]);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : defaultMaxAge[kind];
};

export const getAuthCookieNames = () => (
  process.env.NODE_ENV === 'production' ? COOKIE_NAMES.production : COOKIE_NAMES.development
);

export const getAuthCookieOptions = (kind, overrides = {}) => {
  const options = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  };

  if (kind === 'access' || kind === 'refresh') {
    options.maxAge = configuredMaxAge(kind);
  }

  return { ...options, ...overrides };
};

export const getClearAuthCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/',
});
