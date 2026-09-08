export const ACCESS_TOKEN_COOKIE = 'access_token';
export const REFRESH_TOKEN_COOKIE = 'refresh_token';

/**
 * Danh sách tên cookie chuẩn dùng cho toàn hệ thống
 */
export const getAuthCookieNames = () => ({
  access: ACCESS_TOKEN_COOKIE,
  refresh: REFRESH_TOKEN_COOKIE,
});

const defaultMaxAge = {
  access: 86400,
  refresh: 604800,
};

const configuredMaxAge = (kind) => {
  const envName = kind === 'refresh' ? 'COOKIE_REFRESH_MAX_AGE' : 'COOKIE_ACCESS_MAX_AGE';
  const parsed = Number(process.env[envName]);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : defaultMaxAge[kind];
};

export const getAuthCookieOptions = (kind, overrides = {}) => {
  const isProd = process.env.NODE_ENV?.trim() === 'production';
  const cookieDomain = process.env.COOKIE_DOMAIN?.trim();

  const options = {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
    ...(cookieDomain ? { domain: cookieDomain } : {}),
  };

  if (kind === 'access' || kind === 'refresh') {
    options.maxAge = configuredMaxAge(kind);
  }

  return { ...options, ...overrides };
};

export const getClearAuthCookieOptions = (overrides = {}) => {
  const isProd = process.env.NODE_ENV?.trim() === 'production';
  const cookieDomain = process.env.COOKIE_DOMAIN?.trim();

  return {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
    ...(cookieDomain ? { domain: cookieDomain } : {}),
    ...overrides,
  };
};

export const getParentCookieClearOptions = (overrides = {}) => ({
  httpOnly: true,
  secure: true,
  sameSite: 'none',
  path: '/',
  domain: process.env.PARENT_COOKIE_DOMAIN?.trim() || '.hyperdatalab.org',
  ...overrides,
});
