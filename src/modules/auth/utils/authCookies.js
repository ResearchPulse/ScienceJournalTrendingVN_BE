export const ACCESS_TOKEN_COOKIE = 'access_token';
export const REFRESH_TOKEN_COOKIE = 'refresh_token';

/**
 * Danh sach ten cookie chuan dung cho ca cha va con
 */
export const getAuthCookieNames = () => ({
  access: ACCESS_TOKEN_COOKIE,
  refresh: REFRESH_TOKEN_COOKIE,
});

/**
 * Cookie options cho subdomain con (vn.hyperdatalab.org hoac localhost)
 * @param {Object} extra - Cac options mo rong (maxAge, domain, ...)
 */
export const getCookieOptions = (extra = {}) => {
  const isProd = process.env.NODE_ENV?.trim() === 'production';
  const cookieDomain = process.env.COOKIE_DOMAIN?.trim();

  return {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
    ...(cookieDomain ? { domain: cookieDomain } : {}),
    ...extra,
  };
};

export const getAuthCookieOptions = (kind, overrides = {}) => {
  return getCookieOptions(overrides);
};

export const getChildCookieOptions = (kind = 'access', extra = {}) => {
  return getCookieOptions(extra);
};

export const getClearAuthCookieOptions = (extra = {}) => {
  return getCookieOptions(extra);
};

/**
 * Cookie clear options cho domain cha (.hyperdatalab.org)
 * Dung khi user nhan Logout tai site con de xoa session cua cha
 */
export const getParentCookieClearOptions = (extra = {}) => {
  const isProd = process.env.NODE_ENV?.trim() === 'production';
  const parentDomain = process.env.PARENT_COOKIE_DOMAIN?.trim() || '.hyperdatalab.org';

  return {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
    ...(isProd || parentDomain.startsWith('.') ? { domain: parentDomain } : {}),
    ...extra,
  };
};