export const ACCESS_TOKEN_COOKIE = 'access_token';
export const REFRESH_TOKEN_COOKIE = 'refresh_token';

/**
 * Danh sách tên cookie chuẩn dùng cho cả cha và con
 */
export const getAuthCookieNames = () => ({
  access: ACCESS_TOKEN_COOKIE,
  refresh: REFRESH_TOKEN_COOKIE,
});

/**
 * Cookie options cho subdomain con (vn.hyperdatalab.org hoặc localhost)
 * @param {Object} extra - Các options mở rộng (maxAge, domain, ...)
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

export const getChildCookieOptions = (kind = 'access', extra = {}) => {
  return getCookieOptions(extra);
};

export const getClearAuthCookieOptions = (extra = {}) => {
  return getCookieOptions(extra);
};

/**
 * Cookie clear options cho domain cha (.hyperdatalab.org)
 * Dùng khi user nhấn Logout tại site con để xóa session của cha
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
