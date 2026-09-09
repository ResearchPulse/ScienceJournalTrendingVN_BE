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

/**
 * Danh sách tên cookie chuẩn dùng cho toàn hệ thống
 */
export const getAuthCookieNames = () => (
  process.env.NODE_ENV?.trim() === 'production'
    ? COOKIE_NAMES.production
    : COOKIE_NAMES.development
);

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

  const options = {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
  };

  if (kind === 'access' || kind === 'refresh') {
    options.maxAge = configuredMaxAge(kind);
  }

  return { ...options, ...overrides };
};

export const getClearAuthCookieOptions = (overrides = {}) => {
  const isProd = process.env.NODE_ENV?.trim() === 'production';

  return {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
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

const cookieDomainVariants = (domain) => {
  const bareDomain = String(domain || '').trim().replace(/^\./, '');
  return bareDomain ? [`.${bareDomain}`, bareDomain] : [];
};

/**
 * Return every cookie scope that logout must expire.
 *
 * The first target is deliberately host-only, even when COOKIE_DOMAIN is set,
 * so cookies created by an older deployment cannot survive a configuration
 * change. Domain targets cover both the configured child scope and the shared
 * parent SSO scope.
 */
export const getAuthCookieClearTargets = () => {
  const hostOnlyOptions = getClearAuthCookieOptions();

  const domainTargets = new Map();
  const configuredDomain = process.env.COOKIE_DOMAIN?.trim();
  if (configuredDomain) {
    cookieDomainVariants(configuredDomain).forEach((domain) => {
      domainTargets.set(domain, { ...hostOnlyOptions, domain });
    });
  }

  const parentOptions = getParentCookieClearOptions();
  cookieDomainVariants(parentOptions.domain).forEach((domain) => {
    domainTargets.set(domain, { ...parentOptions, domain });
  });

  return [hostOnlyOptions, ...domainTargets.values()];
};
