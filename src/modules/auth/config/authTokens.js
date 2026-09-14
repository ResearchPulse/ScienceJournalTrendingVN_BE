import jwt from 'jsonwebtoken';

export const CHILD_ACCESS_ISSUER = 'vietnam-api.hyperdatalab.org';
export const CHILD_ACCESS_AUDIENCE = 'vn.hyperdatalab.org';

const requiredSecret = (...names) => {
  for (const name of names) {
    const value = process.env[name]?.trim();
    if (value) return value;
  }
  throw new Error(`Missing ${names.join(' or ')} in environment variables`);
};

export const getChildAccessSecret = () => requiredSecret('VN_JWT_SECRET', 'JWT_SECRET');
export const getChildRefreshSecret = () => requiredSecret('VN_JWT_REFRESH_SECRET', 'JWT_REFRESH_SECRET');
export const getParentAccessSecret = () => requiredSecret('PARENT_JWT_SECRET', 'JWT_SECRET');
export const getSsoBlockSecret = () => requiredSecret('VN_SSO_BLOCK_SECRET', 'VN_JWT_SECRET', 'JWT_SECRET');

const childBaseOptions = {
  algorithm: 'HS256',
  issuer: CHILD_ACCESS_ISSUER,
  audience: CHILD_ACCESS_AUDIENCE,
};

export const signChildAccessToken = (user, options = {}) => jwt.sign(
  {
    user_id: user.user_id,
    email: user.email,
    role: user.role,
    token_use: 'access',
    ...(user.auth_source ? { auth_source: user.auth_source } : {}),
    ...(user.parent_fingerprint ? { parent_fingerprint: user.parent_fingerprint } : {}),
  },
  getChildAccessSecret(),
  {
    ...childBaseOptions,
    expiresIn: options.expiresIn || process.env.JWT_EXPIRES_IN || '1d',
  },
);

const verifyChildToken = (token, secret, expectedUse) => {
  const decoded = jwt.verify(token, secret, {
    algorithms: ['HS256'],
    issuer: CHILD_ACCESS_ISSUER,
    audience: CHILD_ACCESS_AUDIENCE,
  });
  if (decoded.token_use !== expectedUse) throw new Error(`Unexpected token_use: ${decoded.token_use}`);
  return decoded;
};

export const verifyChildAccessToken = (token) => verifyChildToken(token, getChildAccessSecret(), 'access');

export const signChildRefreshToken = (user, options = {}) => jwt.sign(
  {
    user_id: user.user_id,
    email: user.email,
    role: user.role,
    token_use: 'refresh',
  },
  getChildRefreshSecret(),
  {
    ...childBaseOptions,
    expiresIn: options.expiresIn || process.env.JWT_REFRESH_EXPIRES_IN || '30d',
  },
);

export const verifyChildRefreshToken = (token) => verifyChildToken(token, getChildRefreshSecret(), 'refresh');

export const signActivationToken = (user) => jwt.sign(
  { user_id: user.user_id, email: user.email, token_use: 'activation' },
  getChildAccessSecret(),
  { ...childBaseOptions, expiresIn: '24h' },
);

export const verifyActivationToken = (token) => verifyChildToken(token, getChildAccessSecret(), 'activation');

export const verifyParentAccessToken = (token) => {
  const decoded = jwt.verify(token, getParentAccessSecret(), { algorithms: ['HS256'] });
  const audiences = Array.isArray(decoded.aud) ? decoded.aud : [decoded.aud];
  if (decoded.iss === CHILD_ACCESS_ISSUER && audiences.includes(CHILD_ACCESS_AUDIENCE)) {
    throw new Error('Child token cannot be used as a parent session');
  }
  return decoded;
};
