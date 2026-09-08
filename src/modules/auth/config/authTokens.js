import jwt from 'jsonwebtoken';

export const PARENT_DOMAIN = 'hyperdatalab.org';
export const CHILD_DOMAIN = 'vn.hyperdatalab.org';

/**
 * Kiểm tra xem token payload có phải được phát hành bởi hệ thống cha (hyperdatalab.org) hay không
 * @param {Object} decoded - Payload đã giải mã của JWT
 * @returns {boolean}
 */
export const isParentToken = (decoded) => {
  if (!decoded) return false;
  return decoded.domain === PARENT_DOMAIN || decoded.iss === PARENT_DOMAIN;
};

/**
 * Lấy JWT Secret chung cho hệ thống
 */
export const getJwtSecret = () => {
  const secret = process.env.JWT_SECRET || process.env.PARENT_JWT_SECRET;
  if (!secret) {
    throw new Error('Missing JWT_SECRET in environment variables');
  }
  return secret;
};

/**
 * Xác minh access token với JWT_SECRET
 * @param {string} token
 * @returns {Object} decoded payload
 */
export const verifyAccessToken = (token) => {
  const secret = getJwtSecret();
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
};

/**
 * Ký token mới cho site con vn.hyperdatalab.org
 * @param {Object} user
 * @param {Object} extra
 */
export const signChildAccessToken = (user, extra = {}) => {
  const secret = getJwtSecret();
  return jwt.sign(
    {
      user_id: user.user_id,
      email: user.email,
      role: user.role,
      domain: process.env.COOKIE_DOMAIN?.replace(/^\./, '') || CHILD_DOMAIN,
      ...extra,
    },
    secret,
    {
      algorithm: 'HS256',
      expiresIn: process.env.JWT_EXPIRES_IN || '1d',
    }
  );
};
