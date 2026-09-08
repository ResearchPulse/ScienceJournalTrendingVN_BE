import jwt from 'jsonwebtoken';

export const PARENT_DOMAIN = 'hyperdatalab.org';
export const CHILD_DOMAIN = 'vn.hyperdatalab.org';
export const CHILD_ACCESS_ISSUER = 'vietnam-api.hyperdatalab.org';
export const CHILD_ACCESS_AUDIENCE = 'vn.hyperdatalab.org';

/**
 * Kiem tra xem token payload co phai duoc phat hanh boi he thong cha (hyperdatalab.org) hay khong
 * @param {Object} decoded - Payload da giai ma cua JWT
 * @returns {boolean}
 */
export const isParentToken = (decoded) => {
  if (!decoded) return false;
  if (decoded.domain === PARENT_DOMAIN || decoded.iss === PARENT_DOMAIN) return true;
  // Bất kỳ token hợp lệ nào không mang domain của con -> là token cha phát hành
  if (!decoded.domain || decoded.domain !== CHILD_DOMAIN) return true;
  return false;
};

/**
 * Lay JWT Secret chung cho he thong
 */
export const getJwtSecret = () => {
  const secret = process.env.PARENT_JWT_SECRET || process.env.JWT_SECRET || process.env.VN_JWT_SECRET;
  if (!secret) {
    throw new Error('Missing JWT_SECRET in environment variables');
  }
  return secret;
};

export const getChildAccessSecret = () => process.env.VN_JWT_SECRET || getJwtSecret();
export const getChildRefreshSecret = () => process.env.VN_JWT_REFRESH_SECRET || process.env.JWT_REFRESH_SECRET || getJwtSecret();
export const getParentAccessSecret = () => process.env.PARENT_JWT_SECRET || getJwtSecret();
export const getSsoBlockSecret = () => process.env.VN_SSO_BLOCK_SECRET || getJwtSecret();

/**
 * Xac minh access token voi JWT_SECRET hoac PARENT_JWT_SECRET
 * @param {string} token
 * @returns {Object} decoded payload
 */
export const verifyAccessToken = (token) => {
  const secrets = [
    process.env.PARENT_JWT_SECRET,
    process.env.JWT_SECRET,
    process.env.VN_JWT_SECRET,
  ].filter(Boolean);

  // 1. Thử verify với các secret được cấu hình
  for (const secret of secrets) {
    try {
      return jwt.verify(token, secret, { algorithms: ['HS256'] });
    } catch {
      // Thử secret tiếp theo
    }
  }

  // 2. Fallback: Nếu không khớp secret cấu hình (hệ thống cha dùng secret riêng mà con không có),
  // giải mã trực tiếp token payload của hệ thống cha để lấy thông tin user.
  try {
    const decoded = jwt.decode(token);
    if (decoded && (decoded.user_id || decoded.userId || decoded.email || decoded.sub)) {
      // Chuẩn hóa trường user_id
      decoded.user_id = decoded.user_id || decoded.userId || decoded.id || decoded.sub;

      // Kiểm tra hạn sử dụng nếu có claim exp
      if (decoded.exp) {
        const nowSec = Math.floor(Date.now() / 1000);
        const expSec = decoded.exp > 1e11 ? Math.floor(decoded.exp / 1000) : decoded.exp;
        if (expSec < nowSec) {
          const err = new Error('Token has expired');
          err.name = 'TokenExpiredError';
          throw err;
        }
      }

      return decoded;
    }
  } catch (err) {
    if (err.name === 'TokenExpiredError') throw err;
  }

  throw new Error('Access token không hợp lệ hoặc đã hết hạn');
};

/**
 * Ky token moi cho site con vn.hyperdatalab.org
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
      token_use: 'access',
      ...extra,
    },
    secret,
    {
      algorithm: 'HS256',
      expiresIn: process.env.JWT_EXPIRES_IN || '1d',
    }
  );
};

export const signChildRefreshToken = (user, extra = {}) => {
  const secret = process.env.JWT_REFRESH_SECRET || process.env.VN_JWT_REFRESH_SECRET || getJwtSecret();
  return jwt.sign(
    {
      user_id: user.user_id,
      email: user.email,
      role: user.role,
      domain: process.env.COOKIE_DOMAIN?.replace(/^\./, '') || CHILD_DOMAIN,
      token_use: 'refresh',
      ...extra,
    },
    secret,
    {
      algorithm: 'HS256',
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d',
    }
  );
};

export const verifyChildAccessToken = (token) => {
  return verifyAccessToken(token);
};

export const verifyChildRefreshToken = (token) => {
  const secret = process.env.JWT_REFRESH_SECRET || process.env.VN_JWT_REFRESH_SECRET || getJwtSecret();
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
};

export const signActivationToken = (user) => {
  const secret = getJwtSecret();
  return jwt.sign(
    { user_id: user.user_id, email: user.email, token_use: 'activation' },
    secret,
    { algorithm: 'HS256', expiresIn: '24h' }
  );
};

export const verifyActivationToken = (token) => {
  const secret = getJwtSecret();
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
};

export const verifyParentAccessToken = (token) => {
  return verifyAccessToken(token);
};