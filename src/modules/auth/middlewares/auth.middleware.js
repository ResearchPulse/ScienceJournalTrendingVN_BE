import prisma from '../../../config/prisma.js';
import { createLog } from '../../system/services/log.service.js';
import { verifyChildAccessToken } from '../config/authTokens.js';
import { getAuthCookieNames } from '../utils/authCookies.js';
import { verifyBlocker } from '../services/sso.service.js';

const reject = (reply, statusCode, code, message) => reply.status(statusCode).send({
  success: false,
  ...(code ? { code } : {}),
  message,
});

export const authUserRepository = {
  findById: (userId) => prisma.user.findUnique({
    where: { user_id: userId },
    select: { user_id: true, email: true, role: true, status: true, type: true },
  }),
};

const attachCurrentUser = async (request, reply, decoded) => {
  const user = await authUserRepository.findById(decoded.user_id);
  if (!user || user.status !== 'ACTIVE') {
    reject(reply, 403, 'ACCOUNT_UNAVAILABLE', 'Tài khoản không còn hoạt động');
    return false;
  }

  if (decoded.auth_source === 'parent_sso' && decoded.parent_fingerprint) {
    const blocker = verifyBlocker(request.cookies?.[getAuthCookieNames().blocker]);
    if (blocker?.fingerprint === decoded.parent_fingerprint) {
      reject(reply, 401, 'SSO_BLOCKED', 'SSO session was ended on this child system');
      return false;
    }
  }

  request.user = {
    ...decoded,
    user_id: user.user_id,
    email: user.email,
    role: user.role,
    status: user.status,
    type: user.type,
  };
  return true;
};

const tokenFromRequest = (request) => {
  const authHeader = request.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) return authHeader.slice(7).trim();
  return request.cookies?.[getAuthCookieNames().access] || null;
};

export const requireAuth = async (request, reply) => {
  const token = tokenFromRequest(request);
  if (!token) return reject(reply, 401, 'ACCESS_TOKEN_MISSING', 'Không tìm thấy token xác thực');
  try {
    const decoded = verifyChildAccessToken(token);
    await attachCurrentUser(request, reply, decoded);
  } catch (error) {
    if (!reply.sent) reject(reply, 401, 'ACCESS_TOKEN_INVALID', 'Token xác thực không hợp lệ hoặc đã hết hạn');
  }
};

export const verifyToken = async (request, reply) => {
  const token = tokenFromRequest(request);
  if (!token) return reject(reply, 401, 'ACCESS_TOKEN_MISSING', 'Bạn chưa đăng nhập hoặc phiên làm việc đã hết hạn');
  try {
    const decoded = verifyChildAccessToken(token);
    await attachCurrentUser(request, reply, decoded);
  } catch (error) {
    if (!reply.sent) reject(reply, 401, 'ACCESS_TOKEN_INVALID', 'Access token không hợp lệ hoặc đã hết hạn');
  }
};

export const verifyAdmin = async (request, reply) => {
  if (!request.user) return reject(reply, 401, 'UNAUTHENTICATED', 'Xác thực không thành công');
  if (request.user.role !== 'ADMINISTRATOR') {
    await createLog({
      userId: request.user.user_id,
      userRole: request.user.role,
      action: 'SYSTEM',
      level: 'WARNING',
      message: `Tài khoản ${request.user.email} cố gắng truy cập tài nguyên Admin`,
      metadata: { ip: request.ip, path: request.url },
    });
    return reject(reply, 403, 'NO_PERMISSION', 'Bạn không có quyền truy cập tài nguyên này');
  }
};
