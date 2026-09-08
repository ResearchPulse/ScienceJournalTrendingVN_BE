import prisma from '../../../config/prisma.js';
import { createLog } from '../../system/services/log.service.js';
import { verifyChildAccessToken, verifyParentAccessToken } from '../config/authTokens.js';
import { getAuthCookieNames } from '../utils/authCookies.js';
import { resolveLocalSsoUser } from '../services/sso.service.js';

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

const currentLocalUser = async (decoded) => {
  const user = await authUserRepository.findById(decoded.user_id);
  if (!user || user.status !== 'ACTIVE') {
    const error = new Error('Local account is unavailable');
    error.statusCode = 403;
    error.code = 'ACCOUNT_UNAVAILABLE';
    throw error;
  }
  return {
    ...decoded,
    user_id: user.user_id,
    email: user.email,
    role: user.role,
    status: user.status,
    type: user.type,
  };
};

const parentLocalUser = async (decoded) => {
  const user = await resolveLocalSsoUser(decoded.email || decoded.username);
  return {
    user_id: user.user_id,
    email: user.email,
    role: user.role,
    status: user.status,
    type: user.type,
    auth_source: 'parent_sso',
  };
};

const tokenFromRequest = (request) => {
  const bearer = request.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  if (bearer) return { token: bearer, source: 'bearer' };

  const childToken = request.cookies?.[getAuthCookieNames().access];
  if (childToken) return { token: childToken, source: 'child' };

  const parentToken = request.cookies?.access_token;
  return parentToken ? { token: parentToken, source: 'parent' } : null;
};

export const resolveAuthenticatedUser = async (request) => {
  const candidate = tokenFromRequest(request);
  if (!candidate) {
    const error = new Error('Authentication token missing');
    error.statusCode = 401;
    error.code = 'ACCESS_TOKEN_MISSING';
    throw error;
  }

  if (candidate.source === 'child') {
    return currentLocalUser(verifyChildAccessToken(candidate.token));
  }
  if (candidate.source === 'parent') {
    return parentLocalUser(verifyParentAccessToken(candidate.token));
  }

  try {
    return await currentLocalUser(verifyChildAccessToken(candidate.token));
  } catch (childError) {
    if (childError.statusCode === 403) throw childError;
    return parentLocalUser(verifyParentAccessToken(candidate.token));
  }
};

const authenticate = async (request, reply, missingMessage, invalidMessage) => {
  try {
    request.user = await resolveAuthenticatedUser(request);
  } catch (error) {
    const statusCode = error.statusCode || 401;
    const code = error.code || (statusCode === 401 ? 'ACCESS_TOKEN_INVALID' : 'ACCOUNT_UNAVAILABLE');
    const message = code === 'ACCESS_TOKEN_MISSING' ? missingMessage : (error.message || invalidMessage);
    if (!reply.sent) reject(reply, statusCode, code, message);
  }
};

export const requireAuth = async (request, reply) => authenticate(
  request,
  reply,
  'Không tìm thấy token xác thực',
  'Token xác thực không hợp lệ hoặc đã hết hạn',
);

export const verifyToken = async (request, reply) => authenticate(
  request,
  reply,
  'Bạn chưa đăng nhập hoặc phiên làm việc đã hết hạn',
  'Access token không hợp lệ hoặc đã hết hạn',
);

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
