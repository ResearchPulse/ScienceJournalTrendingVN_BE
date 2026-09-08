import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import logger from '../../../utils/logger.js';
import prisma from '../../../config/prisma.js';
import { createLog } from '../../system/services/log.service.js';
import { isParentToken } from '../config/authTokens.js';

export const authUserRepository = {
  findById: (id) => prisma.user.findUnique({ where: { user_id: id } }),
  findByEmail: (email) => prisma.user.findUnique({ where: { email } }),
};

export const requireAuth = async (request, reply) => {
  try {
    let token = null;
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else if (request.cookies?.access_token) {
      token = request.cookies.access_token;
    }

    if (!token) {
      return reply.status(401).send({
        success: false,
        message: 'Không tìm thấy token xác thực hoặc token không hợp lệ'
      });
    }

    if (!process.env.JWT_SECRET) {
      return reply.status(500).send({
        success: false,
        message: 'Lỗi cấu hình JWT trên server'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    request.user = {
      ...decoded,
      auth_source: isParentToken(decoded) ? 'parent_sso' : 'child_local',
    };
  } catch (error) {
    return reply.status(401).send({
      success: false,
      message: 'Token xác thực không hợp lệ hoặc đã hết hạn'
    });
  }
};

export const verifyToken = async (request, reply) => {
  let accessToken = null;

  const authHeader = request.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    accessToken = authHeader.split(' ')[1];
  }

  if (!accessToken && request.cookies) {
    accessToken = request.cookies.access_token;
  }

  if (!accessToken) {
    return reply.status(401).send({
      success: false,
      code: "ACCESS_TOKEN_MISSING",
      message: "Bạn chưa đăng nhập hoặc phiên làm việc đã hết hạn"
    });
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);

    // Stateless Verification cho token do hệ thống cha (hyperdatalab.org) phát hành
    // Không truy vấn DB nội bộ, gán thẳng dữ liệu vào request.user
    if (isParentToken(decoded)) {
      request.user = {
        ...decoded,
        user_id: decoded.user_id,
        role: decoded.role || 'STUDENT',
        email: decoded.email,
        auth_source: 'parent_sso',
        domain: decoded.domain || decoded.iss || 'hyperdatalab.org',
      };
      return;
    }

    // Đối với token do site con cấp: kiểm tra trong DB nội bộ
    let user = null;
    if (decoded.user_id) {
      user = await authUserRepository.findById(decoded.user_id);
    }

    if (!user && decoded.email) {
      user = await authUserRepository.findByEmail(decoded.email);
    }

    if (user && user.status !== 'ACTIVE') {
      return reply.status(403).send({
        success: false,
        code: "ACCOUNT_UNAVAILABLE",
        message: "Tài khoản của bạn đã bị khóa hoặc chưa được kích hoạt"
      });
    }

    request.user = {
      ...decoded,
      user_id: user ? user.user_id : decoded.user_id,
      role: user ? user.role : (decoded.role || 'STUDENT'),
      email: user ? user.email : decoded.email,
      auth_source: 'child_local',
    };
  } catch (error) {
    return reply.status(401).send({
      success: false,
      code: "ACCESS_TOKEN_EXPIRED",
      message: "Access token không hợp lệ hoặc đã hết hạn"
    });
  }
};

export const verifyAdmin = async (request, reply) => {
  if (!request.user) {
    return reply.status(401).send({
      success: false,
      message: 'Xác thực không thành công, không tìm thấy thông tin người dùng.',
      code: 'UNAUTHENTICATED'
    });
  }

  if (request.user.role !== 'ADMINISTRATOR') {
    createLog({
      userId: request.user.user_id,
      userRole: request.user.role,
      action: 'SYSTEM',
      level: 'WARNING',
      message: `Tài khoản ${request.user.email} cố gắng truy cập tài nguyên Admin (Bị từ chối)`,
      metadata: { ip: request.ip, path: request.url }
    });
    return reply.status(403).send({
      success: false,
      message: 'Bạn không có quyền truy cập tài nguyên này',
      code: 'NO_PERMISSION'
    });
  }
};
