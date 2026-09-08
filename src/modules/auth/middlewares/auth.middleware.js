import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import logger from '../../../utils/logger.js';
import prisma from '../../../config/prisma.js';
import { createLog } from '../../system/services/log.service.js';
import { isParentToken, verifyAccessToken } from '../config/authTokens.js';

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
        message: 'Khong tim thay token xac thuc hoac token khong hop le'
      });
    }

    const decoded = verifyAccessToken(token);
    request.user = {
      ...decoded,
      auth_source: isParentToken(decoded) ? 'parent_sso' : 'child_local',
    };
  } catch (error) {
    return reply.status(401).send({
      success: false,
      message: 'Token xac thuc khong hop le hoac da het han'
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
      message: "Ban chua dang nhap hoac phien lam viec da het han"
    });
  }

  try {
    const decoded = verifyAccessToken(accessToken);

    // Stateless Verification cho token do he thong cha (hyperdatalab.org) phat hanh
    // Khong truy van DB noi bo, gan thang du lieu vao request.user
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

    // Doi voi token do site con cap: kiem tra trong DB noi bo
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
        message: "Tai khoan cua ban da bi khoa hoac chua duoc kich hoat"
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
      message: "Access token khong hop le hoac da het han"
    });
  }
};

export const verifyAdmin = async (request, reply) => {
  if (!request.user) {
    return reply.status(401).send({
      success: false,
      message: 'Xac thuc khong thanh cong, khong tim thay thong tin nguoi dung.',
      code: 'UNAUTHENTICATED'
    });
  }

  if (request.user.role !== 'ADMINISTRATOR') {
    createLog({
      userId: request.user.user_id,
      userRole: request.user.role,
      action: 'SYSTEM',
      level: 'WARNING',
      message: `Tai khoan ${request.user.email} co gang truy cap tai nguyen Admin (Bi tu choi)`,
      metadata: { ip: request.ip, path: request.url }
    });
    return reply.status(403).send({
      success: false,
      message: 'Ban khong co quyen truy cap tai nguyen nay',
      code: 'NO_PERMISSION'
    });
  }
};