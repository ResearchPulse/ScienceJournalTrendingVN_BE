import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import logger from '../../../utils/logger.js';
import prisma from '../../../config/prisma.js';
import { createLog } from '../../system/services/log.service.js';

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
        message: 'KhÃ´ng tÃ¬m tháº¥y token xÃ¡c thá»±c hoáº·c token khÃ´ng há»£p lá»‡'
      });
    }

    if (!process.env.JWT_SECRET) {
      return reply.status(500).send({
        success: false,
        message: 'Lá»—i cáº¥u hÃ¬nh JWT trÃªn server'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    request.user = decoded;
  } catch (error) {
    return reply.status(401).send({
      success: false,
      message: 'Token xÃ¡c thá»±c khÃ´ng há»£p lá»‡ hoáº·c Ä‘Ã£ háº¿t háº¡n'
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
      message: "Báº¡n chÆ°a Ä‘Äƒng nháº­p hoáº·c phiÃªn lÃ m viá»‡c Ä‘Ã£ háº¿t háº¡n"
    });
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);

    // TÃ¬m user trong DB local cá»§a vn theo user_id hoáº·c email
    let user = null;
    if (decoded.user_id) {
      user = await prisma.user.findUnique({
        where: { user_id: decoded.user_id }
      });
    }

    if (!user && decoded.email) {
      user = await prisma.user.findUnique({
        where: { email: decoded.email }
      });
    }

    // JIT Provisioning: Náº¿u token há»£p lá»‡ tá»« domain cha nhÆ°ng chÆ°a cÃ³ trong DB cá»§a vn -> tá»± Ä‘á»™ng táº¡o
    if (!user && decoded.email) {
      try {
        user = await prisma.user.create({
          data: {
            user_id: crypto.randomUUID(),
            email: decoded.email,
            first_name: decoded.first_name || decoded.name || null,
            last_name: decoded.last_name || null,
            role: 'STUDENT',
            status: 'ACTIVE',
            type: 'LOCAL'
          }
        });
        logger.info(`[SSO JIT Provisioning]: Tá»± Ä‘á»™ng táº¡o user má»›i ${decoded.email} tá»« SSO Token.`);
      } catch (createErr) {
        user = await prisma.user.findUnique({
          where: { email: decoded.email }
        });
        if (!user) throw createErr;
      }
    }

    if (user && user.status === 'BANNED') {
      return reply.status(403).send({
        success: false,
        code: "USER_BANNED",
        message: "TÃ i khoáº£n cá»§a báº¡n Ä‘Ã£ bá»‹ khÃ³a"
      });
    }

    request.user = {
      ...decoded,
      user_id: user ? user.user_id : decoded.user_id,
      role: user ? user.role : (decoded.role || 'STUDENT'),
      email: user ? user.email : decoded.email
    };
  } catch (error) {
    return reply.status(401).send({
      success: false,
      code: "ACCESS_TOKEN_EXPIRED",
      message: "Access token khÃ´ng há»£p lá»‡ hoáº·c Ä‘Ã£ háº¿t háº¡n"
    });
  }
};

export const verifyAdmin = async (request, reply) => {
  if (!request.user) {
    return reply.status(401).send({
      success: false,
      message: 'Xác thực không th� nh công, không tìm thấy thông tin người dùng.',
      code: 'UNAUTHENTICATED'
    });
  }

  if (request.user.role !== 'ADMINISTRATOR') {
    createLog({
      userId: request.user.user_id,
      userRole: request.user.role,
      action: 'SYSTEM',
      level: 'WARNING',
      message: `T� i khoản ${request.user.email} cố gắng truy cập t� i nguyên Admin (Bị từ chối)`,
      metadata: { ip: request.ip, path: request.url }
    });
    return reply.status(403).send({
      success: false,
      message: 'Bạn không có quyền truy cập t� i nguyên n� y',
      code: 'NO_PERMISSION'
    });
  }
};


