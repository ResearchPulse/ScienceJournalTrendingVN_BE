import { loginWithEmailPassword, signRefreshToken, signToken } from '../services/login.service.js';
import { registerWithEmailPassword, activateAccount, resendActivationEmail } from '../services/register.service.js';
import logger from '../../../utils/logger.js';
import jwt from 'jsonwebtoken';
import { createLog } from '../../system/services/log.service.js';
import { isValidEmail } from '../../../utils/validation.js';

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

export const login = async (request, reply) => {
  try {
    const { email, password, remember = false } = request.body;

    if (!email || !email.trim()) {
      return reply.status(400).send({ success: false, code: 'EMAIL_REQUIRED', message: 'Email khÃ´ng Ä‘Æ°á»£c Ä‘á»ƒ trá»‘ng' });
    }
    if (!isValidEmail(email)) {
      return reply.status(400).send({ success: false, code: "EMAIL_INVALID", message: "Email khÃ´ng Ä‘Ãºng Ä‘á»‹nh dáº¡ng" });
    }
    if (!password || !password.trim()) {
      return reply.status(400).send({ success: false, code: "PASSWORD_REQUIRED", message: "Password khÃ´ng Ä‘Æ°á»£c Ä‘á»ƒ trá»‘ng" });
    }

    const data = await loginWithEmailPassword({ email, password });

    reply.setCookie('access_token', data.token, getCookieOptions({
      maxAge: Number(process.env.COOKIE_ACCESS_MAX_AGE),
    }));

    if (remember === true) {
      const refreshToken = signRefreshToken(data.user);
      reply.setCookie('refresh_token', refreshToken, getCookieOptions({
        maxAge: Number(process.env.COOKIE_REFRESH_MAX_AGE),
      }));
    } else {
      reply.clearCookie('refresh_token', getCookieOptions());
    }

    createLog({
      userId: data.user.user_id,
      userRole: data.user.role,
      action: 'LOGIN',
      message: `NgÆ°á»i dÃ¹ng ${data.user.email} Ä‘Äƒng nháº­p há»‡ thá»‘ng thÃ� nh cÃ´ng`,
      metadata: { ip: request.ip, userAgent: request.headers['user-agent'] }
    });

    return reply.status(200).send({
      success: true,
      code: "LOGIN_SUCCESS",
      message: "ÄÄƒng nháº­p thÃ� nh cÃ´ng",
      data: {
        token: data.token,
      }
    });

  } catch (error) {
    if (!error.statusCode || error.statusCode === 500) {
      logger.error("Lá»—i há»‡ thá»‘ng trong controller Ä‘Äƒng nháº­p:", error);
    }
    return reply.status(error.statusCode || 500).send({
      success: false,
      code: error.code || "LOGIN_FAILED",
      message: error.statusCode ? error.message : "CÃ³ lá»—i xáº£y ra á»Ÿ server",
    });
  }
};

export const refreshToken = async (request, reply) => {
  try {
    const refreshTokenValue = request.cookies.refresh_token;
    
    if (!refreshTokenValue) {
      return reply.status(401).send({
        success: false,
        code: "REFRESH_TOKEN_REQUIRED",
        message: "Refresh token khÃ´ng Ä‘Æ°á»£c Ä‘á»ƒ trá»‘ng",
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(refreshTokenValue, process.env.JWT_REFRESH_SECRET, {
        ignoreExpiration: true,
      });
    } catch (jwtError) {
      return reply.status(401).send({
        success: false,
        code: "INVALID_ACCESS_TOKEN",
        message: "Refresh token cÅ© khÃ´ng há»£p lá»‡ hoáº·c bá»‹ giáº£ máº¡o",
      });
    }

    const newAccessToken = signToken({
      user_id: decoded.user_id,
      email: decoded.email,
      role: decoded.role,
    });

    reply.setCookie("access_token", newAccessToken, getCookieOptions({
      maxAge: Number(process.env.COOKIE_ACCESS_MAX_AGE),
    }));

    return reply.status(200).send({
      success: true,
      code: "REFRESH_TOKEN_SUCCESS",
      message: "Refresh token thÃ� nh cÃ´ng",
      data: {
        token: newAccessToken,
      },
    });
  } catch (error) {
    logger.error("Lá»—i há»‡ thá»‘ng trong controller Ä‘Äƒng nháº­p:", error);
    return reply.status(error.statusCode || 500).send({
      success: false,
      code: error.code || "REFRESH_TOKEN_FAILED",
    });
  }
}

export const checkAuth = async (request, reply) => {
  try {
    let accessToken = request.cookies?.access_token;
    if (!accessToken && request.headers.authorization?.startsWith('Bearer ')) {
      accessToken = request.headers.authorization.split(' ')[1];
    }

    if (!accessToken) {
      return reply.status(401).send({
        success: false,
        authenticated: false,
        code: "ACCESS_TOKEN_MISSING",
        message: "Access token khÃ´ng tá»“n táº¡i",
      });
    }

    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);

    return reply.status(200).send({
      success: true,
      authenticated: true,
      user: decoded,
      access_token: accessToken,
    });

  } catch (error) {
    return reply.status(401).send({
      success: false,
      authenticated: false,
      code: "ACCESS_TOKEN_INVALID",
      message: "Access token khÃ´ng há»£p lá»‡ hoáº·c Ä‘Ã£ háº¿t háº¡n",
    });
  }
};

export const logout = async (request, reply) => {
  try {
    reply.clearCookie('access_token', getCookieOptions());
    reply.clearCookie('refresh_token', getCookieOptions());

    return reply.status(200).send({
      success: true,
      code: "LOGOUT_SUCCESS",
      message: "ÄÄƒng xuáº¥t thÃ� nh cÃ´ng",
    });
  } catch (error) {
    logger.error("Lá»—i há»‡ thá»‘ng trong controller Ä‘Äƒng xuáº¥t:", error);
    return reply.status(500).send({
      success: false,
      code: "LOGOUT_FAILED",
      message: "CÃ³ lá»—i xáº£y ra á»Ÿ server",
    });
  }
};

export const register = async (request, reply) => {
  try {
    const { email, password, first_name, last_name, date_of_birth, gender, role } = request.body;

    if (!email || !email.trim()) {
      return reply.status(400).send({ success: false, code: "EMAIL_REQUIRED", message: "Email khÃ´ng Ä‘Æ°á»£c Ä‘á»ƒ trá»‘ng" });
    }
    if (!isValidEmail(email)) {
      return reply.status(400).send({ success: false, code: "EMAIL_INVALID", message: "Email khÃ´ng Ä‘Ãºng Ä‘á»‹nh dáº¡ng" });
    }
    if (!password || !password.trim()) {
      return reply.status(400).send({ success: false, code: "PASSWORD_REQUIRED", message: "Password khÃ´ng Ä‘Æ°á»£c Ä‘á»ƒ trá»‘ng" });
    }
    if (password.length < 6) {
      return reply.status(400).send({ success: false, code: "PASSWORD_TOO_SHORT", message: "Máº­t kháº©u pháº£i cÃ³ Ã­t nháº¥t 6 kÃ½ tá»±" });
    }
    if (role && !["STUDENT", "LECTURER", "RESEARCHER", "ADMINISTRATOR"].includes(role)) {
      return reply.status(400).send({ success: false, code: "ROLE_INVALID", message: "Vai trÃ² tÃ� i khoáº£n khÃ´ng há»£p lá»‡" });
    }

    const data = await registerWithEmailPassword({ email, password, first_name, last_name, date_of_birth, gender, role });

    logger.info(`[Register]: ÄÄƒng kÃ½ thÃ� nh cÃ´ng cho tÃ� i khoáº£n: ${data.email} (Tráº¡ng thÃ¡i: INACTIVE)`);

    return reply.status(201).send({
      success: true,
      code: data.activation_email_sent ? "REGISTER_SUCCESS" : "REGISTER_SUCCESS_EMAIL_PENDING",
      message: data.activation_email_sent 
        ? "ÄÄƒng kÃ½ tÃ� i khoáº£n thÃ� nh cÃ´ng. Vui lÃ²ng kiá»ƒm tra email Ä‘á»ƒ kÃ­ch hoáº¡t tÃ� i khoáº£n."
        : "TÃ� i khoáº£n Ä‘Ã£ Ä‘Æ°á»£c táº¡o nhÆ°ng email kÃ­ch hoáº¡t chÆ°a gá»­i Ä‘Æ°á»£c. Vui lÃ²ng thá»­ gá»­i láº¡i.",
      data,
    });
  } catch (error) {
    if (!error.statusCode || error.statusCode === 500) {
      logger.error("Lá»—i há»‡ thá»‘ng trong controller Ä‘Äƒng kÃ½:", error);
    }
    return reply.status(error.statusCode || 500).send({
      success: false,
      message: error.statusCode ? error.message : "CÃ³ lá»—i xáº£y ra á»Ÿ server",
    });
  }
};

export const resendActivation = async (request, reply) => {
  try {
    const { email } = request.body;
    if (!email || !email.trim()) {
      return reply.status(400).send({ success: false, code: "EMAIL_REQUIRED", message: "Email khÃ´ng Ä‘Æ°á»£c Ä‘á»ƒ trá»‘ng" });
    }
    if (!isValidEmail(email)) {
      return reply.status(400).send({ success: false, code: "EMAIL_INVALID", message: "Email khÃ´ng Ä‘Ãºng Ä‘á»‹nh dáº¡ng" });
    }
    const data = await resendActivationEmail(email);

    return reply.status(200).send({
      success: true,
      code: "ACTIVATION_EMAIL_RESENT",
      message: "Email kÃ­ch hoáº¡t Ä‘Ã£ Ä‘Æ°á»£c gá»­i láº¡i. Vui lÃ²ng kiá»ƒm tra há»™p thÆ° hoáº·c thÆ° rÃ¡c.",
      data,
    });
  } catch (error) {
    logger.error("Lá»—i gá»­i láº¡i email kÃ­ch hoáº¡t:", error);
    return reply.status(error.statusCode || 500).send({
      success: false,
      code: error.code || "SERVER_ERROR",
      message: error.statusCode ? error.message : "CÃ³ lá»—i xáº£y ra á»Ÿ server",
    });
  }
};

export const verify = async (request, reply) => {
  try {
    const { token } = request.query;
    if (!token) {
      return reply.status(400).send({
        success: false,
        code: "ACTIVATION_TOKEN_REQUIRED",
        message: "Token kÃ­ch hoáº¡t khÃ´ng Ä‘Æ°á»£c Ä‘á»ƒ trá»‘ng",
      });
    }

    const result = await activateAccount(token);
    if (result.alreadyActive) {
      logger.warn(`[Register]: TÃ� i khoáº£n ${result.email} Ä‘Ã£ Ä‘Æ°á»£c kÃ­ch hoáº¡t trÆ°á»›c Ä‘Ã³.`);
      return reply.status(200).send({
        success: true,
        code: "ACCOUNT_ALREADY_ACTIVE",
        message: "TÃ� i khoáº£n Ä‘Ã£ Ä‘Æ°á»£c kÃ­ch hoáº¡t tá»« trÆ°á»›c. Báº¡n cÃ³ thá»ƒ Ä‘Äƒng nháº­p.",
      });
    }

    logger.info(`[Register]: KÃ­ch hoáº¡t tÃ� i khoáº£n thÃ� nh cÃ´ng cho email: ${result.email}`);
    return reply.status(200).send({
      success: true,
      code: "ACCOUNT_ACTIVATION_SUCCESS",
      message: "KÃ­ch hoáº¡t tÃ� i khoáº£n thÃ� nh cÃ´ng! BÃ¢y giá» báº¡n cÃ³ thá»ƒ Ä‘Äƒng nháº­p.",
    });
  } catch (error) {
    if (!error.statusCode || error.statusCode === 500) {
      logger.error("Lá»—i há»‡ thá»‘ng trong controller xÃ¡c thá»±c tÃ� i khoáº£n:", error);
    }
    return reply.status(error.statusCode || 500).send({
      success: false,
      code: error.statusCode === 400 ? "ACCOUNT_ACTIVATION_ERROR" : "SERVER_ERROR",
      message: error.statusCode ? error.message : "CÃ³ lá»—i xáº£y ra á»Ÿ server",
    });
  }
};



import { loginOrCreateWithGoogle, getTokenId } from '../services/google.service.js';

export const googleLogin = async (request, reply) => {
  try {
    const { credential, token, idToken, code } = request.body || {};
    let googleToken = credential || token || idToken;

    if (code) {
      googleToken = await getTokenId(code);
    }

    if (!googleToken) {
      return reply.status(400).send({ success: false, message: 'Google Token không được để trống' });
    }

    const data = await loginOrCreateWithGoogle(googleToken);

    reply.setCookie('access_token', data.token, getCookieOptions({
      maxAge: Number(process.env.COOKIE_ACCESS_MAX_AGE) || 86400,
    }));

    reply.setCookie('refresh_token', data.refreshToken, getCookieOptions({
      maxAge: Number(process.env.COOKIE_REFRESH_MAX_AGE) || 604800,
    }));

    await createLog(data.user.user_id, 'LOGIN', 'Đăng nhập th� nh công bằng Google', request.ip);

    return reply.status(200).send({
      success: true,
      message: 'Đăng nhập Google th� nh công',
      data
    });
  } catch (error) {
    logger.error('[Google Auth Error]:', error);
    if (error.statusCode) {
      return reply.status(error.statusCode).send({ success: false, message: error.message, code: error.code });
    }
    return reply.status(500).send({ success: false, message: 'Lỗi server nội bộ' });
  }
};
