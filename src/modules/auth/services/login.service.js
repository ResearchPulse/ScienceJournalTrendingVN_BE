import bcrypt from 'bcryptjs';
import prisma from '../../../config/prisma.js';
import { signChildAccessToken, signChildRefreshToken } from '../config/authTokens.js';

/**
 * Táº¡o Ä‘á»‘i tÆ°á»£ng lá»—i pháº£n há»“i khi thÃ´ng tin Ä‘Äƒng nháº­p sai (MÃ£ lá»—i 401)
 * @returns {Error} Lá»—i vá»›i thÃ´ng tin "Email hoáº·c máº­t kháº©u khÃ´ng Ä‘Ãºng" vÃ  status 401
 */
const buildLoginError = () => {
  const error = new Error('Email hoáº·c máº­t kháº©u khÃ´ng Ä‘Ãºng');
  error.statusCode = 401;
  return error;
};

/**
 * Sinh token JWT chá»©a ID, email vÃ  vai trÃ² cá»§a user phá»¥c vá»¥ cho phiÃªn Ä‘Äƒng nháº­p
 * @param {Object} user - Äá»‘i tÆ°á»£ng user cáº§n táº¡o token
 * @returns {string} Chuá»—i JWT token
 * @throws {Error} NÃ©m lá»—i náº¿u chÆ°a Ä‘á»‹nh nghÄ©a JWT_SECRET trong mÃ´i trÆ°á»ng
 */
export const signToken = (user) => {
  return signChildAccessToken(user);
};

export const signRefreshToken = (user) => {
  return signChildRefreshToken(user);
};

/**
 * Thá»±c hiá»‡n xÃ¡c thá»±c Ä‘Äƒng nháº­p ngÆ°á»i dÃ¹ng báº±ng email vÃ  máº­t kháº©u truyá»n thá»‘ng
 * @param {Object} credentials - ThÃ´ng tin Ä‘Äƒng nháº­p
 * @param {string} credentials.email - Äá»‹a chá»‰ email Ä‘Äƒng nháº­p
 * @param {string} credentials.password - Máº­t kháº©u Ä‘Äƒng nháº­p
 * @returns {Promise<Object>} Äá»‘i tÆ°á»£ng chá»©a chuá»—i JWT access token vÃ  thÃ´ng tin chi tiáº¿t user
 * @throws {Error} NÃ©m lá»—i 401 náº¿u sai máº­t kháº©u/email, hoáº·c 403 náº¿u tÃ i khoáº£n bá»‹ khÃ³a/chÆ°a kÃ­ch hoáº¡t
 */
export const loginWithEmailPassword = async ({ email, password }) => {
  const normalizedEmail = email.trim().toLowerCase();

  const user = await prisma.user.findFirst({
    where: {
      email: {
        equals: normalizedEmail,
        mode: 'insensitive'
      }
    },
    select: {
      user_id: true,
      email: true,
      password: true,
      type: true,
      status: true,
      role: true,
      last_name: true,
      first_name: true,
      url_image: true,
      date_of_birth: true,
      gender: true
    }
  });

  if (!user) {
    throw buildLoginError();
  }

  if (user.type !== 'LOCAL') {
    const error = new Error('TÃ i khoáº£n nÃ y khÃ´ng há»— trá»£ Ä‘Äƒng nháº­p báº±ng máº­t kháº©u');
    error.statusCode = 403;
    throw error;
  }

  if (user.status !== 'ACTIVE') {
    const error = new Error(
      user.status === 'BANNED'
        ? 'TÃ i khoáº£n Ä‘Ã£ bá»‹ khÃ³a'
        : 'TÃ i khoáº£n chÆ°a Ä‘Æ°á»£c kÃ­ch hoáº¡t'
    );
    error.statusCode = 403;
    throw error;
  }

  if (!user.password) {
    throw buildLoginError();
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    throw buildLoginError();
  }

  const token = signToken(user);

  return {
    token: token,
    user: {
      user_id: user.user_id,
      email: user.email,
      role: user.role
    }
  };
};


