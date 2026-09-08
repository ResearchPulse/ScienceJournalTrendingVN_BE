import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import prisma from '../../../config/prisma.js';
import { emailHelper } from '../../../utils/email.js';
import logger from '../../../utils/logger.js';
import { signActivationToken, verifyActivationToken } from '../config/authTokens.js';

/**
 * ÄÄƒng kÃ½ tÃ i khoáº£n ngÆ°á»i dÃ¹ng má»›i báº±ng Email vÃ  Máº­t kháº©u truyá»n thá»‘ng
 * @param {Object} userData - ThÃ´ng tin tÃ i khoáº£n Ä‘Äƒng kÃ½
 * @param {string} userData.email - Email Ä‘Äƒng kÃ½
 * @param {string} userData.password - Máº­t kháº©u Ä‘Äƒng kÃ½
 * @param {string} [userData.first_name] - TÃªn ngÆ°á»i dÃ¹ng
 * @param {string} [userData.last_name] - Há» ngÆ°á»i dÃ¹ng
 * @param {string} [userData.date_of_birth] - NgÃ y sinh
 * @param {boolean} [userData.gender] - Giá»›i tÃ­nh
 * @param {string} [userData.role] - Vai trÃ²
 * @returns {Promise<Object>} Tráº£ vá» thÃ´ng tin ngÆ°á»i dÃ¹ng vá»«a Ä‘Æ°á»£c táº¡o trong CSDL (status = INACTIVE)
 * @throws {Error} NÃ©m lá»—i 409 náº¿u email Ä‘Ã£ tá»“n táº¡i trong há»‡ thá»‘ng
 */
export const registerWithEmailPassword = async ({
  email,
  password,
  first_name,
  last_name,
  date_of_birth,
  gender,
  role
}) => {
  const normalizedEmail = email.trim().toLowerCase();

  // 1. Kiá»ƒm tra email Ä‘Ã£ tá»“n táº¡i hay chÆ°a
  const existingUser = await prisma.user.findFirst({
    where: {
      email: {
        equals: normalizedEmail,
        mode: 'insensitive'
      }
    },
    select: { user_id: true }
  });

  if (existingUser) {
    const error = new Error('Email Ä‘Ã£ tá»“n táº¡i');
    error.statusCode = 409;
    throw error;
  }

  // 2. BÄƒm máº­t kháº©u
  const hashedPassword = await bcrypt.hash(password, 10);
  const userId = crypto.randomUUID();

  // 3. Insert user má»›i vÃ o Database vá»›i tráº¡ng thÃ¡i máº·c Ä‘á»‹nh lÃ  'INACTIVE'
  const newUser = await prisma.user.create({
    data: {
      user_id: userId,
      email: normalizedEmail,
      password: hashedPassword,
      type: 'LOCAL',
      status: 'INACTIVE', // Äá»•i tá»« ACTIVE thÃ nh INACTIVE Ä‘á»ƒ báº¯t buá»™c xÃ¡c thá»±c email
      role: role || null,
      first_name: first_name || null,
      last_name: last_name || null,
      date_of_birth: date_of_birth ? new Date(date_of_birth) : null,
      gender: gender !== undefined ? gender : null
    },
    select: {
      user_id: true,
      email: true,
      type: true,
      status: true,
      role: true,
      first_name: true,
      last_name: true,
      date_of_birth: true,
      gender: true
    }
  });

  // 4. Táº¡o token kÃ­ch hoáº¡t tÃ i khoáº£n báº±ng JWT (thá»i háº¡n 24 giá»)
  const activationToken = signActivationToken(newUser);

  // 5. Gá»­i email kÃ­ch hoáº¡t vÃ  tráº£ Ä‘Ãºng tráº¡ng thÃ¡i giao nháº­n cho controller/frontend.
  let activationEmailSent = true;
  try {
    await emailHelper.sendActivationEmail(newUser.email, newUser.first_name || 'User', activationToken);
  } catch (emailError) {
    activationEmailSent = false;
    logger.error('Lá»—i gá»­i email kÃ­ch hoáº¡t trong register service:', emailError);
  }

  return {
    ...newUser,
    activation_email_sent: activationEmailSent
  };
};

/**
 * Gá»­i láº¡i email kÃ­ch hoáº¡t cho tÃ i khoáº£n LOCAL Ä‘ang á»Ÿ tráº¡ng thÃ¡i INACTIVE.
 * @param {string} email - Email tÃ i khoáº£n cáº§n nháº­n láº¡i liÃªn káº¿t kÃ­ch hoáº¡t.
 * @returns {Promise<Object>} Email Ä‘Ã£ gá»­i thÃ nh cÃ´ng.
 */
export const resendActivationEmail = async (email) => {
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
      first_name: true,
      status: true,
      type: true
    }
  });

  if (!user) {
    const error = new Error('KhÃ´ng tÃ¬m tháº¥y tÃ i khoáº£n vá»›i email nÃ y');
    error.statusCode = 404;
    error.code = 'ACCOUNT_NOT_FOUND';
    throw error;
  }

  if (user.type !== 'LOCAL') {
    const error = new Error('TÃ i khoáº£n nÃ y khÃ´ng sá»­ dá»¥ng xÃ¡c thá»±c email');
    error.statusCode = 400;
    error.code = 'ACTIVATION_NOT_SUPPORTED';
    throw error;
  }

  if (user.status === 'ACTIVE') {
    const error = new Error('TÃ i khoáº£n Ä‘Ã£ Ä‘Æ°á»£c kÃ­ch hoáº¡t');
    error.statusCode = 409;
    error.code = 'ACCOUNT_ALREADY_ACTIVE';
    throw error;
  }

  if (user.status === 'BANNED') {
    const error = new Error('TÃ i khoáº£n Ä‘Ã£ bá»‹ khÃ³a, khÃ´ng thá»ƒ kÃ­ch hoáº¡t');
    error.statusCode = 403;
    error.code = 'ACCOUNT_BANNED';
    throw error;
  }

  const activationToken = signActivationToken(user);

  await emailHelper.sendActivationEmail(
    user.email,
    user.first_name || 'User',
    activationToken
  );

  return { email: user.email };
};

/**
 * XÃ¡c thá»±c token kÃ­ch hoáº¡t nháº­n Ä‘Æ°á»£c tá»« email vÃ  cáº­p nháº­t tráº¡ng thÃ¡i ngÆ°á»i dÃ¹ng thÃ nh ACTIVE
 * @param {string} token - Chuá»—i Activation JWT Token láº¥y Ä‘Æ°á»£c tá»« email liÃªn káº¿t kÃ­ch hoáº¡t
 * @returns {Promise<Object>} Äá»‘i tÆ°á»£ng chá»©a thuá»™c tÃ­nh alreadyActive biá»ƒu thá»‹ tÃ i khoáº£n Ä‘Ã£ kÃ­ch hoáº¡t tá»« trÆ°á»›c hay chÆ°a, vÃ  email tÆ°Æ¡ng á»©ng
 * @throws {Error} NÃ©m lá»—i 400 náº¿u token háº¿t háº¡n/khÃ´ng há»£p lá»‡, hoáº·c lá»—i 403 náº¿u tÃ i khoáº£n Ä‘Ã£ bá»‹ khÃ³a (BANNED)
 */
export const activateAccount = async (token) => {
  if (!token) {
    const error = new Error('Token kÃ­ch hoáº¡t khÃ´ng Ä‘Æ°á»£c Ä‘á»ƒ trá»‘ng');
    error.statusCode = 400;
    throw error;
  }

  let decoded;
  try {
    decoded = verifyActivationToken(token);
  } catch (err) {
    const error = new Error('Token kÃ­ch hoáº¡t khÃ´ng há»£p lá»‡ hoáº·c Ä‘Ã£ háº¿t háº¡n');
    error.statusCode = 400;
    throw error;
  }

  const { user_id } = decoded;

  // TÃ¬m thÃ´ng tin tráº¡ng thÃ¡i hiá»‡n táº¡i cá»§a user trong database
  const user = await prisma.user.findUnique({
    where: { user_id: user_id },
    select: { user_id: true, status: true, email: true }
  });

  if (!user) {
    const error = new Error('KhÃ´ng tÃ¬m tháº¥y tÃ i khoáº£n tÆ°Æ¡ng á»©ng vá»›i token nÃ y');
    error.statusCode = 400;
    throw error;
  }

  if (user.status === 'ACTIVE') {
    return { alreadyActive: true, email: user.email };
  }

  if (user.status === 'BANNED') {
    const error = new Error('TÃ i khoáº£n nÃ y Ä‘Ã£ bá»‹ khÃ³a, khÃ´ng thá»ƒ kÃ­ch hoáº¡t');
    error.statusCode = 403;
    throw error;
  }

  // Cáº­p nháº­t tráº¡ng thÃ¡i ngÆ°á»i dÃ¹ng thÃ nh ACTIVE
  const updateResult = await prisma.user.update({
    where: { user_id: user_id },
    data: { status: 'ACTIVE' },
    select: { email: true }
  });

  return { alreadyActive: false, email: updateResult.email };
};




