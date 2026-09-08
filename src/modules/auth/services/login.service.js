import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import prisma from '../../../config/prisma.js';

const buildLoginError = () => {
  const error = new Error('Email hoac mat khau khong dung');
  error.statusCode = 401;
  return error;
};

export const signToken = (user, extraClaims = {}) => {
  if (!process.env.JWT_SECRET) {
    throw new Error('Missing JWT_SECRET in environment variables');
  }

  return jwt.sign(
    {
      user_id: user.user_id,
      email: user.email,
      role: user.role,
      domain: process.env.COOKIE_DOMAIN?.replace(/^\./, '') || 'vn.hyperdatalab.org',
      ...extraClaims,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || '1d',
    }
  );
};

export const signRefreshToken = (user, extraClaims = {}) => {
  if (!process.env.JWT_REFRESH_SECRET) {
    throw new Error('Missing JWT_REFRESH_SECRET in environment variables');
  }

  return jwt.sign(
    {
      user_id: user.user_id,
      email: user.email,
      role: user.role,
      domain: process.env.COOKIE_DOMAIN?.replace(/^\./, '') || 'vn.hyperdatalab.org',
      ...extraClaims,
    },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d',
    }
  );
};

export const loginWithEmailPassword = async ({ email, password }) => {
  const normalizedEmail = email.trim().toLowerCase();

  const user = await prisma.user.findFirst({
    where: {
      email: {
        equals: normalizedEmail,
        mode: 'insensitive',
      },
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
      gender: true,
    },
  });

  if (!user) {
    throw buildLoginError();
  }

  if (user.type !== 'LOCAL') {
    const error = new Error('Tai khoan nay khong ho tro dang nhap bang mat khau');
    error.statusCode = 403;
    throw error;
  }

  if (user.status !== 'ACTIVE') {
    const error = new Error(
      user.status === 'BANNED'
        ? 'Tai khoan da bi khoa'
        : 'Tai khoan chua duoc kich hoat'
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
      role: user.role,
    },
  };
};