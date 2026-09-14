import crypto from 'crypto';
import prisma from '../../../config/prisma.js';

export const normalizeEmail = (email) => email.trim().toLowerCase();

export const findUsersByNormalizedEmail = (email) => prisma.user.findMany({
  where: { email: { equals: normalizeEmail(email), mode: 'insensitive' } },
});

export const createJitUser = (email) => prisma.user.create({
  data: {
    user_id: crypto.randomUUID(),
    email: normalizeEmail(email),
    password: null,
    type: null,
    status: 'ACTIVE',
    role: 'STUDENT',
  },
});
