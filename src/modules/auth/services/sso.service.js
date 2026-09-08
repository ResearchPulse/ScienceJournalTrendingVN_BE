import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import {
  getParentAccessSecret,
  getSsoBlockSecret,
  signChildAccessToken,
  verifyParentAccessToken,
} from '../config/authTokens.js';
import { createJitUser, findUsersByNormalizedEmail, normalizeEmail } from '../repositories/sso.repository.js';

const parentCookieName = 'access_token';

const durationSeconds = (value, fallback) => {
  if (!value) return fallback;
  if (/^\d+$/.test(String(value))) return Number(value);
  const match = String(value).match(/^(\d+(?:\.\d+)?)(s|m|h|d)$/i);
  if (!match) return fallback;
  const units = { s: 1, m: 60, h: 3600, d: 86400 };
  return Number(match[1]) * units[match[2].toLowerCase()];
};

export const fingerprintParentToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

const signBlocker = (fingerprint, exp) => {
  const payload = `${fingerprint}.${exp}`;
  const signature = crypto.createHmac('sha256', getSsoBlockSecret()).update(payload).digest('base64url');
  return `${payload}.${signature}`;
};

export const verifyBlocker = (value) => {
  if (!value) return null;
  const [fingerprint, expText, signature] = value.split('.');
  const exp = Number(expText);
  if (!fingerprint || !signature || !Number.isFinite(exp) || exp <= Math.floor(Date.now() / 1000)) return null;
  const expected = crypto.createHmac('sha256', getSsoBlockSecret()).update(`${fingerprint}.${exp}`).digest('base64url');
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  return { fingerprint, exp };
};

const parentFromRequest = (request) => {
  const token = request.cookies?.[parentCookieName];
  if (!token) {
    const error = new Error('Parent session missing');
    error.statusCode = 401;
    error.code = 'PARENT_SESSION_MISSING';
    throw error;
  }
  let parent;
  try {
    parent = verifyParentAccessToken(token);
  } catch {
    const error = new Error('Parent session invalid');
    error.statusCode = 401;
    error.code = 'PARENT_SESSION_INVALID';
    throw error;
  }
  if (!parent.email || !Number.isFinite(parent.iat) || !Number.isFinite(parent.exp)
    || parent.exp <= Math.floor(Date.now() / 1000)) {
    const error = new Error('Parent session invalid');
    error.statusCode = 401;
    error.code = 'PARENT_SESSION_INVALID';
    throw error;
  }
  return { token, parent, fingerprint: fingerprintParentToken(token) };
};

const getOrCreateUser = async (email) => {
  const normalizedEmail = normalizeEmail(email);
  const matches = await findUsersByNormalizedEmail(normalizedEmail);
  if (matches.length > 1) {
    const error = new Error('Multiple local accounts match this email');
    error.statusCode = 409;
    error.code = 'EMAIL_IDENTITY_AMBIGUOUS';
    throw error;
  }
  if (matches[0]) return matches[0];
  try {
    return await createJitUser(normalizedEmail);
  } catch (error) {
    if (error.code !== 'P2002') throw error;
    const retry = await findUsersByNormalizedEmail(normalizedEmail);
    if (retry.length !== 1) throw error;
    return retry[0];
  }
};

export const bootstrapSso = async ({ request, explicit = false }) => {
  const rawCookie = request.headers.cookie || '';
  const legacyAccessCount = (rawCookie.match(/(?:^|;\s*)access_token=/g) || []).length;
  const legacyRefreshCount = (rawCookie.match(/(?:^|;\s*)refresh_token=/g) || []).length;
  if (legacyAccessCount > 1 || legacyRefreshCount > 1) {
    const error = new Error('Legacy cookies cleared; retry bootstrap');
    error.statusCode = 409;
    error.code = 'LEGACY_COOKIE_CLEARED';
    throw error;
  }
  const { token, parent, fingerprint } = parentFromRequest(request);
  if (!explicit) {
    const blocker = verifyBlocker(request.cookies?.[request.authCookieNames.blocker]);
    if (blocker?.fingerprint === fingerprint) {
      const error = new Error('SSO is blocked after child logout');
      error.statusCode = 409;
      error.code = 'SSO_BLOCKED';
      throw error;
    }
  }

  const user = await getOrCreateUser(parent.email);
  if (user.status !== 'ACTIVE' || user.role === 'BANNED') {
    const error = new Error('Account is banned or inactive');
    error.statusCode = 403;
    error.code = 'ACCOUNT_BANNED';
    throw error;
  }

  const now = Math.floor(Date.now() / 1000);
  const parentLifetime = Math.max(1, parent.exp - now);
  const childLifetime = durationSeconds(process.env.SSO_CHILD_ACCESS_EXPIRES_IN || process.env.JWT_EXPIRES_IN, 86400);
  const expiresIn = Math.max(1, Math.min(childLifetime, parentLifetime));
  const tokenValue = signChildAccessToken({
    user_id: user.user_id,
    email: user.email,
    role: user.role,
    auth_source: 'parent_sso',
    parent_fingerprint: fingerprint,
  }, { expiresIn });
  return { token: tokenValue, user, parentToken: token, parentExp: parent.exp, sessionExpiresIn: expiresIn, fingerprint };
};

export const createLogoutBlocker = (parentToken) => {
  const parent = verifyParentAccessToken(parentToken);
  return { value: signBlocker(fingerprintParentToken(parentToken), parent.exp), exp: parent.exp };
};

export const inspectParentCookie = (request) => request.cookies?.[parentCookieName] || null;
