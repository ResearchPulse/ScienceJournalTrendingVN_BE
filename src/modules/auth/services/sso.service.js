import crypto from 'crypto';
import {
  getSsoBlockSecret,
  signChildAccessToken,
  verifyParentAccessToken,
} from '../config/authTokens.js';
import { getAuthCookieNames } from '../utils/authCookies.js';
import { createJitUser, findUsersByNormalizedEmail, normalizeEmail } from '../repositories/sso.repository.js';

const PARENT_ACCESS_COOKIE = 'access_token';

const authError = (statusCode, code, message) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.code = code;
  return error;
};

export const resolveLocalSsoUser = async (email) => {
  if (typeof email !== 'string' || !email.trim()) {
    throw authError(401, 'PARENT_SESSION_INVALID', 'Parent session does not contain an email');
  }

  const normalizedEmail = normalizeEmail(email);
  let matches = await findUsersByNormalizedEmail(normalizedEmail);
  if (matches.length > 1) {
    throw authError(409, 'EMAIL_IDENTITY_AMBIGUOUS', 'Multiple local accounts match this email');
  }

  if (!matches[0]) {
    try {
      matches = [await createJitUser(normalizedEmail)];
    } catch (error) {
      if (error.code !== 'P2002') throw error;
      matches = await findUsersByNormalizedEmail(normalizedEmail);
      if (matches.length !== 1) throw error;
    }
  }

  const user = matches[0];
  if (user.status !== 'ACTIVE' || user.role === 'BANNED') {
    throw authError(403, 'ACCOUNT_UNAVAILABLE', 'Account is banned or inactive');
  }
  return user;
};

const durationSeconds = (value, fallback) => {
  if (!value) return fallback;
  if (/^\d+$/.test(String(value))) return Number(value);
  const match = String(value).match(/^(\d+(?:\.\d+)?)(s|m|h|d)$/i);
  if (!match) return fallback;
  const units = { s: 1, m: 60, h: 3600, d: 86400 };
  return Number(match[1]) * units[match[2].toLowerCase()];
};

export const fingerprintParentToken = (token) => (
  crypto.createHash('sha256').update(token).digest('hex')
);

const signBlocker = (fingerprint, exp) => {
  const payload = `${fingerprint}.${exp}`;
  const signature = crypto
    .createHmac('sha256', getSsoBlockSecret())
    .update(payload)
    .digest('base64url');
  return `${payload}.${signature}`;
};

export const verifyBlocker = (value) => {
  if (!value) return null;
  const [fingerprint, expText, signature] = value.split('.');
  const exp = Number(expText);
  if (!fingerprint || !signature || !Number.isFinite(exp) || exp <= Math.floor(Date.now() / 1000)) {
    return null;
  }

  const expected = crypto
    .createHmac('sha256', getSsoBlockSecret())
    .update(`${fingerprint}.${exp}`)
    .digest('base64url');
  if (
    signature.length !== expected.length
    || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
  ) {
    return null;
  }
  return { fingerprint, exp };
};

const parentTokenFromRequest = (request) => {
  const cookieToken = request.cookies?.[PARENT_ACCESS_COOKIE];
  if (cookieToken) return cookieToken;

  if (process.env.NODE_ENV?.trim() !== 'production') {
    const bearer = request.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
    if (bearer) return bearer;
  }

  throw authError(401, 'PARENT_SESSION_MISSING', 'Parent session missing');
};

const parentFromRequest = (request) => {
  const token = parentTokenFromRequest(request);
  let parent;
  try {
    parent = verifyParentAccessToken(token);
  } catch {
    throw authError(401, 'PARENT_SESSION_INVALID', 'Parent session invalid');
  }

  const email = parent.email || parent.username;
  if (
    typeof email !== 'string'
    || !email.trim()
    || !Number.isFinite(parent.iat)
    || !Number.isFinite(parent.exp)
    || parent.exp <= Math.floor(Date.now() / 1000)
  ) {
    throw authError(401, 'PARENT_SESSION_INVALID', 'Parent session invalid');
  }

  return {
    token,
    parent: { ...parent, email },
    fingerprint: fingerprintParentToken(token),
  };
};

export const bootstrapSso = async ({ request, explicit = false }) => {
  const rawCookie = request.headers.cookie || '';
  const parentAccessCount = (rawCookie.match(/(?:^|;\s*)access_token=/g) || []).length;
  const parentRefreshCount = (rawCookie.match(/(?:^|;\s*)refresh_token=/g) || []).length;
  if (parentAccessCount > 1 || parentRefreshCount > 1) {
    throw authError(409, 'LEGACY_COOKIE_CLEARED', 'Legacy cookies cleared; retry bootstrap');
  }

  const { token, parent, fingerprint } = parentFromRequest(request);
  if (!explicit) {
    const blocker = verifyBlocker(request.cookies?.[getAuthCookieNames().blocker]);
    if (blocker?.fingerprint === fingerprint) {
      throw authError(409, 'SSO_BLOCKED', 'SSO is blocked after child logout');
    }
  }

  const user = await resolveLocalSsoUser(parent.email);
  const now = Math.floor(Date.now() / 1000);
  const parentLifetime = Math.max(1, parent.exp - now);
  const childLifetime = durationSeconds(
    process.env.SSO_CHILD_ACCESS_EXPIRES_IN || process.env.JWT_EXPIRES_IN,
    86400,
  );
  const expiresIn = Math.max(1, Math.min(childLifetime, parentLifetime));
  const childToken = signChildAccessToken({
    user_id: user.user_id,
    email: user.email,
    role: user.role,
    auth_source: 'parent_sso',
    parent_fingerprint: fingerprint,
  }, { expiresIn });

  return {
    token: childToken,
    user,
    parentToken: token,
    parentExp: parent.exp,
    sessionExpiresIn: expiresIn,
    fingerprint,
  };
};

export const createLogoutBlocker = (parentToken) => {
  const parent = verifyParentAccessToken(parentToken);
  return {
    value: signBlocker(fingerprintParentToken(parentToken), parent.exp),
    exp: parent.exp,
  };
};

export const inspectParentCookie = (request) => request.cookies?.[PARENT_ACCESS_COOKIE] || null;
