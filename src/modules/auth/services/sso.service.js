import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import {
  getSsoBlockSecret,
  signChildAccessToken,
  verifyParentAccessToken,
} from '../config/authTokens.js';
import { getAuthCookieNames } from '../utils/authCookies.js';
import { createJitUser, findUsersByNormalizedEmail, normalizeEmail } from '../repositories/sso.repository.js';

const PARENT_ACCESS_COOKIE = 'access_token';

const configurationValue = (name, developmentFallback) => {
  const configured = process.env[name]?.trim();
  if (configured) return configured;
  if (process.env.NODE_ENV?.trim() === 'production') {
    throw authError(500, 'SSO_CONFIGURATION_INVALID', `${name} is required in production`);
  }
  return developmentFallback;
};

const getCentralSsoApiUrl = () => (
  configurationValue('CENTRAL_SSO_API_URL', 'http://localhost:3001')
).replace(/\/+$/, '');

const getCentralSsoIssuer = () => (
  configurationValue('CENTRAL_SSO_ISSUER_URL', getCentralSsoApiUrl())
).replace(/\/+$/, '');

const getSsoClientId = () => configurationValue('SSO_CLIENT_ID', 'demo-client-app');

const getSsoRedirectUri = () => {
  const configured = process.env.SSO_REDIRECT_URI?.trim();
  if (configured) return configured;
  const frontendUrl = configurationValue('FRONTEND_URL', 'http://localhost:5173');
  return frontendUrl.replace(/\/+$/, '') + '/auth/callback';
};

const SSO_REQUEST_TIMEOUT_MS = Math.min(
  Math.max(Number(process.env.CENTRAL_SSO_TIMEOUT_MS || 5000), 1000),
  15000,
);

const fetchWithTimeout = async (url, options = {}, requestId) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SSO_REQUEST_TIMEOUT_MS);

  try {
    return await fetch(url, {
      ...options,
      headers: {
        ...(options.headers || {}),
        ...(requestId ? { 'x-request-id': requestId } : {}),
      },
      signal: controller.signal,
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      throw authError(504, 'SSO_PROVIDER_TIMEOUT', 'Central SSO request timed out');
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
};

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

const issueChildSession = async ({ user, parentToken, parent, fingerprint, authSource }) => {
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
    auth_source: authSource,
    parent_fingerprint: fingerprint,
  }, { expiresIn });

  return {
    token: childToken,
    user,
    parentToken,
    parentExp: parent.exp,
    sessionExpiresIn: expiresIn,
    fingerprint,
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
  return issueChildSession({
    user,
    parentToken: token,
    parent,
    fingerprint,
    authSource: 'parent_sso',
  });
};

const parseResponseJson = async (response) => {
  try {
    return await response.json();
  } catch {
    return {};
  }
};

const hasRequiredSsoScopes = (scope) => {
  const scopes = new Set(typeof scope === 'string' ? scope.split(/\s+/).filter(Boolean) : []);
  return scopes.has('openid') && scopes.has('email');
};

const verifyCentralAccessToken = async (accessToken, requestId) => {
  const decoded = jwt.decode(accessToken, { complete: true });
  const header = decoded?.header;
  if (!header || header.alg !== 'RS256' || !header.kid) {
    throw authError(401, 'SSO_TOKEN_INVALID', 'Central SSO access token header is invalid');
  }

  let jwksResponse;
  try {
    jwksResponse = await fetchWithTimeout(
      getCentralSsoApiUrl() + '/.well-known/jwks.json',
      {},
      requestId,
    );
  } catch (error) {
    if (error.statusCode) throw error;
    throw authError(502, 'SSO_PROVIDER_UNAVAILABLE', 'Central SSO is unavailable');
  }

  const jwks = await parseResponseJson(jwksResponse);
  if (!jwksResponse.ok) {
    throw authError(502, 'SSO_PROVIDER_UNAVAILABLE', 'Central SSO signing keys are unavailable');
  }
  const jwk = Array.isArray(jwks?.keys)
    ? jwks.keys.find((key) => key.kid === header.kid)
    : null;
  if (!jwk) {
    throw authError(401, 'SSO_TOKEN_INVALID', 'Central SSO signing key is unknown');
  }

  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    throw authError(401, 'SSO_TOKEN_INVALID', 'Central SSO signing key is invalid');
  }

  try {
    return jwt.verify(accessToken, publicKey, {
      algorithms: ['RS256'],
      issuer: getCentralSsoIssuer(),
      audience: getSsoClientId(),
    });
  } catch {
    throw authError(401, 'SSO_TOKEN_INVALID', 'Central SSO access token is invalid');
  }
};

const exchangeCentralAuthorizationCode = async ({ code, codeVerifier, redirectUri, clientId, requestId }) => {
  if (!code || !codeVerifier) {
    throw authError(400, 'SSO_CODE_REQUIRED', 'SSO authorization code and verifier are required');
  }
  if (clientId !== getSsoClientId()) {
    throw authError(400, 'SSO_CLIENT_INVALID', 'SSO client is invalid');
  }
  if (redirectUri !== getSsoRedirectUri()) {
    throw authError(400, 'SSO_REDIRECT_URI_INVALID', 'SSO redirect URI is invalid');
  }

  let tokenResponse;
  try {
    tokenResponse = await fetchWithTimeout(getCentralSsoApiUrl() + '/api/v1/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: clientId,
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
      }),
    }, requestId);
  } catch (error) {
    if (error.statusCode) throw error;
    throw authError(502, 'SSO_PROVIDER_UNAVAILABLE', 'Central SSO is unavailable');
  }

  const tokenBody = await parseResponseJson(tokenResponse);
  const accessToken = tokenBody?.access_token || tokenBody?.data?.access_token;
  if (!tokenResponse.ok || !accessToken) {
    throw authError(401, 'SSO_AUTHORIZATION_FAILED', 'SSO authorization code is invalid or expired');
  }

  let userInfoResponse;
  try {
    userInfoResponse = await fetchWithTimeout(getCentralSsoApiUrl() + '/api/v1/oidc/userinfo', {
      headers: { authorization: 'Bearer ' + accessToken },
    }, requestId);
  } catch (error) {
    if (error.statusCode) throw error;
    throw authError(502, 'SSO_PROVIDER_UNAVAILABLE', 'Central SSO is unavailable');
  }

  const claims = await verifyCentralAccessToken(accessToken, requestId);
  const userInfoBody = await parseResponseJson(userInfoResponse);
  const userInfo = userInfoBody?.data && typeof userInfoBody.data === 'object'
    ? userInfoBody.data
    : userInfoBody?.user && typeof userInfoBody.user === 'object'
      ? userInfoBody.user
      : userInfoBody;
  if (
    !userInfoResponse.ok
    || typeof claims?.sub !== 'string'
    || !hasRequiredSsoScopes(claims?.scope)
    || typeof userInfo?.sub !== 'string'
    || userInfo.sub !== claims.sub
    || typeof userInfo?.email !== 'string'
    || !userInfo.email.trim()
  ) {
    throw authError(401, 'SSO_IDENTITY_INVALID', 'Central SSO identity claims are invalid');
  }

  return { accessToken, userInfo, claims };
};

export const bootstrapSsoFromAuthorizationCode = async ({ code, codeVerifier, redirectUri, clientId, requestId }) => {
  const { accessToken, userInfo, claims } = await exchangeCentralAuthorizationCode({
    code,
    codeVerifier,
    redirectUri,
    clientId,
    requestId,
  });
  const now = Math.floor(Date.now() / 1000);
  const childLifetime = durationSeconds(
    process.env.SSO_CHILD_ACCESS_EXPIRES_IN || process.env.JWT_EXPIRES_IN,
    86400,
  );
  const parent = {
    ...claims,
    email: userInfo.email,
    iat: Number.isFinite(claims.iat) ? claims.iat : now,
    exp: Number.isFinite(claims.exp) && claims.exp > now ? claims.exp : now + childLifetime,
  };
  const user = await resolveLocalSsoUser(parent.email);

  return issueChildSession({
    user,
    parentToken: accessToken,
    parent,
    fingerprint: fingerprintParentToken(accessToken),
    authSource: 'central_oidc',
  });
};

export const createLogoutBlocker = (parentToken) => {
  const parent = verifyParentAccessToken(parentToken);
  return {
    value: signBlocker(fingerprintParentToken(parentToken), parent.exp),
    exp: parent.exp,
  };
};

export const inspectParentCookie = (request) => request.cookies?.[PARENT_ACCESS_COOKIE] || null;
