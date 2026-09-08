import { afterEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import {
  CHILD_ACCESS_AUDIENCE,
  CHILD_ACCESS_ISSUER,
  signChildAccessToken,
  signChildRefreshToken,
  verifyChildAccessToken,
  verifyChildRefreshToken,
  verifyParentAccessToken,
} from '../../../modules/auth/config/authTokens.js';

const originalEnv = { ...process.env };
afterEach(() => { process.env = { ...originalEnv }; });

describe('isolated auth token contracts', () => {
  test('child access token has fixed issuer, audience, and token use', () => {
    process.env.NODE_ENV = 'test';
    process.env.VN_JWT_SECRET = 'child-secret';
    const token = signChildAccessToken({ user_id: 'child-1', email: 'user@example.com', role: 'STUDENT' });
    const decoded = verifyChildAccessToken(token);
    assert.equal(decoded.iss, CHILD_ACCESS_ISSUER);
    assert.equal(decoded.aud, CHILD_ACCESS_AUDIENCE);
    assert.equal(decoded.token_use, 'access');
  });

  test('parent and child secrets cannot be substituted', () => {
    process.env.NODE_ENV = 'production';
    process.env.PARENT_JWT_SECRET = 'parent-secret';
    process.env.VN_JWT_SECRET = 'child-secret';
    process.env.VN_JWT_REFRESH_SECRET = 'refresh-secret';
    const parent = jwt.sign({ email: 'user@example.com' }, 'parent-secret', { algorithm: 'HS256', expiresIn: '1h' });
    const child = signChildAccessToken({ user_id: 'child-1', email: 'user@example.com', role: 'STUDENT' });
    assert.equal(verifyParentAccessToken(parent).email, 'user@example.com');
    assert.throws(() => verifyChildAccessToken(parent));
    assert.throws(() => verifyParentAccessToken(child));
  });

  test('access and refresh tokens cannot be substituted', () => {
    process.env.NODE_ENV = 'test';
    process.env.VN_JWT_SECRET = 'child-secret';
    process.env.VN_JWT_REFRESH_SECRET = 'refresh-secret';
    const user = { user_id: 'child-1', email: 'user@example.com', role: 'STUDENT' };
    const access = signChildAccessToken(user);
    const refresh = signChildRefreshToken(user);
    assert.throws(() => verifyChildAccessToken(refresh));
    assert.throws(() => verifyChildRefreshToken(access));
  });

  test('rejects a child-signed no-domain token as a parent assertion', () => {
    process.env.NODE_ENV = 'production';
    process.env.PARENT_JWT_SECRET = 'parent-secret';
    process.env.VN_JWT_SECRET = 'child-secret';
    const forged = jwt.sign({ email: 'admin@example.com', role: 'ADMINISTRATOR' }, 'child-secret', { algorithm: 'HS256' });
    assert.throws(() => verifyParentAccessToken(forged));
  });
});
