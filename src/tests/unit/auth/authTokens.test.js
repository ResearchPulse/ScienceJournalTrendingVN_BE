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
    process.env.JWT_SECRET = 'shared-secret';
    process.env.JWT_REFRESH_SECRET = 'refresh-secret';
    const token = signChildAccessToken({ user_id: 'child-1', email: 'user@example.com', role: 'STUDENT' });
    const decoded = verifyChildAccessToken(token);
    assert.equal(decoded.iss, CHILD_ACCESS_ISSUER);
    assert.equal(decoded.aud, CHILD_ACCESS_AUDIENCE);
    assert.equal(decoded.token_use, 'access');
  });

  test('parent access token signed with shared JWT_SECRET is verified by Trending BE', () => {
    process.env.NODE_ENV = 'production';
    process.env.JWT_SECRET = 'shared-secret';
    process.env.JWT_REFRESH_SECRET = 'refresh-secret';
    const parent = jwt.sign({ user_id: 'parent-1', email: 'user@example.com', role: 'STUDENT' }, 'shared-secret', { algorithm: 'HS256', expiresIn: '1h' });
    const verified = verifyParentAccessToken(parent);
    assert.equal(verified.email, 'user@example.com');
    assert.equal(verified.user_id, 'parent-1');
  });

  test('access and refresh tokens cannot be substituted', () => {
    process.env.NODE_ENV = 'test';
    process.env.JWT_SECRET = 'shared-secret';
    process.env.JWT_REFRESH_SECRET = 'refresh-secret';
    const user = { user_id: 'child-1', email: 'user@example.com', role: 'STUDENT' };
    const access = signChildAccessToken(user);
    const refresh = signChildRefreshToken(user);
    assert.throws(() => verifyChildAccessToken(refresh));
    assert.throws(() => verifyChildRefreshToken(access));
  });

  test('rejects token signed with wrong secret', () => {
    process.env.NODE_ENV = 'production';
    process.env.JWT_SECRET = 'shared-secret';
    process.env.JWT_REFRESH_SECRET = 'refresh-secret';
    const forged = jwt.sign({ email: 'admin@example.com', role: 'ADMINISTRATOR' }, 'wrong-secret', { algorithm: 'HS256' });
    assert.throws(() => verifyParentAccessToken(forged));
  });
});
