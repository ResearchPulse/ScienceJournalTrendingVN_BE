import { afterEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';

import {
  PARENT_DOMAIN,
  CHILD_DOMAIN,
  isParentToken,
  verifyAccessToken,
  signChildAccessToken,
} from '../../../modules/auth/config/authTokens.js';

const originalEnv = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnv };
});

describe('auth token contracts & parent verification', () => {
  test('identifies parent token correctly by domain or iss claim', () => {
    assert.equal(isParentToken({ domain: 'hyperdatalab.org' }), true);
    assert.equal(isParentToken({ iss: 'hyperdatalab.org' }), true);
    assert.equal(isParentToken({ domain: 'vn.hyperdatalab.org' }), false);
    assert.equal(isParentToken({}), false);
    assert.equal(isParentToken(null), false);
  });

  test('verifies token signed with shared secret', () => {
    process.env.JWT_SECRET = 'shared-super-secret-key-12345';
    const parentPayload = {
      user_id: 'parent-user-456',
      email: 'scientist@hyperdatalab.org',
      role: 'RESEARCHER',
      domain: 'hyperdatalab.org',
    };

    const token = jwt.sign(parentPayload, process.env.JWT_SECRET, { expiresIn: '1h' });
    const decoded = verifyAccessToken(token);

    assert.equal(decoded.user_id, 'parent-user-456');
    assert.equal(decoded.email, 'scientist@hyperdatalab.org');
    assert.equal(decoded.domain, PARENT_DOMAIN);
    assert.equal(isParentToken(decoded), true);
  });

  test('signChildAccessToken produces child domain token', () => {
    process.env.JWT_SECRET = 'shared-super-secret-key-12345';
    const localUser = {
      user_id: 'local-123',
      email: 'student@vn.edu',
      role: 'STUDENT',
    };

    const childToken = signChildAccessToken(localUser);
    const decoded = verifyAccessToken(childToken);

    assert.equal(decoded.user_id, 'local-123');
    assert.equal(decoded.domain, CHILD_DOMAIN);
    assert.equal(isParentToken(decoded), false);
  });
});
