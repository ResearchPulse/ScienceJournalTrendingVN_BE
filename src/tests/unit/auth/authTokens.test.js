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
  test('identifies parent token correctly by domain or absence of child domain', () => {
    assert.equal(isParentToken({ domain: 'hyperdatalab.org' }), true);
    assert.equal(isParentToken({ iss: 'hyperdatalab.org' }), true);
    // Token thực tế từ hệ thống cha hyperdatalab.org không có claim domain:
    assert.equal(isParentToken({ user_id: 'parent-123', email: 'user@hyperdatalab.org', role: 'INUETE9' }), true);
    // Token do con phát hành có domain: vn.hyperdatalab.org:
    assert.equal(isParentToken({ domain: 'vn.hyperdatalab.org' }), false);
    assert.equal(isParentToken(null), false);
  });

  test('verifies token signed with shared secret', () => {
    process.env.JWT_SECRET = 'shared-super-secret-key-12345';
    const parentPayload = {
      user_id: 'parent-user-456',
      email: 'scientist@hyperdatalab.org',
      role: 'RESEARCHER',
    };

    const token = jwt.sign(parentPayload, process.env.JWT_SECRET, { expiresIn: '1h' });
    const decoded = verifyAccessToken(token);

    assert.equal(decoded.user_id, 'parent-user-456');
    assert.equal(decoded.email, 'scientist@hyperdatalab.org');
    assert.equal(isParentToken(decoded), true);
  });

  test('verifies token with PARENT_JWT_SECRET when configured differently', () => {
    process.env.PARENT_JWT_SECRET = 'parent-specific-secret';
    process.env.JWT_SECRET = 'child-local-secret';

    const token = jwt.sign({ user_id: 'p-1', email: 'user@hyperdatalab.org' }, 'parent-specific-secret');
    const decoded = verifyAccessToken(token);

    assert.equal(decoded.user_id, 'p-1');
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
