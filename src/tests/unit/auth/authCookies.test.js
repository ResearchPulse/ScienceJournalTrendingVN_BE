import { afterEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { getAuthCookieNames, getAuthCookieOptions, getClearAuthCookieOptions } from '../../../modules/auth/utils/authCookies.js';

const originalEnv = { ...process.env };
afterEach(() => { process.env = { ...originalEnv }; });

describe('isolated child cookie contracts', () => {
  test('production uses unique host-only __Host cookies', () => {
    process.env.NODE_ENV = 'production';
    const names = getAuthCookieNames();
    assert.deepEqual(names, {
      access: '__Host-vn_access_token',
      refresh: '__Host-vn_refresh_token',
      blocker: '__Host-vn_sso_block',
    });
    const options = getAuthCookieOptions('access');
    assert.equal(options.httpOnly, true);
    assert.equal(options.secure, true);
    assert.equal(options.sameSite, 'lax');
    assert.equal(options.path, '/');
    assert.equal('domain' in options, false);
  });

  test('development names cannot collide with parent cookies', () => {
    process.env.NODE_ENV = 'development';
    const names = getAuthCookieNames();
    assert.notEqual(names.access, 'access_token');
    assert.notEqual(names.refresh, 'refresh_token');
    assert.notEqual(names.blocker, 'sso_block');
  });

  test('clear options preserve the host-only scope', () => {
    process.env.NODE_ENV = 'production';
    const options = getClearAuthCookieOptions();
    assert.equal(options.secure, true);
    assert.equal(options.path, '/');
    assert.equal('domain' in options, false);
  });
});
