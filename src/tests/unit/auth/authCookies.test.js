import { afterEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  getAuthCookieNames,
  getAuthCookieOptions,
  getClearAuthCookieOptions,
  getParentCookieClearOptions,
} from '../../../modules/auth/utils/authCookies.js';

const originalEnv = { ...process.env };
afterEach(() => { process.env = { ...originalEnv }; });

describe('auth cookie contracts', () => {
  test('uses standard access_token and refresh_token names', () => {
    const names = getAuthCookieNames();
    assert.deepEqual(names, {
      access: 'access_token',
      refresh: 'refresh_token',
    });
  });

  test('cookie options configuration', () => {
    process.env.NODE_ENV = 'production';
    const options = getAuthCookieOptions('access');
    assert.equal(options.httpOnly, true);
    assert.equal(options.secure, true);
    assert.equal(options.sameSite, 'none');
    assert.equal(options.path, '/');
  });

  test('parent cookie clear options include parent domain and SameSite None', () => {
    const options = getParentCookieClearOptions();
    assert.equal(options.httpOnly, true);
    assert.equal(options.secure, true);
    assert.equal(options.sameSite, 'none');
    assert.equal(options.path, '/');
    assert.equal(options.domain, '.hyperdatalab.org');
  });
});
