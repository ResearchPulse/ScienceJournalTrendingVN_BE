import { afterEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  getAuthCookieNames,
  getAuthCookieOptions,
  getAuthCookieClearTargets,
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

  test('logout clear targets always include host-only, configured, and parent scopes', () => {
    process.env.NODE_ENV = 'production';
    process.env.COOKIE_DOMAIN = '.vn.hyperdatalab.org';
    process.env.PARENT_COOKIE_DOMAIN = '.hyperdatalab.org';

    const targets = getAuthCookieClearTargets();
    assert.equal(targets.some((options) => !Object.hasOwn(options, 'domain')), true);
    assert.equal(targets.some((options) => options.domain === '.vn.hyperdatalab.org'), true);
    assert.equal(targets.some((options) => options.domain === '.hyperdatalab.org'), true);
  });
});
