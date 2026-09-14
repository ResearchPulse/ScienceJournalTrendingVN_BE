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
  test('uses isolated child cookie names in production and development', () => {
    process.env.NODE_ENV = 'production';
    assert.deepEqual(getAuthCookieNames(), {
      access: '__Host-vn_access_token',
      refresh: '__Host-vn_refresh_token',
      blocker: '__Host-vn_sso_block',
    });

    process.env.NODE_ENV = 'development';
    assert.deepEqual(getAuthCookieNames(), {
      access: 'vn_access_token_dev',
      refresh: 'vn_refresh_token_dev',
      blocker: 'vn_sso_block_dev',
    });
  });

  test('child cookies remain host-only even when a shared cookie domain is configured', () => {
    process.env.NODE_ENV = 'production';
    process.env.COOKIE_DOMAIN = '.hyperdatalab.org';
    const options = getAuthCookieOptions('access');
    assert.equal(options.httpOnly, true);
    assert.equal(options.secure, true);
    assert.equal(options.sameSite, 'none');
    assert.equal(options.path, '/');
    assert.equal(Object.hasOwn(options, 'domain'), false);
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
