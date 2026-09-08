import { afterEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  getAuthCookieNames,
  getCookieOptions,
  getClearAuthCookieOptions,
  getParentCookieClearOptions,
  ACCESS_TOKEN_COOKIE,
  REFRESH_TOKEN_COOKIE,
} from '../../../modules/auth/utils/authCookies.js';

const originalEnv = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnv };
});

describe('auth cookie contracts', () => {
  test('standard cookie names are access_token and refresh_token', () => {
    const names = getAuthCookieNames();
    assert.deepEqual(names, {
      access: ACCESS_TOKEN_COOKIE,
      refresh: REFRESH_TOKEN_COOKIE,
    });
    assert.equal(names.access, 'access_token');
    assert.equal(names.refresh, 'refresh_token');
  });

  test('production cookie options for child use secure and proper attributes', () => {
    process.env.NODE_ENV = 'production';
    process.env.COOKIE_DOMAIN = 'vn.hyperdatalab.org';
    const options = getCookieOptions();

    assert.equal(options.httpOnly, true);
    assert.equal(options.secure, true);
    assert.equal(options.sameSite, 'none');
    assert.equal(options.path, '/');
    assert.equal(options.domain, 'vn.hyperdatalab.org');
  });

  test('development cookie options do not restrict cross-site when not in production', () => {
    process.env.NODE_ENV = 'development';
    delete process.env.COOKIE_DOMAIN;
    const options = getCookieOptions();

    assert.equal(options.httpOnly, true);
    assert.equal(options.secure, false);
    assert.equal(options.sameSite, 'lax');
    assert.equal(options.path, '/');
    assert.equal('domain' in options, false);
  });

  test('parent clear options target wildcard domain .hyperdatalab.org', () => {
    process.env.NODE_ENV = 'production';
    const clearOptions = getParentCookieClearOptions();

    assert.equal(clearOptions.domain, '.hyperdatalab.org');
    assert.equal(clearOptions.path, '/');
    assert.equal(clearOptions.httpOnly, true);
  });
});
