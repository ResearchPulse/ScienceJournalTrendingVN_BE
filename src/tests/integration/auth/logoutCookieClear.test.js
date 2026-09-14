import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import { logout } from '../../../modules/auth/controllers/auth.controller.js';
import { getAuthCookieNames } from '../../../modules/auth/utils/authCookies.js';

process.env.NODE_ENV = 'production';
process.env.PARENT_JWT_SECRET = 'parent-secret';
process.env.VN_SSO_BLOCK_SECRET = 'block-secret';

describe('logout cookie clear contracts', () => {
  test('logout clears both stale host-only cookies and shared parent-domain cookies', async () => {
    const originalCookieDomain = process.env.COOKIE_DOMAIN;
    process.env.COOKIE_DOMAIN = '.hyperdatalab.org';

    const app = Fastify();
    try {
      await app.register(cookie);
      app.post('/api/auth/logout', logout);
      const response = await app.inject({ method: 'POST', url: '/api/auth/logout' });

      assert.equal(response.statusCode, 200);
      const cookies = [].concat(response.headers['set-cookie'] || []);
      const names = getAuthCookieNames();

      for (const name of [names.access, names.refresh, names.blocker]) {
        const deletions = cookies.filter((value) => value.startsWith(`${name}=`));
        assert.equal(
          deletions.some((value) => !/;\s*domain=/i.test(value) && /expires=thu, 01 jan 1970/i.test(value)),
          true,
          `${name} must be deleted as a host-only cookie`,
        );
      }

      for (const name of ['access_token', 'refresh_token']) {
        const deletions = cookies.filter((value) => value.startsWith(`${name}=`));
        assert.equal(
          deletions.some((value) => /;\s*domain=\.?hyperdatalab\.org/i.test(value) && /expires=thu, 01 jan 1970/i.test(value)),
          true,
          `${name} must be deleted from the shared parent domain`,
        );
      }
    } finally {
      await app.close();
      if (originalCookieDomain === undefined) delete process.env.COOKIE_DOMAIN;
      else process.env.COOKIE_DOMAIN = originalCookieDomain;
    }
  });
});
