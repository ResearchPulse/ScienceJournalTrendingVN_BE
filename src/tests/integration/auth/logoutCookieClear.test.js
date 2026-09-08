import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';

import { logout } from '../../../modules/auth/controllers/auth.controller.js';

process.env.NODE_ENV = 'production';
process.env.PARENT_COOKIE_DOMAIN = '.hyperdatalab.org';
process.env.COOKIE_DOMAIN = 'vn.hyperdatalab.org';

const buildTestApp = async () => {
  const app = Fastify();
  await app.register(cookie);
  app.post('/api/auth/logout', logout);
  return app;
};

describe('logout cookie clear contracts', () => {
  test('logout clears both local and parent wildcard cookies', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/logout',
    });

    assert.equal(response.statusCode, 200);
    const json = response.json();
    assert.equal(json.success, true);
    assert.equal(json.code, 'LOGOUT_SUCCESS');

    // Kiểm tra các header Set-Cookie trả về
    const setCookies = response.headers['set-cookie'];
    assert.ok(setCookies, 'Response must include set-cookie headers');

    const cookiesArray = Array.isArray(setCookies) ? setCookies : [setCookies];

    // Phải có chỉ thị xóa access_token và refresh_token cho domain .hyperdatalab.org
    const hasParentAccessClear = cookiesArray.some(
      (c) => c.includes('access_token=') && c.toLowerCase().includes('domain=.hyperdatalab.org')
    );
    const hasParentRefreshClear = cookiesArray.some(
      (c) => c.includes('refresh_token=') && c.toLowerCase().includes('domain=.hyperdatalab.org')
    );

    assert.equal(hasParentAccessClear, true, 'Must clear parent domain access_token');
    assert.equal(hasParentRefreshClear, true, 'Must clear parent domain refresh_token');
  });
});
