import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import jwt from 'jsonwebtoken';
import { logout } from '../../../modules/auth/controllers/auth.controller.js';
import { getAuthCookieNames } from '../../../modules/auth/utils/authCookies.js';

process.env.NODE_ENV = 'production';
process.env.PARENT_JWT_SECRET = 'parent-secret';
process.env.VN_SSO_BLOCK_SECRET = 'block-secret';

describe('logout cookie clear contracts', () => {
  test('logout clears host and parent domain cookies', async () => {
    const app = Fastify();
    await app.register(cookie);
    app.post('/api/auth/logout', logout);
    const response = await app.inject({ method: 'POST', url: '/api/auth/logout' });

    assert.equal(response.statusCode, 200);
    const cookies = [].concat(response.headers['set-cookie'] || []);
    const names = getAuthCookieNames();
    assert.equal(cookies.some((value) => value.includes(`${names.access}=`)), true);
    assert.equal(cookies.some((value) => value.includes(`${names.refresh}=`)), true);
    assert.equal(cookies.some((value) => value.toLowerCase().includes('domain=.hyperdatalab.org')), true);
    assert.equal(cookies.some((value) => value.toLowerCase().includes('domain=hyperdatalab.org')), true);
    await app.close();
  });
});
