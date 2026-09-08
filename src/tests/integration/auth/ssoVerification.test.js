import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import jwt from 'jsonwebtoken';

import { verifyToken, requireAuth } from '../../../modules/auth/middlewares/auth.middleware.js';
import { checkAuth } from '../../../modules/auth/controllers/auth.controller.js';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'shared-cross-domain-secret-test';

const buildTestApp = async () => {
  const app = Fastify();
  await app.register(cookie);

  // Route bảo vệ sử dụng verifyToken middleware
  app.get('/api/protected/profile', { preHandler: [verifyToken] }, async (request, reply) => {
    return reply.send({
      success: true,
      user: request.user,
    });
  });

  // Route check-auth
  app.get('/api/auth/check-auth', checkAuth);

  return app;
};

describe('cross-domain sso token verification', () => {
  test('authenticates parent domain token statelessly without db lookup', async () => {
    const app = await buildTestApp();

    const parentPayload = {
      user_id: 'parent-user-999',
      email: 'researcher@hyperdatalab.org',
      role: 'ADMINISTRATOR',
      domain: 'hyperdatalab.org',
    };

    const parentToken = jwt.sign(parentPayload, process.env.JWT_SECRET, { expiresIn: '1h' });

    const response = await app.inject({
      method: 'GET',
      url: '/api/protected/profile',
      cookies: {
        access_token: parentToken,
      },
    });

    assert.equal(response.statusCode, 200);
    const body = response.json();
    assert.equal(body.success, true);
    assert.equal(body.user.user_id, 'parent-user-999');
    assert.equal(body.user.email, 'researcher@hyperdatalab.org');
    assert.equal(body.user.role, 'ADMINISTRATOR');
    assert.equal(body.user.auth_source, 'parent_sso');
  });

  test('checkAuth returns authenticated true with decoded user for parent token', async () => {
    const app = await buildTestApp();

    const parentPayload = {
      user_id: 'parent-user-888',
      email: 'scientist@hyperdatalab.org',
      role: 'USER',
      domain: 'hyperdatalab.org',
    };

    const parentToken = jwt.sign(parentPayload, process.env.JWT_SECRET, { expiresIn: '1h' });

    const response = await app.inject({
      method: 'GET',
      url: '/api/auth/check-auth',
      cookies: {
        access_token: parentToken,
      },
    });

    assert.equal(response.statusCode, 200);
    const body = response.json();
    assert.equal(body.success, true);
    assert.equal(body.authenticated, true);
    assert.equal(body.user.email, 'scientist@hyperdatalab.org');
  });

  test('authenticates real-world parent token without domain or iss claim', async () => {
    const app = await buildTestApp();

    const realParentPayload = {
      user_id: '01b37976-d13a-4713-8ba7-a8e078494a25',
      role: 'INUETE9',
      email: 'cubinvinh@gmail.com',
    };

    const token = jwt.sign(realParentPayload, process.env.JWT_SECRET, { expiresIn: '1h' });

    const response = await app.inject({
      method: 'GET',
      url: '/api/auth/check-auth',
      cookies: {
        access_token: token,
      },
    });

    assert.equal(response.statusCode, 200);
    const body = response.json();
    assert.equal(body.authenticated, true);
    assert.equal(body.user.email, 'cubinvinh@gmail.com');
    assert.equal(body.data.user_id, '01b37976-d13a-4713-8ba7-a8e078494a25');
  });

  test('rejects expired or invalid signature tokens', async () => {
    const app = await buildTestApp();

    const fakeToken = jwt.sign(
      { user_id: 'fake', domain: 'hyperdatalab.org' },
      'wrong-secret-signature'
    );

    const response = await app.inject({
      method: 'GET',
      url: '/api/protected/profile',
      cookies: {
        access_token: fakeToken,
      },
    });

    assert.equal(response.statusCode, 401);
  });
});
