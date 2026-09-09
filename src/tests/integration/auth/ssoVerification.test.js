import { describe, test, mock } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import jwt from 'jsonwebtoken';

process.env.NODE_ENV = 'test';
process.env.PARENT_JWT_SECRET = 'parent-secret';
process.env.VN_JWT_SECRET = 'child-secret';
process.env.VN_JWT_REFRESH_SECRET = 'refresh-secret';
process.env.VN_SSO_BLOCK_SECRET = 'block-secret';

const localUser = { user_id: 'child-user-1', email: 'user@example.com', role: 'STUDENT', status: 'ACTIVE', type: null };
mock.module('../../../modules/auth/repositories/sso.repository.js', {
  namedExports: {
    normalizeEmail: (email) => email.trim().toLowerCase(),
    findUsersByNormalizedEmail: async () => [localUser],
    createJitUser: async () => localUser,
  },
});

const { checkAuth, logout, ssoBootstrap } = await import('../../../modules/auth/controllers/auth.controller.js');
const { authUserRepository } = await import('../../../modules/auth/middlewares/auth.middleware.js');
const { getAuthCookieNames } = await import('../../../modules/auth/utils/authCookies.js');

const readCookieValue = (response, name, predicate = () => true) => {
  const serialized = [].concat(response.headers['set-cookie'] || [])
    .find((value) => value.startsWith(`${name}=`) && predicate(value));
  return serialized?.split(';', 1)[0].slice(name.length + 1) || null;
};

const buildApp = async () => {
  const app = Fastify();
  await app.register(cookie);
  app.get('/auth/check-auth', checkAuth);
  app.post('/auth/sso/bootstrap', ssoBootstrap);
  app.post('/auth/logout', logout);
  return app;
};

describe('parent-to-child SSO exchange', () => {
  test('bootstrap maps verified parent email to local user and sets an isolated child cookie', async () => {
    const app = await buildApp();
    const parentToken = jwt.sign({ email: 'USER@example.com', role: 'ADMINISTRATOR' }, process.env.PARENT_JWT_SECRET, { expiresIn: '1h' });
    const response = await app.inject({ method: 'POST', url: '/auth/sso/bootstrap', cookies: { access_token: parentToken } });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json().data, { user_id: 'child-user-1', email: 'user@example.com', role: 'STUDENT' });
    assert.equal(response.json().access_token, undefined);
    assert.match([].concat(response.headers['set-cookie']).join(';'), new RegExp(`${getAuthCookieNames().access}=`));
    await app.close();
  });

  test('read-only check-auth rejects a parent token until it is exchanged', async () => {
    const app = await buildApp();
    const parentToken = jwt.sign({ email: 'user@example.com' }, process.env.PARENT_JWT_SECRET, { expiresIn: '1h' });
    const response = await app.inject({ method: 'GET', url: '/auth/check-auth', cookies: { access_token: parentToken } });
    assert.equal(response.statusCode, 401);
    assert.equal(response.json().authenticated, false);
    await app.close();
  });

  test('bootstrap rejects a token signed with the child secret', async () => {
    const app = await buildApp();
    const forged = jwt.sign({ email: 'user@example.com', role: 'ADMINISTRATOR' }, process.env.VN_JWT_SECRET, { expiresIn: '1h' });
    const response = await app.inject({ method: 'POST', url: '/auth/sso/bootstrap', cookies: { access_token: forged } });
    assert.equal(response.statusCode, 401);
    assert.equal(response.json().authenticated, false);
    await app.close();
  });

  test('bootstrap keeps compatibility with a parent token that uses username as its email claim', async () => {
    const app = await buildApp();
    const parentToken = jwt.sign({ username: 'USER@example.com', role: 'STUDENT' }, process.env.PARENT_JWT_SECRET, { expiresIn: '1h' });
    const response = await app.inject({ method: 'POST', url: '/auth/sso/bootstrap', cookies: { access_token: parentToken } });

    assert.equal(response.statusCode, 200);
    assert.equal(response.json().data.email, 'user@example.com');
    await app.close();
  });

  test('development bootstrap accepts a parent bearer token and issues a host-only child cookie', async () => {
    const app = await buildApp();
    const parentToken = jwt.sign({ email: 'user@example.com', role: 'STUDENT' }, process.env.PARENT_JWT_SECRET, { expiresIn: '1h' });
    const response = await app.inject({
      method: 'POST',
      url: '/auth/sso/bootstrap',
      headers: { authorization: `Bearer ${parentToken}` },
    });

    assert.equal(response.statusCode, 200);
    const childCookie = [].concat(response.headers['set-cookie'] || [])
      .find((value) => value.startsWith(`${getAuthCookieNames().access}=`));
    assert.ok(childCookie);
    assert.doesNotMatch(childCookie, /;\s*domain=/i);
    await app.close();
  });

  test('child logout remains logged out after reload even if the same parent cookie survives', async () => {
    const app = await buildApp();
    const names = getAuthCookieNames();
    const parentToken = jwt.sign({ email: 'user@example.com', role: 'STUDENT' }, process.env.PARENT_JWT_SECRET, { expiresIn: '1h' });
    authUserRepository.findById = async () => localUser;

    const bootstrap = await app.inject({
      method: 'POST',
      url: '/auth/sso/bootstrap',
      cookies: { access_token: parentToken },
    });
    const childToken = readCookieValue(bootstrap, names.access);
    assert.ok(childToken);

    const authenticated = await app.inject({
      method: 'GET',
      url: '/auth/check-auth',
      cookies: { [names.access]: childToken },
    });
    assert.equal(authenticated.statusCode, 200);

    const loggedOut = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      cookies: { access_token: parentToken, [names.access]: childToken },
    });
    assert.equal(loggedOut.statusCode, 200);
    const blocker = readCookieValue(
      loggedOut,
      names.blocker,
      (value) => !/expires=thu, 01 jan 1970/i.test(value),
    );
    assert.ok(blocker);

    const afterReload = await app.inject({
      method: 'GET',
      url: '/auth/check-auth',
      cookies: {
        [names.access]: childToken,
        [names.blocker]: blocker,
      },
    });
    assert.equal(afterReload.statusCode, 401);
    assert.equal(afterReload.json().code, 'SSO_BLOCKED');

    const repeatedBootstrap = await app.inject({
      method: 'POST',
      url: '/auth/sso/bootstrap',
      cookies: { access_token: parentToken, [names.blocker]: blocker },
    });
    assert.equal(repeatedBootstrap.statusCode, 409);
    assert.equal(repeatedBootstrap.json().code, 'SSO_BLOCKED');
    await app.close();
  });
});
