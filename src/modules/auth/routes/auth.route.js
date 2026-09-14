import * as authController from '../controllers/auth.controller.js';

/**
 * @param {import('fastify').FastifyInstance} fastify
 * @param {Object} options
 */
export default async function authRoutes(fastify, options) {
  fastify.post('/login', authController.ssoOnlyDisabled);
  fastify.post('/refresh', authController.refreshToken);
  fastify.get('/refresh', authController.refreshToken);
  fastify.get('/check-auth', authController.checkAuth);
  fastify.post('/logout', authController.logout);
  fastify.post('/register', authController.ssoOnlyDisabled);
  fastify.post('/resend-activation', authController.ssoOnlyDisabled);
  fastify.get('/verify', authController.ssoOnlyDisabled);
  
  // Google Auth Endpoint
  fastify.post('/google', authController.ssoOnlyDisabled);
  fastify.post('/sso/bootstrap', authController.ssoOnlyDisabled);
  fastify.post('/sso/login', authController.ssoLogin);
}
