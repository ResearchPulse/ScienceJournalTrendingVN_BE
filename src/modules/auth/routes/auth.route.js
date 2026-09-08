import * as authController from '../controllers/auth.controller.js';

/**
 * @param {import('fastify').FastifyInstance} fastify
 * @param {Object} options
 */
export default async function authRoutes(fastify, options) {
  fastify.post('/login', authController.login);
  fastify.post('/refresh', authController.refreshToken);
  fastify.get('/refresh', authController.refreshToken);
  fastify.get('/check-auth', authController.checkAuth);
  fastify.post('/logout', authController.logout);
  fastify.post('/register', authController.register);
  fastify.post('/resend-activation', authController.resendActivation);
  fastify.get('/verify', authController.verify);
  
  // Google Auth Endpoint
  fastify.post('/google', authController.googleLogin);
  fastify.post('/sso/bootstrap', authController.ssoBootstrap);
  fastify.post('/sso/login', authController.ssoLogin);
}
