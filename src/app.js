import Fastify from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import { getAuthCookieNames } from './modules/auth/utils/authCookies.js';


// Tạm thời comment rootRouter express cũ
// import rootRouter from './routes/index.js';
import authRoutes from './modules/auth/routes/auth.route.js';
import userRoutes from './modules/user/routes/user.route.js';
import adminRoutes from './modules/user/routes/admin.route.js';
import articleRoutes from './modules/article/routes/article.route.js';
import commentRoutes from './modules/article/routes/comment.route.js';
import journalRoutes from './modules/journal/routes/journal.route.js';
import issueRoutes from './modules/journal/routes/issue.route.js';
import volumeRoutes from './modules/journal/routes/volume.route.js';
import publisherRoutes from './modules/journal/routes/publisher.route.js';
import authorRoutes from './modules/author/routes/author.route.js';
import institutionRoutes from './modules/author/routes/institution.route.js';
import orcidRoutes from './modules/author/routes/orcid.route.js';
import projectRoutes from './modules/project/routes/project.route.js';
import bookmarkRoutes from './modules/project/routes/bookmark.route.js';
import topicRoutes from './modules/topic/routes/topic.route.js';
import subjectAreaRoutes from './modules/topic/routes/subjectArea.route.js';
import subjectCategoryRoutes from './modules/topic/routes/subjectCategory.route.js';
import keywordRoutes from './modules/topic/routes/keyword.route.js';
import { projectKeywordRoutes } from './modules/topic/routes/keyword.route.js';
import catalogRoutes from './modules/system/routes/catalog.route.js';
import searchRoutes from './modules/system/routes/search.route.js';
import zoneRoutes from './modules/system/routes/zone.route.js';
import trendingVnRoutes from './modules/system/routes/trendingVn.route.js';

const buildApp = async () => {
  const app = Fastify({ logger: true });

  await app.register(cors, {
    origin: (origin, callback) => {
      const allowedOrigin = process.env.FRONTEND_URL || 'http://localhost:5173';
      if (!origin || origin === allowedOrigin) return callback(null, true);
      return callback(new Error('Origin is not allowed'), false);
    },
    credentials: true,
  });

  await app.register(cookie);
  await app.register(formbody);

  app.addContentTypeParser('application/json', { parseAs: 'string' }, (req, body, done) => {
    if (!body || !body.trim()) {
      return done(null, {});
    }
    try {
      done(null, JSON.parse(body));
    } catch (err) {
      err.statusCode = 400;
      done(err, undefined);
    }
  });

  app.addHook('onRequest', async (request, reply) => {
    const sessionRoute = request.url.startsWith('/api/v1/auth/sso/')
      || request.url.startsWith('/api/v1/auth/logout')
      || request.url.startsWith('/api/v1/auth/refresh');
    if (!sessionRoute && !['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) return;
    const names = getAuthCookieNames();
    const cookies = request.cookies || {};
    const allowedOrigin = process.env.FRONTEND_URL || 'http://localhost:5173';
    const contentType = String(request.headers['content-type'] || '').toLowerCase();
    const hasBearer = /^Bearer\s+\S+/i.test(String(request.headers.authorization || ''));
    if (!request.headers.origin && !hasBearer && contentType && !contentType.startsWith('application/json')) {
      return reply.status(403).send({ success: false, code: 'ORIGIN_NOT_ALLOWED', message: 'JSON requests must include an approved Origin' });
    }
    if (!sessionRoute && !cookies[names.access] && !cookies[names.refresh]) return;
    if (request.headers.origin !== allowedOrigin) {
      return reply.status(403).send({ success: false, code: 'ORIGIN_NOT_ALLOWED', message: 'Origin is not allowed' });
    }
  });

  const PORT = process.env.PORT || 5000;
  await app.register(swagger, {
    swagger: {
      info: {
        title: "Tuy?n T?p API Fastify c?a T�i",
        description: "T? i li?u hu?ng d?n s? d?ng c�c API h? th?ng (Fastify)",
        version: "1.0.0",
      },
      host: 'localhost:' + PORT,
      schemes: ['http'],
      consumes: ['application/json'],
      produces: ['application/json'],
      securityDefinitions: {
        bearerAuth: {
          type: 'apiKey',
          name: 'Authorization',
          in: 'header'
        }
      }
    }
  });

  await app.register(swaggerUi, {
    routePrefix: '/api-docs',
    uiConfig: {
      docExpansion: 'none',
      deepLinking: false
    },
    staticCSP: false,
    transformStaticCSP: (header) => header
  });

  // T? d?ng th�m tag cho Swagger d?a tr�n URL prefix d? gom nh�m API
  app.addHook('onRoute', (routeOptions) => {
    if (!routeOptions.schema) routeOptions.schema = {};
    if (!routeOptions.schema.tags) {
      const url = routeOptions.url;
      let tag = 'Kh�c';
      if (url.startsWith('/api/v1/auth')) tag = 'X�c th?c (Auth)';
      else if (url.startsWith('/api/v1/users')) tag = 'Ngu?i d�ng (User)';
      else if (url.startsWith('/api/v1/admin')) tag = 'Qu?n tr? (Admin)';
      else if (url.startsWith('/api/v1/articles')) tag = 'B? i b�o (Article)';
      else if (url.startsWith('/api/v1/comments')) tag = 'B�nh lu?n (Comment)';
      else if (url.includes('journal')) tag = 'T?p ch� (Journal)';
      else if (url.includes('issues')) tag = 'K? xu?t b?n (Issue)';
      else if (url.includes('volumes')) tag = 'T?p san (Volume)';
      else if (url.includes('publishers')) tag = 'Nh?  xu?t b?n (Publisher)';

      else if (url.includes('author')) tag = 'T�c gi? (Author)';
      else if (url.includes('institution')) tag = '�on v? (Institution)';
      else if (url.includes('orcid')) tag = 'Orcid (�?ng b?)';

      else if (url.includes('projects')) tag = 'D? �n (Project)';
      else if (url.includes('bookmarks')) tag = 'D?u trang (Bookmark)';

      else if (url.includes('topics')) tag = 'Ch? d? nghi�n c?u (Topic)';
      else if (url.includes('subject-areas')) tag = 'Linh v?c (Subject Area)';
      else if (url.includes('subject-categories')) tag = 'Danh m?c (Subject Category)';
      else if (url.includes('keywords')) tag = 'T? kh�a (Keyword)';

      else if (url.includes('catalog')) tag = 'H? th?ng - Catalog';
      else if (url.includes('search')) tag = 'H? th?ng - T�m ki?m (Search)';
      else if (url.includes('zones')) tag = 'H? th?ng - V�ng (Zone)';
      else if (url.includes('trending-vn')) tag = 'H? th?ng - Xu hu?ng VN';

      routeOptions.schema.tags = [tag];
    }
  });

  // Register các routes module Fastify mới
  app.register(authRoutes, { prefix: '/api/v1/auth' });
  app.register(userRoutes, { prefix: '/api/v1/users' });
  app.register(adminRoutes, { prefix: '/api/v1/admin' });
  app.register(articleRoutes, { prefix: '/api/v1/articles' });
  app.register(commentRoutes, { prefix: '/api/v1/comments' });
  app.register(journalRoutes, { prefix: '/api/v1/journal' });
  app.register(issueRoutes, { prefix: '/api/v1/issues' });
  app.register(volumeRoutes, { prefix: '/api/v1/volumes' });
  app.register(publisherRoutes, { prefix: '/api/v1/publishers' });
  app.register(authorRoutes, { prefix: '/api/v1/author' });
  app.register(authorRoutes, { prefix: '/api/v1/authors' });
  app.register(institutionRoutes, { prefix: '/api/v1/institution' });
  app.register(orcidRoutes, { prefix: '/api/v1/orcid' });
  app.register(projectRoutes, { prefix: '/api/v1/projects' });
  app.register(bookmarkRoutes, { prefix: '/api/v1/bookmarks' });
  app.register(topicRoutes, { prefix: '/api/v1/topics' });
  app.register(subjectAreaRoutes, { prefix: '/api/v1/subject-areas' });
  app.register(subjectCategoryRoutes, { prefix: '/api/v1/subject-categories' });
  app.register(keywordRoutes, { prefix: '/api/v1/keywords' });

  app.register(projectKeywordRoutes, { prefix: '/api/v1/projects' });


  app.register(catalogRoutes, { prefix: '/api/v1/catalog' });
  app.register(searchRoutes, { prefix: '/api/v1/search' });
  app.register(zoneRoutes, { prefix: '/api/v1/zones' });
  app.register(trendingVnRoutes, { prefix: '/api/v1/trending-vn' });

  return app;
};

export default buildApp;
