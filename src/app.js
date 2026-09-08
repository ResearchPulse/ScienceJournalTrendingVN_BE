import Fastify from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';


// Táº¡m thá»i comment rootRouter express cÅ©
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
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      try {
        const { hostname } = new URL(origin);
        if (
          hostname === 'localhost' ||
          hostname === '127.0.0.1' ||
          hostname === 'hyperdatalab.org' ||
          hostname.endsWith('.hyperdatalab.org') ||
          (process.env.FRONTEND_URL && origin.startsWith(process.env.FRONTEND_URL))
        ) {
          return cb(null, true);
        }
      } catch (e) {
        // URL khong hop le
      }
      return cb(new Error('Not allowed by CORS'), false);
    },
    credentials: true
  });

  await app.register(cookie);
  await app.register(formbody);

  const PORT = process.env.PORT || 5000;
  await app.register(swagger, {
    swagger: {
      info: {
        title: "Tuyển Tập API Fastify của Tôi",
        description: "T� i liệu hướng dẫn sử dụng các API hệ thống (Fastify)",
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

  // Tự động thêm tag cho Swagger dựa trên URL prefix để gom nhóm API
  app.addHook('onRoute', (routeOptions) => {
    if (!routeOptions.schema) routeOptions.schema = {};
    if (!routeOptions.schema.tags) {
      const url = routeOptions.url;
      let tag = 'Khác';
      if (url.startsWith('/api/v1/auth')) tag = 'Xác thực (Auth)';
      else if (url.startsWith('/api/v1/users')) tag = 'Người dùng (User)';
      else if (url.startsWith('/api/v1/admin')) tag = 'Quản trị (Admin)';
      else if (url.startsWith('/api/v1/articles')) tag = 'B� i báo (Article)';
      else if (url.startsWith('/api/v1/comments')) tag = 'Bình luận (Comment)';
      else if (url.includes('journal')) tag = 'Tạp chí (Journal)';
      else if (url.includes('issues')) tag = 'Kỳ xuất bản (Issue)';
      else if (url.includes('volumes')) tag = 'Tập san (Volume)';
      else if (url.includes('publishers')) tag = 'Nh�  xuất bản (Publisher)';

      else if (url.includes('author')) tag = 'Tác giả (Author)';
      else if (url.includes('institution')) tag = 'Đơn vị (Institution)';
      else if (url.includes('orcid')) tag = 'Orcid (Đồng bộ)';

      else if (url.includes('projects')) tag = 'Dự án (Project)';
      else if (url.includes('bookmarks')) tag = 'Dấu trang (Bookmark)';

      else if (url.includes('topics')) tag = 'Chủ đề nghiên cứu (Topic)';
      else if (url.includes('subject-areas')) tag = 'Lĩnh vực (Subject Area)';
      else if (url.includes('subject-categories')) tag = 'Danh mục (Subject Category)';
      else if (url.includes('keywords')) tag = 'Từ khóa (Keyword)';

      else if (url.includes('catalog')) tag = 'Hệ thống - Catalog';
      else if (url.includes('search')) tag = 'Hệ thống - Tìm kiếm (Search)';
      else if (url.includes('zones')) tag = 'Hệ thống - Vùng (Zone)';
      else if (url.includes('trending-vn')) tag = 'Hệ thống - Xu hướng VN';

      routeOptions.schema.tags = [tag];
    }
  });

  // Register cÃ¡c routes module Fastify má»›i
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
