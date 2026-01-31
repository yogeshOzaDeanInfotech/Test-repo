require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const proxy = require('express-http-proxy');
const swaggerUi = require('swagger-ui-express');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

const proxyOptions = (targetUrl) =>
  proxy(targetUrl, {
    timeout: 30000,
    parseReqBody: true,
    proxyReqPathResolver: (req) => req.originalUrl.replace(/^\/v1/, '/api'),
    proxyReqOptDecorator: (proxyReqOpts, srcReq) => {
      if (srcReq.user) {
        proxyReqOpts.headers['x-user-id'] = srcReq.user.userId;
        if (srcReq.user.role) proxyReqOpts.headers['x-user-role'] = srcReq.user.role;
      }
      if (srcReq.headers.authorization) {
        proxyReqOpts.headers['authorization'] = srcReq.headers.authorization;
      }
      return proxyReqOpts;
    },
  });

const validateToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.user = { userId: decoded.userId, role: decoded.role };
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

app.use(express.json());
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ 
  origin: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : ['http://localhost:4005', 'http://localhost:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'api-gateway',
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (req, res) => {
  res.json({
    service: 'API Gateway',
    version: '1.0.0',
    endpoints: { health: '/health', docs: '/api-docs', user: '/v1/user', worksheet: '/v1/worksheet', payment: '/v1/payment', notification: '/v1/notification' },
  });
});

app.get('/swagger.json', async (req, res) => {
  const services = [
    { url: `${process.env.USER_SERVICE_URL}/docs/swagger.json` },
    { url: `${process.env.WORKSHEET_SERVICE_URL}/docs/swagger.json` },
    { url: `${process.env.PAYMENT_SERVICE_URL}/docs/swagger.json` },
    { url: `${process.env.NOTIFICATION_SERVICE_URL}/docs/swagger.json` },
  ];
  const mergedPaths = {};
  const mergedComponents = {};
  const results = await Promise.allSettled(services.map((s) => axios.get(s.url)));
  results.forEach((r, i) => {
    if (r.status === 'fulfilled' && r.value.data) {
      Object.assign(mergedPaths, r.value.data.paths || {});
      Object.assign(mergedComponents, r.value.data.components || {});
    }
  });
  res.json({
    openapi: '3.0.0',
    info: { title: 'API Docs', version: '1.0.0' },
    servers: [{ url: 'http://localhost:3000', description: 'Local' }],
    components: { ...mergedComponents, securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } } },
    security: [{ bearerAuth: [] }],
    paths: mergedPaths,
  });
});

app.use(
  '/api-docs',
  swaggerUi.serve,
  swaggerUi.setup(null, { swaggerUrl: `${process.env.API_GATEWAY_URL || 'http://localhost:3000'}/swagger.json` })
);

app.post('/v1/user/login', proxyOptions(process.env.USER_SERVICE_URL));
app.post('/v1/user/register', proxyOptions(process.env.USER_SERVICE_URL));
app.post('/v1/payment/packages/list', proxyOptions(process.env.PAYMENT_SERVICE_URL));
app.use('/v1/user', validateToken, proxyOptions(process.env.USER_SERVICE_URL));
app.use('/v1/worksheet', validateToken, proxyOptions(process.env.WORKSHEET_SERVICE_URL));
app.use('/v1/payment', validateToken, proxyOptions(process.env.PAYMENT_SERVICE_URL));
app.use('/v1/notification', proxyOptions(process.env.NOTIFICATION_SERVICE_URL));

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message || 'Internal server error' });
});

app.listen(port, () => {
  console.log(`API Gateway running on ${port}`);
});
