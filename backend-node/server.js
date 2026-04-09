require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');

// Import route factories
const productRoutes = require('./routes/products');
const orderRoutes = require('./routes/orders');
const adminRoutes = require('./routes/admin');
const webhookRoutes = require('./routes/webhooks');

const app = express();
const PORT = process.env.PORT || 8000;

// ============ MIDDLEWARE ============

// CORS — mirrors Python's CORSMiddleware
const corsOrigins = process.env.CORS_ORIGINS || '*';
app.use(
  cors({
    origin: corsOrigins === '*' ? '*' : corsOrigins.split(','),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['*']
  })
);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl} ${res.statusCode} - ${ms}ms`);
  });
  next();
});

// ============ DATABASE & SERVER START ============

async function startServer() {
  const mongoUrl = process.env.MONGO_URL;
  const dbName = process.env.DB_NAME;

  if (!mongoUrl || !dbName) {
    console.error('MONGO_URL and DB_NAME environment variables are required');
    process.exit(1);
  }

  let client;
  try {
    client = new MongoClient(mongoUrl);
    await client.connect();
    console.log('✅ Connected to MongoDB');
  } catch (err) {
    console.error('❌ Failed to connect to MongoDB:', err.message);
    process.exit(1);
  }

  const db = client.db(dbName);

  // ============ ROOT API ROUTE ============
  app.get('/api/', (req, res) => {
    res.json({ message: 'E-Commerce API', status: 'active' });
  });
  app.get('/api', (req, res) => {
    res.json({ message: 'E-Commerce API', status: 'active' });
  });

  // ============ MOUNT ROUTES ============
  app.use('/api', productRoutes(db));
  app.use('/api', orderRoutes(db));
  app.use('/api', adminRoutes(db));
  app.use('/api', webhookRoutes(db));

  // ============ HEALTH CHECK ============
  app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
  });

  // ============ GRACEFUL SHUTDOWN ============
  const shutdown = async () => {
    console.log('\nShutting down...');
    await client.close();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // ============ START LISTENING ============
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📦 API base: http://localhost:${PORT}/api`);
  });
}

startServer();
