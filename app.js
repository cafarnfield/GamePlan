const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const axios = require('axios'); // Add axios for HTTP requests
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const steamService = require('./services/steamService');
const rawgService = require('./services/rawgService');

// Import winston logger
const { systemLogger, authLogger, adminLogger, securityLogger } = require('./utils/logger');
const { requestLogger, apiRequestLogger } = require('./middleware/requestLogger');

// Import validation middleware and validators
const { handleValidationErrors } = require('./middleware/validation');

// Import authentication middleware
const { ensureAuthenticated, ensureNotBlocked } = require('./middleware/auth');

// Import centralized error handling
const {
  requestIdMiddleware,
  notFoundHandler,
  errorHandler,
  asyncErrorHandler,
  handleDatabaseErrors
} = require('./middleware/errorHandler');

// Import custom errors
const {
  NotFoundError,
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  DatabaseError,
  ExternalServiceError
} = require('./utils/errors');
const {
  validateEventCreation,
  validateEventEdit,
  validateEventDuplication
} = require('./validators/eventValidators');
const {
  validateSteamSearch,
  validateRawgSearch,
  validateEventFilter,
  validateDuplicateCheck,
  validateSteamEquivalentCheck,
  validateAdminUserFilter,
  validateAdminGameFilter,
  validateAdminEventFilter
} = require('./validators/searchValidators');
const {
  validateUserApproval,
  validateUserRejection,
  validateBulkUserOperation,
  validateGameApproval,
  validateAdminGameAddition,
  validateBulkEventOperation
} = require('./validators/adminValidators');

// Import environment validation middleware
const { validateAndExitIfInvalid, validateProductionSafety, configHealthMiddleware } = require('./middleware/envValidation');

// Initialize Express
const app = express();

// View engine setup
app.set('view engine', 'ejs');

// Load environment variables first
require('dotenv').config();

// Perform startup environment validation
validateAndExitIfInvalid();

// Helmet Security Configuration
const helmetConfig = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: [
        "'self'", 
        "'unsafe-inline'", // Required for EJS templates with inline styles
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com" // For any CDN stylesheets
      ],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'", // Allow inline scripts for development
        "'unsafe-eval'", // Allow eval for development
        "https://www.google.com", // reCAPTCHA
        "https://www.gstatic.com", // reCAPTCHA
        "https://cdnjs.cloudflare.com" // For any CDN scripts
      ],
      scriptSrcAttr: ["'unsafe-inline'"], // Allow inline event handlers
      imgSrc: [
        "'self'", 
        "data:", // For data URLs
        "https:", // Allow all HTTPS images (Steam, RAWG, etc.)
        "http:" // Allow HTTP images for development
      ],
      connectSrc: [
        "'self'",
        "https://api.steampowered.com", // Steam API
        "https://api.rawg.io", // RAWG API
        "https://www.google.com" // reCAPTCHA
      ],
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com"
      ],
      frameSrc: [
        "https://www.google.com" // reCAPTCHA
      ],
      objectSrc: ["'none'"], // Disable object/embed tags
      mediaSrc: ["'self'"],
      childSrc: ["'none'"], // Disable child contexts
      workerSrc: ["'self'"],
      manifestSrc: ["'self'"]
    },
    // Disable CSP in development to avoid blocking functionality
    reportOnly: process.env.NODE_ENV !== 'production'
  },
  // Conditional HSTS configuration
  hsts: process.env.NODE_ENV === 'production' ? {
    maxAge: 31536000, // 1 year in seconds
    includeSubDomains: true,
    preload: true
  } : false, // Disable HSTS in development
  noSniff: true, // X-Content-Type-Options: nosniff
  frameguard: { action: 'deny' }, // X-Frame-Options: DENY
  xssFilter: true, // X-XSS-Protection: 1; mode=block
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  permissionsPolicy: {
    camera: ['none'],
    microphone: ['none'],
    geolocation: ['none'],
    payment: ['none'],
    usb: ['none']
  },
  dnsPrefetchControl: { allow: false }, // X-DNS-Prefetch-Control: off
  ieNoOpen: true, // X-Download-Options: noopen
  hidePoweredBy: true // Remove X-Powered-By header
};

// Apply Helmet security middleware
app.use(helmet(helmetConfig));

// Apply production safety middleware
app.use(validateProductionSafety);

// Apply configuration health middleware
app.use(configHealthMiddleware);

// Middleware with debug logging
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use((req, res, next) => {
  systemLogger.debug('Session middleware accessed', {
    requestId: req.requestId,
    sessionId: req.sessionID,
    hasSession: !!req.session
  });
  next();
});
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_secret_key',
  resave: false, // Don't save session if unmodified
  saveUninitialized: false, // Don't create session until something stored
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 1 day
    httpOnly: true,
    secure: process.env.SECURE_COOKIES === 'true', // Use environment variable for secure cookies
    sameSite: 'lax' // Add sameSite option for CSRF protection
  },
  name: 'gameplan.sid', // Custom session cookie name
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI || 'mongodb://localhost:27017/gameplan',
    collectionName: 'sessions',
    ttl: 24 * 60 * 60, // 1 day in seconds
    touchAfter: 24 * 3600 // lazy session update
  })
}));
app.use((req, res, next) => {
  systemLogger.debug('Session middleware post-init accessed', {
    requestId: req.requestId,
    sessionId: req.sessionID,
    hasSession: !!req.session,
    isAuthenticated: req.isAuthenticated ? req.isAuthenticated() : false,
    userId: req.user?._id,
    userEmail: req.user?.email
  });
  next();
});
app.use((req, res, next) => {
  systemLogger.debug('Session middleware final check', {
    requestId: req.requestId,
    sessionId: req.sessionID,
    sessionData: req.session ? Object.keys(req.session) : []
  });
  next();
});
app.use(passport.initialize());
app.use(passport.session());

// Enhanced MongoDB connection with retry logic and monitoring
const { connect: connectDatabase, on: onDatabaseEvent } = require('./utils/database');
const { connectionMonitor } = require('./utils/connectionMonitor');
const {
  ensureDatabaseConnection,
  addDatabaseMetrics,
  addAdminDatabaseInfo,
  handleDatabaseErrors: handleDbErrors
} = require('./middleware/databaseMiddleware');

// Initialize database connection
const initializeDatabase = async () => {
  try {
    systemLogger.info('Initializing enhanced database connection', {
      mockDb: !!process.env.MOCK_DB,
      environment: process.env.NODE_ENV
    });
    
    // Connect to database with retry logic
    if (process.env.MOCK_DB) {
      await connectDatabase('mongodb://localhost:27017/gameplan');
    } else {
      await connectDatabase();
    }
    
    systemLogger.info('Database connection initialized successfully', {
      connectionState: 'connected',
      environment: process.env.NODE_ENV
    });
  } catch (error) {
    systemLogger.error('Failed to initialize database connection', {
      error: error.message,
      stack: error.stack,
      environment: process.env.NODE_ENV
    });
    
    // In production, we might want to exit the process
    if (process.env.NODE_ENV === 'production') {
      systemLogger.error('Exiting due to database connection failure in production', {
        exitCode: 1,
        reason: 'database_connection_failure'
      });
      process.exit(1);
    } else {
      systemLogger.warn('Continuing in development mode despite database connection failure', {
        environment: 'development',
        allowContinue: true
      });
    }
  }
};

// Setup database event listeners
onDatabaseEvent('connected', () => {
  systemLogger.info('Database connection established - monitoring started', {
    event: 'database_connected',
    monitoringActive: true
  });
});

onDatabaseEvent('disconnected', () => {
  systemLogger.warn('Database connection lost - attempting reconnection', {
    event: 'database_disconnected',
    reconnectionAttempt: true
  });
});

onDatabaseEvent('error', (error) => {
  systemLogger.error('Database connection error', {
    event: 'database_error',
    error: error.message,
    errorType: error.name
  });
});

// Initialize database connection
initializeDatabase();

// Models
const User = require('./models/User');
const Extension = require('./models/Extension');
const Event = require('./models/Event');
const Game = require('./models/Game');
const AuditLog = require('./models/AuditLog');
const RejectedEmail = require('./models/RejectedEmail');
const ErrorLog = require('./models/ErrorLog');

// Import cache services
const cacheService = require('./services/cacheService');
const dashboardCacheService = require('./services/dashboardCacheService');
const apiCacheService = require('./services/apiCacheService');

// Initialize cache warm-up after database connection
const initializeCaches = async () => {
  try {
    systemLogger.info('Initializing cache warm-up');
    
    // Wait a bit for database to be fully ready
    setTimeout(async () => {
      try {
        const models = { User, Event, Game, AuditLog };
        
        // Warm up caches
        await Promise.all([
          cacheService.warmUp(models),
          dashboardCacheService.warmUp(models),
          apiCacheService.warmUp(models)
        ]);
        
        systemLogger.info('Cache initialization completed successfully');
      } catch (error) {
        systemLogger.error('Cache warm-up error', { 
          error: error.message,
          stack: error.stack 
        });
      }
    }, 5000); // Wait 5 seconds for database to be ready
    
  } catch (error) {
    systemLogger.error('Cache initialization error', { 
      error: error.message,
      stack: error.stack 
    });
  }
};

// Initialize caches
initializeCaches();



// Helper function to get client IP address
const getClientIP = (req) => {
  return req.headers['x-forwarded-for'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         req.ip;
};

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window per IP
  message: {
    error: 'Too many API requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return getClientIP(req);
  },
  handler: (req, res) => {
    console.log(`API rate limit exceeded for IP: ${getClientIP(req)} on ${req.path}`);
    res.status(429).json({
      error: 'Too many API requests from this IP, please try again later.',
      retryAfter: Math.round(15 * 60) // 15 minutes in seconds
    });
  }
});

// General rate limiter for other routes (more lenient)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // 1000 requests per window per IP (very lenient for general browsing)
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return getClientIP(req);
  },
  skip: (req) => {
    // Skip rate limiting for admin users in development mode
    if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development') {
      return true;
    }
    // Skip for static assets
    return req.path.startsWith('/public/') || req.path.startsWith('/css/') || req.path.startsWith('/js/') || req.path.startsWith('/images/');
  }
});

// Mock admin user for development auto-login
const mockAdminUser = {
  _id: 'dev-admin-id',
  name: 'Development Admin',
  email: 'dev-admin@gameplan.local',
  gameNickname: 'DevAdmin',
  isAdmin: true,
  isSuperAdmin: true,
  isProtected: false,
  isBlocked: false,
  save: async function() { return this; } // Mock save method
};

// Development auto-login middleware
const autoLoginMiddleware = (req, res, next) => {
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development') {
    // Inject mock admin user
    req.user = mockAdminUser;
    req.isAuthenticated = () => true;
    console.log('Development mode: Auto-logged in as admin');
  }
  next();
};

// Apply auto-login middleware after passport initialization
app.use(autoLoginMiddleware);

// Add request ID middleware for error tracking
app.use(requestIdMiddleware);

// Add request logging middleware
app.use(requestLogger);

// Apply database middleware
app.use(addDatabaseMetrics);
app.use(ensureDatabaseConnection({ skipHealthCheck: true }));

// Apply general rate limiting to all routes (except static assets)
app.use(generalLimiter);

// Apply API rate limiting to all /api routes with enhanced logging
app.use('/api', apiRequestLogger);
app.use('/api', apiLimiter);

// Apply admin database info middleware to admin routes
app.use('/admin', addAdminDatabaseInfo);

// Import and use authentication routes
app.use('/', require('./routes/auth'));

// Import and use admin routes
app.use('/admin', require('./routes/admin'));

// Import and use event routes
app.use('/event', require('./routes/events'));

// Import and use game routes
app.use('/games', require('./routes/games'));

// Import and use cache management routes
app.use('/api/cache', require('./routes/cache'));

// Swagger API Documentation (Admin-only access)
const { specs, swaggerUi, swaggerUiOptions } = require('./config/swagger');
const { ensureAdmin } = require('./middleware/auth');

// Swagger UI endpoint with admin authentication
app.use('/api-docs', ensureAdmin, swaggerUi.serve);
app.get('/api-docs', ensureAdmin, swaggerUi.setup(specs, swaggerUiOptions));

// Steam search API endpoint
/**
 * @swagger
 * /api/steam/search:
 *   get:
 *     tags: [Search]
 *     summary: Search Steam games
 *     description: |
 *       Search for games using the Steam API. Results are cached for performance.
 *       Rate limited to 100 requests per 15 minutes per IP.
 *     parameters:
 *       - in: query
 *         name: q
 *         required: true
 *         schema:
 *           type: string
 *           minLength: 1
 *         description: Search query for game name
 *         example: "counter strike"
 *     responses:
 *       200:
 *         description: Search results from Steam API
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/GameSearchResponse'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
app.get('/api/steam/search', apiLimiter, validateSteamSearch, handleValidationErrors, asyncErrorHandler(async (req, res) => {
  const { q } = req.query;
  console.log('Steam search request for:', q);
  
  if (!q || q.trim().length === 0) {
    throw new ValidationError('Search query is required');
  }
  
  // Use cached Steam search
  const results = await apiCacheService.cachedSteamSearch(q.trim(), steamService);
  res.json(results);
}));

// RAWG search API endpoint
/**
 * @swagger
 * /api/rawg/search:
 *   get:
 *     tags: [Search]
 *     summary: Search RAWG games database
 *     description: |
 *       Search for games using the RAWG API. Results are cached for performance.
 *       Rate limited to 100 requests per 15 minutes per IP.
 *     parameters:
 *       - in: query
 *         name: q
 *         required: true
 *         schema:
 *           type: string
 *           minLength: 1
 *         description: Search query for game name
 *         example: "counter strike"
 *     responses:
 *       200:
 *         description: Search results from RAWG API
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/GameSearchResponse'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
app.get('/api/rawg/search', apiLimiter, validateRawgSearch, handleValidationErrors, asyncErrorHandler(async (req, res) => {
  const { q } = req.query;
  console.log('RAWG search request for:', q);
  
  if (!q || q.trim().length === 0) {
    throw new ValidationError('Search query is required');
  }
  
  // Use cached RAWG search
  const results = await apiCacheService.cachedRawgSearch(q.trim(), rawgService);
  res.json(results);
}));

// Import health service
const healthService = require('./services/healthService');

// Enhanced health check endpoint
/**
 * @swagger
 * /api/health:
 *   get:
 *     tags: [System]
 *     summary: Comprehensive system health check
 *     description: |
 *       Returns detailed health status of all system components including:
 *       - System resources (memory, CPU)
 *       - Database connectivity and performance
 *       - Cache services status
 *       - External API dependencies
 *       - Configuration validation
 *     parameters:
 *       - in: query
 *         name: detailed
 *         schema:
 *           type: boolean
 *           default: false
 *         description: Include detailed system information
 *       - in: query
 *         name: quick
 *         schema:
 *           type: boolean
 *           default: false
 *         description: Return cached quick status (faster response)
 *       - in: query
 *         name: dependencies
 *         schema:
 *           type: boolean
 *           default: true
 *         description: Include external dependency checks
 *     responses:
 *       200:
 *         description: Health check completed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, degraded, unhealthy]
 *                   example: "healthy"
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: "2023-12-01T10:30:00.000Z"
 *                 uptime:
 *                   type: number
 *                   description: "Server uptime in seconds"
 *                   example: 86400
 *                 environment:
 *                   type: string
 *                   example: "development"
 *                 responseTime:
 *                   type: string
 *                   example: "45ms"
 *                 system:
 *                   type: object
 *                   description: "System resource metrics"
 *                 database:
 *                   type: object
 *                   description: "Database health and metrics"
 *                 cache:
 *                   type: object
 *                   description: "Cache services status"
 *                 dependencies:
 *                   type: object
 *                   description: "External API health status"
 *                 configuration:
 *                   type: object
 *                   description: "Configuration validation results"
 *                 warnings:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: "Non-critical issues"
 *                 errors:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: "Critical issues"
 *       503:
 *         description: System is unhealthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "unhealthy"
 *                 error:
 *                   type: string
 *                   example: "Database connection failed"
 */
app.get('/api/health', asyncErrorHandler(async (req, res) => {
  try {
    const { detailed = false, quick = false, dependencies = true } = req.query;
    
    let healthData;
    
    if (quick === 'true') {
      // Return quick cached status for performance
      healthData = healthService.getQuickStatus();
    } else {
      // Perform comprehensive health check
      healthData = await healthService.getHealthStatus({
        detailed: detailed === 'true',
        includeDependencies: dependencies !== 'false'
      });
    }
    
    // Set appropriate HTTP status code based on health
    const statusCode = healthData.status === 'unhealthy' ? 503 : 
                      healthData.status === 'degraded' ? 200 : 200;
    
    res.status(statusCode).json(healthData);
  } catch (error) {
    systemLogger.error('Health endpoint error', {
      error: error.message,
      stack: error.stack,
      requestId: req.requestId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed',
      message: error.message
    });
  }
}));

// Detailed health endpoints for specific components

/**
 * @swagger
 * /api/health/database:
 *   get:
 *     tags: [System]
 *     summary: Database health check
 *     description: Returns detailed database connectivity and performance metrics
 *     responses:
 *       200:
 *         description: Database health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, degraded, unhealthy]
 *                 responseTime:
 *                   type: string
 *                   example: "12ms"
 *                 connection:
 *                   type: object
 *                   description: "Database connection details"
 *                 metrics:
 *                   type: object
 *                   description: "Database performance metrics"
 */
app.get('/api/health/database', asyncErrorHandler(async (req, res) => {
  try {
    const healthData = await healthService.getHealthStatus({ 
      detailed: false, 
      includeDependencies: false 
    });
    
    const statusCode = healthData.database.status === 'unhealthy' ? 503 : 200;
    res.status(statusCode).json({
      timestamp: new Date().toISOString(),
      ...healthData.database
    });
  } catch (error) {
    systemLogger.error('Database health endpoint error', {
      error: error.message,
      requestId: req.requestId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Database health check failed',
      message: error.message
    });
  }
}));

/**
 * @swagger
 * /api/health/system:
 *   get:
 *     tags: [System]
 *     summary: System resource health check
 *     description: Returns system memory, CPU, and resource usage metrics
 *     responses:
 *       200:
 *         description: System health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, degraded, unhealthy]
 *                 memory:
 *                   type: object
 *                   description: "Memory usage metrics"
 *                 cpu:
 *                   type: object
 *                   description: "CPU usage metrics"
 *                 uptime:
 *                   type: object
 *                   description: "System and process uptime"
 */
app.get('/api/health/system', asyncErrorHandler(async (req, res) => {
  try {
    const healthData = await healthService.getHealthStatus({ 
      detailed: false, 
      includeDependencies: false 
    });
    
    const statusCode = healthData.system.status === 'unhealthy' ? 503 : 200;
    res.status(statusCode).json({
      timestamp: new Date().toISOString(),
      ...healthData.system
    });
  } catch (error) {
    systemLogger.error('System health endpoint error', {
      error: error.message,
      requestId: req.requestId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'System health check failed',
      message: error.message
    });
  }
}));

/**
 * @swagger
 * /api/health/cache:
 *   get:
 *     tags: [System]
 *     summary: Cache services health check
 *     description: Returns cache performance metrics and hit rates
 *     responses:
 *       200:
 *         description: Cache health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, degraded, unhealthy]
 *                 services:
 *                   type: object
 *                   description: "Individual cache service metrics"
 *                 summary:
 *                   type: object
 *                   description: "Overall cache summary"
 */
app.get('/api/health/cache', asyncErrorHandler(async (req, res) => {
  try {
    const healthData = await healthService.getHealthStatus({ 
      detailed: false, 
      includeDependencies: false 
    });
    
    const statusCode = healthData.cache.status === 'unhealthy' ? 503 : 200;
    res.status(statusCode).json({
      timestamp: new Date().toISOString(),
      ...healthData.cache
    });
  } catch (error) {
    systemLogger.error('Cache health endpoint error', {
      error: error.message,
      requestId: req.requestId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Cache health check failed',
      message: error.message
    });
  }
}));

/**
 * @swagger
 * /api/health/dependencies:
 *   get:
 *     tags: [System]
 *     summary: External dependencies health check
 *     description: Returns health status of external APIs (Steam, RAWG)
 *     responses:
 *       200:
 *         description: Dependencies health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, degraded, unhealthy, disabled]
 *                 services:
 *                   type: object
 *                   description: "Individual dependency status"
 */
app.get('/api/health/dependencies', asyncErrorHandler(async (req, res) => {
  try {
    const healthData = await healthService.getHealthStatus({ 
      detailed: false, 
      includeDependencies: true 
    });
    
    const statusCode = healthData.dependencies.status === 'unhealthy' ? 503 : 200;
    res.status(statusCode).json({
      timestamp: new Date().toISOString(),
      ...healthData.dependencies
    });
  } catch (error) {
    systemLogger.error('Dependencies health endpoint error', {
      error: error.message,
      requestId: req.requestId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Dependencies health check failed',
      message: error.message
    });
  }
}));

/**
 * @swagger
 * /api/health/history:
 *   get:
 *     tags: [System]
 *     summary: Health check history
 *     description: Returns recent health check history for trend analysis
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *           minimum: 1
 *           maximum: 100
 *         description: Number of recent health checks to return
 *     responses:
 *       200:
 *         description: Health check history
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 history:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       timestamp:
 *                         type: string
 *                         format: date-time
 *                       status:
 *                         type: string
 *                       responseTime:
 *                         type: string
 */
app.get('/api/health/history', asyncErrorHandler(async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const history = healthService.getHealthHistory(limit);
    
    res.json({
      timestamp: new Date().toISOString(),
      limit,
      count: history.length,
      history
    });
  } catch (error) {
    systemLogger.error('Health history endpoint error', {
      error: error.message,
      requestId: req.requestId
    });
    
    res.status(500).json({
      error: 'Health history retrieval failed',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
}));

// Add configuration health endpoint
/**
 * @swagger
 * /api/config-health:
 *   get:
 *     tags: [System]
 *     summary: Configuration health check
 *     description: Returns the current configuration health status including environment variables
 *     responses:
 *       200:
 *         description: Configuration health status
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ConfigHealth'
 */
app.get('/api/config-health', (req, res) => {
  const { getConfigHealth } = require('./utils/configHealth');
  const health = getConfigHealth();
  res.json(health);
});



// Home page route - Display all events
app.get('/', async (req, res) => {
  let query = {};
  
  // Filter events based on user role and visibility
  if (!req.user) {
    // Non-authenticated users only see visible events
    query.isVisible = true;
  } else if (!req.user.isAdmin) {
    // Regular authenticated users see visible events + their own pending events
    query = {
      $or: [
        { isVisible: true },
        { createdBy: req.user._id, gameStatus: 'pending' }
      ]
    };
  }
  // Admins see all events (no query filter)
  
  // Default: Hide events that started more than 1 hour ago
  const oneHourAgo = new Date(Date.now() - 3600000);
  query.date = { $gte: oneHourAgo };
  
  const events = await Event.find(query).populate('createdBy').populate('players').populate('requiredExtensions').populate('game').sort({ date: 1 }); // Sort by date ascending (soonest first)
  
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('index', { events, user: req.user, isDevelopmentAutoLogin });
});







// Add database-specific error handler before general error handler
app.use(handleDbErrors);

// Add 404 handler for unmatched routes
app.use(notFoundHandler);

// Add centralized error handling middleware (must be last)
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
