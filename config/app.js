const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const passport = require('passport');
const session = require('express-session');
const MongoStore = require('connect-mongo');

// Import winston logger
const { systemLogger } = require('../src/utils/logger');
const { requestLogger, apiRequestLogger } = require('../src/middleware/requestLogger');

// Import authentication middleware
const { ensureAuthenticated, ensureNotBlocked, ensurePasswordNotExpired } = require('../src/middleware/auth');

// Import centralized error handling
const {
  requestIdMiddleware,
  notFoundHandler,
  errorHandler,
  handleDatabaseErrors
} = require('../src/middleware/errorHandler');

// Import environment validation middleware
const { validateAndExitIfInvalid, validateProductionSafety, configHealthMiddleware } = require('../src/middleware/envValidation');

// Import security and rate limiting middleware
const { createSecurityMiddleware } = require('./security');
const { generalLimiter, apiLimiter } = require('../src/middleware/rateLimiting');

// Enhanced MongoDB connection with retry logic and monitoring
const { connect: connectDatabase, on: onDatabaseEvent } = require('../src/utils/database');
const { connectionMonitor } = require('../src/utils/connectionMonitor');
const {
  ensureDatabaseConnection,
  addDatabaseMetrics,
  addAdminDatabaseInfo,
  handleDatabaseErrors: handleDbErrors
} = require('../src/middleware/databaseMiddleware');

// Import cache services
const cacheService = require('../src/services/cacheService');
const dashboardCacheService = require('../src/services/dashboardCacheService');
const apiCacheService = require('../src/services/apiCacheService');

// Models
const User = require('../src/models/User');
const Extension = require('../src/models/Extension');
const Event = require('../src/models/Event');
const Game = require('../src/models/Game');
const AuditLog = require('../src/models/AuditLog');
const RejectedEmail = require('../src/models/RejectedEmail');
const ErrorLog = require('../src/models/ErrorLog');

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
const setupDatabaseEventListeners = () => {
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
};

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

// Configure Express application
const configureApp = (app) => {
  // Load environment variables first
  require('dotenv').config();

  // Perform startup environment validation
  validateAndExitIfInvalid();

  // View engine setup
  app.set('view engine', 'ejs');
  app.set('views', './src/views');

  // Apply security middleware
  app.use(createSecurityMiddleware());

  // Apply production safety middleware
  app.use(validateProductionSafety);

  // Apply configuration health middleware
  app.use(configHealthMiddleware);

  // Basic middleware
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());
  app.use(express.static('public'));

  // Session debugging middleware
  app.use((req, res, next) => {
    systemLogger.debug('Session middleware accessed', {
      requestId: req.requestId,
      sessionId: req.sessionID,
      hasSession: !!req.session
    });
    next();
  });

  // Session configuration
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

  // More session debugging middleware
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

  // Passport initialization
  app.use(passport.initialize());
  app.use(passport.session());

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

  return app;
};

// Initialize the entire application
const initializeApp = async () => {
  // Setup database event listeners
  setupDatabaseEventListeners();
  
  // Initialize database connection
  await initializeDatabase();
  
  // Initialize caches
  await initializeCaches();
};

module.exports = {
  configureApp,
  initializeApp,
  initializeDatabase,
  initializeCaches,
  setupDatabaseEventListeners,
  autoLoginMiddleware,
  mockAdminUser
};
