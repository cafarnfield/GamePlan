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



// Health check endpoint for Docker
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Add configuration health endpoint
app.get('/api/config-health', (req, res) => {
  const { getConfigHealth } = require('./utils/configHealth');
  const health = getConfigHealth();
  res.json(health);
});


// Steam search API endpoint
app.get('/api/steam/search', apiLimiter, validateSteamSearch, handleValidationErrors, asyncErrorHandler(async (req, res) => {
  const { q } = req.query;
  console.log('Steam search request for:', q);
  
  if (!q || q.trim().length === 0) {
    throw new ValidationError('Search query is required');
  }
  
  const results = await steamService.searchGames(q.trim());
  res.json(results);
}));

// RAWG search API endpoint
app.get('/api/rawg/search', apiLimiter, validateRawgSearch, handleValidationErrors, asyncErrorHandler(async (req, res) => {
  const { q } = req.query;
  console.log('RAWG search request for:', q);
  
  if (!q || q.trim().length === 0) {
    throw new ValidationError('Search query is required');
  }
  
  const results = await rawgService.searchGames(q.trim());
  res.json(results);
}));

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
