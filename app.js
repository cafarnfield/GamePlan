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
  validateRegistration,
  validateLogin,
  validateProfileUpdate
} = require('./validators/authValidators');
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

// Helper function to create audit log
const createAuditLog = async (adminUser, action, targetUser, notes = '', ipAddress = '', bulkCount = 1, details = {}) => {
  try {
    const auditLog = new AuditLog({
      adminId: adminUser._id,
      adminName: adminUser.name,
      action,
      targetUserId: targetUser ? targetUser._id : null,
      targetUserEmail: targetUser ? targetUser.email : null,
      targetUserName: targetUser ? targetUser.name : null,
      notes,
      ipAddress,
      bulkCount,
      details
    });
    await auditLog.save();
    adminLogger.logAdminAction(action, adminUser._id, targetUser?._id, {
      targetEmail: targetUser?.email,
      notes,
      ipAddress,
      bulkCount,
      details
    });
  } catch (err) {
    adminLogger.error('Error creating audit log', {
      error: err.message,
      action,
      adminId: adminUser._id,
      targetUserId: targetUser?._id
    });
  }
};

// Helper function to get pending counts for admin navigation
const getPendingCounts = async () => {
  try {
    return {
      pendingUsers: await User.countDocuments({ status: 'pending' }),
      pendingEvents: await Event.countDocuments({ gameStatus: 'pending' }),
      pendingGames: await Game.countDocuments({ status: 'pending' })
    };
  } catch (err) {
    adminLogger.error('Error getting pending counts', {
      error: err.message,
      stack: err.stack
    });
    return {
      pendingUsers: 0,
      pendingEvents: 0,
      pendingGames: 0
    };
  }
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

// Passport configuration with debug logging
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      console.log('Passport strategy accessed');
      console.log('Authentication attempt with email:', email);
      const user = await User.findOne({ email });
      if (!user) {
        console.log('No user found with email:', email);
        return done(null, false, { message: 'No user with that email' });
      }

      // Check user status before password verification
      if (user.status === 'pending') {
        console.log('User account pending approval:', email);
        return done(null, false, { message: 'Your account is pending admin approval. Please wait for approval before logging in.' });
      }

      if (user.status === 'rejected') {
        console.log('User account rejected:', email);
        return done(null, false, { message: 'Your account has been rejected. Please contact support for more information.' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        console.log('Password incorrect for user:', email);
        return done(null, false, { message: 'Password incorrect' });
      }

      // Only allow approved users to login
      if (user.status !== 'approved') {
        console.log('User not approved:', email, 'Status:', user.status);
        return done(null, false, { message: 'Your account is not approved for login.' });
      }

      console.log('Authentication successful for user:', email);
      return done(null, user);
    } catch (err) {
      console.error('Error during authentication:', err);
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Middleware to check if user is authenticated
const ensureAuthenticated = (req, res, next) => {
  // Check for auto-login in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development') {
    return next();
  }
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

// Middleware to check if user is admin
const ensureAdmin = (req, res, next) => {
  console.log('ensureAdmin middleware accessed');
  console.log('req.isAuthenticated():', req.isAuthenticated());
  console.log('req.user:', req.user);

  // Check for auto-login admin in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development' && req.user && req.user.isAdmin) {
    return next();
  }

  if (req.isAuthenticated() && req.user && req.user.isAdmin) {
    return next();
  }
  
  throw new AuthorizationError('You are not authorized to perform this action');
};

// Middleware to check if user is super admin
const ensureSuperAdmin = (req, res, next) => {
  console.log('ensureSuperAdmin middleware accessed');
  console.log('req.user:', req.user);

  // Check for auto-login super admin in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development' && req.user && req.user.isSuperAdmin) {
    return next();
  }

  if (req.isAuthenticated() && req.user && req.user.isSuperAdmin) {
    return next();
  }
  
  throw new AuthorizationError('Super Admin privileges required for this action');
};

// Middleware to check admin operation permissions
const checkAdminOperationPermission = async (req, res, next) => {
  try {
    const targetUser = await User.findById(req.params.id);
    
    if (!targetUser) {
      return res.status(404).send('User not found');
    }
    
    // Flamma protection - only Flamma can modify itself
    if (targetUser.isProtected && req.user.email !== targetUser.email) {
      return res.status(403).send('This user is protected and can only be modified by themselves');
    }
    
    // Super Admin operations on admins require super admin privileges
    if (targetUser.isAdmin && !req.user.isSuperAdmin) {
      return res.status(403).send('Super Admin privileges required to modify admin users');
    }
    
    // Cannot delete Super Admins directly (must demote first)
    if (targetUser.isSuperAdmin && req.route.path.includes('delete')) {
      return res.status(403).send('Cannot delete Super Admin directly. Must demote to Admin first.');
    }
    
    // Store target user for use in route handler
    req.targetUser = targetUser;
    next();
  } catch (err) {
    console.error('Error in checkAdminOperationPermission:', err);
    res.status(500).send('Error checking permissions');
  }
};

// Middleware to check if user is blocked
const ensureNotBlocked = (req, res, next) => {
  if (req.isAuthenticated() && req.user.isBlocked) {
    req.logout((err) => {
      if (err) {
        console.error('Error during logout:', err);
      }
      res.status(403).send('Your account has been blocked. Please contact support.');
    });
  } else {
    next();
  }
};

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

// Database monitoring API endpoints
app.get('/api/database/status', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { getStatus } = require('./utils/database');
  const status = getStatus();
  res.json(status);
}));

app.get('/api/database/health', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { healthCheck } = require('./utils/database');
  const health = await healthCheck();
  res.json(health);
}));

app.get('/api/database/monitoring', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { getReport } = require('./utils/connectionMonitor');
  const report = getReport();
  res.json(report);
}));

app.get('/api/database/trends', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { getTrends } = require('./utils/connectionMonitor');
  const trends = getTrends();
  res.json(trends);
}));

app.get('/api/database/metrics', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { exportMetrics } = require('./utils/connectionMonitor');
  const metrics = exportMetrics();
  res.json(metrics);
}));

app.post('/api/database/reconnect', ensureAuthenticated, ensureSuperAdmin, asyncErrorHandler(async (req, res) => {
  const { forceReconnect } = require('./utils/database');
  const clientIP = getClientIP(req);
  
  try {
    await forceReconnect();
    
    // Create audit log for this action
    await createAuditLog(req.user, 'DATABASE_FORCE_RECONNECT', null, 'Forced database reconnection', clientIP, 1, {
      action: 'FORCE_DATABASE_RECONNECT',
      timestamp: new Date()
    });
    
    console.log('Database force reconnect initiated by SuperAdmin:', req.user.email);
    res.json({ success: true, message: 'Database reconnection initiated successfully' });
  } catch (error) {
    console.error('Error during force reconnect:', error.message);
    res.status(500).json({ error: 'Failed to reconnect to database', message: error.message });
  }
}));

app.post('/api/database/reset-metrics', ensureAuthenticated, ensureSuperAdmin, asyncErrorHandler(async (req, res) => {
  const { resetMetrics } = require('./utils/connectionMonitor');
  const clientIP = getClientIP(req);
  
  try {
    resetMetrics();
    
    // Create audit log for this action
    await createAuditLog(req.user, 'DATABASE_METRICS_RESET', null, 'Reset database monitoring metrics', clientIP, 1, {
      action: 'RESET_DATABASE_METRICS',
      timestamp: new Date()
    });
    
    console.log('Database metrics reset by SuperAdmin:', req.user.email);
    res.json({ success: true, message: 'Database monitoring metrics reset successfully' });
  } catch (error) {
    console.error('Error resetting metrics:', error.message);
    res.status(500).json({ error: 'Failed to reset metrics', message: error.message });
  }
}));

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

// Routes
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


// Event routes - New event route must come before /event/:id to avoid conflicts
app.get('/event/new', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    // Get approved games for the game selection
    const games = await Game.find({ status: 'approved' }).sort({ name: 1 });

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('newEvent', {
      user: req.user,
      isDevelopmentAutoLogin,
      games: games // Make sure to pass games as an array
    });
  } catch (err) {
    console.error('Error loading new event page:', err);
    res.status(500).send('Error loading new event page');
  }
});

app.get('/event/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('players')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('event', { event, user: req.user, isDevelopmentAutoLogin });
  } catch (err) {
    console.error('Error fetching event:', err);
    res.status(500).send('Error loading event');
  }
});

// Join event route
app.post('/event/:id/join', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check if user is already in the event
    if (event.players.includes(req.user._id)) {
      return res.redirect(`/event/${req.params.id}`);
    }
    
    // Check if event is full
    if (event.players.length >= event.playerLimit) {
      return res.status(400).send('Event is full');
    }
    
    // Add user to event
    event.players.push(req.user._id);
    await event.save();
    
    res.redirect(`/event/${req.params.id}`);
  } catch (err) {
    console.error('Error joining event:', err);
    res.status(500).send('Error joining event');
  }
});

// Leave event route
app.post('/event/:id/leave', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Remove user from event
    event.players = event.players.filter(playerId => !playerId.equals(req.user._id));
    await event.save();
    
    res.redirect(`/event/${req.params.id}`);
  } catch (err) {
    console.error('Error leaving event:', err);
    res.status(500).send('Error leaving event');
  }
});

// Edit event route
app.get('/event/:id/edit', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('players')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check permissions
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !event.createdBy && event.players.length > 0 && event.players[0]._id.equals(req.user._id);
    const canEdit = isCreator || isLegacyCreator || req.user.isAdmin;
    
    if (!canEdit) {
      return res.status(403).send('You are not authorized to edit this event');
    }
    
    // Get approved games for the game selection
    const games = await Game.find({ status: 'approved' }).sort({ name: 1 });
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('editEvent', { event, games, user: req.user, isDevelopmentAutoLogin });
  } catch (err) {
    console.error('Error loading event for editing:', err);
    res.status(500).send('Error loading event');
  }
});

// Update event route (POST)
app.post('/event/:id/edit', ensureAuthenticated, ensureNotBlocked, validateEventEdit, handleValidationErrors, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('players')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check permissions
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !event.createdBy && event.players.length > 0 && event.players[0]._id.equals(req.user._id);
    const canEdit = isCreator || isLegacyCreator || req.user.isAdmin;
    
    if (!canEdit) {
      return res.status(403).send('You are not authorized to edit this event');
    }
    
    const { name, gameId, description, playerLimit, date, platforms, extensions } = req.body;
    
    // Update basic event fields
    event.name = name;
    event.description = description;
    event.playerLimit = parseInt(playerLimit);
    event.date = new Date(date);
    event.platforms = Array.isArray(platforms) ? platforms : [platforms];
    
    // Handle game change
    if (gameId && gameId !== event.game._id.toString()) {
      event.game = gameId;
    }
    
    // Handle extensions
    if (extensions && extensions.trim() !== '') {
      try {
        const extensionsData = JSON.parse(extensions);
        
        // Delete old extensions
        if (event.requiredExtensions && event.requiredExtensions.length > 0) {
          await Extension.deleteMany({ _id: { $in: event.requiredExtensions } });
        }
        
        // Create new extensions
        const extensionIds = [];
        for (const extData of extensionsData) {
          if (extData.name && extData.downloadLink && extData.installationTime) {
            const extension = new Extension({
              name: extData.name,
              downloadLink: extData.downloadLink,
              installationTime: parseInt(extData.installationTime),
              description: extData.description || ''
            });
            await extension.save();
            extensionIds.push(extension._id);
          }
        }
        event.requiredExtensions = extensionIds;
      } catch (err) {
        console.error('Error parsing extensions:', err);
        // Continue without extensions if parsing fails
        event.requiredExtensions = [];
      }
    } else {
      // No extensions provided, clear existing ones
      if (event.requiredExtensions && event.requiredExtensions.length > 0) {
        await Extension.deleteMany({ _id: { $in: event.requiredExtensions } });
      }
      event.requiredExtensions = [];
    }
    
    await event.save();
    
    console.log('Event updated successfully:', {
      eventId: event._id,
      updatedBy: req.user.email,
      changes: { name, gameId, description, playerLimit, date, platforms }
    });
    
    res.redirect(`/event/${event._id}`);
  } catch (err) {
    console.error('Error updating event:', err);
    res.status(500).send('Error updating event');
  }
});

// Duplicate event route
app.get('/event/:id/duplicate', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('players')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check permissions
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !event.createdBy && event.players.length > 0 && event.players[0]._id.equals(req.user._id);
    const canDuplicate = isCreator || isLegacyCreator || req.user.isAdmin;
    
    if (!canDuplicate) {
      return res.status(403).send('You are not authorized to duplicate this event');
    }
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('duplicateEvent', { originalEvent: event, user: req.user, isDevelopmentAutoLogin });
  } catch (err) {
    console.error('Error loading event for duplication:', err);
    res.status(500).send('Error loading event');
  }
});

// Duplicate event POST route
app.post('/event/:id/duplicate', ensureAuthenticated, ensureNotBlocked, validateEventDuplication, handleValidationErrors, async (req, res) => {
  try {
    const originalEvent = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('players')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!originalEvent) {
      return res.status(404).send('Original event not found');
    }
    
    // Check permissions (same as GET route)
    const isCreator = originalEvent.createdBy && originalEvent.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !originalEvent.createdBy && originalEvent.players.length > 0 && originalEvent.players[0]._id.equals(req.user._id);
    const canDuplicate = isCreator || isLegacyCreator || req.user.isAdmin;
    
    if (!canDuplicate) {
      return res.status(403).send('You are not authorized to duplicate this event');
    }
    
    const { name, description, date, playerLimit, platforms, 'copy-extensions': copyExtensions } = req.body;
    
    // Create the new event data
    const newEventData = {
      name: name || originalEvent.name,
      description: description || originalEvent.description,
      date: new Date(date),
      playerLimit: parseInt(playerLimit) || originalEvent.playerLimit,
      platforms: Array.isArray(platforms) ? platforms : [platforms],
      game: originalEvent.game._id,
      createdBy: req.user._id,
      players: [req.user._id], // Creator automatically joins
      isVisible: originalEvent.game && originalEvent.game.status === 'approved' ? true : false,
      gameStatus: originalEvent.game && originalEvent.game.status === 'approved' ? 'approved' : 'pending'
    };
    
    // Handle extensions if copy-extensions is checked
    if (copyExtensions && originalEvent.requiredExtensions && originalEvent.requiredExtensions.length > 0) {
      const newExtensionIds = [];
      
      for (const originalExtension of originalEvent.requiredExtensions) {
        // Create a new extension (duplicate the original)
        const newExtension = new Extension({
          name: originalExtension.name,
          downloadLink: originalExtension.downloadLink,
          installationTime: originalExtension.installationTime,
          description: originalExtension.description || ''
        });
        await newExtension.save();
        newExtensionIds.push(newExtension._id);
      }
      
      newEventData.requiredExtensions = newExtensionIds;
    }
    
    // Create the new event
    const newEvent = new Event(newEventData);
    await newEvent.save();
    
    console.log('Event duplicated successfully:', {
      originalId: originalEvent._id,
      newId: newEvent._id,
      creator: req.user.email
    });
    
    res.redirect(`/event/${newEvent._id}`);
  } catch (err) {
    console.error('Error duplicating event:', err);
    res.status(500).send('Error duplicating event');
  }
});

// Delete event route
app.post('/event/:id/delete', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('createdBy').populate('players');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check permissions
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !event.createdBy && event.players.length > 0 && event.players[0]._id.equals(req.user._id);
    const canDelete = isCreator || isLegacyCreator || req.user.isAdmin;
    
    if (!canDelete) {
      return res.status(403).send('You are not authorized to delete this event');
    }
    
    await Event.findByIdAndDelete(req.params.id);
    res.redirect('/');
  } catch (err) {
    console.error('Error deleting event:', err);
    res.status(500).send('Error deleting event');
  }
});

// Admin routes
app.get('/admin', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    // Calculate statistics for dashboard
    const stats = {
      totalUsers: await User.countDocuments(),
      approvedUsers: await User.countDocuments({ status: 'approved' }),
      pendingUsers: await User.countDocuments({ status: 'pending' }),
      blockedUsers: await User.countDocuments({ isBlocked: true }),
      totalEvents: await Event.countDocuments(),
      activeEvents: await Event.countDocuments({ date: { $gte: new Date() } }),
      eventsToday: await Event.countDocuments({ 
        date: { 
          $gte: new Date(new Date().setHours(0, 0, 0, 0)),
          $lt: new Date(new Date().setHours(23, 59, 59, 999))
        }
      }),
      eventsThisWeek: await Event.countDocuments({ 
        date: { 
          $gte: new Date(new Date().setDate(new Date().getDate() - new Date().getDay())),
          $lt: new Date(new Date().setDate(new Date().getDate() - new Date().getDay() + 7))
        }
      }),
      totalGames: await Game.countDocuments(),
      steamGames: await Game.countDocuments({ source: 'steam' }),
      manualGames: await Game.countDocuments({ source: 'manual' }),
      pendingGames: await Game.countDocuments({ gameStatus: 'pending' }),
      recentRegistrations: await User.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
      }),
      probationaryUsers: await User.countDocuments({ 
        probationaryUntil: { $gte: new Date() }
      })
    };

    // Calculate approval rate
    const totalProcessed = stats.approvedUsers + await User.countDocuments({ status: 'rejected' });
    stats.approvalRate = totalProcessed > 0 ? Math.round((stats.approvedUsers / totalProcessed) * 100) : 100;

    // Get recent admin activity
    const recentActivity = await AuditLog.find()
      .sort({ timestamp: -1 })
      .limit(10);

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminDashboard', { 
      stats, 
      recentActivity, 
      user: req.user, 
      isDevelopmentAutoLogin 
    });
  } catch (err) {
    console.error('Error loading admin dashboard:', err);
    res.status(500).send('Error loading admin dashboard');
  }
});

// Admin users management
app.get('/admin/users', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const { filter, search, page = 1 } = req.query;
    const limit = 20;
    const skip = (page - 1) * limit;

    let query = {};
    if (filter === 'pending') query.status = 'pending';
    else if (filter === 'approved') query.status = 'approved';
    else if (filter === 'rejected') query.status = 'rejected';
    else if (filter === 'blocked') query.isBlocked = true;
    else if (filter === 'admin') query.isAdmin = true;

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { gameNickname: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const totalUsers = await User.countDocuments(query);
    const totalPages = Math.ceil(totalUsers / limit);

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminUsers', { 
      users, 
      filter, 
      search, 
      currentPage: parseInt(page), 
      totalPages, 
      user: req.user, 
      isDevelopmentAutoLogin 
    });
  } catch (err) {
    console.error('Error loading admin users:', err);
    res.status(500).send('Error loading users');
  }
});

// Admin events management
app.get('/admin/events', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const { status, search, page = 1, game: selectedGame, dateFrom, dateTo, creator } = req.query;
    const limit = 20;
    const skip = (page - 1) * limit;

    let query = {};

    // Status/filter logic
    if (status === 'upcoming') {
      query.date = { $gte: new Date() };
    } else if (status === 'past') {
      query.date = { $lt: new Date() };
    } else if (status === 'live') {
      const now = new Date();
      const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);
      query.date = { $gte: twoHoursAgo, $lte: now };
    } else if (status === 'pending') {
      query.gameStatus = 'pending';
    }

    // Game filter
    if (selectedGame) {
      query.game = selectedGame;
    }

    // Date range filters
    if (dateFrom || dateTo) {
      query.date = query.date || {};
      if (dateFrom) {
        query.date.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        const endDate = new Date(dateTo);
        endDate.setHours(23, 59, 59, 999); // End of day
        query.date.$lte = endDate;
      }
    }

    // Search filter
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    // Creator filter
    if (creator) {
      const creatorUsers = await User.find({
        $or: [
          { name: { $regex: creator, $options: 'i' } },
          { gameNickname: { $regex: creator, $options: 'i' } }
        ]
      }).select('_id');

      if (creatorUsers.length > 0) {
        query.createdBy = { $in: creatorUsers.map(u => u._id) };
      }
    }

    const events = await Event.find(query)
      .populate('createdBy')
      .populate('players')
      .populate('game')
      .sort({ date: -1 })
      .skip(skip)
      .limit(limit);

    const totalEvents = await Event.countDocuments(query);
    const totalPages = Math.ceil(totalEvents / limit);

    // Get all games for the filter dropdown
    const games = await Game.find().sort({ name: 1 });

    // Get pending counts for navigation badges
    const pendingCounts = await getPendingCounts();

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminEvents', {
      events,
      filter: status, // Pass status as filter for template compatibility
      search,
      selectedGame,
      dateFrom,
      dateTo,
      creator,
      games, // Added games list
      currentPage: parseInt(page),
      totalPages,
      user: req.user,
      isDevelopmentAutoLogin,
      ...pendingCounts // Spread the pending counts for navigation badges
    });
  } catch (err) {
    console.error('Error loading admin events:', err);
    res.status(500).send('Error loading events');
  }
});

// Admin games management
app.get('/admin/games', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const { status: filter, source: sourceFilter, search, page = 1, addedBy } = req.query;
    const limit = 20;
    const skip = (page - 1) * limit;

    let query = {};
    
    // Status/filter logic
    if (filter === 'pending') {
      query.status = 'pending';
    } else if (filter === 'approved') {
      query.status = 'approved';
    } else if (filter === 'rejected') {
      query.status = 'rejected';
    }

    // Source filter
    if (sourceFilter) {
      query.source = sourceFilter;
    }

    // Search filter
    if (search) {
      query.name = { $regex: search, $options: 'i' };
    }

    // Added by filter
    if (addedBy) {
      const addedByUsers = await User.find({
        $or: [
          { name: { $regex: addedBy, $options: 'i' } },
          { email: { $regex: addedBy, $options: 'i' } },
          { gameNickname: { $regex: addedBy, $options: 'i' } }
        ]
      }).select('_id');
      
      if (addedByUsers.length > 0) {
        query.addedBy = { $in: addedByUsers.map(u => u._id) };
      }
    }

    const games = await Game.find(query)
      .populate('addedBy')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const totalGames = await Game.countDocuments(query);
    const totalPages = Math.ceil(totalGames / limit);

    // Get pending counts for navigation badges
    const pendingCounts = await getPendingCounts();

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminGames', { 
      games, 
      filter, // Changed from 'source' to 'filter' for status filtering
      sourceFilter, // Changed from 'source' to 'sourceFilter' for source filtering
      search, 
      addedBy, // Added addedBy filter
      currentPage: parseInt(page), 
      totalPages, 
      user: req.user, 
      isDevelopmentAutoLogin,
      ...pendingCounts // Spread the pending counts for navigation badges
    });
  } catch (err) {
    console.error('Error loading admin games:', err);
    res.status(500).send('Error loading games');
  }
});

// Create new event route
app.post('/event/new', ensureAuthenticated, ensureNotBlocked, validateEventCreation, handleValidationErrors, async (req, res) => {
  try {
    const { name, description, date, playerLimit, platforms, gameSelection, extensions } = req.body;
    
    // Parse game selection and extensions
    const gameData = JSON.parse(gameSelection);
    const extensionsData = extensions ? JSON.parse(extensions) : [];
    
    // Create the event object
    const eventData = {
      name,
      description,
      date: new Date(date),
      playerLimit: parseInt(playerLimit),
      platforms: Array.isArray(platforms) ? platforms : [platforms],
      createdBy: req.user._id,
      players: [req.user._id], // Creator automatically joins
      isVisible: true
    };
    
    // Handle game selection based on type
    if (gameData.type === 'existing') {
      eventData.game = gameData.gameId;
    } else if (gameData.type === 'steam') {
      // Create or find Steam game
      let game = await Game.findOne({ steamAppId: gameData.data.appid });
      if (!game) {
        game = new Game({
          name: gameData.data.name,
          description: gameData.data.short_description || '',
          source: 'steam',
          steamAppId: gameData.data.appid,
          steamData: gameData.data,
          status: 'approved',
          addedBy: req.user._id
        });
        await game.save();
      }
      eventData.game = game._id;
    } else if (gameData.type === 'rawg') {
      // Create or find RAWG game
      let game = await Game.findOne({ rawgId: gameData.data.id });
      if (!game) {
        game = new Game({
          name: gameData.data.name,
          description: gameData.data.short_description || '',
          source: 'rawg',
          rawgId: gameData.data.id,
          rawgData: gameData.data,
          status: 'approved',
          addedBy: req.user._id
        });
        await game.save();
      }
      eventData.game = game._id;
    } else if (gameData.type === 'manual') {
      // Create manual game (requires approval)
      const game = new Game({
        name: gameData.data.name,
        description: gameData.data.description,
        source: 'manual',
        categories: gameData.data.categories,
        status: 'pending',
        addedBy: req.user._id
      });
      await game.save();
      eventData.game = game._id;
      eventData.gameStatus = 'pending';
      eventData.isVisible = false; // Hide until game is approved
    }
    
    // Handle extensions
    if (extensionsData.length > 0) {
      const extensionIds = [];
      for (const extData of extensionsData) {
        const extension = new Extension({
          name: extData.name,
          downloadLink: extData.downloadLink,
          installationTime: parseInt(extData.installationTime),
          description: extData.description || ''
        });
        await extension.save();
        extensionIds.push(extension._id);
      }
      eventData.requiredExtensions = extensionIds;
    }
    
    // Create the event
    const event = new Event(eventData);
    await event.save();
    
    res.redirect(`/event/${event._id}`);
  } catch (err) {
    console.error('Error creating event:', err);
    res.status(500).send('Error creating event');
  }
});

// Admin system management
app.get('/admin/system', ensureAuthenticated, ensureSuperAdmin, async (req, res) => {
  try {
    // Gather system health data
    const systemHealth = {
      databaseConnected: mongoose.connection.readyState === 1,
      uptime: process.uptime(),
      nodeVersion: process.version,
      environment: process.env.NODE_ENV || 'development',
      memoryUsage: process.memoryUsage()
    };

    // Gather system statistics
    const systemStats = {
      totalUsers: await User.countDocuments(),
      totalEvents: await Event.countDocuments(),
      totalGames: await Game.countDocuments(),
      totalAuditLogs: await AuditLog.countDocuments(),
      blockedUsers: await User.countDocuments({ isBlocked: true }),
      rejectedUsers: await User.countDocuments({ status: 'rejected' }),
      probationaryUsers: await User.countDocuments({ 
        probationaryUntil: { $gte: new Date() }
      }),
      recentUsers: await User.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      }),
      recentEvents: await Event.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      })
    };

    // Find suspicious IP addresses (3+ registrations)
    const suspiciousIPs = await User.aggregate([
      {
        $group: {
          _id: '$registrationIP',
          count: { $sum: 1 },
          users: {
            $push: {
              email: '$email',
              status: '$status',
              createdAt: '$createdAt'
            }
          }
        }
      },
      {
        $match: {
          count: { $gte: 3 },
          _id: { $ne: null }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    // Get recent audit logs
    const recentAuditLogs = await AuditLog.find()
      .sort({ timestamp: -1 })
      .limit(20);

    // Get pending counts for navigation badges
    const pendingCounts = await getPendingCounts();

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminSystem', { 
      user: req.user, 
      isDevelopmentAutoLogin,
      systemHealth,
      systemStats,
      suspiciousIPs,
      recentAuditLogs,
      ...pendingCounts // Spread the pending counts for navigation badges
    });
  } catch (err) {
    console.error('Error loading admin system:', err);
    res.status(500).send('Error loading system page');
  }
});

// Add game page
app.get('/admin/add-game', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('addGame', { 
      user: req.user, 
      isDevelopmentAutoLogin 
    });
  } catch (err) {
    console.error('Error loading add game page:', err);
    res.status(500).send('Error loading add game page');
  }
});

// API endpoint for pending count (used by dashboard auto-refresh)
app.get('/api/admin/pending-count', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const pendingUsers = await User.countDocuments({ status: 'pending' });
    const pendingEvents = await Event.countDocuments({ gameStatus: 'pending' });
    const pendingGames = await Game.countDocuments({ gameStatus: 'pending' });
    
    res.json({ 
      count: pendingUsers + pendingEvents + pendingGames,
      users: pendingUsers,
      events: pendingEvents,
      games: pendingGames
    });
  } catch (err) {
    console.error('Error getting pending count:', err);
    res.status(500).json({ error: 'Error getting pending count' });
  }
});


// User Management Routes

// Approve user
app.post('/admin/user/approve/:id', ensureAuthenticated, ensureAdmin, validateUserApproval, handleValidationErrors, checkAdminOperationPermission, async (req, res) => {
  try {
    const { notes } = req.body;
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    // Update user status
    user.status = 'approved';
    user.approvedAt = new Date();
    user.approvedBy = req.user._id;
    user.approvalNotes = notes || '';
    
    // Set probationary period for new users (30 days)
    setProbationaryPeriod(user, 30);
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'USER_APPROVED', user, notes, clientIP);

    console.log('User approved:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User approved successfully' });
  } catch (err) {
    console.error('Error approving user:', err);
    res.status(500).json({ error: 'Error approving user' });
  }
});

// Reject user
app.post('/admin/user/reject/:id', ensureAuthenticated, ensureAdmin, validateUserRejection, handleValidationErrors, checkAdminOperationPermission, async (req, res) => {
  try {
    const { notes } = req.body;
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    if (!notes || notes.trim() === '') {
      return res.status(400).json({ error: 'Rejection reason is required' });
    }

    // Update user status
    user.status = 'rejected';
    user.rejectedAt = new Date();
    user.rejectedBy = req.user._id;
    user.rejectionReason = notes;
    
    await user.save();

    // Add email to rejected list to prevent re-registration
    const rejectedEmail = new RejectedEmail({
      email: user.email.toLowerCase(),
      rejectedBy: req.user._id,
      reason: notes,
      originalUserId: user._id
    });
    await rejectedEmail.save();

    // Create audit log
    await createAuditLog(req.user, 'USER_REJECTED', user, notes, clientIP);

    console.log('User rejected:', user.email, 'by:', req.user.email, 'reason:', notes);
    res.status(200).json({ success: true, message: 'User rejected successfully' });
  } catch (err) {
    console.error('Error rejecting user:', err);
    res.status(500).json({ error: 'Error rejecting user' });
  }
});

// Block user
app.post('/admin/user/block/:id', ensureAuthenticated, ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    user.isBlocked = true;
    user.blockedAt = new Date();
    user.blockedBy = req.user._id;
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'USER_BLOCKED', user, '', clientIP);

    console.log('User blocked:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User blocked successfully' });
  } catch (err) {
    console.error('Error blocking user:', err);
    res.status(500).json({ error: 'Error blocking user' });
  }
});

// Unblock user
app.post('/admin/user/unblock/:id', ensureAuthenticated, ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    user.isBlocked = false;
    user.unblockedAt = new Date();
    user.unblockedBy = req.user._id;
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'USER_UNBLOCKED', user, '', clientIP);

    console.log('User unblocked:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User unblocked successfully' });
  } catch (err) {
    console.error('Error unblocking user:', err);
    res.status(500).json({ error: 'Error unblocking user' });
  }
});

// Delete user
app.post('/admin/user/delete/:id', ensureAuthenticated, ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    // Create audit log before deletion
    await createAuditLog(req.user, 'USER_DELETED', user, '', clientIP);

    // Delete the user
    await User.findByIdAndDelete(user._id);

    console.log('User deleted:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User deleted successfully' });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Error deleting user' });
  }
});

// Toggle admin status
app.post('/admin/user/toggle-admin/:id', ensureAuthenticated, ensureSuperAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    const wasAdmin = user.isAdmin;
    user.isAdmin = !user.isAdmin;
    
    if (user.isAdmin) {
      user.adminPromotedAt = new Date();
      user.adminPromotedBy = req.user._id;
    } else {
      user.adminDemotedAt = new Date();
      user.adminDemotedBy = req.user._id;
      // If demoting from admin, also remove super admin status
      user.isSuperAdmin = false;
    }
    
    await user.save();

    // Create audit log
    const action = wasAdmin ? 'ADMIN_DEMOTED' : 'ADMIN_PROMOTED';
    await createAuditLog(req.user, action, user, '', clientIP);

    console.log('User admin status toggled:', user.email, 'by:', req.user.email, 'isAdmin:', user.isAdmin);
    res.status(200).json({ success: true, message: `User ${user.isAdmin ? 'promoted to' : 'demoted from'} admin successfully` });
  } catch (err) {
    console.error('Error toggling admin status:', err);
    res.status(500).json({ error: 'Error updating admin status' });
  }
});

// End probation
app.post('/admin/user/end-probation/:id', ensureAuthenticated, ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    user.probationaryUntil = null;
    user.probationEndedAt = new Date();
    user.probationEndedBy = req.user._id;
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'PROBATION_ENDED', user, '', clientIP);

    console.log('Probation ended for user:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'Probation ended successfully' });
  } catch (err) {
    console.error('Error ending probation:', err);
    res.status(500).json({ error: 'Error ending probation' });
  }
});

// Promote to super admin
app.post('/admin/user/promote-super-admin/:id', ensureAuthenticated, ensureSuperAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    if (!user.isAdmin) {
      return res.status(400).json({ error: 'User must be an admin before promoting to super admin' });
    }

    if (user.isSuperAdmin) {
      return res.status(400).json({ error: 'User is already a super admin' });
    }

    user.isSuperAdmin = true;
    user.superAdminPromotedAt = new Date();
    user.superAdminPromotedBy = req.user._id;
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'SUPER_ADMIN_PROMOTED', user, '', clientIP);

    console.log('User promoted to super admin:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User promoted to super admin successfully' });
  } catch (err) {
    console.error('Error promoting to super admin:', err);
    res.status(500).json({ error: 'Error promoting to super admin' });
  }
});

// Demote super admin
app.post('/admin/user/demote-super-admin/:id', ensureAuthenticated, ensureSuperAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    if (!user.isSuperAdmin) {
      return res.status(400).json({ error: 'User is not a super admin' });
    }

    if (user.isProtected) {
      return res.status(403).json({ error: 'Cannot demote protected super admin' });
    }

    user.isSuperAdmin = false;
    user.superAdminDemotedAt = new Date();
    user.superAdminDemotedBy = req.user._id;
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'SUPER_ADMIN_DEMOTED', user, '', clientIP);

    console.log('User demoted from super admin:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User demoted from super admin successfully' });
  } catch (err) {
    console.error('Error demoting super admin:', err);
    res.status(500).json({ error: 'Error demoting super admin' });
  }
});

// Bulk approve users
app.post('/admin/users/bulk-approve', ensureAuthenticated, ensureAdmin, validateBulkUserOperation, handleValidationErrors, async (req, res) => {
  try {
    const { userIds, notes } = req.body;
    const clientIP = getClientIP(req);

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'User IDs array is required' });
    }

    const users = await User.find({ _id: { $in: userIds } });
    let successCount = 0;
    let errorCount = 0;

    for (const user of users) {
      try {
        // Check if user can be approved
        if (user.status !== 'pending') {
          errorCount++;
          continue;
        }

        // Update user status
        user.status = 'approved';
        user.approvedAt = new Date();
        user.approvedBy = req.user._id;
        user.approvalNotes = notes || '';
        
        // Set probationary period
        setProbationaryPeriod(user, 30);
        
        await user.save();

        // Create audit log
        await createAuditLog(req.user, 'USER_APPROVED', user, notes, clientIP);

        successCount++;
      } catch (err) {
        console.error('Error in bulk approve for user:', user.email, err);
        errorCount++;
      }
    }

    // Create bulk audit log
    await createAuditLog(req.user, 'BULK_USER_APPROVED', null, notes, clientIP, successCount, { 
      successCount, 
      errorCount, 
      totalRequested: userIds.length 
    });

    console.log('Bulk approve completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    res.status(200).json({ 
      success: true, 
      message: `Bulk approve completed: ${successCount} successful, ${errorCount} errors`,
      successCount,
      errorCount
    });
  } catch (err) {
    console.error('Error in bulk approve:', err);
    res.status(500).json({ error: 'Error in bulk approve operation' });
  }
});

// Bulk reject users
app.post('/admin/users/bulk-reject', ensureAuthenticated, ensureAdmin, validateBulkUserOperation, handleValidationErrors, async (req, res) => {
  try {
    const { userIds, notes } = req.body;
    const clientIP = getClientIP(req);

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'User IDs array is required' });
    }

    if (!notes || notes.trim() === '') {
      return res.status(400).json({ error: 'Rejection reason is required for bulk rejection' });
    }

    const users = await User.find({ _id: { $in: userIds } });
    let successCount = 0;
    let errorCount = 0;

    for (const user of users) {
      try {
        // Update user status
        user.status = 'rejected';
        user.rejectedAt = new Date();
        user.rejectedBy = req.user._id;
        user.rejectionReason = notes;
        
        await user.save();

        // Add email to rejected list
        const rejectedEmail = new RejectedEmail({
          email: user.email.toLowerCase(),
          rejectedBy: req.user._id,
          reason: notes,
          originalUserId: user._id
        });
        await rejectedEmail.save();

        // Create audit log
        await createAuditLog(req.user, 'USER_REJECTED', user, notes, clientIP);

        successCount++;
      } catch (err) {
        console.error('Error in bulk reject for user:', user.email, err);
        errorCount++;
      }
    }

    // Create bulk audit log
    await createAuditLog(req.user, 'BULK_USER_REJECTED', null, notes, clientIP, successCount, { 
      successCount, 
      errorCount, 
      totalRequested: userIds.length 
    });

    console.log('Bulk reject completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    res.status(200).json({ 
      success: true, 
      message: `Bulk reject completed: ${successCount} successful, ${errorCount} errors`,
      successCount,
      errorCount
    });
  } catch (err) {
    console.error('Error in bulk reject:', err);
    res.status(500).json({ error: 'Error in bulk reject operation' });
  }
});

// Bulk delete users
app.post('/admin/users/bulk-delete', ensureAuthenticated, ensureAdmin, validateBulkUserOperation, handleValidationErrors, async (req, res) => {
  try {
    const { userIds, notes } = req.body;
    const clientIP = getClientIP(req);

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'User IDs array is required' });
    }

    const users = await User.find({ _id: { $in: userIds } });
    let successCount = 0;
    let errorCount = 0;

    for (const user of users) {
      try {
        // Check permissions for each user
        if (user.isProtected && req.user.email !== user.email) {
          errorCount++;
          continue;
        }

        if (user.isAdmin && !req.user.isSuperAdmin) {
          errorCount++;
          continue;
        }

        if (user.isSuperAdmin) {
          errorCount++;
          continue;
        }

        // Create audit log before deletion
        await createAuditLog(req.user, 'USER_DELETED', user, notes, clientIP);

        // Delete the user
        await User.findByIdAndDelete(user._id);

        successCount++;
      } catch (err) {
        console.error('Error in bulk delete for user:', user.email, err);
        errorCount++;
      }
    }

    // Create bulk audit log
    await createAuditLog(req.user, 'BULK_USER_DELETED', null, notes, clientIP, successCount, { 
      successCount, 
      errorCount, 
      totalRequested: userIds.length 
    });

    console.log('Bulk delete completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    res.status(200).json({ 
      success: true, 
      message: `Bulk delete completed: ${successCount} successful, ${errorCount} errors`,
      successCount,
      errorCount
    });
  } catch (err) {
    console.error('Error in bulk delete:', err);
    res.status(500).json({ error: 'Error in bulk delete operation' });
  }
});

// Error Logs Management Routes
app.get('/admin/error-logs', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const { 
      filter, 
      errorType, 
      severity, 
      status, 
      search, 
      dateFrom, 
      dateTo, 
      page = 1 
    } = req.query;
    
    const limit = 20;
    const skip = (page - 1) * limit;
    
    // Build query
    let query = {};
    
    // Quick filters
    if (filter === 'unresolved') {
      query['resolution.status'] = { $in: ['new', 'investigating'] };
    } else if (filter === 'critical') {
      query['analytics.severity'] = 'critical';
    } else if (filter === 'today') {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const tomorrow = new Date(today);
      tomorrow.setDate(tomorrow.getDate() + 1);
      query.timestamp = { $gte: today, $lt: tomorrow };
    } else if (filter === 'hour') {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      query.timestamp = { $gte: oneHourAgo };
    }
    
    // Specific filters
    if (errorType) query.errorType = errorType;
    if (severity) query['analytics.severity'] = severity;
    if (status) query['resolution.status'] = status;
    
    // Date range
    if (dateFrom || dateTo) {
      query.timestamp = {};
      if (dateFrom) query.timestamp.$gte = new Date(dateFrom);
      if (dateTo) {
        const endDate = new Date(dateTo);
        endDate.setHours(23, 59, 59, 999);
        query.timestamp.$lte = endDate;
      }
    }
    
    // Search
    if (search) {
      query.$or = [
        { message: { $regex: search, $options: 'i' } },
        { 'userContext.email': { $regex: search, $options: 'i' } },
        { 'requestContext.url': { $regex: search, $options: 'i' } }
      ];
    }
    
    // Get error logs
    const errorLogs = await ErrorLog.find(query)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit);
    
    const totalErrors = await ErrorLog.countDocuments(query);
    const totalPages = Math.ceil(totalErrors / limit);
    
    // Calculate statistics
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    
    const stats = {
      total: await ErrorLog.countDocuments(),
      unresolved: await ErrorLog.countDocuments({ 'resolution.status': { $in: ['new', 'investigating'] } }),
      critical: await ErrorLog.countDocuments({ 'analytics.severity': 'critical' }),
      today: await ErrorLog.countDocuments({ timestamp: { $gte: today } }),
      lastHour: await ErrorLog.countDocuments({ timestamp: { $gte: oneHourAgo } })
    };
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    res.render('adminErrorLogs', {
      title: 'Error Logs',
      currentPage: 'error-logs',
      errorLogs,
      stats,
      filter,
      errorType,
      severity,
      status,
      search,
      dateFrom,
      dateTo,
      page: parseInt(page),
      totalPages,
      totalErrors,
      user: req.user,
      isDevelopmentAutoLogin,
      req // Pass req for URL building in template
    });
  } catch (err) {
    console.error('Error loading error logs:', err);
    throw new DatabaseError('Failed to load error logs');
  }
}));

// Export error logs (must come before parameterized routes)
app.get('/admin/error-logs/export', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { 
    filter, 
    errorType, 
    severity, 
    status, 
    search, 
    dateFrom, 
    dateTo 
  } = req.query;
  
  // Build same query as main listing
  let query = {};
  
  if (filter === 'unresolved') {
    query['resolution.status'] = { $in: ['new', 'investigating'] };
  } else if (filter === 'critical') {
    query['analytics.severity'] = 'critical';
  } else if (filter === 'today') {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    query.timestamp = { $gte: today, $lt: tomorrow };
  } else if (filter === 'hour') {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    query.timestamp = { $gte: oneHourAgo };
  }
  
  if (errorType) query.errorType = errorType;
  if (severity) query['analytics.severity'] = severity;
  if (status) query['resolution.status'] = status;
  
  if (dateFrom || dateTo) {
    query.timestamp = {};
    if (dateFrom) query.timestamp.$gte = new Date(dateFrom);
    if (dateTo) {
      const endDate = new Date(dateTo);
      endDate.setHours(23, 59, 59, 999);
      query.timestamp.$lte = endDate;
    }
  }
  
  if (search) {
    query.$or = [
      { message: { $regex: search, $options: 'i' } },
      { 'userContext.email': { $regex: search, $options: 'i' } },
      { 'requestContext.url': { $regex: search, $options: 'i' } }
    ];
  }
  
  const errorLogs = await ErrorLog.find(query)
    .sort({ timestamp: -1 })
    .limit(1000); // Limit export to 1000 records
  
  // Create CSV content
  const csvHeader = 'Timestamp,Type,Message,User,URL,Severity,Status,Request ID\n';
  const csvRows = errorLogs.map(error => {
    const timestamp = error.timestamp.toISOString();
    const type = error.errorType;
    const message = `"${error.message.replace(/"/g, '""')}"`;
    const user = error.userContext.email || 'Anonymous';
    const url = `"${error.requestContext.originalUrl}"`;
    const severity = error.analytics.severity;
    const status = error.resolution.status;
    const requestId = error.requestId;
    
    return `${timestamp},${type},${message},${user},${url},${severity},${status},${requestId}`;
  }).join('\n');
  
  const csvContent = csvHeader + csvRows;
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="error-logs-${new Date().toISOString().split('T')[0]}.csv"`);
  res.send(csvContent);
}));

// Get single error log details
app.get('/admin/error-logs/:id', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const errorLog = await ErrorLog.findById(req.params.id);
  if (!errorLog) {
    throw new NotFoundError('Error log', req.params.id);
  }
  res.json(errorLog);
}));

// Get error log in AI-friendly format
app.get('/admin/error-logs/:id/ai-format', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const errorLog = await ErrorLog.findById(req.params.id);
  if (!errorLog) {
    throw new NotFoundError('Error log', req.params.id);
  }
  
  const aiFormat = `ERROR ANALYSIS REQUEST

Error Summary:
- Type: ${errorLog.errorType}
- Occurred: ${errorLog.timestamp.toISOString()}
- Endpoint: ${errorLog.requestContext.method} ${errorLog.requestContext.originalUrl}
- User: ${errorLog.userContext.email || 'Anonymous'}
- Status: ${errorLog.resolution.status}
- Severity: ${errorLog.analytics.severity}

Context:
- User Action: ${errorLog.getUserActionDescription()}
- Error Message: ${errorLog.message}
- Status Code: ${errorLog.statusCode}
- Request ID: ${errorLog.requestId}

Technical Details:
${errorLog.errorDetails.stack || 'No stack trace available'}

Request Context:
${JSON.stringify(errorLog.requestContext, null, 2)}

User Context:
${JSON.stringify(errorLog.userContext, null, 2)}

Environment:
- Node.js: ${errorLog.environment.nodeVersion}
- Environment: ${errorLog.environment.nodeEnv}
- Platform: ${errorLog.environment.platform}

${errorLog.analytics.frequency > 1 ? `
Pattern Analysis:
- This error has occurred ${errorLog.analytics.frequency} times
- Category: ${errorLog.analytics.category}
- Impact Level: ${errorLog.analytics.impact}
` : ''}

${errorLog.resolution.adminNotes ? `
Admin Notes:
${errorLog.resolution.adminNotes}
` : ''}

Please analyze this error and provide:
1. Root cause analysis
2. Potential fixes
3. Prevention strategies
4. Impact assessment`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(aiFormat);
}));

// Get technical details
app.get('/admin/error-logs/:id/technical', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const errorLog = await ErrorLog.findById(req.params.id);
  if (!errorLog) {
    throw new NotFoundError('Error log', req.params.id);
  }
  
  const technical = `TECHNICAL ERROR DETAILS

Error Information:
- Type: ${errorLog.errorType}
- Message: ${errorLog.message}
- Status Code: ${errorLog.statusCode}
- Request ID: ${errorLog.requestId}
- Timestamp: ${errorLog.timestamp.toISOString()}

Stack Trace:
${errorLog.errorDetails.stack || 'No stack trace available'}

Request Details:
- Method: ${errorLog.requestContext.method}
- URL: ${errorLog.requestContext.originalUrl}
- IP: ${errorLog.requestContext.ip}
- User Agent: ${errorLog.requestContext.userAgent}
- Query: ${JSON.stringify(errorLog.requestContext.query, null, 2)}
- Body: ${JSON.stringify(errorLog.requestContext.body, null, 2)}

Environment:
- Node.js: ${errorLog.environment.nodeVersion}
- Environment: ${errorLog.environment.nodeEnv}
- Platform: ${errorLog.environment.platform}
- PID: ${errorLog.environment.pid}
- Uptime: ${errorLog.environment.uptime}s
- Memory: ${JSON.stringify(errorLog.environment.memoryUsage, null, 2)}

Original Error:
${JSON.stringify(errorLog.errorDetails.originalError, null, 2)}`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(technical);
}));

// Get user context
app.get('/admin/error-logs/:id/user-context', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const errorLog = await ErrorLog.findById(req.params.id);
  if (!errorLog) {
    throw new NotFoundError('Error log', req.params.id);
  }
  
  const userContext = `USER CONTEXT ANALYSIS

User Information:
- Email: ${errorLog.userContext.email || 'Anonymous'}
- Name: ${errorLog.userContext.name || 'N/A'}
- Authenticated: ${errorLog.userContext.isAuthenticated ? 'Yes' : 'No'}
- Admin: ${errorLog.userContext.isAdmin ? 'Yes' : 'No'}
- Super Admin: ${errorLog.userContext.isSuperAdmin ? 'Yes' : 'No'}
- Probationary: ${errorLog.userContext.probationaryStatus ? 'Yes' : 'No'}

Session Information:
- Session ID: ${errorLog.userContext.sessionId || 'N/A'}
- IP Address: ${errorLog.requestContext.ip}
- User Agent: ${errorLog.requestContext.userAgent}

User Journey:
- Action Attempted: ${errorLog.getUserActionDescription()}
- Endpoint: ${errorLog.requestContext.method} ${errorLog.requestContext.originalUrl}
- Referer: ${errorLog.requestContext.referer || 'Direct access'}
- Time: ${errorLog.timestamp.toISOString()}

Request Details:
- Protocol: ${errorLog.requestContext.protocol}
- Secure: ${errorLog.requestContext.secure ? 'Yes' : 'No'}
- XHR: ${errorLog.requestContext.xhr ? 'Yes (AJAX)' : 'No (Page load)'}

Error Impact:
- Severity: ${errorLog.analytics.severity}
- Category: ${errorLog.analytics.category}
- User Impact: ${errorLog.analytics.impact}`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(userContext);
}));

// Update error status
app.post('/admin/error-logs/:id/status', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { status, resolution, notes } = req.body;
  
  const errorLog = await ErrorLog.findById(req.params.id);
  if (!errorLog) {
    throw new NotFoundError('Error log', req.params.id);
  }
  
  if (status === 'resolved') {
    await errorLog.markAsResolved(req.user, resolution, notes);
  } else {
    errorLog.resolution.status = status;
    if (notes) {
      await errorLog.addAdminNote(req.user, notes);
    }
    await errorLog.save();
  }
  
  res.json({ success: true, message: 'Status updated successfully' });
}));

// Export error logs
app.get('/admin/error-logs/export', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { 
    filter, 
    errorType, 
    severity, 
    status, 
    search, 
    dateFrom, 
    dateTo 
  } = req.query;
  
  // Build same query as main listing
  let query = {};
  
  if (filter === 'unresolved') {
    query['resolution.status'] = { $in: ['new', 'investigating'] };
  } else if (filter === 'critical') {
    query['analytics.severity'] = 'critical';
  } else if (filter === 'today') {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    query.timestamp = { $gte: today, $lt: tomorrow };
  } else if (filter === 'hour') {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    query.timestamp = { $gte: oneHourAgo };
  }
  
  if (errorType) query.errorType = errorType;
  if (severity) query['analytics.severity'] = severity;
  if (status) query['resolution.status'] = status;
  
  if (dateFrom || dateTo) {
    query.timestamp = {};
    if (dateFrom) query.timestamp.$gte = new Date(dateFrom);
    if (dateTo) {
      const endDate = new Date(dateTo);
      endDate.setHours(23, 59, 59, 999);
      query.timestamp.$lte = endDate;
    }
  }
  
  if (search) {
    query.$or = [
      { message: { $regex: search, $options: 'i' } },
      { 'userContext.email': { $regex: search, $options: 'i' } },
      { 'requestContext.url': { $regex: search, $options: 'i' } }
    ];
  }
  
  const errorLogs = await ErrorLog.find(query)
    .sort({ timestamp: -1 })
    .limit(1000); // Limit export to 1000 records
  
  // Create CSV content
  const csvHeader = 'Timestamp,Type,Message,User,URL,Severity,Status,Request ID\n';
  const csvRows = errorLogs.map(error => {
    const timestamp = error.timestamp.toISOString();
    const type = error.errorType;
    const message = `"${error.message.replace(/"/g, '""')}"`;
    const user = error.userContext.email || 'Anonymous';
    const url = `"${error.requestContext.originalUrl}"`;
    const severity = error.analytics.severity;
    const status = error.resolution.status;
    const requestId = error.requestId;
    
    return `${timestamp},${type},${message},${user},${url},${severity},${status},${requestId}`;
  }).join('\n');
  
  const csvContent = csvHeader + csvRows;
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="error-logs-${new Date().toISOString().split('T')[0]}.csv"`);
  res.send(csvContent);
}));

// Cleanup old error logs
app.post('/admin/error-logs/cleanup', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const result = await ErrorLog.cleanupOldLogs(90); // 90 days retention
  res.json({ 
    success: true, 
    deletedCount: result.deletedCount,
    message: `Cleaned up ${result.deletedCount} old error logs`
  });
}));

// Clear all error logs (SuperAdmin only)
app.post('/admin/error-logs/clear-all', ensureAuthenticated, ensureSuperAdmin, asyncErrorHandler(async (req, res) => {
  const clientIP = getClientIP(req);
  
  try {
    // Count logs before deletion for audit
    const totalLogs = await ErrorLog.countDocuments();
    
    // Delete all error logs
    const result = await ErrorLog.deleteMany({});
    
    // Create audit log for this critical action
    await createAuditLog(req.user, 'ERROR_LOGS_CLEARED_ALL', null, `Cleared all ${totalLogs} error logs`, clientIP, totalLogs, {
      totalDeleted: result.deletedCount,
      action: 'CLEAR_ALL_ERROR_LOGS'
    });
    
    console.log('All error logs cleared by SuperAdmin:', req.user.email, 'Count:', result.deletedCount);
    
    res.json({ 
      success: true, 
      deletedCount: result.deletedCount,
      message: `All error logs cleared: ${result.deletedCount} logs deleted`
    });
  } catch (err) {
    console.error('Error clearing all logs:', err);
    throw new DatabaseError('Failed to clear all error logs');
  }
}));

// Bulk mark as investigating
app.post('/admin/error-logs/bulk-investigate', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { errorIds, notes } = req.body;
  const clientIP = getClientIP(req);
  
  if (!errorIds || !Array.isArray(errorIds) || errorIds.length === 0) {
    throw new ValidationError('Error IDs array is required');
  }
  
  let successCount = 0;
  let errorCount = 0;
  
  try {
    for (const errorId of errorIds) {
      try {
        const errorLog = await ErrorLog.findById(errorId);
        if (!errorLog) {
          errorCount++;
          continue;
        }
        
        errorLog.resolution.status = 'investigating';
        if (notes) {
          await errorLog.addAdminNote(req.user, notes);
        }
        await errorLog.save();
        
        successCount++;
      } catch (err) {
        console.error('Error in bulk investigate for log:', errorId, err);
        errorCount++;
      }
    }
    
    // Create audit log
    await createAuditLog(req.user, 'BULK_ERROR_LOGS_INVESTIGATING', null, notes, clientIP, successCount, {
      successCount,
      errorCount,
      totalRequested: errorIds.length,
      action: 'BULK_MARK_INVESTIGATING'
    });
    
    console.log('Bulk investigate completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    
    res.json({ 
      success: true, 
      successCount,
      errorCount,
      message: `Bulk operation completed: ${successCount} updated, ${errorCount} errors`
    });
  } catch (err) {
    console.error('Error in bulk investigate:', err);
    throw new DatabaseError('Failed to perform bulk investigate operation');
  }
}));

// Bulk mark as resolved
app.post('/admin/error-logs/bulk-resolve', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { errorIds, resolution, notes } = req.body;
  const clientIP = getClientIP(req);
  
  if (!errorIds || !Array.isArray(errorIds) || errorIds.length === 0) {
    throw new ValidationError('Error IDs array is required');
  }
  
  if (!resolution || resolution.trim() === '') {
    throw new ValidationError('Resolution details are required');
  }
  
  let successCount = 0;
  let errorCount = 0;
  
  try {
    for (const errorId of errorIds) {
      try {
        const errorLog = await ErrorLog.findById(errorId);
        if (!errorLog) {
          errorCount++;
          continue;
        }
        
        await errorLog.markAsResolved(req.user, resolution, notes);
        successCount++;
      } catch (err) {
        console.error('Error in bulk resolve for log:', errorId, err);
        errorCount++;
      }
    }
    
    // Create audit log
    await createAuditLog(req.user, 'BULK_ERROR_LOGS_RESOLVED', null, `Resolution: ${resolution}. Notes: ${notes || 'None'}`, clientIP, successCount, {
      successCount,
      errorCount,
      totalRequested: errorIds.length,
      resolution,
      action: 'BULK_MARK_RESOLVED'
    });
    
    console.log('Bulk resolve completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    
    res.json({ 
      success: true, 
      successCount,
      errorCount,
      message: `Bulk operation completed: ${successCount} resolved, ${errorCount} errors`
    });
  } catch (err) {
    console.error('Error in bulk resolve:', err);
    throw new DatabaseError('Failed to perform bulk resolve operation');
  }
}));

// Bulk delete error logs (SuperAdmin only)
app.post('/admin/error-logs/bulk-delete', ensureAuthenticated, ensureSuperAdmin, asyncErrorHandler(async (req, res) => {
  const { errorIds } = req.body;
  const clientIP = getClientIP(req);
  
  if (!errorIds || !Array.isArray(errorIds) || errorIds.length === 0) {
    throw new ValidationError('Error IDs array is required');
  }
  
  try {
    // Get error logs for audit before deletion
    const errorLogs = await ErrorLog.find({ _id: { $in: errorIds } }).select('_id timestamp errorType message');
    
    // Delete the error logs
    const result = await ErrorLog.deleteMany({ _id: { $in: errorIds } });
    
    // Create audit log
    await createAuditLog(req.user, 'BULK_ERROR_LOGS_DELETED', null, `Deleted ${result.deletedCount} error logs`, clientIP, result.deletedCount, {
      deletedCount: result.deletedCount,
      requestedCount: errorIds.length,
      action: 'BULK_DELETE_ERROR_LOGS',
      deletedIds: errorLogs.map(log => log._id.toString())
    });
    
    console.log('Bulk delete completed:', result.deletedCount, 'deleted by SuperAdmin:', req.user.email);
    
    res.json({ 
      success: true, 
      deletedCount: result.deletedCount,
      message: `Bulk deletion completed: ${result.deletedCount} error logs deleted`
    });
  } catch (err) {
    console.error('Error in bulk delete:', err);
    throw new DatabaseError('Failed to perform bulk delete operation');
  }
}));

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
