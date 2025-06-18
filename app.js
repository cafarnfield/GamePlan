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
