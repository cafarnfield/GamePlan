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

// Import validation middleware and validators
const { handleValidationErrors } = require('./middleware/validation');
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
  console.log('Session middleware accessed');
  console.log('Session before middleware:', req.session);
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
  console.log('Session middleware accessed');
  console.log('Session before middleware:', req.session);
  console.log('Authenticated user:', req.isAuthenticated ? req.isAuthenticated() : false, req.user);
  next();
});
app.use((req, res, next) => {
  console.log('Session after middleware:', req.session);
  next();
});
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection

// Mock database connection for testing
if (process.env.MOCK_DB) {
  mongoose.connect('mongodb://localhost:27017/gameplan');
} else {
  mongoose.connect(process.env.MONGO_URI);
}

// Models
const User = require('./models/User');
const Extension = require('./models/Extension');
const Event = require('./models/Event');
const Game = require('./models/Game');
const AuditLog = require('./models/AuditLog');
const RejectedEmail = require('./models/RejectedEmail');

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
    console.log('Audit log created:', action, targetUser ? targetUser.email : 'bulk action');
  } catch (err) {
    console.error('Error creating audit log:', err);
  }
};

// Helper function to verify reCAPTCHA
const verifyRecaptcha = async (recaptchaResponse) => {
  if (!process.env.RECAPTCHA_SECRET_KEY) {
    console.warn('reCAPTCHA secret key not configured, skipping verification');
    return true; // Skip verification if not configured
  }

  try {
    const response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
      params: {
        secret: process.env.RECAPTCHA_SECRET_KEY,
        response: recaptchaResponse
      }
    });
    return response.data.success;
  } catch (error) {
    console.error('reCAPTCHA verification error:', error);
    return false;
  }
};

// Helper function to set probationary period
const setProbationaryPeriod = (user, days = 30) => {
  const probationEnd = new Date();
  probationEnd.setDate(probationEnd.getDate() + days);
  user.probationaryUntil = probationEnd;
  return user;
};

// Helper function to check if user is in probation
const isUserInProbation = (user) => {
  return user.probationaryUntil && new Date() < user.probationaryUntil;
};

// Rate limiting configurations
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window per IP
  message: {
    error: 'Too many login attempts from this IP, please try again in 15 minutes.'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  keyGenerator: (req) => {
    return getClientIP(req); // Use the existing helper function for IP detection
  },
  handler: (req, res) => {
    console.log(`Login rate limit exceeded for IP: ${getClientIP(req)}`);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.status(429).render('login', { 
      isDevelopmentAutoLogin,
      error: 'Too many login attempts from this IP, please try again in 15 minutes.'
    });
  }
});

const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 attempts per window per IP
  message: {
    error: 'Too many registration attempts from this IP, please try again in an hour.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return getClientIP(req);
  },
  handler: (req, res) => {
    console.log(`Registration rate limit exceeded for IP: ${getClientIP(req)}`);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
    res.status(429).render('register', { 
      isDevelopmentAutoLogin, 
      recaptchaSiteKey,
      error: 'Too many registration attempts from this IP, please try again in an hour.'
    });
  }
});

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

// Apply general rate limiting to all routes (except static assets)
app.use(generalLimiter);

// Apply API rate limiting to all /api routes
app.use('/api', apiLimiter);

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
  res.status(403).send('You are not authorized to perform this action');
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
  res.status(403).send('Super Admin privileges required for this action');
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

// Steam search API endpoint
app.get('/api/steam/search', apiLimiter, validateSteamSearch, handleValidationErrors, async (req, res) => {
  try {
    const { q } = req.query;
    console.log('Steam search request for:', q);
    
    if (!q || q.trim().length === 0) {
      return res.status(400).json({ error: 'Search query is required' });
    }
    
    const results = await steamService.searchGames(q.trim());
    res.json(results);
  } catch (error) {
    console.error('Steam search error:', error);
    res.status(500).json({ error: 'Failed to search Steam games' });
  }
});

// RAWG search API endpoint
app.get('/api/rawg/search', apiLimiter, validateRawgSearch, handleValidationErrors, async (req, res) => {
  try {
    const { q } = req.query;
    console.log('RAWG search request for:', q);
    
    if (!q || q.trim().length === 0) {
      return res.status(400).json({ error: 'Search query is required' });
    }
    
    const results = await rawgService.searchGames(q.trim());
    res.json(results);
  } catch (error) {
    console.error('RAWG search error:', error);
    res.status(500).json({ error: 'Failed to search RAWG games' });
  }
});

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

// User profile route
app.get('/profile', ensureAuthenticated, ensureNotBlocked, (req, res) => {
  console.log('Profile route accessed');
  console.log('User:', req.user);
  // For development, if no user is authenticated, create a mock user
  const user = req.user || { name: 'Development User', email: 'dev@example.com', gameNickname: 'DevNick' };
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('profile', { user, isDevelopmentAutoLogin });
});

// Update profile route
app.post('/profile/update', ensureAuthenticated, ensureNotBlocked, validateProfileUpdate, handleValidationErrors, async (req, res) => {
  try {
    const { gameNickname } = req.body;
    req.user.gameNickname = gameNickname;
    await req.user.save();
    res.redirect('/profile');
  } catch (err) {
    res.status(500).send('Error updating profile');
  }
});

app.get('/register', (req, res) => {
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
  res.render('register', { isDevelopmentAutoLogin, recaptchaSiteKey, error: null });
});

app.post('/register', registrationLimiter, validateRegistration, handleValidationErrors, async (req, res) => {
  try {
    const { name, email, password, gameNickname, 'g-recaptcha-response': recaptchaResponse } = req.body;
    const clientIP = getClientIP(req);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';

    // Check if email is in rejected list
    const rejectedEmail = await RejectedEmail.findOne({ email: email.toLowerCase() });
    if (rejectedEmail) {
      return res.render('register', { 
        isDevelopmentAutoLogin, 
        recaptchaSiteKey,
        error: 'This email address has been rejected and cannot be used for registration. Please contact support if you believe this is an error.' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.render('register', { 
        isDevelopmentAutoLogin, 
        recaptchaSiteKey,
        error: 'An account with this email already exists.' 
      });
    }

    // Verify reCAPTCHA
    const recaptchaValid = await verifyRecaptcha(recaptchaResponse);
    if (!recaptchaValid) {
      return res.render('register', { 
        isDevelopmentAutoLogin, 
        recaptchaSiteKey,
        error: 'Please complete the CAPTCHA verification.' 
      });
    }

    // Create user with pending status
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ 
      name, 
      email: email.toLowerCase(), 
      password: hashedPassword, 
      gameNickname: gameNickname || '',
      status: 'pending',
      registrationIP: clientIP
    });
    
    await user.save();
    console.log('New user registered with pending status:', email, 'IP:', clientIP);
    
    // Redirect to a pending approval page
    res.render('registrationPending', { isDevelopmentAutoLogin });
  } catch (err) {
    console.error('Error registering user:', err);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
    res.render('register', { 
      isDevelopmentAutoLogin, 
      recaptchaSiteKey,
      error: 'Error registering user. Please try again.' 
    });
  }
});

app.get('/login', (req, res) => {
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('login', { isDevelopmentAutoLogin });
});

app.post('/login', loginLimiter, validateLogin, handleValidationErrors, (req, res, next) => {
  console.log('Login route accessed');
  console.log('Login attempt with email:', req.body.email);

  passport.authenticate('local', (err, user, info) => {
    if (err) {
      console.error('Error during authentication:', err);
      return next(err);
    }
    if (!user) {
      console.log('Authentication failed:', info.message);
      return res.redirect('/login');
    }
    console.log('Authentication successful:', user);
    req.logIn(user, (err) => {
      if (err) {
        console.error('Error during login:', err);
        return next(err);
      }
      console.log('User logged in:', req.isAuthenticated());
      console.log('Session after login:', req.session);
      res.redirect('/');
    });
  })(req, res, next);
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
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('editEvent', { event, user: req.user, isDevelopmentAutoLogin });
  } catch (err) {
    console.error('Error loading event for editing:', err);
    res.status(500).send('Error loading event');
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
      isDevelopmentAutoLogin
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
      isDevelopmentAutoLogin 
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

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminSystem', { 
      user: req.user, 
      isDevelopmentAutoLogin,
      systemHealth,
      systemStats,
      suspiciousIPs,
      recentAuditLogs
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

// Simplify logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log('Error destroying session:', err);
      return res.status(500).send('Logout failed');
    }
    res.clearCookie('gameplan.sid', { path: '/' });
    res.redirect('/'); // or res.status(200).send('Logout successful')
  });
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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
