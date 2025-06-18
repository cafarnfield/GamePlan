const express = require('express');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const rateLimit = require('express-rate-limit');

// Import models
const User = require('../models/User');
const RejectedEmail = require('../models/RejectedEmail');
const AuditLog = require('../models/AuditLog');

// Import validation middleware and validators
const { handleValidationErrors } = require('../middleware/validation');
const {
  validateRegistration,
  validateLogin,
  validateProfileUpdate
} = require('../validators/authValidators');

// Import logger
const { authLogger, securityLogger } = require('../utils/logger');

const router = express.Router();

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
    authLogger.logAdminAction(action, adminUser._id, targetUser?._id, {
      targetEmail: targetUser?.email,
      notes,
      ipAddress,
      bulkCount,
      details
    });
  } catch (err) {
    authLogger.error('Error creating audit log', {
      error: err.message,
      action,
      adminId: adminUser._id,
      targetUserId: targetUser?._id
    });
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
    securityLogger.logSecurityEvent('RATE_LIMIT_EXCEEDED', 'warn', {
      type: 'login_rate_limit',
      ip: getClientIP(req),
      limit: 5,
      window: '15 minutes'
    });
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
    res.status(429).render('register', { 
      isDevelopmentAutoLogin,
      error: 'Too many registration attempts from this IP, please try again in an hour.'
    });
  }
});

// Import authentication middleware
const { ensureAuthenticated, ensureNotBlocked } = require('../middleware/auth');

// Registration routes
/**
 * @swagger
 * /register:
 *   get:
 *     tags: [Authentication]
 *     summary: Display user registration form
 *     description: Shows the registration form for new users to create an account
 *     responses:
 *       200:
 *         description: Registration form displayed successfully
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "HTML registration form"
 */
router.get('/register', (req, res) => {
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('register', { isDevelopmentAutoLogin, error: null });
});

/**
 * @swagger
 * /register:
 *   post:
 *     tags: [Authentication]
 *     summary: Register a new user account
 *     description: |
 *       Creates a new user account with pending status.
 *       Account will need admin approval before the user can log in.
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             $ref: '#/components/schemas/UserRegistration'
 *     responses:
 *       200:
 *         description: Registration successful, account pending approval
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "Registration pending approval page"
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
router.post('/register', registrationLimiter, validateRegistration, (req, res, next) => {
  // Custom validation error handler for registration to show specific errors
  const { validationResult } = require('express-validator');
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    // Create detailed error message for debugging
    const errorMessages = errors.array().map(error => `${error.path}: ${error.msg}`);
    const detailedError = `Validation failed:\n${errorMessages.join('\n')}`;
    
    console.log('Registration validation errors:', errors.array());
    
    return res.render('register', { 
      isDevelopmentAutoLogin,
      error: detailedError
    });
  }
  
  next();
}, async (req, res) => {
  try {
    const { name, email, password, gameNickname } = req.body;
    const clientIP = getClientIP(req);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';

    // Check if email is in rejected list
    const rejectedEmail = await RejectedEmail.findOne({ email: email.toLowerCase() });
    if (rejectedEmail) {
      return res.render('register', { 
        isDevelopmentAutoLogin,
        error: 'This email address has been rejected and cannot be used for registration. Please contact support if you believe this is an error.' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.render('register', { 
        isDevelopmentAutoLogin,
        error: 'An account with this email already exists.' 
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
    res.render('register', { 
      isDevelopmentAutoLogin,
      error: 'Error registering user. Please try again.' 
    });
  }
});

// Login routes
/**
 * @swagger
 * /login:
 *   get:
 *     tags: [Authentication]
 *     summary: Display login form
 *     description: Shows the login form for existing users
 *     responses:
 *       200:
 *         description: Login form displayed successfully
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "HTML login form"
 */
router.get('/login', (req, res) => {
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('login', { isDevelopmentAutoLogin });
});

/**
 * @swagger
 * /login:
 *   post:
 *     tags: [Authentication]
 *     summary: Authenticate user login
 *     description: |
 *       Authenticates user credentials and creates a session.
 *       Only approved users can successfully log in.
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             $ref: '#/components/schemas/UserLogin'
 *     responses:
 *       302:
 *         description: Login successful, redirected to home page
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
router.post('/login', loginLimiter, validateLogin, handleValidationErrors, (req, res, next) => {
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

// Profile routes
/**
 * @swagger
 * /profile:
 *   get:
 *     tags: [Authentication]
 *     summary: Display user profile
 *     description: Shows the current user's profile information and settings
 *     security:
 *       - SessionAuth: []
 *     responses:
 *       200:
 *         description: Profile page displayed successfully
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "HTML profile page"
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 */
router.get('/profile', ensureAuthenticated, ensureNotBlocked, (req, res) => {
  console.log('Profile route accessed');
  console.log('User:', req.user);
  // For development, if no user is authenticated, create a mock user
  const user = req.user || { name: 'Development User', email: 'dev@example.com', gameNickname: 'DevNick' };
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('profile', { user, isDevelopmentAutoLogin });
});

/**
 * @swagger
 * /profile/update:
 *   post:
 *     tags: [Authentication]
 *     summary: Update user profile
 *     description: Updates the current user's profile information (currently only game nickname)
 *     security:
 *       - SessionAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             $ref: '#/components/schemas/UserProfileUpdate'
 *     responses:
 *       302:
 *         description: Profile updated successfully, redirected to profile page
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
router.post('/profile/update', ensureAuthenticated, ensureNotBlocked, validateProfileUpdate, handleValidationErrors, async (req, res) => {
  try {
    const { gameNickname } = req.body;
    req.user.gameNickname = gameNickname;
    await req.user.save();
    res.redirect('/profile');
  } catch (err) {
    res.status(500).send('Error updating profile');
  }
});

// Logout route
/**
 * @swagger
 * /logout:
 *   get:
 *     tags: [Authentication]
 *     summary: Log out current user
 *     description: |
 *       Destroys the current user session and clears authentication cookies.
 *       Redirects to the home page after successful logout.
 *     responses:
 *       302:
 *         description: Logout successful, redirected to home page
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
router.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log('Error destroying session:', err);
      return res.status(500).send('Logout failed');
    }
    res.clearCookie('gameplan.sid', { path: '/' });
    res.redirect('/'); // or res.status(200).send('Logout successful')
  });
});

module.exports = router;
