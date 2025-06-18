const express = require('express');
const bcrypt = require('bcrypt');
const passport = require('passport');
const axios = require('axios');
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
    const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
    res.status(429).render('register', { 
      isDevelopmentAutoLogin, 
      recaptchaSiteKey,
      error: 'Too many registration attempts from this IP, please try again in an hour.'
    });
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

// Registration routes
router.get('/register', (req, res) => {
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
  res.render('register', { isDevelopmentAutoLogin, recaptchaSiteKey, error: null });
});

router.post('/register', registrationLimiter, validateRegistration, (req, res, next) => {
  // Custom validation error handler for registration to show specific errors
  const { validationResult } = require('express-validator');
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
    
    // Create detailed error message for debugging
    const errorMessages = errors.array().map(error => `${error.path}: ${error.msg}`);
    const detailedError = `Validation failed:\n${errorMessages.join('\n')}`;
    
    console.log('Registration validation errors:', errors.array());
    
    return res.render('register', { 
      isDevelopmentAutoLogin, 
      recaptchaSiteKey,
      error: detailedError
    });
  }
  
  next();
}, async (req, res) => {
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

// Login routes
router.get('/login', (req, res) => {
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('login', { isDevelopmentAutoLogin });
});

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
router.get('/profile', ensureAuthenticated, ensureNotBlocked, (req, res) => {
  console.log('Profile route accessed');
  console.log('User:', req.user);
  // For development, if no user is authenticated, create a mock user
  const user = req.user || { name: 'Development User', email: 'dev@example.com', gameNickname: 'DevNick' };
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('profile', { user, isDevelopmentAutoLogin });
});

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
