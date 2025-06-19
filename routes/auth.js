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
  validateProfileUpdate,
  validatePasswordResetRequest,
  validatePasswordReset
} = require('../validators/authValidators');

// Import logger
const { authLogger, securityLogger } = require('../utils/logger');

// Import password reset utilities
const emailService = require('../services/emailService');
const TokenUtils = require('../utils/tokenUtils');

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

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: parseInt(process.env.EMAIL_RATE_LIMIT) || 5, // 5 attempts per window per IP
  message: {
    error: 'Too many password reset requests from this IP, please try again in an hour.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return getClientIP(req);
  },
  handler: (req, res) => {
    console.log(`Password reset rate limit exceeded for IP: ${getClientIP(req)}`);
    securityLogger.logSecurityEvent('RATE_LIMIT_EXCEEDED', 'warn', {
      type: 'password_reset_rate_limit',
      ip: getClientIP(req),
      limit: parseInt(process.env.EMAIL_RATE_LIMIT) || 5,
      window: '1 hour'
    });
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.status(429).render('forgotPassword', { 
      isDevelopmentAutoLogin,
      error: 'Too many password reset requests from this IP, please try again in an hour.'
    });
  }
});

// Import authentication middleware
const { ensureAuthenticated, ensureNotBlocked, ensurePasswordNotExpired } = require('../middleware/auth');

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
  
  // Get success message from session and clear it
  const profileUpdateSuccess = req.session.profileUpdateSuccess;
  delete req.session.profileUpdateSuccess;
  
  res.render('profile', { user, isDevelopmentAutoLogin, profileUpdateSuccess });
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

// Password Reset routes
/**
 * @swagger
 * /forgot-password:
 *   get:
 *     tags: [Authentication]
 *     summary: Display forgot password form
 *     description: Shows the form for users to request a password reset
 *     responses:
 *       200:
 *         description: Forgot password form displayed successfully
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "HTML forgot password form"
 */
router.get('/forgot-password', (req, res) => {
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('forgotPassword', { isDevelopmentAutoLogin, error: null, success: null });
});

/**
 * @swagger
 * /forgot-password:
 *   post:
 *     tags: [Authentication]
 *     summary: Process password reset request
 *     description: |
 *       Processes a password reset request by generating a secure token
 *       and sending a reset email to the user if the email exists.
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             $ref: '#/components/schemas/PasswordResetRequest'
 *     responses:
 *       200:
 *         description: Password reset email sent (or email not found message)
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "Password reset confirmation page"
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       429:
 *         $ref: '#/components/responses/RateLimitError'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
router.post('/forgot-password', passwordResetLimiter, validatePasswordResetRequest, handleValidationErrors, async (req, res) => {
  try {
    const { email } = req.body;
    const clientIP = getClientIP(req);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';

    // Always show success message to prevent email enumeration
    const successMessage = 'If an account with that email exists, you will receive a password reset email shortly.';

    // Find user by email
    const user = await User.findOne({ 
      email: email.toLowerCase(),
      status: 'approved' // Only allow password reset for approved users
    });

    if (user) {
      // Check if user already has an active reset token
      const hasActiveToken = await TokenUtils.hasActiveResetToken(email.toLowerCase());
      
      if (!hasActiveToken) {
        // Generate reset token
        const resetToken = await TokenUtils.createPasswordResetToken(user);

        // Send reset email
        const emailSent = await emailService.sendPasswordResetEmail(
          user.email,
          resetToken,
          user.name
        );

        if (emailSent) {
          authLogger.info('Password reset email sent', {
            userId: user._id,
            email: user.email,
            ip: clientIP
          });
        } else {
          authLogger.error('Failed to send password reset email', {
            userId: user._id,
            email: user.email,
            ip: clientIP
          });
        }
      } else {
        authLogger.info('Password reset requested for user with active token', {
          userId: user._id,
          email: user.email,
          ip: clientIP
        });
      }
    } else {
      // Log attempt for non-existent email
      authLogger.warn('Password reset requested for non-existent email', {
        email: email.toLowerCase(),
        ip: clientIP
      });
    }

    // Always show success message regardless of whether email exists
    res.render('forgotPassword', { 
      isDevelopmentAutoLogin,
      error: null,
      success: successMessage
    });

  } catch (err) {
    console.error('Error processing password reset request:', err);
    authLogger.error('Password reset request error', {
      error: err.message,
      email: req.body.email,
      ip: getClientIP(req)
    });

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('forgotPassword', { 
      isDevelopmentAutoLogin,
      error: 'An error occurred while processing your request. Please try again.',
      success: null
    });
  }
});

/**
 * @swagger
 * /reset-password/{token}:
 *   get:
 *     tags: [Authentication]
 *     summary: Display password reset form
 *     description: Shows the password reset form if the token is valid
 *     parameters:
 *       - in: path
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *         description: Password reset token
 *     responses:
 *       200:
 *         description: Password reset form displayed successfully
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "HTML password reset form"
 *       400:
 *         description: Invalid or expired token
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "Token expired page"
 */
router.get('/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';

    // Validate the reset token
    const user = await TokenUtils.validateResetToken(token);

    if (!user) {
      return res.render('resetExpired', { 
        isDevelopmentAutoLogin,
        error: 'This password reset link is invalid or has expired. Please request a new password reset.'
      });
    }

    // Show password reset form
    res.render('resetPassword', { 
      isDevelopmentAutoLogin,
      token: token,
      error: null
    });

  } catch (err) {
    console.error('Error displaying password reset form:', err);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('resetExpired', { 
      isDevelopmentAutoLogin,
      error: 'An error occurred. Please request a new password reset.'
    });
  }
});

/**
 * @swagger
 * /reset-password:
 *   post:
 *     tags: [Authentication]
 *     summary: Process password reset
 *     description: |
 *       Processes the password reset by validating the token
 *       and updating the user's password.
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             $ref: '#/components/schemas/PasswordReset'
 *     responses:
 *       200:
 *         description: Password reset successful
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "Password reset success page"
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
router.post('/reset-password', validatePasswordReset, handleValidationErrors, async (req, res) => {
  try {
    const { password, token } = req.body;
    const clientIP = getClientIP(req);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';

    // Validate the reset token
    const user = await TokenUtils.validateResetToken(token);

    if (!user) {
      return res.render('resetExpired', { 
        isDevelopmentAutoLogin,
        error: 'This password reset link is invalid or has expired. Please request a new password reset.'
      });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update user's password
    user.password = hashedPassword;
    await user.save();

    // Mark token as used
    await TokenUtils.markTokenAsUsed(user);

    // Log successful password reset
    authLogger.info('Password reset completed', {
      userId: user._id,
      email: user.email,
      ip: clientIP
    });

    // Show success page
    res.render('resetSuccess', { 
      isDevelopmentAutoLogin,
      message: 'Your password has been successfully reset. You can now log in with your new password.'
    });

  } catch (err) {
    console.error('Error processing password reset:', err);
    authLogger.error('Password reset processing error', {
      error: err.message,
      token: req.body.token ? req.body.token.substring(0, 8) + '...' : 'null',
      ip: getClientIP(req)
    });

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('resetPassword', { 
      isDevelopmentAutoLogin,
      token: req.body.token,
      error: 'An error occurred while resetting your password. Please try again.'
    });
  }
});

// Forced Password Change routes
/**
 * @swagger
 * /change-password:
 *   get:
 *     tags: [Authentication]
 *     summary: Display forced password change form
 *     description: Shows the password change form for users who must change their password
 *     security:
 *       - SessionAuth: []
 *     responses:
 *       200:
 *         description: Password change form displayed successfully
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *               example: "HTML password change form"
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 */
router.get('/change-password', ensureAuthenticated, (req, res) => {
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  const isVoluntary = req.query.source === 'profile';
  
  // If this is a voluntary change from profile, allow it regardless of mustChangePassword
  if (isVoluntary) {
    return res.render('changePassword', { 
      isDevelopmentAutoLogin,
      user: req.user,
      error: null,
      reason: 'Voluntary password change for enhanced security.',
      isVoluntary: true
    });
  }
  
  // For forced changes, check if user actually needs to change password
  if (!req.user.mustChangePassword) {
    return res.redirect('/');
  }
  
  res.render('changePassword', { 
    isDevelopmentAutoLogin,
    user: req.user,
    error: null,
    reason: req.user.mustChangePasswordReason || 'Your password must be changed for security reasons.',
    isVoluntary: false
  });
});

/**
 * @swagger
 * /change-password:
 *   post:
 *     tags: [Authentication]
 *     summary: Process forced password change
 *     description: |
 *       Processes the forced password change by validating the current password
 *       and updating to the new password.
 *     security:
 *       - SessionAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *               - confirmPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 description: Current password
 *               newPassword:
 *                 type: string
 *                 description: New password
 *               confirmPassword:
 *                 type: string
 *                 description: Confirm new password
 *     responses:
 *       302:
 *         description: Password changed successfully, redirected to home page
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
router.post('/change-password', ensureAuthenticated, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const clientIP = getClientIP(req);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    const isVoluntary = req.query.source === 'profile';
    
    // Determine the reason and context for error messages
    const defaultReason = isVoluntary ? 
      'Voluntary password change for enhanced security.' : 
      (req.user.mustChangePasswordReason || 'Your password must be changed for security reasons.');
    
    // Basic validation
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.render('changePassword', {
        isDevelopmentAutoLogin,
        user: req.user,
        error: 'All fields are required.',
        reason: defaultReason,
        isVoluntary
      });
    }
    
    if (newPassword !== confirmPassword) {
      return res.render('changePassword', {
        isDevelopmentAutoLogin,
        user: req.user,
        error: 'New passwords do not match.',
        reason: defaultReason,
        isVoluntary
      });
    }
    
    // Validate password strength
    if (newPassword.length < 8) {
      return res.render('changePassword', {
        isDevelopmentAutoLogin,
        user: req.user,
        error: 'New password must be at least 8 characters long.',
        reason: defaultReason,
        isVoluntary
      });
    }
    
    // Check if new password meets complexity requirements
    const hasUpperCase = /[A-Z]/.test(newPassword);
    const hasLowerCase = /[a-z]/.test(newPassword);
    const hasNumbers = /\d/.test(newPassword);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(newPassword);
    
    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
      return res.render('changePassword', {
        isDevelopmentAutoLogin,
        user: req.user,
        error: 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
        reason: defaultReason,
        isVoluntary
      });
    }
    
    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, req.user.password);
    if (!isCurrentPasswordValid) {
      return res.render('changePassword', {
        isDevelopmentAutoLogin,
        user: req.user,
        error: 'Current password is incorrect.',
        reason: defaultReason,
        isVoluntary
      });
    }
    
    // Check if new password is different from current
    const isSamePassword = await bcrypt.compare(newPassword, req.user.password);
    if (isSamePassword) {
      return res.render('changePassword', {
        isDevelopmentAutoLogin,
        user: req.user,
        error: 'New password must be different from your current password.',
        reason: defaultReason,
        isVoluntary
      });
    }
    
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    
    // Update user's password
    req.user.password = hashedPassword;
    req.user.passwordChangedAt = new Date();
    
    // Clear forced change flags if this was a forced change
    if (!isVoluntary && req.user.mustChangePassword) {
      req.user.mustChangePassword = false;
      req.user.mustChangePasswordReason = null;
    }
    
    await req.user.save();
    
    // Log the password change
    const logMessage = isVoluntary ? 'Voluntary password change completed' : 'Forced password change completed';
    authLogger.info(logMessage, {
      userId: req.user._id,
      email: req.user.email,
      ip: clientIP,
      voluntary: isVoluntary,
      resetBy: req.user.passwordResetBy
    });
    
    // Create audit log if this was an admin-forced change
    if (!isVoluntary && req.user.passwordResetBy) {
      try {
        const resetByAdmin = await User.findById(req.user.passwordResetBy);
        if (resetByAdmin) {
          await createAuditLog(resetByAdmin, 'FORCED_PASSWORD_CHANGE_COMPLETED', req.user, 'User completed forced password change', clientIP);
        }
      } catch (auditErr) {
        console.error('Error creating audit log for password change completion:', auditErr);
      }
    }
    
    console.log(`${isVoluntary ? 'Voluntary' : 'Forced'} password change completed for user:`, req.user.email);
    
    // Redirect based on the source
    if (isVoluntary) {
      // For voluntary changes, redirect back to profile with success message
      req.session.profileUpdateSuccess = 'Password updated successfully!';
      res.redirect('/profile');
    } else {
      // For forced changes, redirect to home page
      req.session.passwordChangeSuccess = true;
      res.redirect('/');
    }
    
  } catch (err) {
    console.error('Error processing password change:', err);
    const logMessage = isVoluntary ? 'Voluntary password change error' : 'Forced password change error';
    authLogger.error(logMessage, {
      error: err.message,
      userId: req.user._id,
      email: req.user.email,
      ip: getClientIP(req),
      voluntary: isVoluntary
    });
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    const isVoluntary = req.query.source === 'profile';
    const defaultReason = isVoluntary ? 
      'Voluntary password change for enhanced security.' : 
      (req.user.mustChangePasswordReason || 'Your password must be changed for security reasons.');
    
    res.render('changePassword', {
      isDevelopmentAutoLogin,
      user: req.user,
      error: 'An error occurred while changing your password. Please try again.',
      reason: defaultReason,
      isVoluntary
    });
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
