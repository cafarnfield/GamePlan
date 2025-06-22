/**
 * Authentication middleware for GamePlan application
 * Provides reusable authentication and authorization middleware functions
 */

/**
 * Middleware to check if user is authenticated
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const ensureAuthenticated = (req, res, next) => {
  // Check for auto-login in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development') {
    return next();
  }
  if (req.isAuthenticated && typeof req.isAuthenticated === 'function' && req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

/**
 * Middleware to check if user must change password
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const ensurePasswordNotExpired = (req, res, next) => {
  // Skip check for auto-login in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development') {
    return next();
  }
  
  // Skip check if not authenticated
  if (!req.isAuthenticated || !req.isAuthenticated() || !req.user) {
    return next();
  }
  
  // Skip check for password change routes to avoid infinite redirect
  if (req.path === '/change-password' || req.path === '/logout') {
    return next();
  }
  
  // Check if user must change password
  if (req.user.mustChangePassword) {
    return res.redirect('/change-password');
  }
  
  next();
};

/**
 * Middleware to check if user is blocked
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const ensureNotBlocked = (req, res, next) => {
  if (req.isAuthenticated && req.isAuthenticated() && req.user && req.user.isBlocked) {
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

/**
 * Middleware to check if user is an admin
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const ensureAdmin = (req, res, next) => {
  // Check for auto-login in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development') {
    return next();
  }
  
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.redirect('/login');
  }
  
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).send('Access denied. Admin privileges required.');
  }
  
  next();
};

/**
 * Middleware to check if user is a super admin
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const ensureSuperAdmin = (req, res, next) => {
  // Check for auto-login in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development') {
    return next();
  }
  
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.redirect('/login');
  }
  
  if (!req.user || !req.user.isSuperAdmin) {
    return res.status(403).send('Access denied. Super admin privileges required.');
  }
  
  next();
};

module.exports = {
  ensureAuthenticated,
  ensurePasswordNotExpired,
  ensureNotBlocked,
  ensureAdmin,
  ensureSuperAdmin
};
