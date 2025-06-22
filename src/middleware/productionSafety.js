const { validateEnvironment } = require('./startupValidation');

/**
 * Middleware to validate environment variables for each request
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const validateEnvVarsMiddleware = (req, res, next) => {
  // Quick validation without verbose output - only check critical variables
  const criticalVars = ['NODE_ENV', 'MONGO_URI', 'SESSION_SECRET'];
  const missingVars = criticalVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    return res.status(500).json({
      error: 'Server configuration error',
      message: 'Critical environment variables missing. Please contact support.'
    });
  }

  next();
};

/**
 * Middleware to enforce HTTPS in production
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const enforceHttps = (req, res, next) => {
  if (process.env.NODE_ENV === 'production' && 
      process.env.FORCE_HTTPS === 'true' && 
      !req.secure) {
    // Redirect to HTTPS only if FORCE_HTTPS is explicitly enabled
    return res.redirect(`https://${req.get('host')}${req.url}`);
  }

  next();
};

/**
 * Middleware to enforce secure cookies in production
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const enforceSecureCookies = (req, res, next) => {
  if (process.env.NODE_ENV === 'production' && process.env.SECURE_COOKIES === 'true') {
    // Ensure all cookies are secure
    res.cookie('gameplan.sid', req.sessionID, {
      secure: true,
      httpOnly: true,
      sameSite: 'lax'
    });
  }

  next();
};

/**
 * Middleware to check for development-only configurations in production
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkDevConfigs = (req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    // Check for development-only configurations
    const devConfigs = [
      { name: 'MOCK_DB', value: process.env.MOCK_DB },
      { name: 'AUTO_LOGIN_ADMIN', value: process.env.AUTO_LOGIN_ADMIN }
    ];

    const enabledDevConfigs = devConfigs.filter(config => config.value === 'true');

    if (enabledDevConfigs.length > 0) {
      console.warn(`⚠️ Development configurations enabled in production:`);
      enabledDevConfigs.forEach(config => {
        console.warn(`  - ${config.name}=${config.value}`);
      });
      // Don't block the request, but log a warning
    }
  }

  next();
};

/**
 * Middleware to validate all production safety checks
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const validateProductionSafety = (req, res, next) => {
  // Apply all production safety checks
  validateEnvVarsMiddleware(req, res, () => {
    enforceHttps(req, res, () => {
      enforceSecureCookies(req, res, () => {
        checkDevConfigs(req, res, next);
      });
    });
  });
};

module.exports = {
  validateEnvVarsMiddleware,
  enforceHttps,
  enforceSecureCookies,
  checkDevConfigs,
  validateProductionSafety
};
