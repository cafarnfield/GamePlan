const { validateEnvironment, validateAndExitIfInvalid } = require('./startupValidation');
const { validateProductionSafety } = require('./productionSafety');
const { configHealthMiddleware } = require('../utils/configHealth');

/**
 * Middleware to validate required environment variables
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const validateRequiredEnvVars = (req, res, next) => {
  const requiredVars = [
    'NODE_ENV',
    'MONGO_URI',
    'SESSION_SECRET',
    'MONGO_ROOT_PASSWORD',
    'MONGO_PASSWORD',
    'ADMIN_EMAIL',
    'ADMIN_PASSWORD',
    'ADMIN_NAME'
  ];

  const missingVars = requiredVars.filter(varName => !process.env[varName]);

  if (missingVars.length > 0) {
    console.error(`Missing required environment variables: ${missingVars.join(', ')}`);
    return res.status(500).json({
      error: 'Server configuration error',
      message: 'Missing required environment variables. Please contact support.'
    });
  }

  next();
};

/**
 * Middleware to check for AUTO_LOGIN_ADMIN in production
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkAutoLoginAdmin = (req, res, next) => {
  if (process.env.NODE_ENV === 'production' && process.env.AUTO_LOGIN_ADMIN === 'true') {
    console.error('Security violation: AUTO_LOGIN_ADMIN is enabled in production');
    return res.status(500).json({
      error: 'Server configuration error',
      message: 'Invalid server configuration. Please contact support.'
    });
  }

  next();
};

/**
 * Middleware to validate optional environment variables and log warnings
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const validateOptionalEnvVars = (req, res, next) => {
  const optionalVars = [
    'STEAM_API_KEY',
    'RAWG_API_KEY',
    'RECAPTCHA_SITE_KEY',
    'RECAPTCHA_SECRET_KEY'
  ];

  const missingOptionalVars = optionalVars.filter(varName => !process.env[varName]);

  if (missingOptionalVars.length > 0) {
    console.warn(`Missing optional environment variables: ${missingOptionalVars.join(', ')}`);
    // Log warning but continue execution
  }

  next();
};

/**
 * Middleware to validate all environment variables
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const validateEnvVars = (req, res, next) => {
  validateRequiredEnvVars(req, res, () => {
    checkAutoLoginAdmin(req, res, () => {
      validateOptionalEnvVars(req, res, next);
    });
  });
};

module.exports = {
  validateEnvVars,
  validateEnvironment,
  validateAndExitIfInvalid,
  validateProductionSafety,
  configHealthMiddleware
};
