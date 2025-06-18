const { validateEnvironment } = require('../middleware/startupValidation');

/**
 * Get configuration health status
 * @returns {Object} Configuration health status
 */
const getConfigHealth = () => {
  const health = {
    status: 'healthy',
    environment: process.env.NODE_ENV || 'development',
    requiredVars: {},
    optionalVars: {},
    productionChecks: {},
    warnings: [],
    errors: []
  };

  // Check required environment variables
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

  requiredVars.forEach(varName => {
    health.requiredVars[varName] = {
      present: !!process.env[varName],
      value: process.env[varName] ? '✓ Present' : '✗ Missing'
    };

    if (!process.env[varName]) {
      health.errors.push(`Missing required variable: ${varName}`);
      health.status = 'unhealthy';
    }
  });

  // Check optional environment variables
  const optionalVars = [
    'STEAM_API_KEY',
    'RAWG_API_KEY'
  ];

  optionalVars.forEach(varName => {
    health.optionalVars[varName] = {
      present: !!process.env[varName],
      value: process.env[varName] ? '✓ Present' : '✗ Missing'
    };

    if (!process.env[varName]) {
      health.warnings.push(`Missing optional variable: ${varName}`);
    }
  });

  // Check production-specific configurations
  if (process.env.NODE_ENV === 'production') {
    health.productionChecks = {
      autoLoginAdmin: {
        status: process.env.AUTO_LOGIN_ADMIN !== 'true',
        message: process.env.AUTO_LOGIN_ADMIN === 'true' ?
                  '❌ AUTO_LOGIN_ADMIN is enabled in production' :
                  '✅ AUTO_LOGIN_ADMIN is disabled'
      },
      https: {
        status: process.env.FORCE_HTTPS === 'true',
        message: process.env.FORCE_HTTPS === 'true' ?
                 '✅ HTTPS is enforced' :
                 '❌ HTTPS is not enforced'
      },
      secureCookies: {
        status: process.env.SECURE_COOKIES === 'true',
        message: process.env.SECURE_COOKIES === 'true' ?
                 '✅ Secure cookies are enabled' :
                 '❌ Secure cookies are not enabled'
      },
      mongoUri: {
        status: false,
        message: '❌ MongoDB URI validation not implemented in health check'
      }
    };

    // Check for development configurations in production
    const devConfigs = [
      { name: 'MOCK_DB', value: process.env.MOCK_DB },
      { name: 'AUTO_LOGIN_ADMIN', value: process.env.AUTO_LOGIN_ADMIN }
    ];

    devConfigs.forEach(config => {
      if (config.value === 'true') {
        health.warnings.push(`Development configuration enabled in production: ${config.name}=${config.value}`);
      }
    });
  }

  return health;
};

/**
 * Express middleware to expose configuration health
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const configHealthMiddleware = (req, res, next) => {
  if (req.path === '/api/config-health') {
    const health = getConfigHealth();
    return res.json(health);
  }

  next();
};

module.exports = {
  getConfigHealth,
  configHealthMiddleware
};
