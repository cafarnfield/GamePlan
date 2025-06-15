const fs = require('fs');
const path = require('path');
const { exit } = require('process');

/**
 * Validate required environment variables at startup
 * @returns {boolean} True if all required variables are present, false otherwise
 */
const validateRequiredEnvVars = () => {
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
    console.error(`\n❌ CRITICAL ERROR: Missing required environment variables:`);
    missingVars.forEach(varName => {
      console.error(`  - ${varName}`);
    });
    console.error(`\nApplication cannot start without these variables. Please check your .env file.\n`);
    return false;
  }

  console.log('\n✅ All required environment variables are present.');
  return true;
};

/**
 * Validate optional environment variables and log warnings
 * @returns {void}
 */
const validateOptionalEnvVars = () => {
  const optionalVars = [
    'STEAM_API_KEY',
    'RAWG_API_KEY',
    'RECAPTCHA_SITE_KEY',
    'RECAPTCHA_SECRET_KEY'
  ];

  const missingOptionalVars = optionalVars.filter(varName => !process.env[varName]);

  if (missingOptionalVars.length > 0) {
    console.warn(`\n⚠️ Missing optional environment variables (recommended for full functionality):`);
    missingOptionalVars.forEach(varName => {
      console.warn(`  - ${varName}`);
    });
    console.warn(`\nConsider adding these variables to your .env file for better functionality.\n`);
  } else {
    console.log('\n✅ All optional environment variables are present.');
  }
};

/**
 * Check for AUTO_LOGIN_ADMIN in production
 * @returns {boolean} True if configuration is safe, false otherwise
 */
const checkAutoLoginAdmin = () => {
  if (process.env.NODE_ENV === 'production' && process.env.AUTO_LOGIN_ADMIN === 'true') {
    console.error(`\n❌ SECURITY VIOLATION: AUTO_LOGIN_ADMIN is enabled in production!`);
    console.error(`This is a critical security risk. Please set AUTO_LOGIN_ADMIN=false in your .env file.\n`);
    return false;
  }

  if (process.env.AUTO_LOGIN_ADMIN === 'true') {
    console.warn(`\n⚠️ AUTO_LOGIN_ADMIN is enabled (NODE_ENV=${process.env.NODE_ENV || 'development'}):`);
    console.warn(`This is only safe in development mode. Ensure it's disabled in production.\n`);
  } else {
    console.log('\n✅ AUTO_LOGIN_ADMIN is disabled (production-safe).');
  }

  return true;
};

/**
 * Validate production-specific configurations
 * @returns {boolean} True if all production checks pass, false otherwise
 */
const validateProductionConfig = () => {
  if (process.env.NODE_ENV !== 'production') {
    console.log(`\n✅ Running in ${process.env.NODE_ENV || 'development'} mode.`);
    return true;
  }

  console.log('\n✅ Running in production mode. Performing additional production checks:');

  let hasErrors = false;

  // Check for HTTPS configuration (warning only for local development)
  if (!process.env.FORCE_HTTPS || process.env.FORCE_HTTPS.toLowerCase() !== 'true') {
    console.warn(`  ⚠️ HTTPS not enforced (FORCE_HTTPS is not set to 'true')`);
    // Only treat as error if this looks like a real production deployment
    if (process.env.MONGO_URI && !process.env.MONGO_URI.includes('localhost')) {
      console.warn(`  ⚠️ Consider enabling HTTPS for production deployments`);
    }
  } else {
    console.log(`  ✅ HTTPS is enforced`);
  }

  // Check for secure cookies (warning only for local development)
  if (!process.env.SECURE_COOKIES || process.env.SECURE_COOKIES.toLowerCase() !== 'true') {
    console.warn(`  ⚠️ Secure cookies not enabled (SECURE_COOKIES is not set to 'true')`);
    // Only treat as error if this looks like a real production deployment
    if (process.env.MONGO_URI && !process.env.MONGO_URI.includes('localhost')) {
      console.warn(`  ⚠️ Consider enabling secure cookies for production deployments`);
    }
  } else {
    console.log(`  ✅ Secure cookies are enabled`);
  }

  // Check for proper MongoDB URI format in production
  try {
    const mongoUri = new URL(process.env.MONGO_URI);
    if (!mongoUri.protocol.startsWith('mongodb') || !mongoUri.hostname) {
      console.error(`  ❌ Invalid MongoDB URI format: ${process.env.MONGO_URI}`);
      hasErrors = true;
    } else {
      console.log(`  ✅ MongoDB URI format is valid`);
    }
  } catch (err) {
    console.error(`  ❌ Invalid MongoDB URI: ${process.env.MONGO_URI}`);
    hasErrors = true;
  }

  return !hasErrors;
};

/**
 * Perform comprehensive environment validation at startup
 * @returns {boolean} True if all validations pass, false otherwise
 */
const validateEnvironment = () => {
  console.log('\n================================================');
  console.log('🔍  PERFORMING ENVIRONMENT VALIDATION');
  console.log('================================================\n');

  const requiredVarsValid = validateRequiredEnvVars();
  validateOptionalEnvVars();
  const autoLoginAdminValid = checkAutoLoginAdmin();
  const productionConfigValid = validateProductionConfig();

  console.log('================================================\n');

  return requiredVarsValid && autoLoginAdminValid && productionConfigValid;
};

/**
 * Exit the application with an error code
 * @param {number} code - The exit code
 * @param {string} message - The error message
 */
const exitWithError = (code, message) => {
  console.error(`\n❌ FATAL ERROR: ${message}`);
  console.error(`Application cannot start. Exiting with code ${code}.`);
  console.error(`Please check your .env file and fix the configuration issues.\n`);
  exit(code);
};

/**
 * Perform environment validation and exit if validation fails
 */
const validateAndExitIfInvalid = () => {
  if (!validateEnvironment()) {
    exitWithError(1, 'Environment validation failed. Critical configuration issues detected.');
  }
};

module.exports = {
  validateEnvironment,
  validateAndExitIfInvalid
};
