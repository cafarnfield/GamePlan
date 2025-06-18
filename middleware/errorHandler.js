/**
 * Centralized Error Handling Middleware for GamePlan Application
 * Provides consistent error responses and logging across the application
 */

const {
  generateRequestId,
  expectsJson,
  createErrorContext,
  logError,
  createErrorResponse,
  ErrorFactory
} = require('../utils/errorUtils');

const {
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  DatabaseError,
  ExternalServiceError,
  ConfigurationError
} = require('../utils/errors');

const ErrorLog = require('../models/ErrorLog');

/**
 * Request ID middleware - adds unique ID to each request for tracking
 */
const requestIdMiddleware = (req, res, next) => {
  req.requestId = generateRequestId();
  res.setHeader('X-Request-ID', req.requestId);
  next();
};

/**
 * 404 Not Found handler - catches requests to non-existent routes
 */
const notFoundHandler = (req, res, next) => {
  const error = new NotFoundError('Route', req.originalUrl);
  next(error);
};

/**
 * Main error handling middleware
 * Processes all errors and sends appropriate responses
 */
const errorHandler = (error, req, res, next) => {
  const isDevelopment = process.env.NODE_ENV === 'development';
  const requestId = req.requestId || generateRequestId();

  // Convert known error types to our custom errors
  let processedError = processError(error);

  // Create error context for logging
  const context = createErrorContext(req, processedError, requestId);

  // Log the error to console
  logError(processedError, context);

  // Save error to database (async, don't block response)
  saveErrorToDatabase(processedError, req, requestId).catch(dbError => {
    console.error('Failed to save error to database:', dbError);
  });

  // Don't send response if headers already sent
  if (res.headersSent) {
    return next(processedError);
  }

  // Set status code
  const statusCode = processedError.statusCode || 500;
  res.status(statusCode);

  // Add retry-after header for rate limit errors
  if (processedError.retryAfter) {
    res.setHeader('Retry-After', processedError.retryAfter);
  }

  // Determine response format based on request type
  if (expectsJson(req)) {
    // JSON response for API requests
    const errorResponse = createErrorResponse(processedError, requestId, isDevelopment);
    res.json(errorResponse);
  } else {
    // HTML response for web requests
    handleWebError(req, res, processedError, isDevelopment);
  }
};

/**
 * Process and convert various error types to our custom errors
 * @param {Error} error - Original error
 * @returns {AppError} Processed error
 */
const processError = (error) => {
  // Already our custom error
  if (error instanceof AppError) {
    return error;
  }

  // Mongoose/MongoDB errors
  if (error.name === 'MongoError' || error.name === 'MongooseError' || 
      error.name === 'ValidationError' || error.name === 'CastError' || 
      error.code === 11000) {
    return ErrorFactory.fromMongooseError(error);
  }

  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    return new AuthenticationError('Invalid token');
  }

  if (error.name === 'TokenExpiredError') {
    return new AuthenticationError('Token expired');
  }

  // Multer errors (file upload)
  if (error.code === 'LIMIT_FILE_SIZE') {
    return new ValidationError('File too large');
  }

  if (error.code === 'LIMIT_FILE_COUNT') {
    return new ValidationError('Too many files');
  }

  if (error.code === 'LIMIT_UNEXPECTED_FILE') {
    return new ValidationError('Unexpected file field');
  }

  // Axios/HTTP errors (external services)
  if (error.isAxiosError) {
    const service = error.config?.baseURL || 'External service';
    return new ExternalServiceError(service, `${service} request failed`);
  }

  // Rate limit errors
  if (error.type === 'entity.too.large') {
    return new ValidationError('Request entity too large');
  }

  // Syntax errors
  if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
    return new ValidationError('Invalid JSON in request body');
  }

  // Default to generic app error
  return new AppError(error.message || 'An unexpected error occurred', 500);
};

/**
 * Handle web (HTML) error responses
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {AppError} error - Processed error
 * @param {boolean} isDevelopment - Development mode flag
 */
const handleWebError = (req, res, error, isDevelopment) => {
  const statusCode = error.statusCode || 500;
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && isDevelopment;

  // Handle specific routes that need custom error handling
  if (req.originalUrl.includes('/register')) {
    return res.render('register', {
      isDevelopmentAutoLogin,
      error: error.message
    });
  }

  if (req.originalUrl.includes('/login')) {
    return res.render('login', {
      isDevelopmentAutoLogin,
      error: error.message
    });
  }

  // Handle authentication errors
  if (error instanceof AuthenticationError) {
    return res.redirect('/login');
  }

  // Handle authorization errors
  if (error instanceof AuthorizationError) {
    if (req.user) {
      // User is logged in but doesn't have permission
      return res.render('error', {
        error: {
          status: 403,
          message: error.message,
          details: isDevelopment ? error.details : null
        },
        user: req.user,
        isDevelopmentAutoLogin
      });
    } else {
      // User not logged in
      return res.redirect('/login');
    }
  }

  // For other errors, render error page or send simple response
  if (statusCode === 404) {
    return res.render('error', {
      error: {
        status: 404,
        message: 'Page not found',
        details: isDevelopment ? `Route '${req.originalUrl}' not found` : null
      },
      user: req.user,
      isDevelopmentAutoLogin
    });
  }

  // Check if error template exists, otherwise send simple response
  try {
    res.render('error', {
      error: {
        status: statusCode,
        message: error.message,
        details: isDevelopment ? error.details : null
      },
      user: req.user,
      isDevelopmentAutoLogin
    });
  } catch (renderError) {
    // Fallback if error template doesn't exist
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Error ${statusCode}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          .error { background: #f8f8f8; padding: 20px; border-radius: 5px; }
          .error-code { color: #d32f2f; font-size: 24px; font-weight: bold; }
          .error-message { margin: 10px 0; }
          .back-link { margin-top: 20px; }
          .back-link a { color: #1976d2; text-decoration: none; }
        </style>
      </head>
      <body>
        <div class="error">
          <div class="error-code">Error ${statusCode}</div>
          <div class="error-message">${error.message}</div>
          ${isDevelopment && error.details ? `<pre>${JSON.stringify(error.details, null, 2)}</pre>` : ''}
          <div class="back-link">
            <a href="/">← Back to Home</a>
          </div>
        </div>
      </body>
      </html>
    `);
  }
};

/**
 * Async error wrapper for route handlers
 * Use this to wrap async route handlers to automatically catch errors
 */
const asyncErrorHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Validation error handler for express-validator
 * Converts validation results to our error format
 */
const handleValidationErrors = (req, res, next) => {
  const { validationResult } = require('express-validator');
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const validationError = ErrorFactory.fromValidationResult(errors);
    return next(validationError);
  }
  
  next();
};

/**
 * Save error to database for analysis and tracking
 * @param {AppError} error - Processed error
 * @param {Object} req - Express request object
 * @param {string} requestId - Unique request ID
 */
const saveErrorToDatabase = async (error, req, requestId) => {
  try {
    // Sanitize request body to remove sensitive data
    const sanitizedBody = sanitizeRequestData(req.body);
    const sanitizedHeaders = sanitizeHeaders(req.headers);

    // Create error log entry
    const errorLogData = {
      requestId,
      errorType: error.constructor.name,
      statusCode: error.statusCode || 500,
      message: error.message,
      errorCode: error.code,
      
      requestContext: {
        method: req.method,
        url: req.url,
        originalUrl: req.originalUrl,
        baseUrl: req.baseUrl,
        path: req.path,
        query: req.query,
        body: sanitizedBody,
        headers: sanitizedHeaders,
        ip: req.ip || req.connection?.remoteAddress,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        protocol: req.protocol,
        secure: req.secure,
        xhr: req.xhr
      },
      
      userContext: req.user ? {
        userId: req.user._id,
        email: req.user.email,
        name: req.user.name,
        isAdmin: req.user.isAdmin,
        isSuperAdmin: req.user.isSuperAdmin,
        isAuthenticated: true,
        sessionId: req.sessionID,
        probationaryStatus: req.user.probationaryUntil && new Date() < req.user.probationaryUntil
      } : {
        isAuthenticated: false,
        sessionId: req.sessionID
      },
      
      errorDetails: {
        stack: error.stack,
        originalError: error.originalError,
        validationErrors: error.validationErrors,
        databaseError: error.name?.includes('Mongo') ? {
          name: error.name,
          code: error.code,
          codeName: error.codeName
        } : undefined,
        externalServiceError: error.isAxiosError ? {
          config: {
            method: error.config?.method,
            url: error.config?.url,
            baseURL: error.config?.baseURL
          },
          response: error.response ? {
            status: error.response.status,
            statusText: error.response.statusText
          } : undefined
        } : undefined
      },
      
      environment: {
        nodeVersion: process.version,
        nodeEnv: process.env.NODE_ENV,
        appVersion: process.env.npm_package_version || '1.0.0',
        platform: process.platform,
        hostname: require('os').hostname(),
        pid: process.pid,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage()
      }
    };

    // Create and save error log
    const errorLog = new ErrorLog(errorLogData);
    await errorLog.save();

    // Check for similar errors and update frequency
    const similarErrors = await ErrorLog.findSimilarErrors(errorLog, 5);
    if (similarErrors.length > 0) {
      // Update frequency for the most recent similar error
      const recentSimilar = similarErrors[0];
      recentSimilar.analytics.frequency += 1;
      await recentSimilar.save();
      
      // Link related errors
      errorLog.analytics.relatedErrors = similarErrors.map(e => e._id);
      await errorLog.save();
    }

    console.log(`Error saved to database with ID: ${errorLog._id}`);
  } catch (dbError) {
    // Don't throw here to avoid infinite loop
    console.error('Failed to save error to database:', dbError.message);
  }
};

/**
 * Sanitize request data to remove sensitive information
 * @param {Object} data - Request data to sanitize
 * @returns {Object} Sanitized data
 */
const sanitizeRequestData = (data) => {
  if (!data || typeof data !== 'object') return data;
  
  const sensitiveFields = [
    'password', 'token', 'secret', 'key', 'auth', 'authorization',
    'cookie', 'session', 'csrf', 'api_key', 'apikey', 'access_token',
    'refresh_token', 'private_key', 'passphrase'
  ];
  
  const sanitized = { ...data };
  
  for (const field of sensitiveFields) {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  }
  
  return sanitized;
};

/**
 * Sanitize headers to remove sensitive information
 * @param {Object} headers - Request headers to sanitize
 * @returns {Object} Sanitized headers
 */
const sanitizeHeaders = (headers) => {
  if (!headers || typeof headers !== 'object') return headers;
  
  const sensitiveHeaders = [
    'authorization', 'cookie', 'x-api-key', 'x-auth-token',
    'x-access-token', 'x-csrf-token', 'x-session-token'
  ];
  
  const sanitized = { ...headers };
  
  for (const header of sensitiveHeaders) {
    if (sanitized[header]) {
      sanitized[header] = '[REDACTED]';
    }
  }
  
  return sanitized;
};

/**
 * Database connection error handler
 */
const handleDatabaseErrors = () => {
  const mongoose = require('mongoose');
  
  mongoose.connection.on('error', (error) => {
    console.error('MongoDB connection error:', error);
  });

  mongoose.connection.on('disconnected', () => {
    console.warn('MongoDB disconnected');
  });

  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // In production, you might want to gracefully shutdown
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    }
  });

  // Handle uncaught exceptions
  process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    // In production, gracefully shutdown
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    }
  });
};

module.exports = {
  requestIdMiddleware,
  notFoundHandler,
  errorHandler,
  asyncErrorHandler,
  handleValidationErrors,
  handleDatabaseErrors,
  processError
};
