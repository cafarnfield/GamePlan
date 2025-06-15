/**
 * Error Utilities for GamePlan Application
 * Provides helper functions for error handling, logging, and request tracking
 */

const crypto = require('crypto');
const { AppError } = require('./errors');

/**
 * Generate a unique request ID for error tracking
 * @returns {string} Unique request ID
 */
const generateRequestId = () => {
  return crypto.randomBytes(4).toString('hex'); // Generate 8-character hex string
};

/**
 * Extract client IP address from request
 * @param {Object} req - Express request object
 * @returns {string} Client IP address
 */
const getClientIP = (req) => {
  return req.headers['x-forwarded-for'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         req.ip ||
         'unknown';
};

/**
 * Get user agent from request
 * @param {Object} req - Express request object
 * @returns {string} User agent string
 */
const getUserAgent = (req) => {
  return req.headers['user-agent'] || 'unknown';
};

/**
 * Determine if request expects JSON response
 * @param {Object} req - Express request object
 * @returns {boolean} True if JSON response expected
 */
const expectsJson = (req) => {
  return req.xhr || 
         req.headers.accept?.includes('application/json') ||
         req.path.startsWith('/api/') ||
         req.method === 'POST' && req.headers['content-type']?.includes('application/json');
};

/**
 * Sanitize error message for production
 * @param {Error} error - Error object
 * @param {boolean} isDevelopment - Whether in development mode
 * @returns {string} Sanitized error message
 */
const sanitizeErrorMessage = (error, isDevelopment = false) => {
  if (isDevelopment) {
    return error.message;
  }

  // In production, only show user-friendly messages for operational errors
  if (error.isOperational) {
    return error.message;
  }

  // For programming errors, show generic message
  return 'An unexpected error occurred. Please try again later.';
};

/**
 * Create error context object for logging
 * @param {Object} req - Express request object
 * @param {Error} error - Error object
 * @param {string} requestId - Request ID
 * @returns {Object} Error context
 */
const createErrorContext = (req, error, requestId) => {
  const context = {
    requestId,
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl || req.url,
    ip: getClientIP(req),
    userAgent: getUserAgent(req),
    error: {
      name: error.name,
      message: error.message,
      statusCode: error.statusCode || 500,
      errorCode: error.errorCode || 'INTERNAL_ERROR',
      stack: error.stack
    }
  };

  // Add user context if available
  if (req.user) {
    context.user = {
      id: req.user._id,
      email: req.user.email,
      isAdmin: req.user.isAdmin || false,
      isSuperAdmin: req.user.isSuperAdmin || false
    };
  }

  // Add session context if available
  if (req.session) {
    context.session = {
      id: req.sessionID,
      authenticated: req.isAuthenticated ? req.isAuthenticated() : false
    };
  }

  // Add request body for non-GET requests (excluding sensitive fields)
  if (req.method !== 'GET' && req.body) {
    context.body = sanitizeRequestBody(req.body);
  }

  // Add query parameters
  if (req.query && Object.keys(req.query).length > 0) {
    context.query = req.query;
  }

  return context;
};

/**
 * Sanitize request body by removing sensitive fields
 * @param {Object} body - Request body
 * @returns {Object} Sanitized body
 */
const sanitizeRequestBody = (body) => {
  const sensitiveFields = ['password', 'token', 'secret', 'key', 'auth'];
  const sanitized = { ...body };

  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });

  return sanitized;
};

/**
 * Log error with appropriate level and context
 * @param {Error} error - Error object
 * @param {Object} context - Error context
 * @param {string} level - Log level (error, warn, info)
 */
const logError = (error, context, level = 'error') => {
  const logData = {
    level,
    message: error.message,
    ...context
  };

  // Use different logging based on error severity
  if (error.statusCode >= 500) {
    console.error('SERVER ERROR:', JSON.stringify(logData, null, 2));
  } else if (error.statusCode >= 400) {
    console.warn('CLIENT ERROR:', JSON.stringify(logData, null, 2));
  } else {
    console.info('INFO:', JSON.stringify(logData, null, 2));
  }
};

/**
 * Create standardized error response object
 * @param {Error} error - Error object
 * @param {string} requestId - Request ID
 * @param {boolean} isDevelopment - Whether in development mode
 * @returns {Object} Standardized error response
 */
const createErrorResponse = (error, requestId, isDevelopment = false) => {
  const response = {
    error: {
      type: error.name || 'Error',
      message: sanitizeErrorMessage(error, isDevelopment),
      code: error.errorCode || 'INTERNAL_ERROR',
      timestamp: new Date().toISOString(),
      requestId
    }
  };

  // Add details in development or for operational errors
  if (isDevelopment || error.isOperational) {
    if (error.details) {
      response.error.details = error.details;
    }
  }

  // Add stack trace only in development
  if (isDevelopment && error.stack) {
    response.error.stack = error.stack;
  }

  // Add retry-after header info for rate limit errors
  if (error.retryAfter) {
    response.error.retryAfter = error.retryAfter;
  }

  return response;
};

/**
 * Convert validation errors to standardized format
 * @param {Array} validationErrors - Array of validation errors
 * @returns {Object} Formatted validation error details
 */
const formatValidationErrors = (validationErrors) => {
  return validationErrors.map(error => ({
    field: error.path || error.param || error.field,
    message: error.msg || error.message,
    value: error.value,
    location: error.location
  }));
};

/**
 * Wrap async route handlers to catch errors
 * @param {Function} fn - Async route handler function
 * @returns {Function} Wrapped function that catches errors
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Create error factory functions for common scenarios
 */
const ErrorFactory = {
  /**
   * Create validation error from express-validator results
   * @param {Object} validationResult - Express-validator result
   * @returns {ValidationError} Validation error
   */
  fromValidationResult: (validationResult) => {
    const { ValidationError } = require('./errors');
    const errors = validationResult.array();
    const details = formatValidationErrors(errors);
    const message = errors.length === 1 
      ? errors[0].msg 
      : `Validation failed for ${errors.length} fields`;
    
    return new ValidationError(message, details);
  },

  /**
   * Create database error from mongoose error
   * @param {Error} mongooseError - Mongoose error
   * @returns {AppError} Appropriate error type
   */
  fromMongooseError: (mongooseError) => {
    const { DatabaseError, ConflictError, ValidationError } = require('./errors');
    
    if (mongooseError.code === 11000) {
      // Duplicate key error
      const field = Object.keys(mongooseError.keyPattern || {})[0] || 'field';
      return new ConflictError(`${field} already exists`, {
        field,
        value: mongooseError.keyValue?.[field]
      });
    }
    
    if (mongooseError.name === 'ValidationError') {
      const details = Object.values(mongooseError.errors).map(err => ({
        field: err.path,
        message: err.message,
        value: err.value
      }));
      return new ValidationError('Database validation failed', details);
    }
    
    if (mongooseError.name === 'CastError') {
      return new ValidationError(`Invalid ${mongooseError.path}: ${mongooseError.value}`);
    }
    
    return new DatabaseError(mongooseError.message, mongooseError.name);
  }
};

module.exports = {
  generateRequestId,
  getClientIP,
  getUserAgent,
  expectsJson,
  sanitizeErrorMessage,
  createErrorContext,
  sanitizeRequestBody,
  logError,
  createErrorResponse,
  formatValidationErrors,
  asyncHandler,
  ErrorFactory
};
