const Joi = require('joi');
const { ValidationError } = require('../../utils/errors');
const { ErrorFactory } = require('../../utils/errorUtils');

/**
 * Helper function to get client IP address
 * @param {Object} req - Express request object
 * @returns {string} Client IP address
 */
const getClientIP = (req) => {
  return req.headers['x-forwarded-for'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         req.ip;
};

/**
 * Create Joi validation middleware
 * @param {Object} schema - Joi schema object
 * @param {string} source - Source of data to validate ('body', 'query', 'params')
 * @param {Object} options - Validation options
 * @returns {Function} Express middleware function
 */
const createJoiValidator = (schema, source = 'body', options = {}) => {
  const defaultOptions = {
    abortEarly: false, // Return all validation errors
    allowUnknown: false, // Don't allow unknown fields
    stripUnknown: true, // Remove unknown fields
    convert: true, // Convert types when possible
    ...options
  };

  return (req, res, next) => {
    // Get data to validate based on source
    let dataToValidate;
    switch (source) {
      case 'query':
        dataToValidate = req.query;
        break;
      case 'params':
        dataToValidate = req.params;
        break;
      case 'headers':
        dataToValidate = req.headers;
        break;
      case 'body':
      default:
        dataToValidate = req.body;
        break;
    }

    // Add context data for conditional validation
    const context = {
      twoYearsFromNow: new Date(Date.now() + (2 * 365 * 24 * 60 * 60 * 1000)),
      operation: dataToValidate.operation,
      user: req.user,
      isAdmin: req.user && (req.user.role === 'admin' || req.user.role === 'superadmin'),
      isSuperAdmin: req.user && req.user.role === 'superadmin'
    };

    // Validate data against schema
    const { error, value } = schema.validate(dataToValidate, {
      ...defaultOptions,
      context
    });

    if (error) {
      // Log validation errors for security monitoring
      console.log('Joi validation errors:', {
        ip: getClientIP(req),
        url: req.originalUrl,
        method: req.method,
        source,
        errors: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value
        })),
        timestamp: new Date().toISOString()
      });

      // Create standardized validation error
      const validationError = new ValidationError(
        'Validation failed',
        error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value
        }))
      );

      return next(validationError);
    }

    // Replace the original data with validated and sanitized data
    switch (source) {
      case 'query':
        req.query = value;
        break;
      case 'params':
        req.params = value;
        break;
      case 'headers':
        req.headers = { ...req.headers, ...value };
        break;
      case 'body':
      default:
        req.body = value;
        break;
    }

    next();
  };
};

/**
 * Validate request body with Joi schema
 * @param {Object} schema - Joi schema
 * @param {Object} options - Validation options
 * @returns {Function} Express middleware
 */
const validateBody = (schema, options = {}) => {
  return createJoiValidator(schema, 'body', options);
};

/**
 * Validate query parameters with Joi schema
 * @param {Object} schema - Joi schema
 * @param {Object} options - Validation options
 * @returns {Function} Express middleware
 */
const validateQuery = (schema, options = {}) => {
  return createJoiValidator(schema, 'query', options);
};

/**
 * Validate route parameters with Joi schema
 * @param {Object} schema - Joi schema
 * @param {Object} options - Validation options
 * @returns {Function} Express middleware
 */
const validateParams = (schema, options = {}) => {
  return createJoiValidator(schema, 'params', options);
};

/**
 * Validate headers with Joi schema
 * @param {Object} schema - Joi schema
 * @param {Object} options - Validation options
 * @returns {Function} Express middleware
 */
const validateHeaders = (schema, options = {}) => {
  return createJoiValidator(schema, 'headers', options);
};

/**
 * Validate multiple sources with different schemas
 * @param {Object} schemas - Object with schemas for different sources
 * @param {Object} options - Validation options
 * @returns {Function} Express middleware
 */
const validateMultiple = (schemas, options = {}) => {
  return (req, res, next) => {
    const errors = [];
    const context = {
      twoYearsFromNow: new Date(Date.now() + (2 * 365 * 24 * 60 * 60 * 1000)),
      operation: req.body?.operation || req.query?.operation,
      user: req.user,
      isAdmin: req.user && (req.user.role === 'admin' || req.user.role === 'superadmin'),
      isSuperAdmin: req.user && req.user.role === 'superadmin'
    };

    const defaultOptions = {
      abortEarly: false,
      allowUnknown: false,
      stripUnknown: true,
      convert: true,
      context,
      ...options
    };

    // Validate each source
    Object.entries(schemas).forEach(([source, schema]) => {
      let dataToValidate;
      switch (source) {
        case 'query':
          dataToValidate = req.query;
          break;
        case 'params':
          dataToValidate = req.params;
          break;
        case 'headers':
          dataToValidate = req.headers;
          break;
        case 'body':
        default:
          dataToValidate = req.body;
          break;
      }

      const { error, value } = schema.validate(dataToValidate, defaultOptions);

      if (error) {
        errors.push(...error.details.map(detail => ({
          source,
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value
        })));
      } else {
        // Update request with validated data
        switch (source) {
          case 'query':
            req.query = value;
            break;
          case 'params':
            req.params = value;
            break;
          case 'headers':
            req.headers = { ...req.headers, ...value };
            break;
          case 'body':
          default:
            req.body = value;
            break;
        }
      }
    });

    if (errors.length > 0) {
      // Log validation errors
      console.log('Joi multi-source validation errors:', {
        ip: getClientIP(req),
        url: req.originalUrl,
        method: req.method,
        errors,
        timestamp: new Date().toISOString()
      });

      const validationError = new ValidationError('Validation failed', errors);
      return next(validationError);
    }

    next();
  };
};

/**
 * Create conditional validation middleware
 * @param {Function} condition - Function that returns boolean based on request
 * @param {Object} schema - Joi schema to apply if condition is true
 * @param {string} source - Source of data to validate
 * @param {Object} options - Validation options
 * @returns {Function} Express middleware
 */
const validateConditional = (condition, schema, source = 'body', options = {}) => {
  return (req, res, next) => {
    if (condition(req)) {
      return createJoiValidator(schema, source, options)(req, res, next);
    }
    next();
  };
};

/**
 * Sanitize and validate file uploads
 * @param {Object} schema - Joi schema for file validation
 * @param {Object} options - Validation options
 * @returns {Function} Express middleware
 */
const validateFiles = (schema, options = {}) => {
  return (req, res, next) => {
    if (!req.files || Object.keys(req.files).length === 0) {
      return next();
    }

    const { error, value } = schema.validate(req.files, {
      abortEarly: false,
      allowUnknown: false,
      stripUnknown: true,
      ...options
    });

    if (error) {
      console.log('File validation errors:', {
        ip: getClientIP(req),
        url: req.originalUrl,
        method: req.method,
        errors: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message
        })),
        timestamp: new Date().toISOString()
      });

      const validationError = new ValidationError(
        'File validation failed',
        error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message
        }))
      );

      return next(validationError);
    }

    req.files = value;
    next();
  };
};

module.exports = {
  createJoiValidator,
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  validateMultiple,
  validateConditional,
  validateFiles
};
