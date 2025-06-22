const { validationResult } = require('express-validator');
const { ValidationError } = require('../utils/errors');
const { ErrorFactory } = require('../utils/errorUtils');

/**
 * Middleware to handle validation errors
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    // Log validation errors for security monitoring
    console.log('Validation errors:', {
      ip: getClientIP(req),
      url: req.originalUrl,
      method: req.method,
      errors: errors.array(),
      timestamp: new Date().toISOString()
    });
    
    // Create standardized validation error and pass to centralized handler
    const validationError = ErrorFactory.fromValidationResult(errors);
    return next(validationError);
  }
  
  next();
};

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
 * Sanitize HTML content to prevent XSS attacks
 * @param {string} input - Input string to sanitize
 * @returns {string} Sanitized string
 */
const sanitizeHtml = (input) => {
  if (typeof input !== 'string') return input;
  
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

/**
 * Custom validator to check for potential XSS patterns
 * @param {string} value - Value to check
 * @returns {boolean} True if safe, throws error if dangerous
 */
const checkXSS = (value) => {
  if (typeof value !== 'string') return true;
  
  const xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe/gi,
    /<object/gi,
    /<embed/gi,
    /<link/gi,
    /<meta/gi,
    /expression\s*\(/gi,
    /vbscript:/gi,
    /data:text\/html/gi
  ];
  
  for (const pattern of xssPatterns) {
    if (pattern.test(value)) {
      throw new Error('Potentially dangerous content detected');
    }
  }
  
  return true;
};

/**
 * Custom validator for strong passwords
 * @param {string} value - Password to validate
 * @returns {boolean} True if valid, throws error if invalid
 */
const validateStrongPassword = (value) => {
  if (typeof value !== 'string') {
    throw new Error('Password must be a string');
  }
  
  if (value.length < 8) {
    throw new Error('Password must be at least 8 characters long');
  }
  
  if (!/(?=.*[a-z])/.test(value)) {
    throw new Error('Password must contain at least one lowercase letter');
  }
  
  if (!/(?=.*[A-Z])/.test(value)) {
    throw new Error('Password must contain at least one uppercase letter');
  }
  
  if (!/(?=.*\d)/.test(value)) {
    throw new Error('Password must contain at least one number');
  }
  
  if (!/(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/.test(value)) {
    throw new Error('Password must contain at least one special character');
  }
  
  return true;
};

/**
 * Custom validator for future dates
 * @param {string} value - Date string to validate
 * @returns {boolean} True if valid, throws error if invalid
 */
const validateFutureDate = (value) => {
  const date = new Date(value);
  const now = new Date();
  
  if (isNaN(date.getTime())) {
    throw new Error('Invalid date format');
  }
  
  // Add 30-minute buffer to prevent events scheduled too close to now
  const minimumTime = new Date(now.getTime() + (30 * 60 * 1000)); // 30 minutes from now
  
  if (date <= minimumTime) {
    const bufferMinutes = Math.ceil((minimumTime - now) / (60 * 1000));
    throw new Error(`Event date must be at least ${bufferMinutes} minutes in the future`);
  }
  
  // Check if date is not too far in the future (e.g., 2 years)
  const twoYearsFromNow = new Date();
  twoYearsFromNow.setFullYear(twoYearsFromNow.getFullYear() + 2);
  
  if (date > twoYearsFromNow) {
    throw new Error('Date cannot be more than 2 years in the future');
  }
  
  return true;
};

/**
 * Custom validator for game nicknames
 * @param {string} value - Game nickname to validate
 * @returns {boolean} True if valid, throws error if invalid
 */
const validateGameNickname = (value) => {
  if (!value) return true; // Optional field
  
  if (typeof value !== 'string') {
    throw new Error('Game nickname must be a string');
  }
  
  if (value.length > 50) {
    throw new Error('Game nickname cannot be longer than 50 characters');
  }
  
  // Allow alphanumeric, spaces, hyphens, underscores
  if (!/^[a-zA-Z0-9\s\-_]+$/.test(value)) {
    throw new Error('Game nickname can only contain letters, numbers, spaces, hyphens, and underscores');
  }
  
  return true;
};

module.exports = {
  handleValidationErrors,
  sanitizeHtml,
  checkXSS,
  validateStrongPassword,
  validateFutureDate,
  validateGameNickname,
  getClientIP
};
