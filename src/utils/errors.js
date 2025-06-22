/**
 * Custom Error Classes for GamePlan Application
 * Provides standardized error types with consistent structure
 */

/**
 * Base Application Error class
 * All custom errors should extend this class
 */
class AppError extends Error {
  constructor(message, statusCode = 500, errorCode = 'INTERNAL_ERROR', details = null) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.isOperational = true; // Distinguishes operational errors from programming errors
    this.timestamp = new Date().toISOString();
    
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON() {
    return {
      type: this.name,
      message: this.message,
      code: this.errorCode,
      statusCode: this.statusCode,
      details: this.details,
      timestamp: this.timestamp
    };
  }
}

/**
 * Validation Error - 400 Bad Request
 * Used for input validation failures
 */
class ValidationError extends AppError {
  constructor(message = 'Validation failed', details = null) {
    super(message, 400, 'VALIDATION_FAILED', details);
  }
}

/**
 * Authentication Error - 401 Unauthorized
 * Used for authentication failures
 */
class AuthenticationError extends AppError {
  constructor(message = 'Authentication required') {
    super(message, 401, 'AUTHENTICATION_REQUIRED');
  }
}

/**
 * Authorization Error - 403 Forbidden
 * Used for permission/authorization failures
 */
class AuthorizationError extends AppError {
  constructor(message = 'Access denied') {
    super(message, 403, 'ACCESS_DENIED');
  }
}

/**
 * Not Found Error - 404 Not Found
 * Used when requested resources don't exist
 */
class NotFoundError extends AppError {
  constructor(resource = 'Resource', id = null) {
    const message = id ? `${resource} with ID '${id}' not found` : `${resource} not found`;
    super(message, 404, 'RESOURCE_NOT_FOUND', { resource, id });
  }
}

/**
 * Conflict Error - 409 Conflict
 * Used for business logic conflicts (e.g., duplicate entries)
 */
class ConflictError extends AppError {
  constructor(message = 'Resource conflict', details = null) {
    super(message, 409, 'RESOURCE_CONFLICT', details);
  }
}

/**
 * Rate Limit Error - 429 Too Many Requests
 * Used when rate limits are exceeded
 */
class RateLimitError extends AppError {
  constructor(message = 'Too many requests', retryAfter = null) {
    super(message, 429, 'RATE_LIMIT_EXCEEDED', { retryAfter });
    this.retryAfter = retryAfter;
  }
}

/**
 * Database Error - 500 Internal Server Error
 * Used for database operation failures
 */
class DatabaseError extends AppError {
  constructor(message = 'Database operation failed', operation = null) {
    super(message, 500, 'DATABASE_ERROR', { operation });
  }
}

/**
 * External Service Error - 502 Bad Gateway
 * Used for external API failures (Steam, RAWG, etc.)
 */
class ExternalServiceError extends AppError {
  constructor(service = 'External service', message = 'External service unavailable') {
    super(message, 502, 'EXTERNAL_SERVICE_ERROR', { service });
  }
}

/**
 * Account Status Error - 403 Forbidden
 * Used for account-specific issues (blocked, pending, etc.)
 */
class AccountStatusError extends AppError {
  constructor(status, message = null) {
    const defaultMessages = {
      pending: 'Your account is pending admin approval',
      rejected: 'Your account has been rejected',
      blocked: 'Your account has been blocked'
    };
    
    const errorMessage = message || defaultMessages[status] || 'Account access restricted';
    super(errorMessage, 403, 'ACCOUNT_STATUS_ERROR', { status });
  }
}

/**
 * File Upload Error - 400 Bad Request
 * Used for file upload related issues
 */
class FileUploadError extends AppError {
  constructor(message = 'File upload failed', details = null) {
    super(message, 400, 'FILE_UPLOAD_ERROR', details);
  }
}

/**
 * Session Error - 401 Unauthorized
 * Used for session-related issues
 */
class SessionError extends AppError {
  constructor(message = 'Session expired or invalid') {
    super(message, 401, 'SESSION_ERROR');
  }
}

/**
 * Configuration Error - 500 Internal Server Error
 * Used for server configuration issues
 */
class ConfigurationError extends AppError {
  constructor(message = 'Server configuration error') {
    super(message, 500, 'CONFIGURATION_ERROR');
  }
}

/**
 * Business Logic Error - 422 Unprocessable Entity
 * Used for business rule violations
 */
class BusinessLogicError extends AppError {
  constructor(message = 'Business rule violation', rule = null) {
    super(message, 422, 'BUSINESS_LOGIC_ERROR', { rule });
  }
}

module.exports = {
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  DatabaseError,
  ExternalServiceError,
  AccountStatusError,
  FileUploadError,
  SessionError,
  ConfigurationError,
  BusinessLogicError
};
