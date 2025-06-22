/**
 * Request Logging Middleware for GamePlan Application
 * Logs HTTP requests with structured data and performance metrics
 */

const { apiLogger } = require('../utils/logger');

/**
 * Request logging middleware
 * Logs all HTTP requests with timing, user context, and response details
 */
const requestLogger = (req, res, next) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';
  
  // Capture original end function
  const originalEnd = res.end;
  
  // Override res.end to capture response details
  res.end = function(chunk, encoding) {
    const duration = Date.now() - startTime;
    const statusCode = res.statusCode;
    
    // Determine log level based on status code
    let logLevel = 'info';
    if (statusCode >= 500) {
      logLevel = 'error';
    } else if (statusCode >= 400) {
      logLevel = 'warn';
    }
    
    // Skip logging for certain paths to reduce noise
    const skipPaths = [
      '/favicon.ico',
      '/robots.txt',
      '/health',
      '/api/health'
    ];
    
    const shouldSkip = skipPaths.some(path => req.path === path) ||
                      req.path.startsWith('/public/') ||
                      req.path.startsWith('/css/') ||
                      req.path.startsWith('/js/') ||
                      req.path.startsWith('/images/');
    
    if (!shouldSkip) {
      const logData = {
        method: req.method,
        url: req.originalUrl,
        path: req.path,
        statusCode,
        duration,
        requestId,
        ip: req.ip || req.connection?.remoteAddress,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        contentLength: res.get('Content-Length'),
        responseTime: `${duration}ms`
      };
      
      // Add user context if available
      if (req.user) {
        logData.userId = req.user._id;
        logData.userEmail = req.user.email;
        logData.isAdmin = req.user.isAdmin;
        logData.authenticated = true;
      } else {
        logData.authenticated = false;
      }
      
      // Add query parameters if present (filtered for sensitive data)
      if (Object.keys(req.query).length > 0) {
        logData.query = req.query;
      }
      
      // Log the request
      apiLogger[logLevel](`${req.method} ${req.originalUrl} ${statusCode}`, logData);
      
      // Log slow requests as warnings
      if (duration > 5000) { // 5 seconds
        apiLogger.warn(`Slow request detected: ${req.method} ${req.originalUrl}`, {
          ...logData,
          slowRequest: true,
          threshold: '5000ms'
        });
      }
    }
    
    // Call original end function
    originalEnd.call(this, chunk, encoding);
  };
  
  next();
};

/**
 * Enhanced request logger for API endpoints
 * Includes request body logging (with sensitive data filtering)
 */
const apiRequestLogger = (req, res, next) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';
  
  // Log incoming API request
  const requestData = {
    method: req.method,
    url: req.originalUrl,
    requestId,
    ip: req.ip || req.connection?.remoteAddress,
    userAgent: req.get('User-Agent'),
    contentType: req.get('Content-Type'),
    contentLength: req.get('Content-Length')
  };
  
  // Add user context
  if (req.user) {
    requestData.userId = req.user._id;
    requestData.userEmail = req.user.email;
    requestData.authenticated = true;
  }
  
  // Add request body for POST/PUT/PATCH (will be filtered by logger)
  if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
    requestData.requestBody = req.body;
  }
  
  // Add query parameters
  if (Object.keys(req.query).length > 0) {
    requestData.query = req.query;
  }
  
  apiLogger.info(`API Request: ${req.method} ${req.originalUrl}`, requestData);
  
  // Capture response
  const originalJson = res.json;
  const originalSend = res.send;
  
  res.json = function(data) {
    const duration = Date.now() - startTime;
    
    apiLogger.info(`API Response: ${req.method} ${req.originalUrl} ${res.statusCode}`, {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration,
      requestId,
      responseType: 'json',
      responseSize: JSON.stringify(data).length
    });
    
    return originalJson.call(this, data);
  };
  
  res.send = function(data) {
    const duration = Date.now() - startTime;
    
    apiLogger.info(`API Response: ${req.method} ${req.originalUrl} ${res.statusCode}`, {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration,
      requestId,
      responseType: 'text',
      responseSize: typeof data === 'string' ? data.length : 0
    });
    
    return originalSend.call(this, data);
  };
  
  next();
};

/**
 * Security event logger middleware
 * Logs security-related events like failed logins, rate limiting, etc.
 */
const securityLogger = (eventType, severity = 'warn') => {
  return (req, res, next) => {
    const { securityLogger: logger } = require('../utils/logger');
    
    const securityData = {
      eventType,
      ip: req.ip || req.connection?.remoteAddress,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
      timestamp: new Date().toISOString()
    };
    
    // Add user context if available
    if (req.user) {
      securityData.userId = req.user._id;
      securityData.userEmail = req.user.email;
    }
    
    // Add specific data based on event type
    switch (eventType) {
      case 'RATE_LIMIT_EXCEEDED':
        securityData.rateLimitInfo = {
          limit: req.rateLimit?.limit,
          remaining: req.rateLimit?.remaining,
          resetTime: req.rateLimit?.resetTime
        };
        break;
      case 'FAILED_LOGIN':
        securityData.attemptedEmail = req.body?.email;
        break;
      case 'UNAUTHORIZED_ACCESS':
        securityData.requiredRole = req.requiredRole;
        break;
    }
    
    logger.logSecurityEvent(eventType, severity, securityData);
    next();
  };
};

module.exports = {
  requestLogger,
  apiRequestLogger,
  securityLogger
};
