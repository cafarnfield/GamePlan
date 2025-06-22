/**
 * Database Middleware for GamePlan Application
 * Provides request-level database handling, connection checks, and safety measures
 */

const { dbManager, getStatus, healthCheck } = require('../utils/database');
const { connectionMonitor } = require('../utils/connectionMonitor');
const { DatabaseError, ExternalServiceError } = require('../utils/errors');

/**
 * Middleware to ensure database connection is available before processing requests
 */
const ensureDatabaseConnection = (options = {}) => {
  const {
    skipHealthCheck = false,
    maxWaitTime = 5000, // 5 seconds
    retryAttempts = 3,
    skipForPaths = ['/api/health', '/api/config-health']
  } = options;

  return async (req, res, next) => {
    // Skip check for certain paths
    if (skipForPaths.some(path => req.path.startsWith(path))) {
      return next();
    }

    try {
      // Quick connection state check
      if (!dbManager.isConnected) {
        console.warn(`⚠️ Database not connected for request: ${req.method} ${req.path}`);
        
        // Try to reconnect if not already connecting
        if (!dbManager.isConnecting) {
          console.log('🔄 Attempting to reconnect database...');
          
          // Wait for connection with timeout
          const connectionPromise = dbManager.connect();
          const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Connection timeout')), maxWaitTime);
          });
          
          try {
            await Promise.race([connectionPromise, timeoutPromise]);
          } catch (error) {
            throw new DatabaseError(`Database connection failed: ${error.message}`);
          }
        } else {
          // Wait for existing connection attempt
          await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
              reject(new Error('Connection timeout while waiting for existing connection'));
            }, maxWaitTime);
            
            dbManager.once('connected', () => {
              clearTimeout(timeout);
              resolve();
            });
            
            dbManager.once('error', (error) => {
              clearTimeout(timeout);
              reject(error);
            });
          });
        }
      }

      // Optional health check
      if (!skipHealthCheck) {
        const health = await healthCheck();
        if (health.status !== 'healthy') {
          console.warn(`⚠️ Database health check failed: ${health.message}`);
          throw new DatabaseError(`Database health check failed: ${health.message}`);
        }
      }

      // Add database status to request object for use in routes
      req.dbStatus = getStatus();
      
      next();
    } catch (error) {
      console.error(`❌ Database middleware error for ${req.method} ${req.path}:`, error.message);
      
      // Handle different types of requests differently
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        // API request - return JSON error
        res.status(503).json({
          error: 'Database temporarily unavailable',
          message: 'Please try again in a moment',
          requestId: req.requestId,
          retryAfter: 30
        });
      } else {
        // Web request - render error page or redirect
        if (req.path.startsWith('/admin')) {
          // Admin routes - show detailed error
          res.status(503).render('error', {
            error: {
              status: 503,
              message: 'Database Connection Error',
              details: process.env.NODE_ENV === 'development' ? error.message : 'Database temporarily unavailable'
            },
            user: req.user,
            isDevelopmentAutoLogin: process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development'
          });
        } else {
          // Regular routes - show generic error
          res.status(503).send(`
            <!DOCTYPE html>
            <html>
            <head>
              <title>Service Temporarily Unavailable</title>
              <style>
                body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                .error { background: #f8f8f8; padding: 30px; border-radius: 10px; max-width: 500px; margin: 0 auto; }
                .error-code { color: #d32f2f; font-size: 48px; font-weight: bold; margin-bottom: 20px; }
                .error-message { font-size: 18px; margin-bottom: 20px; }
                .retry-info { color: #666; margin-top: 20px; }
                .back-link { margin-top: 30px; }
                .back-link a { color: #1976d2; text-decoration: none; }
              </style>
            </head>
            <body>
              <div class="error">
                <div class="error-code">503</div>
                <div class="error-message">Service Temporarily Unavailable</div>
                <p>We're experiencing technical difficulties. Please try again in a moment.</p>
                <div class="retry-info">This page will automatically retry in 30 seconds.</div>
                <div class="back-link">
                  <a href="/">← Back to Home</a>
                </div>
              </div>
              <script>
                setTimeout(() => {
                  window.location.reload();
                }, 30000);
              </script>
            </body>
            </html>
          `);
        }
      }
    }
  };
};

/**
 * Middleware to add database performance monitoring to requests
 */
const addDatabaseMetrics = (req, res, next) => {
  // Add start time for request-level metrics
  req.dbRequestStart = Date.now();
  
  // Override res.end to capture response time
  const originalEnd = res.end;
  res.end = function(...args) {
    const responseTime = Date.now() - req.dbRequestStart;
    
    // Emit metrics event
    connectionMonitor.emit('requestCompleted', {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      responseTime,
      userAgent: req.get('User-Agent'),
      ip: req.ip
    });
    
    // Log slow requests
    const slowRequestThreshold = parseInt(process.env.DB_SLOW_REQUEST_THRESHOLD) || 5000; // 5 seconds
    if (responseTime > slowRequestThreshold) {
      console.warn(`🐌 Slow request detected: ${req.method} ${req.path} took ${responseTime}ms`);
    }
    
    originalEnd.apply(this, args);
  };
  
  next();
};

/**
 * Middleware to handle database transaction safety
 */
const transactionSafety = (options = {}) => {
  const {
    requireTransaction = false,
    isolationLevel = 'readCommitted'
  } = options;

  return async (req, res, next) => {
    if (!dbManager.isConnected) {
      return next(new DatabaseError('Database not connected'));
    }

    // Add transaction helpers to request
    req.db = {
      // Start a new session for transactions
      startSession: async () => {
        const session = await dbManager.connection.startSession();
        req.dbSession = session;
        return session;
      },
      
      // Commit transaction
      commitTransaction: async () => {
        if (req.dbSession) {
          await req.dbSession.commitTransaction();
          await req.dbSession.endSession();
          req.dbSession = null;
        }
      },
      
      // Abort transaction
      abortTransaction: async () => {
        if (req.dbSession) {
          await req.dbSession.abortTransaction();
          await req.dbSession.endSession();
          req.dbSession = null;
        }
      }
    };

    // Auto-cleanup session on response end
    const originalEnd = res.end;
    res.end = function(...args) {
      if (req.dbSession) {
        req.dbSession.endSession().catch(err => {
          console.error('Error ending database session:', err);
        });
      }
      originalEnd.apply(this, args);
    };

    next();
  };
};

/**
 * Middleware to enforce read-only mode during maintenance
 */
const readOnlyMode = (req, res, next) => {
  const isReadOnlyMode = process.env.DB_READ_ONLY_MODE === 'true';
  
  if (!isReadOnlyMode) {
    return next();
  }

  // Allow read operations
  const readOnlyMethods = ['GET', 'HEAD', 'OPTIONS'];
  const readOnlyPaths = ['/api/health', '/api/config-health', '/logout'];
  
  if (readOnlyMethods.includes(req.method) || readOnlyPaths.includes(req.path)) {
    return next();
  }

  // Block write operations
  console.warn(`🚫 Blocked write operation in read-only mode: ${req.method} ${req.path}`);
  
  if (req.xhr || req.headers.accept?.includes('application/json')) {
    res.status(503).json({
      error: 'Read-only mode',
      message: 'System is in maintenance mode. Only read operations are allowed.',
      retryAfter: 300 // 5 minutes
    });
  } else {
    res.status(503).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Maintenance Mode</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
          .maintenance { background: #fff3cd; padding: 30px; border-radius: 10px; max-width: 500px; margin: 0 auto; border: 1px solid #ffeaa7; }
          .maintenance-icon { font-size: 48px; margin-bottom: 20px; }
          .maintenance-message { font-size: 18px; margin-bottom: 20px; }
          .back-link { margin-top: 30px; }
          .back-link a { color: #1976d2; text-decoration: none; }
        </style>
      </head>
      <body>
        <div class="maintenance">
          <div class="maintenance-icon">🔧</div>
          <div class="maintenance-message">System Maintenance</div>
          <p>The system is currently in maintenance mode. Only read operations are allowed.</p>
          <p>Please try again later.</p>
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
 * Middleware to add database connection info to admin routes
 */
const addAdminDatabaseInfo = async (req, res, next) => {
  if (!req.path.startsWith('/admin')) {
    return next();
  }

  try {
    // Add comprehensive database info for admin routes
    req.dbInfo = {
      status: getStatus(),
      monitoring: connectionMonitor.getReport(),
      health: await healthCheck()
    };
  } catch (error) {
    console.error('Error getting database info for admin:', error.message);
    req.dbInfo = {
      status: { error: error.message },
      monitoring: { error: 'Monitoring unavailable' },
      health: { status: 'error', message: error.message }
    };
  }

  next();
};

/**
 * Middleware to handle database connection pooling optimization
 */
const optimizeConnectionPool = (req, res, next) => {
  // Add connection pool optimization hints based on request type
  const isLongRunningOperation = req.path.includes('/admin/') && 
    ['POST', 'PUT', 'DELETE'].includes(req.method);
  
  const isReportGeneration = req.path.includes('/export') || 
    req.path.includes('/report');
  
  if (isLongRunningOperation || isReportGeneration) {
    // Hint that this might be a long-running operation
    req.dbHints = {
      longRunning: true,
      priority: 'low',
      timeout: 60000 // 60 seconds
    };
  } else {
    // Regular operation
    req.dbHints = {
      longRunning: false,
      priority: 'normal',
      timeout: 30000 // 30 seconds
    };
  }

  next();
};

/**
 * Error handler specifically for database-related errors
 */
const handleDatabaseErrors = (error, req, res, next) => {
  // Only handle database-related errors
  if (!(error instanceof DatabaseError) && 
      !error.message?.includes('mongo') && 
      !error.message?.includes('database')) {
    return next(error);
  }

  console.error(`💾 Database error on ${req.method} ${req.path}:`, error.message);

  // Log to monitoring system
  connectionMonitor.emit('databaseError', {
    error: error.message,
    path: req.path,
    method: req.method,
    timestamp: new Date()
  });

  // Determine response based on error type and request
  const statusCode = error.statusCode || 500;
  
  if (req.xhr || req.headers.accept?.includes('application/json')) {
    res.status(statusCode).json({
      error: 'Database error',
      message: process.env.NODE_ENV === 'development' 
        ? error.message 
        : 'A database error occurred',
      requestId: req.requestId,
      timestamp: new Date().toISOString()
    });
  } else {
    res.status(statusCode).render('error', {
      error: {
        status: statusCode,
        message: 'Database Error',
        details: process.env.NODE_ENV === 'development' ? error.message : null
      },
      user: req.user,
      isDevelopmentAutoLogin: process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development'
    });
  }
};

module.exports = {
  ensureDatabaseConnection,
  addDatabaseMetrics,
  transactionSafety,
  readOnlyMode,
  addAdminDatabaseInfo,
  optimizeConnectionPool,
  handleDatabaseErrors
};
