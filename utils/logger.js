/**
 * Winston Logger Configuration for GamePlan Application
 * Provides structured logging with rotation, filtering, and environment-aware configuration
 */

const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '..', 'logs');
const appLogsDir = path.join(logsDir, 'application');
const errorLogsDir = path.join(logsDir, 'errors');
const debugLogsDir = path.join(logsDir, 'debug');

[logsDir, appLogsDir, errorLogsDir, debugLogsDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Environment configuration
const isDevelopment = process.env.NODE_ENV === 'development';
const logLevel = process.env.LOG_LEVEL || (isDevelopment ? 'debug' : 'info');
const maxSize = process.env.LOG_MAX_SIZE || '100m';
const maxFiles = process.env.LOG_MAX_FILES || '30d';
const datePattern = process.env.LOG_DATE_PATTERN || 'YYYY-MM-DD';
const compress = process.env.LOG_COMPRESS === 'true' || true;

// Sensitive fields to filter from logs
const SENSITIVE_FIELDS = [
  'password', 'newPassword', 'confirmPassword', 'oldPassword',
  'token', 'accessToken', 'refreshToken', 'apiKey', 'secret',
  'authorization', 'cookie', 'session', 'csrf', 'key',
  'privateKey', 'passphrase', 'auth', 'credentials'
];

/**
 * Recursively filter sensitive data from objects
 * @param {any} obj - Object to filter
 * @returns {any} Filtered object
 */
const filterSensitiveData = (obj) => {
  if (obj === null || obj === undefined) return obj;
  
  if (typeof obj === 'string') {
    // Don't log very long strings that might contain sensitive data
    return obj.length > 1000 ? `[TRUNCATED:${obj.length}chars]` : obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(filterSensitiveData);
  }
  
  if (typeof obj === 'object') {
    const filtered = {};
    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      const isSensitive = SENSITIVE_FIELDS.some(field => 
        lowerKey.includes(field.toLowerCase())
      );
      
      if (isSensitive) {
        filtered[key] = '[REDACTED]';
      } else {
        filtered[key] = filterSensitiveData(value);
      }
    }
    return filtered;
  }
  
  return obj;
};

/**
 * Custom format for development (human-readable)
 */
const developmentFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize(),
  winston.format.printf(({ timestamp, level, message, category, requestId, userId, ...meta }) => {
    let logMessage = `${timestamp} [${level}]`;
    
    if (category) logMessage += ` [${category}]`;
    if (requestId) logMessage += ` [${requestId}]`;
    if (userId) logMessage += ` [user:${userId}]`;
    
    logMessage += `: ${message}`;
    
    // Add metadata if present
    const filteredMeta = filterSensitiveData(meta);
    if (Object.keys(filteredMeta).length > 0) {
      logMessage += `\n${JSON.stringify(filteredMeta, null, 2)}`;
    }
    
    return logMessage;
  })
);

/**
 * Custom format for production (JSON)
 */
const productionFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf((info) => {
    // Filter sensitive data from the entire log entry
    const filtered = filterSensitiveData(info);
    return JSON.stringify(filtered);
  })
);

/**
 * Create daily rotate file transport
 */
const createRotateTransport = (filename, dirname, level = null) => {
  return new DailyRotateFile({
    filename: path.join(dirname, `${filename}-%DATE%.log`),
    datePattern,
    maxSize,
    maxFiles,
    compress,
    level,
    format: productionFormat,
    auditFile: path.join(dirname, `.${filename}-audit.json`)
  });
};

// Configure transports
const transports = [];

// Console transport (always enabled in development, optional in production)
if (isDevelopment || process.env.LOG_CONSOLE === 'true') {
  transports.push(
    new winston.transports.Console({
      format: isDevelopment ? developmentFormat : productionFormat,
      level: logLevel
    })
  );
}

// File transports
transports.push(
  // Combined application logs
  createRotateTransport('app', appLogsDir),
  
  // Error-only logs
  createRotateTransport('error', errorLogsDir, 'error')
);

// Debug logs (only in development)
if (isDevelopment) {
  transports.push(
    createRotateTransport('debug', debugLogsDir, 'debug')
  );
}

// Create the main logger
const logger = winston.createLogger({
  level: logLevel,
  format: productionFormat,
  transports,
  exitOnError: false,
  
  // Handle uncaught exceptions and rejections
  exceptionHandlers: [
    new DailyRotateFile({
      filename: path.join(errorLogsDir, 'exceptions-%DATE%.log'),
      datePattern,
      maxSize,
      maxFiles,
      compress
    })
  ],
  
  rejectionHandlers: [
    new DailyRotateFile({
      filename: path.join(errorLogsDir, 'rejections-%DATE%.log'),
      datePattern,
      maxSize,
      maxFiles,
      compress
    })
  ]
});

/**
 * Create a child logger with specific category and context
 * @param {string} category - Log category (e.g., 'auth', 'database', 'admin')
 * @param {Object} defaultMeta - Default metadata to include in all logs
 * @returns {Object} Child logger instance
 */
const createLogger = (category, defaultMeta = {}) => {
  const childLogger = logger.child({ category, ...defaultMeta });
  
  return {
    error: (message, meta = {}) => childLogger.error(message, { ...meta }),
    warn: (message, meta = {}) => childLogger.warn(message, { ...meta }),
    info: (message, meta = {}) => childLogger.info(message, { ...meta }),
    debug: (message, meta = {}) => childLogger.debug(message, { ...meta }),
    
    // Convenience methods for common patterns
    logUserAction: (action, userId, meta = {}) => {
      childLogger.info(`User action: ${action}`, {
        action,
        userId,
        userAction: true,
        ...meta
      });
    },
    
    logAdminAction: (action, adminId, targetId = null, meta = {}) => {
      childLogger.info(`Admin action: ${action}`, {
        action,
        adminId,
        targetId,
        adminAction: true,
        ...meta
      });
    },
    
    logApiRequest: (method, url, statusCode, duration, meta = {}) => {
      const level = statusCode >= 400 ? 'warn' : 'info';
      childLogger[level](`${method} ${url} ${statusCode}`, {
        method,
        url,
        statusCode,
        duration,
        apiRequest: true,
        ...meta
      });
    },
    
    logDatabaseOperation: (operation, collection, duration = null, meta = {}) => {
      childLogger.info(`Database ${operation}: ${collection}`, {
        operation,
        collection,
        duration,
        databaseOperation: true,
        ...meta
      });
    },
    
    logSecurityEvent: (event, severity = 'warn', meta = {}) => {
      childLogger[severity](`Security event: ${event}`, {
        event,
        securityEvent: true,
        ...meta
      });
    }
  };
};

/**
 * Get log file information for admin interface
 * @returns {Object} Log file statistics
 */
const getLogStats = () => {
  const stats = {
    directories: {},
    totalSize: 0,
    totalFiles: 0
  };
  
  const scanDirectory = (dir, name) => {
    if (!fs.existsSync(dir)) return;
    
    const files = fs.readdirSync(dir);
    let dirSize = 0;
    let fileCount = 0;
    
    files.forEach(file => {
      if (file.endsWith('.log') || file.endsWith('.gz')) {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);
        dirSize += stat.size;
        fileCount++;
      }
    });
    
    stats.directories[name] = {
      path: dir,
      size: dirSize,
      files: fileCount,
      sizeFormatted: formatBytes(dirSize)
    };
    
    stats.totalSize += dirSize;
    stats.totalFiles += fileCount;
  };
  
  scanDirectory(appLogsDir, 'application');
  scanDirectory(errorLogsDir, 'errors');
  scanDirectory(debugLogsDir, 'debug');
  
  stats.totalSizeFormatted = formatBytes(stats.totalSize);
  
  return stats;
};

/**
 * Get available log files for a specific date and type
 * @param {string} date - Date in YYYY-MM-DD format
 * @param {string} type - Log type ('app', 'error', 'debug')
 * @returns {Array} Available log files
 */
const getLogFiles = (date = null, type = 'app') => {
  const dirMap = {
    app: appLogsDir,
    error: errorLogsDir,
    debug: debugLogsDir
  };
  
  const dir = dirMap[type];
  if (!dir || !fs.existsSync(dir)) return [];
  
  const files = fs.readdirSync(dir);
  let logFiles = files.filter(file => file.endsWith('.log'));
  
  if (date) {
    logFiles = logFiles.filter(file => file.includes(date));
  }
  
  return logFiles.map(file => ({
    name: file,
    path: path.join(dir, file),
    size: fs.statSync(path.join(dir, file)).size,
    sizeFormatted: formatBytes(fs.statSync(path.join(dir, file)).size),
    modified: fs.statSync(path.join(dir, file)).mtime
  })).sort((a, b) => b.modified - a.modified);
};

/**
 * Format bytes to human readable format
 * @param {number} bytes - Bytes to format
 * @returns {string} Formatted string
 */
const formatBytes = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * Clean up old log files
 * @param {number} daysToKeep - Number of days to keep
 * @returns {Object} Cleanup results
 */
const cleanupOldLogs = (daysToKeep = 30) => {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);
  
  const results = {
    deletedFiles: 0,
    freedSpace: 0,
    errors: []
  };
  
  const cleanDirectory = (dir) => {
    if (!fs.existsSync(dir)) return;
    
    const files = fs.readdirSync(dir);
    files.forEach(file => {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      
      if (stat.mtime < cutoffDate && (file.endsWith('.log') || file.endsWith('.gz'))) {
        try {
          results.freedSpace += stat.size;
          fs.unlinkSync(filePath);
          results.deletedFiles++;
        } catch (error) {
          results.errors.push(`Failed to delete ${file}: ${error.message}`);
        }
      }
    });
  };
  
  cleanDirectory(appLogsDir);
  cleanDirectory(errorLogsDir);
  cleanDirectory(debugLogsDir);
  
  return results;
};

// Export the main logger and utilities
module.exports = {
  logger,
  createLogger,
  getLogStats,
  getLogFiles,
  cleanupOldLogs,
  formatBytes,
  
  // Pre-configured loggers for common categories
  authLogger: createLogger('auth'),
  dbLogger: createLogger('database'),
  adminLogger: createLogger('admin'),
  apiLogger: createLogger('api'),
  systemLogger: createLogger('system'),
  securityLogger: createLogger('security')
};
