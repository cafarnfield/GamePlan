/**
 * Database Configuration for GamePlan
 * Centralized database connection settings and options
 */

/**
 * Get optimized connection options based on environment
 */
const getConnectionOptions = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  const isDevelopment = process.env.NODE_ENV === 'development';

  const baseOptions = {
    // Connection pool settings
    maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || (isProduction ? 20 : 10),
    minPoolSize: parseInt(process.env.DB_MIN_POOL_SIZE) || (isProduction ? 5 : 2),
    maxIdleTimeMS: parseInt(process.env.DB_MAX_IDLE_TIME) || 30000, // 30 seconds
    
    // Connection timeouts
    serverSelectionTimeoutMS: parseInt(process.env.DB_CONNECTION_TIMEOUT) || 30000,
    socketTimeoutMS: parseInt(process.env.DB_SOCKET_TIMEOUT) || 45000, // 45 seconds
    connectTimeoutMS: parseInt(process.env.DB_CONNECTION_TIMEOUT) || 30000,
    
    // Heartbeat and monitoring
    heartbeatFrequencyMS: parseInt(process.env.DB_HEARTBEAT_FREQUENCY) || 10000, // 10 seconds
    
    // Write and read concerns
    writeConcern: {
      w: process.env.DB_WRITE_CONCERN || (isProduction ? 'majority' : 1),
      j: process.env.DB_JOURNAL === 'true' || isProduction, // Journal in production
      wtimeout: parseInt(process.env.DB_WRITE_TIMEOUT) || 10000
    },
    readConcern: {
      level: process.env.DB_READ_CONCERN || (isProduction ? 'majority' : 'local')
    },
    readPreference: process.env.DB_READ_PREFERENCE || 'primary',
    
    // Compression (if supported)
    compressors: process.env.DB_COMPRESSION ? process.env.DB_COMPRESSION.split(',') : ['zlib'],
    
    // Buffer settings
    bufferCommands: process.env.DB_BUFFER_COMMANDS !== 'false',
    
    // Additional options
    autoIndex: isDevelopment, // Only auto-create indexes in development
    autoCreate: isDevelopment, // Only auto-create collections in development
    
    // Monitoring
    monitorCommands: process.env.DB_MONITOR_COMMANDS === 'true' || isDevelopment,
    
    // Family preference for IPv4/IPv6
    family: parseInt(process.env.DB_IP_FAMILY) || 4,
    
    // SSL/TLS settings (if needed)
    ...(process.env.DB_SSL === 'true' && {
      ssl: true,
      sslValidate: process.env.DB_SSL_VALIDATE !== 'false',
      sslCA: process.env.DB_SSL_CA,
      sslCert: process.env.DB_SSL_CERT,
      sslKey: process.env.DB_SSL_KEY
    })
  };

  return baseOptions;
};

/**
 * Database configuration settings
 */
const databaseConfig = {
  // Connection settings
  maxRetryAttempts: parseInt(process.env.DB_MAX_RETRY_ATTEMPTS) || 10,
  retryDelay: parseInt(process.env.DB_RETRY_DELAY) || 5000, // 5 seconds
  maxRetryDelay: parseInt(process.env.DB_MAX_RETRY_DELAY) || 60000, // 60 seconds
  connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT) || 30000, // 30 seconds
  gracefulShutdownTimeout: parseInt(process.env.DB_SHUTDOWN_TIMEOUT) || 10000, // 10 seconds
  
  // Default URI
  defaultUri: process.env.MONGO_URI || 'mongodb://localhost:27017/gameplan',
  
  // Connection options factory
  getConnectionOptions
};

module.exports = {
  databaseConfig,
  getConnectionOptions
};
