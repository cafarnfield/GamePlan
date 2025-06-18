/**
 * Enhanced MongoDB Connection Manager for GamePlan
 * Provides robust connection handling with retry logic, pooling, and graceful shutdown
 */

const mongoose = require('mongoose');
const EventEmitter = require('events');

class DatabaseManager extends EventEmitter {
  constructor() {
    super();
    this.isConnected = false;
    this.isConnecting = false;
    this.connectionAttempts = 0;
    this.maxRetryAttempts = parseInt(process.env.DB_MAX_RETRY_ATTEMPTS) || 10;
    this.retryDelay = parseInt(process.env.DB_RETRY_DELAY) || 5000; // 5 seconds
    this.maxRetryDelay = parseInt(process.env.DB_MAX_RETRY_DELAY) || 60000; // 60 seconds
    this.connectionTimeout = parseInt(process.env.DB_CONNECTION_TIMEOUT) || 30000; // 30 seconds
    this.gracefulShutdownTimeout = parseInt(process.env.DB_SHUTDOWN_TIMEOUT) || 10000; // 10 seconds
    
    // Connection state tracking
    this.connectionState = 'disconnected';
    this.lastConnectionAttempt = null;
    this.lastSuccessfulConnection = null;
    this.connectionErrors = [];
    this.metrics = {
      totalConnections: 0,
      failedConnections: 0,
      reconnections: 0,
      totalQueries: 0,
      avgResponseTime: 0
    };

    // Bind event handlers
    this.setupEventHandlers();
    
    // Setup graceful shutdown handlers
    this.setupGracefulShutdown();
  }

  /**
   * Get optimized connection options based on environment
   */
  getConnectionOptions() {
    const isProduction = process.env.NODE_ENV === 'production';
    const isDevelopment = process.env.NODE_ENV === 'development';

    const baseOptions = {
      // Connection pool settings
      maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || (isProduction ? 20 : 10),
      minPoolSize: parseInt(process.env.DB_MIN_POOL_SIZE) || (isProduction ? 5 : 2),
      maxIdleTimeMS: parseInt(process.env.DB_MAX_IDLE_TIME) || 30000, // 30 seconds
      
      // Connection timeouts
      serverSelectionTimeoutMS: this.connectionTimeout,
      socketTimeoutMS: parseInt(process.env.DB_SOCKET_TIMEOUT) || 45000, // 45 seconds
      connectTimeoutMS: this.connectionTimeout,
      
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
  }

  /**
   * Setup mongoose event handlers for connection monitoring
   */
  setupEventHandlers() {
    // Connection events
    mongoose.connection.on('connecting', () => {
      this.connectionState = 'connecting';
      this.isConnecting = true;
      console.log('📡 MongoDB: Connecting...');
      this.emit('connecting');
    });

    mongoose.connection.on('connected', () => {
      this.connectionState = 'connected';
      this.isConnected = true;
      this.isConnecting = false;
      this.connectionAttempts = 0;
      this.lastSuccessfulConnection = new Date();
      this.metrics.totalConnections++;
      
      console.log('✅ MongoDB: Connected successfully');
      console.log(`📊 Connection pool: ${mongoose.connection.db?.serverConfig?.s?.poolSize || 'N/A'} connections`);
      this.emit('connected');
    });

    mongoose.connection.on('open', () => {
      console.log('🔓 MongoDB: Connection opened');
      this.emit('open');
    });

    mongoose.connection.on('disconnecting', () => {
      this.connectionState = 'disconnecting';
      console.log('📡 MongoDB: Disconnecting...');
      this.emit('disconnecting');
    });

    mongoose.connection.on('disconnected', () => {
      this.connectionState = 'disconnected';
      this.isConnected = false;
      this.isConnecting = false;
      
      console.log('❌ MongoDB: Disconnected');
      this.emit('disconnected');
      
      // Attempt reconnection if not intentionally disconnected
      if (!this.isShuttingDown) {
        this.scheduleReconnection();
      }
    });

    mongoose.connection.on('close', () => {
      this.connectionState = 'closed';
      console.log('🔒 MongoDB: Connection closed');
      this.emit('close');
    });

    mongoose.connection.on('error', (error) => {
      this.connectionState = 'error';
      this.isConnecting = false;
      this.metrics.failedConnections++;
      
      // Store error for analysis
      this.connectionErrors.push({
        error: error.message,
        timestamp: new Date(),
        attempt: this.connectionAttempts
      });
      
      // Keep only last 10 errors
      if (this.connectionErrors.length > 10) {
        this.connectionErrors = this.connectionErrors.slice(-10);
      }
      
      console.error('❌ MongoDB connection error:', error.message);
      this.emit('error', error);
      
      // Schedule reconnection on error
      if (!this.isShuttingDown) {
        this.scheduleReconnection();
      }
    });

    mongoose.connection.on('reconnected', () => {
      this.connectionState = 'connected';
      this.isConnected = true;
      this.metrics.reconnections++;
      
      console.log('🔄 MongoDB: Reconnected successfully');
      this.emit('reconnected');
    });

    // Command monitoring for performance metrics
    if (process.env.DB_MONITOR_COMMANDS === 'true' || process.env.NODE_ENV === 'development') {
      mongoose.connection.on('commandStarted', (event) => {
        this.emit('commandStarted', event);
      });

      mongoose.connection.on('commandSucceeded', (event) => {
        this.metrics.totalQueries++;
        this.emit('commandSucceeded', event);
      });

      mongoose.connection.on('commandFailed', (event) => {
        this.emit('commandFailed', event);
      });
    }
  }

  /**
   * Connect to MongoDB with retry logic
   */
  async connect(mongoUri = null) {
    if (this.isConnected) {
      console.log('📡 MongoDB: Already connected');
      return mongoose.connection;
    }

    if (this.isConnecting) {
      console.log('📡 MongoDB: Connection already in progress');
      return new Promise((resolve, reject) => {
        this.once('connected', () => resolve(mongoose.connection));
        this.once('error', reject);
      });
    }

    const uri = mongoUri || process.env.MONGO_URI || 'mongodb://localhost:27017/gameplan';
    const options = this.getConnectionOptions();

    this.connectionAttempts++;
    this.lastConnectionAttempt = new Date();

    try {
      console.log(`📡 MongoDB: Attempting connection (attempt ${this.connectionAttempts}/${this.maxRetryAttempts})`);
      console.log(`🔧 Connection options: Pool size ${options.maxPoolSize}, Timeout ${options.serverSelectionTimeoutMS}ms`);
      
      await mongoose.connect(uri, options);
      return mongoose.connection;
    } catch (error) {
      console.error(`❌ MongoDB connection failed (attempt ${this.connectionAttempts}):`, error.message);
      
      if (this.connectionAttempts >= this.maxRetryAttempts) {
        const finalError = new Error(`Failed to connect to MongoDB after ${this.maxRetryAttempts} attempts. Last error: ${error.message}`);
        finalError.originalError = error;
        finalError.attempts = this.connectionAttempts;
        throw finalError;
      }
      
      // Schedule retry with exponential backoff
      await this.scheduleReconnection();
      return this.connect(mongoUri);
    }
  }

  /**
   * Schedule reconnection with exponential backoff and jitter
   */
  async scheduleReconnection() {
    if (this.isShuttingDown || this.connectionAttempts >= this.maxRetryAttempts) {
      return;
    }

    // Exponential backoff with jitter
    const baseDelay = Math.min(this.retryDelay * Math.pow(2, this.connectionAttempts - 1), this.maxRetryDelay);
    const jitter = Math.random() * 1000; // Add up to 1 second of jitter
    const delay = baseDelay + jitter;

    console.log(`⏰ MongoDB: Scheduling reconnection in ${Math.round(delay)}ms (attempt ${this.connectionAttempts + 1}/${this.maxRetryAttempts})`);
    
    return new Promise((resolve) => {
      setTimeout(() => {
        if (!this.isShuttingDown) {
          this.connect().then(resolve).catch(() => resolve());
        } else {
          resolve();
        }
      }, delay);
    });
  }

  /**
   * Gracefully disconnect from MongoDB
   */
  async disconnect() {
    if (!this.isConnected && !this.isConnecting) {
      console.log('📡 MongoDB: Already disconnected');
      return;
    }

    console.log('📡 MongoDB: Initiating graceful disconnect...');
    
    try {
      // Close the connection
      await mongoose.connection.close();
      console.log('✅ MongoDB: Gracefully disconnected');
    } catch (error) {
      console.error('❌ MongoDB: Error during disconnect:', error.message);
      throw error;
    }
  }

  /**
   * Setup graceful shutdown handlers
   */
  setupGracefulShutdown() {
    const gracefulShutdown = async (signal) => {
      console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);
      this.isShuttingDown = true;

      try {
        // Set a timeout for graceful shutdown
        const shutdownTimeout = setTimeout(() => {
          console.error('⚠️ Graceful shutdown timeout reached. Forcing exit...');
          process.exit(1);
        }, this.gracefulShutdownTimeout);

        // Wait for ongoing operations to complete
        if (this.isConnected) {
          console.log('📡 MongoDB: Waiting for ongoing operations to complete...');
          
          // Close the connection gracefully
          await this.disconnect();
        }

        clearTimeout(shutdownTimeout);
        console.log('✅ Graceful shutdown completed');
        process.exit(0);
      } catch (error) {
        console.error('❌ Error during graceful shutdown:', error.message);
        process.exit(1);
      }
    };

    // Handle different shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGUSR2', () => gracefulShutdown('SIGUSR2')); // Nodemon restart

    // Handle uncaught exceptions and unhandled rejections
    process.on('uncaughtException', (error) => {
      console.error('💥 Uncaught Exception:', error);
      gracefulShutdown('UNCAUGHT_EXCEPTION');
    });

    process.on('unhandledRejection', (reason, promise) => {
      console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
      gracefulShutdown('UNHANDLED_REJECTION');
    });
  }

  /**
   * Get current connection status and metrics
   */
  getStatus() {
    return {
      isConnected: this.isConnected,
      isConnecting: this.isConnecting,
      connectionState: this.connectionState,
      connectionAttempts: this.connectionAttempts,
      lastConnectionAttempt: this.lastConnectionAttempt,
      lastSuccessfulConnection: this.lastSuccessfulConnection,
      readyState: mongoose.connection.readyState,
      readyStateText: this.getReadyStateText(mongoose.connection.readyState),
      host: mongoose.connection.host,
      port: mongoose.connection.port,
      name: mongoose.connection.name,
      metrics: { ...this.metrics },
      recentErrors: this.connectionErrors.slice(-5), // Last 5 errors
      poolSize: mongoose.connection.db?.serverConfig?.s?.poolSize || 0,
      config: {
        maxRetryAttempts: this.maxRetryAttempts,
        retryDelay: this.retryDelay,
        maxRetryDelay: this.maxRetryDelay,
        connectionTimeout: this.connectionTimeout
      }
    };
  }

  /**
   * Get human-readable ready state text
   */
  getReadyStateText(state) {
    const states = {
      0: 'disconnected',
      1: 'connected',
      2: 'connecting',
      3: 'disconnecting'
    };
    return states[state] || 'unknown';
  }

  /**
   * Health check for the database connection
   */
  async healthCheck() {
    try {
      if (!this.isConnected) {
        return {
          status: 'unhealthy',
          message: 'Database not connected',
          details: this.getStatus()
        };
      }

      // Perform a simple ping operation
      const startTime = Date.now();
      await mongoose.connection.db.admin().ping();
      const responseTime = Date.now() - startTime;

      return {
        status: 'healthy',
        message: 'Database connection is healthy',
        responseTime: `${responseTime}ms`,
        details: this.getStatus()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        message: `Database health check failed: ${error.message}`,
        error: error.message,
        details: this.getStatus()
      };
    }
  }

  /**
   * Force reconnection (useful for admin operations)
   */
  async forceReconnect() {
    console.log('🔄 MongoDB: Forcing reconnection...');
    
    try {
      if (this.isConnected) {
        await this.disconnect();
      }
      
      // Reset connection attempts for forced reconnection
      this.connectionAttempts = 0;
      return await this.connect();
    } catch (error) {
      console.error('❌ MongoDB: Force reconnection failed:', error.message);
      throw error;
    }
  }
}

// Create singleton instance
const dbManager = new DatabaseManager();

// Export both the manager instance and convenience functions
module.exports = {
  dbManager,
  connect: (uri) => dbManager.connect(uri),
  disconnect: () => dbManager.disconnect(),
  getStatus: () => dbManager.getStatus(),
  healthCheck: () => dbManager.healthCheck(),
  forceReconnect: () => dbManager.forceReconnect(),
  
  // Event emitter methods
  on: (event, listener) => dbManager.on(event, listener),
  once: (event, listener) => dbManager.once(event, listener),
  off: (event, listener) => dbManager.off(event, listener),
  
  // Mongoose connection reference
  get connection() {
    return mongoose.connection;
  },
  
  // Connection state getters
  get isConnected() {
    return dbManager.isConnected;
  },
  
  get isConnecting() {
    return dbManager.isConnecting;
  }
};
