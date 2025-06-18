/**
 * MongoDB Connection Monitoring and Performance Tracking
 * Provides detailed monitoring, metrics collection, and alerting for database connections
 */

const EventEmitter = require('events');
const { dbManager } = require('./database');

class ConnectionMonitor extends EventEmitter {
  constructor() {
    super();
    this.metrics = {
      // Connection metrics
      connectionUptime: 0,
      totalConnections: 0,
      failedConnections: 0,
      reconnections: 0,
      
      // Performance metrics
      queryCount: 0,
      slowQueries: 0,
      avgQueryTime: 0,
      maxQueryTime: 0,
      minQueryTime: Infinity,
      
      // Error tracking
      errorCount: 0,
      errorRate: 0,
      lastError: null,
      
      // Pool metrics
      activeConnections: 0,
      availableConnections: 0,
      poolUtilization: 0,
      
      // Health metrics
      lastHealthCheck: null,
      healthCheckCount: 0,
      healthCheckFailures: 0
    };
    
    this.queryTimes = [];
    this.maxQueryHistorySize = 1000;
    this.slowQueryThreshold = parseInt(process.env.DB_SLOW_QUERY_THRESHOLD) || 1000; // 1 second
    this.healthCheckInterval = parseInt(process.env.DB_HEALTH_CHECK_INTERVAL) || 30000; // 30 seconds
    this.metricsRetentionPeriod = parseInt(process.env.DB_METRICS_RETENTION) || 86400000; // 24 hours
    
    this.connectionStartTime = null;
    this.healthCheckTimer = null;
    this.isMonitoring = false;
    
    this.setupEventListeners();
  }

  /**
   * Setup event listeners for database events
   */
  setupEventListeners() {
    // Connection events
    dbManager.on('connected', () => {
      this.connectionStartTime = new Date();
      this.metrics.totalConnections++;
      this.emit('connectionEstablished');
      console.log('📊 Connection Monitor: Started monitoring database connection');
    });

    dbManager.on('disconnected', () => {
      if (this.connectionStartTime) {
        this.metrics.connectionUptime += Date.now() - this.connectionStartTime.getTime();
        this.connectionStartTime = null;
      }
      this.emit('connectionLost');
      console.log('📊 Connection Monitor: Connection lost');
    });

    dbManager.on('reconnected', () => {
      this.connectionStartTime = new Date();
      this.metrics.reconnections++;
      this.emit('connectionReestablished');
      console.log('📊 Connection Monitor: Connection reestablished');
    });

    dbManager.on('error', (error) => {
      this.metrics.errorCount++;
      this.metrics.lastError = {
        message: error.message,
        timestamp: new Date(),
        type: error.constructor.name
      };
      this.emit('connectionError', error);
    });

    // Command monitoring
    dbManager.on('commandStarted', (event) => {
      event.startTime = Date.now();
    });

    dbManager.on('commandSucceeded', (event) => {
      this.recordQueryMetrics(event);
    });

    dbManager.on('commandFailed', (event) => {
      this.metrics.errorCount++;
      this.recordQueryMetrics(event, true);
    });
  }

  /**
   * Record query performance metrics
   */
  recordQueryMetrics(event, failed = false) {
    if (!event.startTime) return;

    const duration = Date.now() - event.startTime;
    this.metrics.queryCount++;
    
    // Track query times
    this.queryTimes.push({
      duration,
      command: event.commandName,
      timestamp: new Date(),
      failed
    });
    
    // Maintain query history size
    if (this.queryTimes.length > this.maxQueryHistorySize) {
      this.queryTimes = this.queryTimes.slice(-this.maxQueryHistorySize);
    }
    
    // Update performance metrics
    this.updatePerformanceMetrics(duration);
    
    // Check for slow queries
    if (duration > this.slowQueryThreshold) {
      this.metrics.slowQueries++;
      this.emit('slowQuery', {
        command: event.commandName,
        duration,
        threshold: this.slowQueryThreshold,
        details: event
      });
      console.warn(`🐌 Slow query detected: ${event.commandName} took ${duration}ms`);
    }
  }

  /**
   * Update performance metrics with new query duration
   */
  updatePerformanceMetrics(duration) {
    // Update min/max
    this.metrics.maxQueryTime = Math.max(this.metrics.maxQueryTime, duration);
    this.metrics.minQueryTime = Math.min(this.metrics.minQueryTime, duration);
    
    // Calculate average (simple moving average)
    const totalQueries = this.metrics.queryCount;
    this.metrics.avgQueryTime = ((this.metrics.avgQueryTime * (totalQueries - 1)) + duration) / totalQueries;
  }

  /**
   * Start monitoring with periodic health checks
   */
  startMonitoring() {
    if (this.isMonitoring) {
      console.log('📊 Connection Monitor: Already monitoring');
      return;
    }

    this.isMonitoring = true;
    console.log('📊 Connection Monitor: Starting periodic monitoring');
    
    // Start periodic health checks
    this.healthCheckTimer = setInterval(() => {
      this.performHealthCheck();
    }, this.healthCheckInterval);
    
    // Initial health check
    this.performHealthCheck();
    
    this.emit('monitoringStarted');
  }

  /**
   * Stop monitoring
   */
  stopMonitoring() {
    if (!this.isMonitoring) {
      return;
    }

    this.isMonitoring = false;
    
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
    
    console.log('📊 Connection Monitor: Stopped monitoring');
    this.emit('monitoringStopped');
  }

  /**
   * Perform health check and update metrics
   */
  async performHealthCheck() {
    try {
      this.metrics.healthCheckCount++;
      const healthResult = await dbManager.healthCheck();
      
      this.metrics.lastHealthCheck = {
        timestamp: new Date(),
        status: healthResult.status,
        responseTime: healthResult.responseTime
      };
      
      // Update pool metrics if available
      this.updatePoolMetrics();
      
      // Calculate error rate
      this.calculateErrorRate();
      
      this.emit('healthCheckCompleted', healthResult);
      
      if (healthResult.status !== 'healthy') {
        this.metrics.healthCheckFailures++;
        this.emit('healthCheckFailed', healthResult);
      }
    } catch (error) {
      this.metrics.healthCheckFailures++;
      this.metrics.lastHealthCheck = {
        timestamp: new Date(),
        status: 'error',
        error: error.message
      };
      
      this.emit('healthCheckError', error);
      console.error('📊 Connection Monitor: Health check failed:', error.message);
    }
  }

  /**
   * Update connection pool metrics
   */
  updatePoolMetrics() {
    try {
      const dbStatus = dbManager.getStatus();
      
      if (dbStatus.poolSize) {
        this.metrics.activeConnections = dbStatus.poolSize;
        // Estimate available connections (this is approximate)
        const maxPoolSize = parseInt(process.env.DB_MAX_POOL_SIZE) || 20;
        this.metrics.availableConnections = Math.max(0, maxPoolSize - dbStatus.poolSize);
        this.metrics.poolUtilization = (dbStatus.poolSize / maxPoolSize) * 100;
      }
    } catch (error) {
      console.error('📊 Connection Monitor: Error updating pool metrics:', error.message);
    }
  }

  /**
   * Calculate error rate over recent period
   */
  calculateErrorRate() {
    const recentPeriod = 5 * 60 * 1000; // 5 minutes
    const cutoffTime = Date.now() - recentPeriod;
    
    const recentQueries = this.queryTimes.filter(q => q.timestamp.getTime() > cutoffTime);
    const recentErrors = recentQueries.filter(q => q.failed);
    
    this.metrics.errorRate = recentQueries.length > 0 
      ? (recentErrors.length / recentQueries.length) * 100 
      : 0;
  }

  /**
   * Get comprehensive monitoring report
   */
  getMonitoringReport() {
    const currentUptime = this.connectionStartTime 
      ? Date.now() - this.connectionStartTime.getTime()
      : 0;
    
    const totalUptime = this.metrics.connectionUptime + currentUptime;
    
    return {
      timestamp: new Date(),
      isMonitoring: this.isMonitoring,
      
      // Connection metrics
      connection: {
        isConnected: dbManager.isConnected,
        uptime: totalUptime,
        uptimeFormatted: this.formatDuration(totalUptime),
        totalConnections: this.metrics.totalConnections,
        failedConnections: this.metrics.failedConnections,
        reconnections: this.metrics.reconnections,
        successRate: this.calculateConnectionSuccessRate()
      },
      
      // Performance metrics
      performance: {
        queryCount: this.metrics.queryCount,
        slowQueries: this.metrics.slowQueries,
        slowQueryRate: this.metrics.queryCount > 0 
          ? (this.metrics.slowQueries / this.metrics.queryCount) * 100 
          : 0,
        avgQueryTime: Math.round(this.metrics.avgQueryTime * 100) / 100,
        maxQueryTime: this.metrics.maxQueryTime,
        minQueryTime: this.metrics.minQueryTime === Infinity ? 0 : this.metrics.minQueryTime,
        queriesPerSecond: this.calculateQueriesPerSecond()
      },
      
      // Error metrics
      errors: {
        errorCount: this.metrics.errorCount,
        errorRate: Math.round(this.metrics.errorRate * 100) / 100,
        lastError: this.metrics.lastError
      },
      
      // Pool metrics
      pool: {
        activeConnections: this.metrics.activeConnections,
        availableConnections: this.metrics.availableConnections,
        utilization: Math.round(this.metrics.poolUtilization * 100) / 100,
        maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || 20
      },
      
      // Health metrics
      health: {
        lastHealthCheck: this.metrics.lastHealthCheck,
        healthCheckCount: this.metrics.healthCheckCount,
        healthCheckFailures: this.metrics.healthCheckFailures,
        healthCheckSuccessRate: this.calculateHealthCheckSuccessRate()
      },
      
      // Recent activity
      recentActivity: this.getRecentActivity()
    };
  }

  /**
   * Calculate connection success rate
   */
  calculateConnectionSuccessRate() {
    const totalAttempts = this.metrics.totalConnections + this.metrics.failedConnections;
    return totalAttempts > 0 
      ? (this.metrics.totalConnections / totalAttempts) * 100 
      : 100;
  }

  /**
   * Calculate health check success rate
   */
  calculateHealthCheckSuccessRate() {
    return this.metrics.healthCheckCount > 0 
      ? ((this.metrics.healthCheckCount - this.metrics.healthCheckFailures) / this.metrics.healthCheckCount) * 100 
      : 100;
  }

  /**
   * Calculate queries per second over recent period
   */
  calculateQueriesPerSecond() {
    const recentPeriod = 60 * 1000; // 1 minute
    const cutoffTime = Date.now() - recentPeriod;
    
    const recentQueries = this.queryTimes.filter(q => q.timestamp.getTime() > cutoffTime);
    return recentQueries.length / 60; // queries per second
  }

  /**
   * Get recent activity summary
   */
  getRecentActivity() {
    const recentPeriod = 5 * 60 * 1000; // 5 minutes
    const cutoffTime = Date.now() - recentPeriod;
    
    const recentQueries = this.queryTimes.filter(q => q.timestamp.getTime() > cutoffTime);
    
    // Group by command type
    const commandCounts = {};
    recentQueries.forEach(q => {
      commandCounts[q.command] = (commandCounts[q.command] || 0) + 1;
    });
    
    return {
      period: '5 minutes',
      totalQueries: recentQueries.length,
      commandBreakdown: commandCounts,
      slowQueries: recentQueries.filter(q => q.duration > this.slowQueryThreshold).length,
      failedQueries: recentQueries.filter(q => q.failed).length
    };
  }

  /**
   * Get performance trends over time
   */
  getPerformanceTrends() {
    const now = Date.now();
    const intervals = [
      { name: '1m', duration: 60 * 1000 },
      { name: '5m', duration: 5 * 60 * 1000 },
      { name: '15m', duration: 15 * 60 * 1000 },
      { name: '1h', duration: 60 * 60 * 1000 }
    ];
    
    return intervals.map(interval => {
      const cutoffTime = now - interval.duration;
      const queries = this.queryTimes.filter(q => q.timestamp.getTime() > cutoffTime);
      
      const avgTime = queries.length > 0 
        ? queries.reduce((sum, q) => sum + q.duration, 0) / queries.length 
        : 0;
      
      return {
        interval: interval.name,
        queryCount: queries.length,
        avgQueryTime: Math.round(avgTime * 100) / 100,
        slowQueries: queries.filter(q => q.duration > this.slowQueryThreshold).length,
        errorRate: queries.length > 0 
          ? (queries.filter(q => q.failed).length / queries.length) * 100 
          : 0
      };
    });
  }

  /**
   * Format duration in human-readable format
   */
  formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) {
      return `${days}d ${hours % 24}h ${minutes % 60}m`;
    } else if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }

  /**
   * Reset metrics (useful for testing or periodic resets)
   */
  resetMetrics() {
    console.log('📊 Connection Monitor: Resetting metrics');
    
    this.metrics = {
      connectionUptime: 0,
      totalConnections: 0,
      failedConnections: 0,
      reconnections: 0,
      queryCount: 0,
      slowQueries: 0,
      avgQueryTime: 0,
      maxQueryTime: 0,
      minQueryTime: Infinity,
      errorCount: 0,
      errorRate: 0,
      lastError: null,
      activeConnections: 0,
      availableConnections: 0,
      poolUtilization: 0,
      lastHealthCheck: null,
      healthCheckCount: 0,
      healthCheckFailures: 0
    };
    
    this.queryTimes = [];
    this.connectionStartTime = dbManager.isConnected ? new Date() : null;
    
    this.emit('metricsReset');
  }

  /**
   * Export metrics for external monitoring systems
   */
  exportMetrics() {
    const report = this.getMonitoringReport();
    
    return {
      timestamp: report.timestamp.toISOString(),
      metrics: {
        // Prometheus-style metrics
        'mongodb_connection_uptime_seconds': Math.floor(report.connection.uptime / 1000),
        'mongodb_connections_total': report.connection.totalConnections,
        'mongodb_connections_failed_total': report.connection.failedConnections,
        'mongodb_reconnections_total': report.connection.reconnections,
        'mongodb_queries_total': report.performance.queryCount,
        'mongodb_slow_queries_total': report.performance.slowQueries,
        'mongodb_query_duration_avg_ms': report.performance.avgQueryTime,
        'mongodb_query_duration_max_ms': report.performance.maxQueryTime,
        'mongodb_errors_total': report.errors.errorCount,
        'mongodb_error_rate_percent': report.errors.errorRate,
        'mongodb_pool_active_connections': report.pool.activeConnections,
        'mongodb_pool_utilization_percent': report.pool.utilization,
        'mongodb_health_checks_total': report.health.healthCheckCount,
        'mongodb_health_check_failures_total': report.health.healthCheckFailures
      }
    };
  }
}

// Create singleton instance
const connectionMonitor = new ConnectionMonitor();

// Auto-start monitoring when database connects
dbManager.on('connected', () => {
  if (!connectionMonitor.isMonitoring) {
    connectionMonitor.startMonitoring();
  }
});

module.exports = {
  connectionMonitor,
  
  // Convenience methods
  startMonitoring: () => connectionMonitor.startMonitoring(),
  stopMonitoring: () => connectionMonitor.stopMonitoring(),
  getReport: () => connectionMonitor.getMonitoringReport(),
  getTrends: () => connectionMonitor.getPerformanceTrends(),
  exportMetrics: () => connectionMonitor.exportMetrics(),
  resetMetrics: () => connectionMonitor.resetMetrics(),
  
  // Event emitter methods
  on: (event, listener) => connectionMonitor.on(event, listener),
  once: (event, listener) => connectionMonitor.once(event, listener),
  off: (event, listener) => connectionMonitor.off(event, listener)
};
