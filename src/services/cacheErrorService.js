const ErrorLog = require('../models/ErrorLog');
const { systemLogger } = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

/**
 * Cache Error Logging Service
 * Provides comprehensive error logging and monitoring for the cache system
 */
class CacheErrorService {
  constructor() {
    this.errorThresholds = {
      hitRate: {
        warning: 50,  // Below 50% hit rate
        critical: 25  // Below 25% hit rate
      },
      errorRate: {
        warning: 5,   // Above 5% error rate
        critical: 15  // Above 15% error rate
      },
      memoryUsage: {
        warning: 500, // Above 500 cache keys
        critical: 1000 // Above 1000 cache keys
      }
    };
    
    this.lastHealthCheck = null;
    this.healthCheckInterval = 5 * 60 * 1000; // 5 minutes
  }

  /**
   * Log cache operation errors to ErrorLog model
   */
  async logCacheError(errorType, error, context = {}) {
    try {
      const requestId = context.requestId || uuidv4();
      
      const errorLog = new ErrorLog({
        requestId,
        errorType: `Cache${errorType}`,
        statusCode: 500,
        message: error.message || `Cache ${errorType.toLowerCase()} error`,
        errorCode: `CACHE_${errorType.toUpperCase()}`,
        
        requestContext: {
          method: 'CACHE',
          url: `/cache/${errorType.toLowerCase()}`,
          originalUrl: context.operation || 'unknown',
          path: context.cacheKey || 'unknown',
          query: context.params || {},
          ip: context.ip || 'system',
          userAgent: 'CacheService/1.0',
          protocol: 'internal',
          secure: true,
          xhr: false
        },
        
        userContext: {
          userId: context.userId || null,
          email: context.userEmail || 'system',
          name: context.userName || 'Cache System',
          isAdmin: context.isAdmin || false,
          isSuperAdmin: context.isSuperAdmin || false,
          isAuthenticated: !!context.userId,
          sessionId: context.sessionId || 'cache-system'
        },
        
        errorDetails: {
          stack: error.stack,
          originalError: {
            name: error.name,
            message: error.message,
            code: error.code
          },
          cacheDetails: {
            cacheType: context.cacheType,
            operation: context.operation,
            key: context.cacheKey,
            ttl: context.ttl,
            memoryUsage: context.memoryUsage,
            stats: context.stats
          }
        },
        
        environment: {
          nodeVersion: process.version,
          nodeEnv: process.env.NODE_ENV || 'development',
          appVersion: '1.0.0',
          platform: process.platform,
          hostname: require('os').hostname(),
          pid: process.pid,
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage()
        },
        
        analytics: {
          severity: this.determineSeverity(errorType, context),
          category: 'system',
          impact: this.determineImpact(errorType, context)
        },
        
        metadata: {
          source: 'cache-system',
          version: '1.0',
          processed: false
        }
      });
      
      await errorLog.save();
      
      systemLogger.error('Cache error logged to database', {
        requestId,
        errorType,
        cacheType: context.cacheType,
        operation: context.operation,
        errorLogId: errorLog._id
      });
      
      return errorLog;
    } catch (logError) {
      systemLogger.error('Failed to log cache error to database', {
        originalError: error.message,
        logError: logError.message,
        errorType,
        context
      });
      throw logError;
    }
  }

  /**
   * Log cache performance issues
   */
  async logPerformanceIssue(issueType, metrics, context = {}) {
    try {
      const severity = this.getPerformanceSeverity(issueType, metrics);
      
      if (severity === 'low') {
        // Don't log low severity performance issues to reduce noise
        return null;
      }
      
      const requestId = uuidv4();
      
      const errorLog = new ErrorLog({
        requestId,
        errorType: 'CachePerformanceIssue',
        statusCode: 503, // Service Unavailable
        message: this.getPerformanceMessage(issueType, metrics),
        errorCode: `CACHE_PERF_${issueType.toUpperCase()}`,
        
        requestContext: {
          method: 'MONITOR',
          url: '/cache/performance',
          originalUrl: 'performance-monitoring',
          path: issueType,
          query: metrics,
          ip: 'system',
          userAgent: 'CacheMonitor/1.0',
          protocol: 'internal',
          secure: true,
          xhr: false
        },
        
        userContext: {
          email: 'system',
          name: 'Cache Performance Monitor',
          isAuthenticated: false,
          sessionId: 'cache-monitor'
        },
        
        errorDetails: {
          originalError: {
            type: 'PerformanceIssue',
            issue: issueType,
            metrics: metrics
          },
          cacheDetails: {
            performanceIssue: issueType,
            currentMetrics: metrics,
            thresholds: this.errorThresholds,
            recommendations: this.getPerformanceRecommendations(issueType, metrics)
          }
        },
        
        environment: {
          nodeVersion: process.version,
          nodeEnv: process.env.NODE_ENV || 'development',
          appVersion: '1.0.0',
          platform: process.platform,
          hostname: require('os').hostname(),
          pid: process.pid,
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage()
        },
        
        analytics: {
          severity: severity,
          category: 'system',
          impact: severity === 'critical' ? 'high' : 'medium'
        },
        
        metadata: {
          source: 'cache-performance-monitor',
          version: '1.0',
          processed: false
        }
      });
      
      await errorLog.save();
      
      systemLogger.warn('Cache performance issue logged', {
        requestId,
        issueType,
        severity,
        metrics,
        errorLogId: errorLog._id
      });
      
      return errorLog;
    } catch (logError) {
      systemLogger.error('Failed to log cache performance issue', {
        issueType,
        metrics,
        logError: logError.message
      });
      throw logError;
    }
  }

  /**
   * Monitor cache health and log issues
   */
  async monitorCacheHealth(cacheStats, context = {}) {
    try {
      const now = Date.now();
      
      // Skip if we've checked recently
      if (this.lastHealthCheck && (now - this.lastHealthCheck) < this.healthCheckInterval) {
        return;
      }
      
      this.lastHealthCheck = now;
      
      const issues = [];
      
      // Check hit rate
      const totalRequests = cacheStats.overall.hits + cacheStats.overall.misses;
      if (totalRequests > 10) { // Only check if we have meaningful data
        const hitRate = (cacheStats.overall.hits / totalRequests) * 100;
        
        if (hitRate < this.errorThresholds.hitRate.critical) {
          issues.push({
            type: 'low_hit_rate',
            severity: 'critical',
            metrics: { hitRate, totalRequests, threshold: this.errorThresholds.hitRate.critical }
          });
        } else if (hitRate < this.errorThresholds.hitRate.warning) {
          issues.push({
            type: 'low_hit_rate',
            severity: 'warning',
            metrics: { hitRate, totalRequests, threshold: this.errorThresholds.hitRate.warning }
          });
        }
      }
      
      // Check error rate
      if (totalRequests > 0) {
        const errorRate = (cacheStats.overall.errors / totalRequests) * 100;
        
        if (errorRate > this.errorThresholds.errorRate.critical) {
          issues.push({
            type: 'high_error_rate',
            severity: 'critical',
            metrics: { errorRate, totalErrors: cacheStats.overall.errors, totalRequests }
          });
        } else if (errorRate > this.errorThresholds.errorRate.warning) {
          issues.push({
            type: 'high_error_rate',
            severity: 'warning',
            metrics: { errorRate, totalErrors: cacheStats.overall.errors, totalRequests }
          });
        }
      }
      
      // Check memory usage
      const totalKeys = Object.values(cacheStats.memory).reduce((sum, count) => sum + count, 0);
      
      if (totalKeys > this.errorThresholds.memoryUsage.critical) {
        issues.push({
          type: 'high_memory_usage',
          severity: 'critical',
          metrics: { totalKeys, memoryBreakdown: cacheStats.memory }
        });
      } else if (totalKeys > this.errorThresholds.memoryUsage.warning) {
        issues.push({
          type: 'high_memory_usage',
          severity: 'warning',
          metrics: { totalKeys, memoryBreakdown: cacheStats.memory }
        });
      }
      
      // Log issues
      for (const issue of issues) {
        await this.logPerformanceIssue(issue.type, issue.metrics, {
          ...context,
          severity: issue.severity
        });
      }
      
      if (issues.length > 0) {
        systemLogger.warn('Cache health issues detected', {
          issueCount: issues.length,
          issues: issues.map(i => ({ type: i.type, severity: i.severity }))
        });
      }
      
      return issues;
    } catch (error) {
      systemLogger.error('Error monitoring cache health', {
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get cache error statistics
   */
  async getCacheErrorStats(timeWindow = 24) {
    try {
      const timeAgo = new Date(Date.now() - timeWindow * 60 * 60 * 1000);
      
      const stats = await ErrorLog.aggregate([
        {
          $match: {
            timestamp: { $gte: timeAgo },
            errorType: { $regex: /^Cache/ }
          }
        },
        {
          $group: {
            _id: {
              errorType: '$errorType',
              severity: '$analytics.severity'
            },
            count: { $sum: 1 },
            lastOccurred: { $max: '$timestamp' }
          }
        },
        { $sort: { count: -1 } }
      ]);
      
      const summary = {
        totalCacheErrors: stats.reduce((sum, stat) => sum + stat.count, 0),
        errorsByType: {},
        errorsBySeverity: { low: 0, medium: 0, high: 0, critical: 0 },
        lastError: stats.length > 0 ? stats[0].lastOccurred : null
      };
      
      stats.forEach(stat => {
        const type = stat._id.errorType;
        const severity = stat._id.severity;
        
        if (!summary.errorsByType[type]) {
          summary.errorsByType[type] = 0;
        }
        summary.errorsByType[type] += stat.count;
        summary.errorsBySeverity[severity] += stat.count;
      });
      
      return summary;
    } catch (error) {
      systemLogger.error('Error getting cache error statistics', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Get recent cache errors
   */
  async getRecentCacheErrors(limit = 10) {
    try {
      return await ErrorLog.find({
        errorType: { $regex: /^Cache/ }
      })
      .sort({ timestamp: -1 })
      .limit(limit)
      .select('timestamp errorType message analytics.severity resolution.status errorDetails.cacheDetails');
    } catch (error) {
      systemLogger.error('Error getting recent cache errors', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Helper methods
   */
  determineSeverity(errorType, context) {
    if (errorType.includes('Critical') || context.cacheType === 'systemHealth') {
      return 'critical';
    } else if (errorType.includes('Connection') || errorType.includes('Memory')) {
      return 'high';
    } else if (errorType.includes('Performance') || errorType.includes('Timeout')) {
      return 'medium';
    }
    return 'low';
  }

  determineImpact(errorType, context) {
    if (context.cacheType === 'dashboard' || context.cacheType === 'systemHealth') {
      return 'high';
    } else if (context.cacheType === 'api' || context.cacheType === 'gameLists') {
      return 'medium';
    }
    return 'low';
  }

  getPerformanceSeverity(issueType, metrics) {
    switch (issueType) {
      case 'low_hit_rate':
        if (metrics.hitRate < this.errorThresholds.hitRate.critical) return 'critical';
        if (metrics.hitRate < this.errorThresholds.hitRate.warning) return 'medium';
        return 'low';
      
      case 'high_error_rate':
        if (metrics.errorRate > this.errorThresholds.errorRate.critical) return 'critical';
        if (metrics.errorRate > this.errorThresholds.errorRate.warning) return 'medium';
        return 'low';
      
      case 'high_memory_usage':
        if (metrics.totalKeys > this.errorThresholds.memoryUsage.critical) return 'critical';
        if (metrics.totalKeys > this.errorThresholds.memoryUsage.warning) return 'medium';
        return 'low';
      
      default:
        return 'low';
    }
  }

  getPerformanceMessage(issueType, metrics) {
    switch (issueType) {
      case 'low_hit_rate':
        return `Cache hit rate is ${metrics.hitRate.toFixed(2)}% (below ${metrics.threshold}% threshold)`;
      
      case 'high_error_rate':
        return `Cache error rate is ${metrics.errorRate.toFixed(2)}% (${metrics.totalErrors} errors out of ${metrics.totalRequests} requests)`;
      
      case 'high_memory_usage':
        return `Cache memory usage is high: ${metrics.totalKeys} total keys (above ${this.errorThresholds.memoryUsage.warning} threshold)`;
      
      default:
        return `Cache performance issue: ${issueType}`;
    }
  }

  getPerformanceRecommendations(issueType, metrics) {
    switch (issueType) {
      case 'low_hit_rate':
        return [
          'Consider increasing TTL values for frequently accessed data',
          'Implement cache warming strategies',
          'Review cache key patterns for optimization',
          'Check if cache invalidation is too aggressive'
        ];
      
      case 'high_error_rate':
        return [
          'Investigate cache service stability',
          'Check database connection health',
          'Review error logs for patterns',
          'Consider implementing circuit breaker pattern'
        ];
      
      case 'high_memory_usage':
        return [
          'Implement cache cleanup strategies',
          'Reduce TTL values for less critical data',
          'Clear old search caches',
          'Consider cache size limits'
        ];
      
      default:
        return ['Review cache configuration and usage patterns'];
    }
  }

  /**
   * Clean up old cache error logs
   */
  async cleanupOldCacheErrors(retentionDays = 30) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
      
      const result = await ErrorLog.deleteMany({
        timestamp: { $lt: cutoffDate },
        errorType: { $regex: /^Cache/ },
        'resolution.status': { $in: ['resolved', 'ignored'] }
      });
      
      systemLogger.info('Cache error logs cleaned up', {
        deletedCount: result.deletedCount,
        retentionDays,
        cutoffDate
      });
      
      return result.deletedCount;
    } catch (error) {
      systemLogger.error('Error cleaning up cache error logs', {
        error: error.message
      });
      throw error;
    }
  }
}

module.exports = new CacheErrorService();
