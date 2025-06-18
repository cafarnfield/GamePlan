/**
 * Comprehensive Health Monitoring Service for GamePlan
 * Provides detailed health checks for all system components
 */

const os = require('os');
const { healthCheck: dbHealthCheck, getStatus: getDbStatus } = require('../utils/database');
const { getConfigHealth } = require('../utils/configHealth');
const steamService = require('./steamService');
const rawgService = require('./rawgService');
const cacheService = require('./cacheService');
const dashboardCacheService = require('./dashboardCacheService');
const apiCacheService = require('./apiCacheService');
const { systemLogger } = require('../utils/logger');

class HealthService {
  constructor() {
    this.lastHealthCheck = null;
    this.healthHistory = [];
    this.maxHistorySize = 100;
    this.dependencyCache = new Map();
    this.cacheTimeout = 30000; // 30 seconds cache for dependency checks
  }

  /**
   * Get comprehensive system health status
   * @param {Object} options - Health check options
   * @param {boolean} options.detailed - Include detailed information
   * @param {boolean} options.includeDependencies - Check external dependencies
   * @returns {Object} Complete health status
   */
  async getHealthStatus(options = {}) {
    const { detailed = false, includeDependencies = true } = options;
    
    try {
      const startTime = Date.now();
      
      // Collect all health data in parallel
      const [
        systemHealth,
        databaseHealth,
        configHealth,
        cacheHealth,
        dependencyHealth
      ] = await Promise.all([
        this.getSystemHealth(),
        this.getDatabaseHealth(),
        this.getConfigurationHealth(),
        this.getCacheHealth(),
        includeDependencies ? this.getDependencyHealth() : { status: 'skipped' }
      ]);

      const responseTime = Date.now() - startTime;
      
      // Determine overall status
      const overallStatus = this.determineOverallStatus({
        system: systemHealth,
        database: databaseHealth,
        configuration: configHealth,
        cache: cacheHealth,
        dependencies: dependencyHealth
      });

      const healthData = {
        status: overallStatus.status,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        responseTime: `${responseTime}ms`,
        version: process.env.npm_package_version || '1.0.0',
        system: systemHealth,
        database: databaseHealth,
        cache: cacheHealth,
        configuration: configHealth.status === 'healthy' ? { status: 'healthy' } : configHealth,
        ...(includeDependencies && { dependencies: dependencyHealth }),
        ...(detailed && {
          detailed: {
            nodeVersion: process.version,
            platform: os.platform(),
            architecture: os.arch(),
            hostname: os.hostname(),
            processId: process.pid,
            parentProcessId: process.ppid || 'N/A'
          }
        }),
        warnings: overallStatus.warnings,
        errors: overallStatus.errors
      };

      // Store in history
      this.addToHistory(healthData);
      this.lastHealthCheck = healthData;

      return healthData;
    } catch (error) {
      systemLogger.error('Health check failed', {
        error: error.message,
        stack: error.stack
      });

      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Health check system failure',
        message: error.message
      };
    }
  }

  /**
   * Get system resource health
   * @returns {Object} System health metrics
   */
  async getSystemHealth() {
    try {
      const memUsage = process.memoryUsage();
      const systemMem = os.totalmem();
      const freeMem = os.freemem();
      const usedMem = systemMem - freeMem;
      const memUsagePercent = (usedMem / systemMem) * 100;
      
      const loadAvg = os.loadavg();
      const cpuCount = os.cpus().length;
      
      // Calculate memory usage in human-readable format
      const formatBytes = (bytes) => {
        const sizes = ['B', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 B';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
      };

      const systemHealth = {
        status: memUsagePercent > 90 ? 'unhealthy' : memUsagePercent > 75 ? 'degraded' : 'healthy',
        memory: {
          process: {
            rss: formatBytes(memUsage.rss),
            heapUsed: formatBytes(memUsage.heapUsed),
            heapTotal: formatBytes(memUsage.heapTotal),
            external: formatBytes(memUsage.external),
            arrayBuffers: formatBytes(memUsage.arrayBuffers || 0)
          },
          system: {
            total: formatBytes(systemMem),
            free: formatBytes(freeMem),
            used: formatBytes(usedMem),
            usagePercent: `${memUsagePercent.toFixed(1)}%`
          }
        },
        cpu: {
          loadAverage: loadAvg.map(load => load.toFixed(2)),
          cores: cpuCount,
          loadPercent: `${((loadAvg[0] / cpuCount) * 100).toFixed(1)}%`
        },
        uptime: {
          process: `${Math.floor(process.uptime())}s`,
          system: `${Math.floor(os.uptime())}s`
        }
      };

      return systemHealth;
    } catch (error) {
      systemLogger.error('System health check failed', { error: error.message });
      return {
        status: 'unhealthy',
        error: 'Failed to collect system metrics',
        message: error.message
      };
    }
  }

  /**
   * Get database health status
   * @returns {Object} Database health metrics
   */
  async getDatabaseHealth() {
    try {
      const dbHealth = await dbHealthCheck();
      const dbStatus = getDbStatus();
      
      return {
        status: dbHealth.status,
        responseTime: dbHealth.responseTime || 'N/A',
        connection: {
          state: dbStatus.connectionState,
          host: dbStatus.host || 'N/A',
          port: dbStatus.port || 'N/A',
          database: dbStatus.name || 'N/A',
          poolSize: dbStatus.poolSize || 0
        },
        metrics: {
          totalConnections: dbStatus.metrics.totalConnections,
          failedConnections: dbStatus.metrics.failedConnections,
          reconnections: dbStatus.metrics.reconnections,
          totalQueries: dbStatus.metrics.totalQueries
        },
        lastSuccessfulConnection: dbStatus.lastSuccessfulConnection,
        ...(dbHealth.status !== 'healthy' && {
          recentErrors: dbStatus.recentErrors?.slice(-3) || []
        })
      };
    } catch (error) {
      systemLogger.error('Database health check failed', { error: error.message });
      return {
        status: 'unhealthy',
        error: 'Database health check failed',
        message: error.message
      };
    }
  }

  /**
   * Get cache services health
   * @returns {Object} Cache health metrics
   */
  async getCacheHealth() {
    try {
      const cacheStats = {
        mainCache: this.getCacheServiceStats(cacheService, 'Main Cache'),
        dashboardCache: this.getCacheServiceStats(dashboardCacheService, 'Dashboard Cache'),
        apiCache: this.getCacheServiceStats(apiCacheService, 'API Cache')
      };

      // Determine overall cache status
      const cacheStatuses = Object.values(cacheStats).map(cache => cache.status);
      const overallStatus = cacheStatuses.includes('unhealthy') ? 'unhealthy' :
                           cacheStatuses.includes('degraded') ? 'degraded' : 'healthy';

      return {
        status: overallStatus,
        services: cacheStats,
        summary: {
          totalKeys: Object.values(cacheStats).reduce((sum, cache) => sum + (cache.keys || 0), 0),
          totalMemory: Object.values(cacheStats).reduce((sum, cache) => {
            if (cache.memoryUsage && typeof cache.memoryUsage === 'string') {
              const match = cache.memoryUsage.match(/(\d+\.?\d*)/);
              return sum + (match ? parseFloat(match[1]) : 0);
            }
            return sum;
          }, 0).toFixed(1) + ' MB'
        }
      };
    } catch (error) {
      systemLogger.error('Cache health check failed', { error: error.message });
      return {
        status: 'unhealthy',
        error: 'Cache health check failed',
        message: error.message
      };
    }
  }

  /**
   * Get individual cache service statistics
   * @param {Object} cacheService - Cache service instance
   * @param {string} name - Cache service name
   * @returns {Object} Cache service stats
   */
  getCacheServiceStats(cacheService, name) {
    try {
      if (!cacheService || typeof cacheService.getStats !== 'function') {
        return {
          status: 'unknown',
          name,
          error: 'Cache service not available or missing getStats method'
        };
      }

      const stats = cacheService.getStats();
      const hitRate = stats.requests > 0 ? ((stats.hits / stats.requests) * 100).toFixed(1) : '0.0';
      
      return {
        status: stats.requests > 0 && parseFloat(hitRate) < 50 ? 'degraded' : 'healthy',
        name,
        hitRate: `${hitRate}%`,
        hits: stats.hits || 0,
        misses: stats.misses || 0,
        requests: stats.requests || 0,
        keys: stats.keys || 0,
        memoryUsage: this.formatBytes(stats.vsize || 0)
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        name,
        error: error.message
      };
    }
  }

  /**
   * Get external dependency health
   * @returns {Object} Dependency health status
   */
  async getDependencyHealth() {
    try {
      const dependencies = {};
      
      // Check Steam API
      if (process.env.STEAM_API_KEY) {
        dependencies.steamAPI = await this.checkDependency('steam', async () => {
          const testResult = await steamService.searchGames('test', { limit: 1 });
          return testResult && Array.isArray(testResult);
        });
      } else {
        dependencies.steamAPI = {
          status: 'disabled',
          message: 'Steam API key not configured'
        };
      }

      // Check RAWG API
      if (process.env.RAWG_API_KEY) {
        dependencies.rawgAPI = await this.checkDependency('rawg', async () => {
          const testResult = await rawgService.searchGames('test', { page_size: 1 });
          return testResult && testResult.results && Array.isArray(testResult.results);
        });
      } else {
        dependencies.rawgAPI = {
          status: 'disabled',
          message: 'RAWG API key not configured'
        };
      }

      // Determine overall dependency status
      const dependencyStatuses = Object.values(dependencies)
        .filter(dep => dep.status !== 'disabled')
        .map(dep => dep.status);
      
      const overallStatus = dependencyStatuses.length === 0 ? 'disabled' :
                           dependencyStatuses.includes('unhealthy') ? 'degraded' :
                           dependencyStatuses.every(status => status === 'healthy') ? 'healthy' : 'degraded';

      return {
        status: overallStatus,
        services: dependencies
      };
    } catch (error) {
      systemLogger.error('Dependency health check failed', { error: error.message });
      return {
        status: 'unhealthy',
        error: 'Dependency health check failed',
        message: error.message
      };
    }
  }

  /**
   * Check individual dependency with caching
   * @param {string} name - Dependency name
   * @param {Function} checkFunction - Function to test the dependency
   * @returns {Object} Dependency health status
   */
  async checkDependency(name, checkFunction) {
    const cacheKey = `dependency_${name}`;
    const cached = this.dependencyCache.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp) < this.cacheTimeout) {
      return cached.result;
    }

    const startTime = Date.now();
    try {
      const isHealthy = await Promise.race([
        checkFunction(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Timeout')), 10000)
        )
      ]);
      
      const responseTime = Date.now() - startTime;
      const result = {
        status: isHealthy ? 'healthy' : 'unhealthy',
        responseTime: `${responseTime}ms`,
        lastCheck: new Date().toISOString()
      };

      this.dependencyCache.set(cacheKey, {
        result,
        timestamp: Date.now()
      });

      return result;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      const result = {
        status: 'unhealthy',
        responseTime: `${responseTime}ms`,
        lastCheck: new Date().toISOString(),
        error: error.message
      };

      this.dependencyCache.set(cacheKey, {
        result,
        timestamp: Date.now()
      });

      return result;
    }
  }

  /**
   * Get configuration health
   * @returns {Object} Configuration health status
   */
  getConfigurationHealth() {
    try {
      return getConfigHealth();
    } catch (error) {
      systemLogger.error('Configuration health check failed', { error: error.message });
      return {
        status: 'unhealthy',
        error: 'Configuration health check failed',
        message: error.message
      };
    }
  }

  /**
   * Determine overall system status based on component health
   * @param {Object} components - All component health statuses
   * @returns {Object} Overall status with warnings and errors
   */
  determineOverallStatus(components) {
    const warnings = [];
    const errors = [];
    
    // Check each component
    Object.entries(components).forEach(([component, health]) => {
      if (health.status === 'unhealthy') {
        errors.push(`${component}: ${health.error || health.message || 'Unhealthy'}`);
      } else if (health.status === 'degraded') {
        warnings.push(`${component}: Performance degraded`);
      }
      
      // Add specific warnings
      if (health.warnings && Array.isArray(health.warnings)) {
        warnings.push(...health.warnings.map(w => `${component}: ${w}`));
      }
      if (health.errors && Array.isArray(health.errors)) {
        errors.push(...health.errors.map(e => `${component}: ${e}`));
      }
    });

    // Determine overall status
    let status = 'healthy';
    if (errors.length > 0) {
      status = 'unhealthy';
    } else if (warnings.length > 0) {
      status = 'degraded';
    }

    return { status, warnings, errors };
  }

  /**
   * Add health check result to history
   * @param {Object} healthData - Health check result
   */
  addToHistory(healthData) {
    this.healthHistory.push({
      timestamp: healthData.timestamp,
      status: healthData.status,
      responseTime: healthData.responseTime
    });

    // Keep only recent history
    if (this.healthHistory.length > this.maxHistorySize) {
      this.healthHistory = this.healthHistory.slice(-this.maxHistorySize);
    }
  }

  /**
   * Get health check history
   * @param {number} limit - Number of recent checks to return
   * @returns {Array} Health check history
   */
  getHealthHistory(limit = 10) {
    return this.healthHistory.slice(-limit);
  }

  /**
   * Format bytes to human readable format
   * @param {number} bytes - Bytes to format
   * @returns {string} Formatted string
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  }

  /**
   * Get quick health status (cached for performance)
   * @returns {Object} Quick health status
   */
  getQuickStatus() {
    if (this.lastHealthCheck && 
        (Date.now() - new Date(this.lastHealthCheck.timestamp).getTime()) < 30000) {
      return {
        status: this.lastHealthCheck.status,
        timestamp: this.lastHealthCheck.timestamp,
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        cached: true
      };
    }

    return {
      status: 'unknown',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development',
      message: 'Health check not yet performed'
    };
  }
}

// Create singleton instance
const healthService = new HealthService();

module.exports = healthService;
