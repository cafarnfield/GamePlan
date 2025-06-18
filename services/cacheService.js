const NodeCache = require('node-cache');
const { systemLogger } = require('../utils/logger');
const cacheErrorService = require('./cacheErrorService');

/**
 * Centralized Cache Service
 * Manages multiple cache instances with different TTL values and purposes
 */
class CacheService {
  constructor() {
    // Dashboard statistics cache - 5 minutes TTL
    this.dashboardCache = new NodeCache({
      stdTTL: 300, // 5 minutes
      checkperiod: 60, // Check for expired keys every minute
      useClones: false, // Better performance, but be careful with object mutations
      deleteOnExpire: true,
      maxKeys: 100
    });

    // Game lists cache - 30 minutes TTL
    this.gameListsCache = new NodeCache({
      stdTTL: 1800, // 30 minutes
      checkperiod: 300, // Check every 5 minutes
      useClones: false,
      deleteOnExpire: true,
      maxKeys: 50
    });

    // User counts cache - 2 minutes TTL
    this.userCountsCache = new NodeCache({
      stdTTL: 120, // 2 minutes
      checkperiod: 30, // Check every 30 seconds
      useClones: false,
      deleteOnExpire: true,
      maxKeys: 20
    });

    // API responses cache - 1 hour TTL
    this.apiCache = new NodeCache({
      stdTTL: 3600, // 1 hour
      checkperiod: 600, // Check every 10 minutes
      useClones: false,
      deleteOnExpire: true,
      maxKeys: 200
    });

    // System health cache - 1 minute TTL
    this.systemHealthCache = new NodeCache({
      stdTTL: 60, // 1 minute
      checkperiod: 15, // Check every 15 seconds
      useClones: false,
      deleteOnExpire: true,
      maxKeys: 10
    });

    // Cache statistics
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      errors: 0
    };

    // Setup event listeners for monitoring
    this.setupEventListeners();

    systemLogger.info('Cache service initialized', {
      caches: ['dashboard', 'gameLists', 'userCounts', 'api', 'systemHealth'],
      ttls: {
        dashboard: 300,
        gameLists: 1800,
        userCounts: 120,
        api: 3600,
        systemHealth: 60
      }
    });
  }

  /**
   * Setup event listeners for cache monitoring
   */
  setupEventListeners() {
    const caches = [
      { name: 'dashboard', cache: this.dashboardCache },
      { name: 'gameLists', cache: this.gameListsCache },
      { name: 'userCounts', cache: this.userCountsCache },
      { name: 'api', cache: this.apiCache },
      { name: 'systemHealth', cache: this.systemHealthCache }
    ];

    caches.forEach(({ name, cache }) => {
      cache.on('set', (key, value) => {
        this.stats.sets++;
        systemLogger.debug(`Cache SET: ${name}:${key}`);
      });

      cache.on('del', (key, value) => {
        this.stats.deletes++;
        systemLogger.debug(`Cache DEL: ${name}:${key}`);
      });

      cache.on('expired', (key, value) => {
        systemLogger.debug(`Cache EXPIRED: ${name}:${key}`);
      });

      cache.on('flush', () => {
        systemLogger.info(`Cache FLUSH: ${name}`);
      });
    });
  }

  /**
   * Get value from dashboard cache
   */
  getDashboard(key) {
    try {
      const value = this.dashboardCache.get(key);
      if (value !== undefined) {
        this.stats.hits++;
        systemLogger.debug(`Cache HIT: dashboard:${key}`);
        return value;
      }
      this.stats.misses++;
      systemLogger.debug(`Cache MISS: dashboard:${key}`);
      return null;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache get error', { cache: 'dashboard', key, error: error.message });
      
      // Log to error service for critical cache failures
      if (error.message.includes('ENOTFOUND') || error.message.includes('ECONNREFUSED')) {
        cacheErrorService.logCacheError('GetError', error, {
          cacheType: 'dashboard',
          operation: 'get',
          cacheKey: key,
          stats: this.stats
        }).catch(logError => {
          systemLogger.error('Failed to log cache error', { logError: logError.message });
        });
      }
      
      return null;
    }
  }

  /**
   * Set value in dashboard cache
   */
  setDashboard(key, value, ttl = null) {
    try {
      const result = this.dashboardCache.set(key, value, ttl);
      systemLogger.debug(`Cache SET: dashboard:${key}`, { ttl: ttl || 'default' });
      return result;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache set error', { cache: 'dashboard', key, error: error.message });
      return false;
    }
  }

  /**
   * Get value from game lists cache
   */
  getGameList(key) {
    try {
      const value = this.gameListsCache.get(key);
      if (value !== undefined) {
        this.stats.hits++;
        systemLogger.debug(`Cache HIT: gameLists:${key}`);
        return value;
      }
      this.stats.misses++;
      systemLogger.debug(`Cache MISS: gameLists:${key}`);
      return null;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache get error', { cache: 'gameLists', key, error: error.message });
      return null;
    }
  }

  /**
   * Set value in game lists cache
   */
  setGameList(key, value, ttl = null) {
    try {
      const result = this.gameListsCache.set(key, value, ttl);
      systemLogger.debug(`Cache SET: gameLists:${key}`, { ttl: ttl || 'default' });
      return result;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache set error', { cache: 'gameLists', key, error: error.message });
      return false;
    }
  }

  /**
   * Get value from user counts cache
   */
  getUserCount(key) {
    try {
      const value = this.userCountsCache.get(key);
      if (value !== undefined) {
        this.stats.hits++;
        systemLogger.debug(`Cache HIT: userCounts:${key}`);
        return value;
      }
      this.stats.misses++;
      systemLogger.debug(`Cache MISS: userCounts:${key}`);
      return null;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache get error', { cache: 'userCounts', key, error: error.message });
      return null;
    }
  }

  /**
   * Set value in user counts cache
   */
  setUserCount(key, value, ttl = null) {
    try {
      const result = this.userCountsCache.set(key, value, ttl);
      systemLogger.debug(`Cache SET: userCounts:${key}`, { ttl: ttl || 'default' });
      return result;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache set error', { cache: 'userCounts', key, error: error.message });
      return false;
    }
  }

  /**
   * Get value from API cache
   */
  getApi(key) {
    try {
      const value = this.apiCache.get(key);
      if (value !== undefined) {
        this.stats.hits++;
        systemLogger.debug(`Cache HIT: api:${key}`);
        return value;
      }
      this.stats.misses++;
      systemLogger.debug(`Cache MISS: api:${key}`);
      return null;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache get error', { cache: 'api', key, error: error.message });
      return null;
    }
  }

  /**
   * Set value in API cache
   */
  setApi(key, value, ttl = null) {
    try {
      const result = this.apiCache.set(key, value, ttl);
      systemLogger.debug(`Cache SET: api:${key}`, { ttl: ttl || 'default' });
      return result;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache set error', { cache: 'api', key, error: error.message });
      return false;
    }
  }

  /**
   * Get value from system health cache
   */
  getSystemHealth(key) {
    try {
      const value = this.systemHealthCache.get(key);
      if (value !== undefined) {
        this.stats.hits++;
        systemLogger.debug(`Cache HIT: systemHealth:${key}`);
        return value;
      }
      this.stats.misses++;
      systemLogger.debug(`Cache MISS: systemHealth:${key}`);
      return null;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache get error', { cache: 'systemHealth', key, error: error.message });
      return null;
    }
  }

  /**
   * Set value in system health cache
   */
  setSystemHealth(key, value, ttl = null) {
    try {
      const result = this.systemHealthCache.set(key, value, ttl);
      systemLogger.debug(`Cache SET: systemHealth:${key}`, { ttl: ttl || 'default' });
      return result;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache set error', { cache: 'systemHealth', key, error: error.message });
      return false;
    }
  }

  /**
   * Delete key from specific cache
   */
  delete(cacheType, key) {
    try {
      let result = false;
      switch (cacheType) {
        case 'dashboard':
          result = this.dashboardCache.del(key);
          break;
        case 'gameLists':
          result = this.gameListsCache.del(key);
          break;
        case 'userCounts':
          result = this.userCountsCache.del(key);
          break;
        case 'api':
          result = this.apiCache.del(key);
          break;
        case 'systemHealth':
          result = this.systemHealthCache.del(key);
          break;
        default:
          systemLogger.warn('Invalid cache type for delete', { cacheType, key });
          return false;
      }
      systemLogger.debug(`Cache DELETE: ${cacheType}:${key}`, { success: result });
      return result;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache delete error', { cacheType, key, error: error.message });
      return false;
    }
  }

  /**
   * Clear specific cache
   */
  clear(cacheType) {
    try {
      switch (cacheType) {
        case 'dashboard':
          this.dashboardCache.flushAll();
          break;
        case 'gameLists':
          this.gameListsCache.flushAll();
          break;
        case 'userCounts':
          this.userCountsCache.flushAll();
          break;
        case 'api':
          this.apiCache.flushAll();
          break;
        case 'systemHealth':
          this.systemHealthCache.flushAll();
          break;
        case 'all':
          this.dashboardCache.flushAll();
          this.gameListsCache.flushAll();
          this.userCountsCache.flushAll();
          this.apiCache.flushAll();
          this.systemHealthCache.flushAll();
          break;
        default:
          systemLogger.warn('Invalid cache type for clear', { cacheType });
          return false;
      }
      systemLogger.info(`Cache cleared: ${cacheType}`);
      return true;
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache clear error', { cacheType, error: error.message });
      return false;
    }
  }

  /**
   * Get cache statistics
   */
  getStats() {
    const cacheStats = {
      dashboard: this.dashboardCache.getStats(),
      gameLists: this.gameListsCache.getStats(),
      userCounts: this.userCountsCache.getStats(),
      api: this.apiCache.getStats(),
      systemHealth: this.systemHealthCache.getStats()
    };

    const stats = {
      overall: this.stats,
      individual: cacheStats,
      memory: {
        dashboard: this.dashboardCache.keys().length,
        gameLists: this.gameListsCache.keys().length,
        userCounts: this.userCountsCache.keys().length,
        api: this.apiCache.keys().length,
        systemHealth: this.systemHealthCache.keys().length
      },
      hitRate: this.stats.hits + this.stats.misses > 0 
        ? ((this.stats.hits / (this.stats.hits + this.stats.misses)) * 100).toFixed(2) + '%'
        : '0%'
    };

    // Monitor cache health and log issues if needed
    this.monitorHealth(stats);

    return stats;
  }

  /**
   * Monitor cache health and log issues
   */
  async monitorHealth(stats) {
    try {
      await cacheErrorService.monitorCacheHealth(stats);
    } catch (error) {
      systemLogger.error('Error monitoring cache health', {
        error: error.message
      });
    }
  }

  /**
   * Get all cache keys for debugging
   */
  getAllKeys() {
    return {
      dashboard: this.dashboardCache.keys(),
      gameLists: this.gameListsCache.keys(),
      userCounts: this.userCountsCache.keys(),
      api: this.apiCache.keys(),
      systemHealth: this.systemHealthCache.keys()
    };
  }

  /**
   * Invalidate related caches when data changes
   */
  invalidateRelated(dataType, operation = null) {
    try {
      switch (dataType) {
        case 'user':
          this.clear('userCounts');
          this.clear('dashboard');
          systemLogger.info('Invalidated user-related caches', { operation });
          break;
        case 'event':
          this.clear('dashboard');
          systemLogger.info('Invalidated event-related caches', { operation });
          break;
        case 'game':
          this.clear('gameLists');
          this.clear('dashboard');
          systemLogger.info('Invalidated game-related caches', { operation });
          break;
        case 'system':
          this.clear('systemHealth');
          systemLogger.info('Invalidated system health cache', { operation });
          break;
        default:
          systemLogger.warn('Unknown data type for cache invalidation', { dataType, operation });
      }
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache invalidation error', { dataType, operation, error: error.message });
    }
  }

  /**
   * Warm up caches with frequently accessed data
   */
  async warmUp(models) {
    try {
      systemLogger.info('Starting cache warm-up');
      
      // Warm up user counts
      if (models.User) {
        const pendingUsers = await models.User.countDocuments({ status: 'pending' });
        this.setUserCount('pending_users', pendingUsers);
      }

      // Warm up basic dashboard stats
      if (models.User && models.Event && models.Game) {
        const basicStats = {
          totalUsers: await models.User.countDocuments(),
          totalEvents: await models.Event.countDocuments(),
          totalGames: await models.Game.countDocuments()
        };
        this.setDashboard('basic_stats', basicStats);
      }

      systemLogger.info('Cache warm-up completed');
    } catch (error) {
      this.stats.errors++;
      systemLogger.error('Cache warm-up error', { error: error.message });
    }
  }
}

// Create singleton instance
const cacheService = new CacheService();

module.exports = cacheService;
