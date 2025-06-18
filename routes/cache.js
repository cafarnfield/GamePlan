const express = require('express');
const router = express.Router();

// Import cache services
const cacheService = require('../services/cacheService');
const dashboardCacheService = require('../services/dashboardCacheService');
const apiCacheService = require('../services/apiCacheService');
const cacheErrorService = require('../services/cacheErrorService');

// Import authentication middleware
const { ensureAuthenticated, ensureAdmin, ensureSuperAdmin } = require('../middleware/auth');

// Import centralized error handling
const { asyncErrorHandler } = require('../middleware/errorHandler');

// Import loggers
const { systemLogger } = require('../utils/logger');

/**
 * Cache Management API Routes
 * Provides endpoints for monitoring and managing the cache system
 */

// Get cache statistics
router.get('/stats', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const overallStats = cacheService.getStats();
    const rawApiStats = apiCacheService.getApiCacheStats();
    const rawDashboardStatus = dashboardCacheService.getCacheStatus();
    
    // Calculate cache health metrics (same as admin route)
    const totalRequests = overallStats.overall.hits + overallStats.overall.misses;
    const hitRate = totalRequests > 0 ? ((overallStats.overall.hits / totalRequests) * 100).toFixed(2) : 0;
    const errorRate = totalRequests > 0 ? ((overallStats.overall.errors / totalRequests) * 100).toFixed(2) : 0;
    
    // Transform data to match what the JavaScript expects
    const stats = {
      success: true,
      stats: {
        totalRequests,
        hits: overallStats.overall.hits,
        misses: overallStats.overall.misses,
        errors: overallStats.overall.errors,
        hitRate: parseFloat(hitRate),
        errorRate: parseFloat(errorRate)
      },
      overall: overallStats,
      api: rawApiStats,
      dashboard: rawDashboardStatus,
      timestamp: new Date().toISOString()
    };
    
    systemLogger.info('Cache statistics requested', {
      requestedBy: req.user.email,
      hitRate: hitRate
    });
    
    res.json(stats);
  } catch (error) {
    systemLogger.error('Error getting cache statistics', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ 
      success: false,
      error: 'Failed to get cache statistics' 
    });
  }
}));

// Get all cache keys (for debugging)
router.get('/keys', ensureAuthenticated, ensureSuperAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const allKeys = cacheService.getAllKeys();
    
    systemLogger.info('Cache keys requested', {
      requestedBy: req.user.email,
      totalKeys: Object.values(allKeys).reduce((sum, keys) => sum + keys.length, 0)
    });
    
    res.json(allKeys);
  } catch (error) {
    systemLogger.error('Error getting cache keys', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to get cache keys' });
  }
}));

// Clear specific cache type
router.post('/clear/:cacheType', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const { cacheType } = req.params;
    const validCacheTypes = ['dashboard', 'gameLists', 'userCounts', 'api', 'systemHealth', 'all'];
    
    if (!validCacheTypes.includes(cacheType)) {
      return res.status(400).json({ 
        error: 'Invalid cache type',
        validTypes: validCacheTypes
      });
    }
    
    const success = cacheService.clear(cacheType);
    
    if (success) {
      systemLogger.info('Cache cleared', {
        cacheType,
        clearedBy: req.user.email
      });
      
      res.json({ 
        success: true, 
        message: `${cacheType} cache cleared successfully`,
        cacheType,
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(500).json({ error: 'Failed to clear cache' });
    }
  } catch (error) {
    systemLogger.error('Error clearing cache', {
      error: error.message,
      cacheType: req.params.cacheType,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to clear cache' });
  }
}));

// Invalidate dashboard caches
router.post('/invalidate/dashboard', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    dashboardCacheService.invalidateDashboardCaches();
    
    systemLogger.info('Dashboard caches invalidated', {
      invalidatedBy: req.user.email
    });
    
    res.json({ 
      success: true, 
      message: 'Dashboard caches invalidated successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    systemLogger.error('Error invalidating dashboard caches', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to invalidate dashboard caches' });
  }
}));

// Invalidate user-related caches
router.post('/invalidate/users', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    dashboardCacheService.invalidateUserCaches();
    
    systemLogger.info('User caches invalidated', {
      invalidatedBy: req.user.email
    });
    
    res.json({ 
      success: true, 
      message: 'User caches invalidated successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    systemLogger.error('Error invalidating user caches', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to invalidate user caches' });
  }
}));

// Invalidate game-related caches
router.post('/invalidate/games', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    dashboardCacheService.invalidateGameCaches();
    apiCacheService.invalidateGameListCaches();
    
    systemLogger.info('Game caches invalidated', {
      invalidatedBy: req.user.email
    });
    
    res.json({ 
      success: true, 
      message: 'Game caches invalidated successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    systemLogger.error('Error invalidating game caches', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to invalidate game caches' });
  }
}));

// Invalidate search caches
router.post('/invalidate/search', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    apiCacheService.invalidateSearchCaches();
    
    systemLogger.info('Search caches invalidated', {
      invalidatedBy: req.user.email
    });
    
    res.json({ 
      success: true, 
      message: 'Search caches invalidated successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    systemLogger.error('Error invalidating search caches', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to invalidate search caches' });
  }
}));

// Warm up caches
router.post('/warmup', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    // Import models
    const User = require('../models/User');
    const Event = require('../models/Event');
    const Game = require('../models/Game');
    const AuditLog = require('../models/AuditLog');
    
    const models = { User, Event, Game, AuditLog };
    
    // Warm up all caches
    await Promise.all([
      cacheService.warmUp(models),
      dashboardCacheService.warmUp(models),
      apiCacheService.warmUp(models)
    ]);
    
    systemLogger.info('Cache warm-up completed', {
      initiatedBy: req.user.email
    });
    
    res.json({ 
      success: true, 
      message: 'Cache warm-up completed successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    systemLogger.error('Error during cache warm-up', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to warm up caches' });
  }
}));

// Clean up old search caches
router.post('/cleanup/search', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const { olderThanHours = 24 } = req.body;
    const clearedCount = apiCacheService.clearOldSearchCaches(olderThanHours);
    
    systemLogger.info('Old search caches cleaned up', {
      clearedCount,
      olderThanHours,
      initiatedBy: req.user.email
    });
    
    res.json({ 
      success: true, 
      message: `Cleaned up ${clearedCount} old search cache entries`,
      clearedCount,
      olderThanHours,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    systemLogger.error('Error cleaning up old search caches', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to clean up old search caches' });
  }
}));

// Get cache health status
router.get('/health', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const stats = cacheService.getStats();
    const apiStats = apiCacheService.getApiCacheStats();
    
    // Calculate health metrics
    const totalRequests = stats.overall.hits + stats.overall.misses;
    const hitRate = totalRequests > 0 ? (stats.overall.hits / totalRequests) * 100 : 0;
    const errorRate = totalRequests > 0 ? (stats.overall.errors / totalRequests) * 100 : 0;
    
    const health = {
      status: 'healthy',
      metrics: {
        hitRate: Math.round(hitRate * 100) / 100,
        errorRate: Math.round(errorRate * 100) / 100,
        totalRequests,
        totalCacheKeys: stats.memory.dashboard + stats.memory.gameLists + 
                       stats.memory.userCounts + stats.memory.api + stats.memory.systemHealth
      },
      thresholds: {
        hitRate: { min: 70, current: hitRate, status: hitRate >= 70 ? 'good' : 'warning' },
        errorRate: { max: 5, current: errorRate, status: errorRate <= 5 ? 'good' : 'warning' }
      },
      cacheTypes: {
        dashboard: stats.memory.dashboard,
        gameLists: stats.memory.gameLists,
        userCounts: stats.memory.userCounts,
        api: stats.memory.api,
        systemHealth: stats.memory.systemHealth
      },
      timestamp: new Date().toISOString()
    };
    
    // Determine overall health status
    if (hitRate < 50 || errorRate > 10) {
      health.status = 'unhealthy';
    } else if (hitRate < 70 || errorRate > 5) {
      health.status = 'warning';
    }
    
    res.json(health);
  } catch (error) {
    systemLogger.error('Error getting cache health', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ 
      status: 'error',
      error: 'Failed to get cache health status' 
    });
  }
}));

// Get cache configuration
router.get('/config', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const config = {
      ttls: {
        dashboard: 300, // 5 minutes
        gameLists: 1800, // 30 minutes
        userCounts: 120, // 2 minutes
        api: 3600, // 1 hour
        systemHealth: 60 // 1 minute
      },
      maxKeys: {
        dashboard: 100,
        gameLists: 50,
        userCounts: 20,
        api: 200,
        systemHealth: 10
      },
      checkPeriods: {
        dashboard: 60, // 1 minute
        gameLists: 300, // 5 minutes
        userCounts: 30, // 30 seconds
        api: 600, // 10 minutes
        systemHealth: 15 // 15 seconds
      },
      features: {
        useClones: false,
        deleteOnExpire: true,
        automaticWarmup: true,
        invalidationOnDataChange: true
      },
      timestamp: new Date().toISOString()
    };
    
    res.json(config);
  } catch (error) {
    systemLogger.error('Error getting cache configuration', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to get cache configuration' });
  }
}));

// Convenience alias routes
router.post('/clear-all', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const success = cacheService.clear('all');
    
    if (success) {
      systemLogger.info('All caches cleared', {
        clearedBy: req.user.email
      });
      
      res.json({ 
        success: true, 
        message: 'All caches cleared successfully',
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(500).json({ error: 'Failed to clear all caches' });
    }
  } catch (error) {
    systemLogger.error('Error clearing all caches', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to clear all caches' });
  }
}));

router.post('/warmup-all', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    // Import models
    const User = require('../models/User');
    const Event = require('../models/Event');
    const Game = require('../models/Game');
    const AuditLog = require('../models/AuditLog');
    
    const models = { User, Event, Game, AuditLog };
    
    // Warm up all caches
    await Promise.all([
      cacheService.warmUp(models),
      dashboardCacheService.warmUp(models),
      apiCacheService.warmUp(models)
    ]);
    
    systemLogger.info('All caches warmed up', {
      initiatedBy: req.user.email
    });
    
    res.json({ 
      success: true, 
      message: 'All caches warmed up successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    systemLogger.error('Error warming up all caches', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to warm up all caches' });
  }
}));

// Get cache contents (for debugging)
router.get('/contents', ensureAuthenticated, ensureSuperAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const allKeys = cacheService.getAllKeys();
    const stats = cacheService.getStats();
    
    const contents = {
      keys: allKeys,
      stats: stats,
      summary: {
        totalKeys: Object.values(allKeys).reduce((sum, keys) => sum + keys.length, 0),
        totalMemoryUsage: Object.values(stats.memory).reduce((sum, count) => sum + count, 0),
        hitRate: stats.hitRate
      },
      timestamp: new Date().toISOString()
    };
    
    systemLogger.info('Cache contents viewed', {
      requestedBy: req.user.email,
      totalKeys: contents.summary.totalKeys
    });
    
    res.json({ success: true, contents });
  } catch (error) {
    systemLogger.error('Error getting cache contents', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to get cache contents' });
  }
}));

// Get performance report
router.get('/performance-report', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const stats = cacheService.getStats();
    const apiStats = apiCacheService.getApiCacheStats();
    const dashboardStatus = dashboardCacheService.getCacheStatus();
    
    const totalRequests = stats.overall.hits + stats.overall.misses;
    const hitRate = totalRequests > 0 ? (stats.overall.hits / totalRequests) * 100 : 0;
    const errorRate = totalRequests > 0 ? (stats.overall.errors / totalRequests) * 100 : 0;
    
    const report = {
      summary: {
        totalRequests,
        hitRate: Math.round(hitRate * 100) / 100,
        errorRate: Math.round(errorRate * 100) / 100,
        totalCacheKeys: Object.values(stats.memory).reduce((sum, count) => sum + count, 0)
      },
      performance: {
        cacheHits: stats.overall.hits,
        cacheMisses: stats.overall.misses,
        cacheErrors: stats.overall.errors,
        cacheSets: stats.overall.sets,
        cacheDeletes: stats.overall.deletes
      },
      memoryUsage: stats.memory,
      cacheTypes: {
        dashboard: {
          keys: stats.individual.dashboard.keys,
          hits: stats.individual.dashboard.hits,
          misses: stats.individual.dashboard.misses,
          hitRate: stats.individual.dashboard.hits + stats.individual.dashboard.misses > 0 ? 
            (stats.individual.dashboard.hits / (stats.individual.dashboard.hits + stats.individual.dashboard.misses) * 100).toFixed(2) : 0
        },
        api: {
          keys: stats.individual.api.keys,
          hits: stats.individual.api.hits,
          misses: stats.individual.api.misses,
          hitRate: stats.individual.api.hits + stats.individual.api.misses > 0 ? 
            (stats.individual.api.hits / (stats.individual.api.hits + stats.individual.api.misses) * 100).toFixed(2) : 0
        },
        gameLists: {
          keys: stats.individual.gameLists.keys,
          hits: stats.individual.gameLists.hits,
          misses: stats.individual.gameLists.misses,
          hitRate: stats.individual.gameLists.hits + stats.individual.gameLists.misses > 0 ? 
            (stats.individual.gameLists.hits / (stats.individual.gameLists.hits + stats.individual.gameLists.misses) * 100).toFixed(2) : 0
        },
        userCounts: {
          keys: stats.individual.userCounts.keys,
          hits: stats.individual.userCounts.hits,
          misses: stats.individual.userCounts.misses,
          hitRate: stats.individual.userCounts.hits + stats.individual.userCounts.misses > 0 ? 
            (stats.individual.userCounts.hits / (stats.individual.userCounts.hits + stats.individual.userCounts.misses) * 100).toFixed(2) : 0
        },
        systemHealth: {
          keys: stats.individual.systemHealth.keys,
          hits: stats.individual.systemHealth.hits,
          misses: stats.individual.systemHealth.misses,
          hitRate: stats.individual.systemHealth.hits + stats.individual.systemHealth.misses > 0 ? 
            (stats.individual.systemHealth.hits / (stats.individual.systemHealth.hits + stats.individual.systemHealth.misses) * 100).toFixed(2) : 0
        }
      },
      apiCacheStats: apiStats,
      dashboardStatus: dashboardStatus,
      recommendations: [],
      timestamp: new Date().toISOString()
    };
    
    // Add performance recommendations
    if (hitRate < 50) {
      report.recommendations.push('Consider increasing TTL values or implementing cache warming strategies');
    }
    if (errorRate > 5) {
      report.recommendations.push('High error rate detected - investigate cache service stability');
    }
    if (Object.values(stats.memory).reduce((sum, count) => sum + count, 0) > 500) {
      report.recommendations.push('High memory usage - consider implementing cache cleanup strategies');
    }
    
    systemLogger.info('Performance report generated', {
      requestedBy: req.user.email,
      hitRate: report.summary.hitRate,
      totalKeys: report.summary.totalCacheKeys
    });
    
    res.json({ success: true, report });
  } catch (error) {
    systemLogger.error('Error generating performance report', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to generate performance report' });
  }
}));

// Export cache statistics
router.get('/export-stats', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const stats = cacheService.getStats();
    const apiStats = apiCacheService.getApiCacheStats();
    const dashboardStatus = dashboardCacheService.getCacheStatus();
    
    const exportData = {
      exportInfo: {
        exportedAt: new Date().toISOString(),
        exportedBy: req.user.email,
        version: '1.0'
      },
      cacheStats: stats,
      apiStats: apiStats,
      dashboardStatus: dashboardStatus,
      summary: {
        totalRequests: stats.overall.hits + stats.overall.misses,
        hitRate: stats.hitRate,
        totalKeys: Object.values(stats.memory).reduce((sum, count) => sum + count, 0)
      }
    };
    
    systemLogger.info('Cache statistics exported', {
      exportedBy: req.user.email
    });
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=cache-stats-${new Date().toISOString().split('T')[0]}.json`);
    res.json(exportData);
  } catch (error) {
    systemLogger.error('Error exporting cache statistics', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to export cache statistics' });
  }
}));

// Optimize memory usage
router.post('/optimize-memory', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const beforeStats = cacheService.getStats();
    const beforeKeys = Object.values(beforeStats.memory).reduce((sum, count) => sum + count, 0);
    
    // Clear old search caches
    const clearedSearchCaches = apiCacheService.clearOldSearchCaches(1); // Clear caches older than 1 hour
    
    // Force garbage collection on cache instances (if supported)
    cacheService.clear('systemHealth'); // Clear least important cache
    
    const afterStats = cacheService.getStats();
    const afterKeys = Object.values(afterStats.memory).reduce((sum, count) => sum + count, 0);
    
    const optimization = {
      before: {
        totalKeys: beforeKeys,
        memoryUsage: beforeStats.memory
      },
      after: {
        totalKeys: afterKeys,
        memoryUsage: afterStats.memory
      },
      optimization: {
        keysCleared: beforeKeys - afterKeys,
        searchCachesCleared: clearedSearchCaches,
        memoryFreed: beforeKeys - afterKeys > 0
      },
      timestamp: new Date().toISOString()
    };
    
    systemLogger.info('Memory optimization completed', {
      optimizedBy: req.user.email,
      keysCleared: optimization.optimization.keysCleared,
      searchCachesCleared: clearedSearchCaches
    });
    
    res.json({ 
      success: true, 
      message: `Memory optimization completed. Cleared ${optimization.optimization.keysCleared} cache keys.`,
      optimization
    });
  } catch (error) {
    systemLogger.error('Error optimizing memory', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ error: 'Failed to optimize memory' });
  }
}));

// Get cache error statistics
router.get('/errors/stats', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const { timeWindow = 24 } = req.query;
    const errorStats = await cacheErrorService.getCacheErrorStats(parseInt(timeWindow));
    
    systemLogger.info('Cache error statistics requested', {
      requestedBy: req.user.email,
      timeWindow,
      totalErrors: errorStats.totalCacheErrors
    });
    
    res.json({
      success: true,
      errorStats,
      timeWindow: parseInt(timeWindow),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    systemLogger.error('Error getting cache error statistics', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ 
      success: false,
      error: 'Failed to get cache error statistics' 
    });
  }
}));

// Get recent cache errors
router.get('/errors/recent', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const recentErrors = await cacheErrorService.getRecentCacheErrors(parseInt(limit));
    
    systemLogger.info('Recent cache errors requested', {
      requestedBy: req.user.email,
      limit,
      errorsFound: recentErrors.length
    });
    
    res.json({
      success: true,
      errors: recentErrors,
      limit: parseInt(limit),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    systemLogger.error('Error getting recent cache errors', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ 
      success: false,
      error: 'Failed to get recent cache errors' 
    });
  }
}));

// Clean up old cache error logs
router.post('/errors/cleanup', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const { retentionDays = 30 } = req.body;
    const deletedCount = await cacheErrorService.cleanupOldCacheErrors(parseInt(retentionDays));
    
    systemLogger.info('Cache error logs cleaned up', {
      deletedCount,
      retentionDays,
      initiatedBy: req.user.email
    });
    
    res.json({
      success: true,
      message: `Cleaned up ${deletedCount} old cache error logs`,
      deletedCount,
      retentionDays: parseInt(retentionDays),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    systemLogger.error('Error cleaning up cache error logs', {
      error: error.message,
      requestedBy: req.user.email
    });
    res.status(500).json({ 
      success: false,
      error: 'Failed to clean up cache error logs' 
    });
  }
}));

// Dynamic cache type management routes
router.post('/:cacheType/:action', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const { cacheType, action } = req.params;
    const validCacheTypes = ['dashboard', 'api', 'games', 'user-counts', 'all'];
    const validActions = ['refresh', 'warm', 'clear', 'preload-popular', 'invalidate-stale'];
    
    if (!validCacheTypes.includes(cacheType)) {
      return res.status(400).json({ 
        error: 'Invalid cache type',
        validTypes: validCacheTypes
      });
    }
    
    if (!validActions.includes(action)) {
      return res.status(400).json({ 
        error: 'Invalid action',
        validActions: validActions
      });
    }
    
    let result = { success: false, message: '' };
    
    // Handle different cache type and action combinations
    switch (`${cacheType}:${action}`) {
      case 'dashboard:refresh':
        dashboardCacheService.invalidateDashboardCaches();
        result = { success: true, message: 'Dashboard caches refreshed successfully' };
        break;
        
      case 'dashboard:warm':
        const User = require('../models/User');
        const Event = require('../models/Event');
        const Game = require('../models/Game');
        const AuditLog = require('../models/AuditLog');
        const models = { User, Event, Game, AuditLog };
        await dashboardCacheService.warmUp(models);
        result = { success: true, message: 'Dashboard caches warmed up successfully' };
        break;
        
      case 'dashboard:clear':
        cacheService.clear('dashboard');
        result = { success: true, message: 'Dashboard caches cleared successfully' };
        break;
        
      case 'api:refresh':
        apiCacheService.invalidateSearchCaches();
        result = { success: true, message: 'API caches refreshed successfully' };
        break;
        
      case 'api:warm':
        const modelsForApi = { 
          User: require('../models/User'),
          Event: require('../models/Event'),
          Game: require('../models/Game'),
          AuditLog: require('../models/AuditLog')
        };
        await apiCacheService.warmUp(modelsForApi);
        result = { success: true, message: 'API caches warmed up successfully' };
        break;
        
      case 'api:clear':
        cacheService.clear('api');
        result = { success: true, message: 'API caches cleared successfully' };
        break;
        
      case 'games:preload-popular':
        const gameModels = { 
          Game: require('../models/Game')
        };
        await apiCacheService.getGamesForDropdown(gameModels, 'approved');
        result = { success: true, message: 'Popular games preloaded successfully' };
        break;
        
      case 'user-counts:refresh':
        dashboardCacheService.invalidateUserCaches();
        result = { success: true, message: 'User counts refreshed successfully' };
        break;
        
      case 'all:invalidate-stale':
        // Clear old search caches and invalidate stale data
        const clearedCount = apiCacheService.clearOldSearchCaches(2); // Clear caches older than 2 hours
        dashboardCacheService.invalidateDashboardCaches();
        result = { success: true, message: `Stale data invalidated. Cleared ${clearedCount} old cache entries.` };
        break;
        
      default:
        return res.status(400).json({ 
          error: `Unsupported combination: ${cacheType}:${action}` 
        });
    }
    
    systemLogger.info(`Cache operation completed: ${cacheType}:${action}`, {
      performedBy: req.user.email,
      cacheType,
      action
    });
    
    res.json({
      ...result,
      cacheType,
      action,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    systemLogger.error('Error in dynamic cache management', {
      error: error.message,
      cacheType: req.params.cacheType,
      action: req.params.action,
      requestedBy: req.user.email
    });
    res.status(500).json({ 
      error: `Failed to ${req.params.action} ${req.params.cacheType} cache: ${error.message}` 
    });
  }
}));

module.exports = router;
