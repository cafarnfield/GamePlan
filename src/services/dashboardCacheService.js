const cacheService = require('./cacheService');
const { systemLogger } = require('../utils/logger');

/**
 * Dashboard-specific caching service
 * Handles caching of dashboard statistics and related data
 */
class DashboardCacheService {
  constructor() {
    this.cacheKeys = {
      DASHBOARD_STATS: 'dashboard_stats',
      PENDING_COUNTS: 'pending_counts',
      RECENT_ACTIVITY: 'recent_activity',
      SYSTEM_HEALTH: 'system_health',
      APPROVAL_RATE: 'approval_rate',
      USER_STATS: 'user_stats',
      EVENT_STATS: 'event_stats',
      GAME_STATS: 'game_stats'
    };
  }

  /**
   * Get or calculate dashboard statistics
   */
  async getDashboardStats(models) {
    try {
      // Try to get from cache first
      const cached = cacheService.getDashboard(this.cacheKeys.DASHBOARD_STATS);
      if (cached) {
        systemLogger.debug('Dashboard stats served from cache');
        return cached;
      }

      // Calculate fresh statistics
      systemLogger.debug('Calculating fresh dashboard statistics');
      const stats = await this.calculateDashboardStats(models);
      
      // Cache the results
      cacheService.setDashboard(this.cacheKeys.DASHBOARD_STATS, stats);
      
      return stats;
    } catch (error) {
      systemLogger.error('Error getting dashboard stats', { error: error.message });
      throw error;
    }
  }

  /**
   * Calculate dashboard statistics from database
   */
  async calculateDashboardStats(models) {
    const { User, Event, Game } = models;

    // Calculate all statistics in parallel for better performance
    const [
      totalUsers,
      approvedUsers,
      pendingUsers,
      blockedUsers,
      totalEvents,
      activeEvents,
      eventsToday,
      eventsThisWeek,
      totalGames,
      steamGames,
      manualGames,
      pendingGames,
      recentRegistrations,
      probationaryUsers,
      rejectedUsers
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ status: 'approved' }),
      User.countDocuments({ status: 'pending' }),
      User.countDocuments({ isBlocked: true }),
      Event.countDocuments(),
      Event.countDocuments({ date: { $gte: new Date() } }),
      Event.countDocuments({ 
        date: { 
          $gte: new Date(new Date().setHours(0, 0, 0, 0)),
          $lt: new Date(new Date().setHours(23, 59, 59, 999))
        }
      }),
      Event.countDocuments({ 
        date: { 
          $gte: new Date(new Date().setDate(new Date().getDate() - new Date().getDay())),
          $lt: new Date(new Date().setDate(new Date().getDate() - new Date().getDay() + 7))
        }
      }),
      Game.countDocuments(),
      Game.countDocuments({ source: 'steam' }),
      Game.countDocuments({ source: 'manual' }),
      Game.countDocuments({ status: 'pending' }),
      User.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
      }),
      User.countDocuments({ 
        probationaryUntil: { $gte: new Date() }
      }),
      User.countDocuments({ status: 'rejected' })
    ]);

    // Calculate approval rate
    const totalProcessed = approvedUsers + rejectedUsers;
    const approvalRate = totalProcessed > 0 ? Math.round((approvedUsers / totalProcessed) * 100) : 100;

    const stats = {
      totalUsers,
      approvedUsers,
      pendingUsers,
      blockedUsers,
      totalEvents,
      activeEvents,
      eventsToday,
      eventsThisWeek,
      totalGames,
      steamGames,
      manualGames,
      pendingGames,
      recentRegistrations,
      probationaryUsers,
      approvalRate,
      calculatedAt: new Date()
    };

    systemLogger.info('Dashboard statistics calculated', {
      totalUsers,
      pendingUsers,
      totalEvents,
      totalGames,
      approvalRate
    });

    return stats;
  }

  /**
   * Get or calculate pending counts for navigation badges
   */
  async getPendingCounts(models) {
    try {
      // Try to get from cache first
      const cached = cacheService.getUserCount(this.cacheKeys.PENDING_COUNTS);
      if (cached) {
        systemLogger.debug('Pending counts served from cache');
        return cached;
      }

      // Calculate fresh counts
      systemLogger.debug('Calculating fresh pending counts');
      const counts = await this.calculatePendingCounts(models);
      
      // Cache the results with shorter TTL since this changes frequently
      cacheService.setUserCount(this.cacheKeys.PENDING_COUNTS, counts);
      
      return counts;
    } catch (error) {
      systemLogger.error('Error getting pending counts', { error: error.message });
      // Return default values on error
      return {
        pendingUsers: 0,
        pendingEvents: 0,
        pendingGames: 0
      };
    }
  }

  /**
   * Calculate pending counts from database
   */
  async calculatePendingCounts(models) {
    const { User, Event, Game } = models;

    const [pendingUsers, pendingEvents, pendingGames] = await Promise.all([
      User.countDocuments({ status: 'pending' }),
      Event.countDocuments({ gameStatus: 'pending' }),
      Game.countDocuments({ status: 'pending' })
    ]);

    const counts = {
      pendingUsers,
      pendingEvents,
      pendingGames,
      calculatedAt: new Date()
    };

    systemLogger.debug('Pending counts calculated', counts);
    return counts;
  }

  /**
   * Get or fetch recent activity
   */
  async getRecentActivity(models) {
    try {
      // Try to get from cache first
      const cached = cacheService.getDashboard(this.cacheKeys.RECENT_ACTIVITY);
      if (cached) {
        systemLogger.debug('Recent activity served from cache');
        return cached;
      }

      // Fetch fresh activity
      systemLogger.debug('Fetching fresh recent activity');
      const activity = await models.AuditLog.find()
        .sort({ timestamp: -1 })
        .limit(10);
      
      // Cache the results
      cacheService.setDashboard(this.cacheKeys.RECENT_ACTIVITY, activity, 180); // 3 minutes TTL
      
      return activity;
    } catch (error) {
      systemLogger.error('Error getting recent activity', { error: error.message });
      return [];
    }
  }

  /**
   * Get or calculate system health data
   */
  async getSystemHealth() {
    try {
      // Try to get from cache first
      const cached = cacheService.getSystemHealth(this.cacheKeys.SYSTEM_HEALTH);
      if (cached) {
        systemLogger.debug('System health served from cache');
        return cached;
      }

      // Calculate fresh system health
      systemLogger.debug('Calculating fresh system health');
      const health = await this.calculateSystemHealth();
      
      // Cache the results
      cacheService.setSystemHealth(this.cacheKeys.SYSTEM_HEALTH, health);
      
      return health;
    } catch (error) {
      systemLogger.error('Error getting system health', { error: error.message });
      throw error;
    }
  }

  /**
   * Calculate system health data
   */
  async calculateSystemHealth() {
    const mongoose = require('mongoose');
    
    const health = {
      databaseConnected: mongoose.connection.readyState === 1,
      uptime: process.uptime(),
      nodeVersion: process.version,
      environment: process.env.NODE_ENV || 'development',
      memoryUsage: process.memoryUsage(),
      calculatedAt: new Date()
    };

    systemLogger.debug('System health calculated', {
      databaseConnected: health.databaseConnected,
      uptime: health.uptime,
      environment: health.environment
    });

    return health;
  }

  /**
   * Invalidate dashboard-related caches
   */
  invalidateDashboardCaches() {
    try {
      cacheService.delete('dashboard', this.cacheKeys.DASHBOARD_STATS);
      cacheService.delete('userCounts', this.cacheKeys.PENDING_COUNTS);
      cacheService.delete('dashboard', this.cacheKeys.RECENT_ACTIVITY);
      
      systemLogger.info('Dashboard caches invalidated');
    } catch (error) {
      systemLogger.error('Error invalidating dashboard caches', { error: error.message });
    }
  }

  /**
   * Invalidate user-related caches
   */
  invalidateUserCaches() {
    try {
      cacheService.delete('dashboard', this.cacheKeys.DASHBOARD_STATS);
      cacheService.delete('userCounts', this.cacheKeys.PENDING_COUNTS);
      cacheService.delete('dashboard', this.cacheKeys.USER_STATS);
      
      systemLogger.info('User-related caches invalidated');
    } catch (error) {
      systemLogger.error('Error invalidating user caches', { error: error.message });
    }
  }

  /**
   * Invalidate event-related caches
   */
  invalidateEventCaches() {
    try {
      cacheService.delete('dashboard', this.cacheKeys.DASHBOARD_STATS);
      cacheService.delete('dashboard', this.cacheKeys.EVENT_STATS);
      
      systemLogger.info('Event-related caches invalidated');
    } catch (error) {
      systemLogger.error('Error invalidating event caches', { error: error.message });
    }
  }

  /**
   * Invalidate game-related caches
   */
  invalidateGameCaches() {
    try {
      cacheService.delete('dashboard', this.cacheKeys.DASHBOARD_STATS);
      cacheService.delete('dashboard', this.cacheKeys.GAME_STATS);
      cacheService.delete('userCounts', this.cacheKeys.PENDING_COUNTS);
      
      systemLogger.info('Game-related caches invalidated');
    } catch (error) {
      systemLogger.error('Error invalidating game caches', { error: error.message });
    }
  }

  /**
   * Warm up dashboard caches
   */
  async warmUp(models) {
    try {
      systemLogger.info('Warming up dashboard caches');
      
      // Pre-load dashboard stats
      await this.getDashboardStats(models);
      
      // Pre-load pending counts
      await this.getPendingCounts(models);
      
      // Pre-load recent activity
      await this.getRecentActivity(models);
      
      // Pre-load system health
      await this.getSystemHealth();
      
      systemLogger.info('Dashboard cache warm-up completed');
    } catch (error) {
      systemLogger.error('Dashboard cache warm-up error', { error: error.message });
    }
  }

  /**
   * Get cache status for dashboard monitoring
   */
  getCacheStatus() {
    const keys = Object.values(this.cacheKeys);
    const status = {
      dashboard: {},
      userCounts: {},
      systemHealth: {}
    };

    // Check dashboard cache
    keys.forEach(key => {
      if (key === this.cacheKeys.PENDING_COUNTS) {
        status.userCounts[key] = cacheService.getUserCount(key) !== null;
      } else if (key === this.cacheKeys.SYSTEM_HEALTH) {
        status.systemHealth[key] = cacheService.getSystemHealth(key) !== null;
      } else {
        status.dashboard[key] = cacheService.getDashboard(key) !== null;
      }
    });

    return status;
  }
}

// Create singleton instance
const dashboardCacheService = new DashboardCacheService();

module.exports = dashboardCacheService;
