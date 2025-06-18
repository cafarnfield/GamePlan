const cacheService = require('./cacheService');
const { systemLogger } = require('../utils/logger');

/**
 * API-specific caching service
 * Handles caching of external API responses (Steam, RAWG, etc.)
 */
class ApiCacheService {
  constructor() {
    this.cacheKeys = {
      STEAM_SEARCH: 'steam_search',
      RAWG_SEARCH: 'rawg_search',
      GAME_LISTS: 'game_lists',
      PENDING_API_COUNT: 'pending_api_count'
    };
  }

  /**
   * Generate cache key for Steam search
   */
  getSteamSearchKey(query) {
    return `${this.cacheKeys.STEAM_SEARCH}:${query.toLowerCase().trim()}`;
  }

  /**
   * Generate cache key for RAWG search
   */
  getRawgSearchKey(query) {
    return `${this.cacheKeys.RAWG_SEARCH}:${query.toLowerCase().trim()}`;
  }

  /**
   * Generate cache key for game lists
   */
  getGameListKey(filter = 'all') {
    return `${this.cacheKeys.GAME_LISTS}:${filter}`;
  }

  /**
   * Get cached Steam search results
   */
  getSteamSearch(query) {
    try {
      const key = this.getSteamSearchKey(query);
      const cached = cacheService.getApi(key);
      
      if (cached) {
        systemLogger.debug('Steam search served from cache', { query });
        return cached;
      }
      
      systemLogger.debug('Steam search cache miss', { query });
      return null;
    } catch (error) {
      systemLogger.error('Error getting Steam search from cache', { 
        query, 
        error: error.message 
      });
      return null;
    }
  }

  /**
   * Cache Steam search results
   */
  setSteamSearch(query, results, ttl = null) {
    try {
      const key = this.getSteamSearchKey(query);
      const success = cacheService.setApi(key, results, ttl);
      
      if (success) {
        systemLogger.debug('Steam search cached', { 
          query, 
          resultCount: results?.length || 0,
          ttl: ttl || 'default'
        });
      }
      
      return success;
    } catch (error) {
      systemLogger.error('Error caching Steam search', { 
        query, 
        error: error.message 
      });
      return false;
    }
  }

  /**
   * Get cached RAWG search results
   */
  getRawgSearch(query) {
    try {
      const key = this.getRawgSearchKey(query);
      const cached = cacheService.getApi(key);
      
      if (cached) {
        systemLogger.debug('RAWG search served from cache', { query });
        return cached;
      }
      
      systemLogger.debug('RAWG search cache miss', { query });
      return null;
    } catch (error) {
      systemLogger.error('Error getting RAWG search from cache', { 
        query, 
        error: error.message 
      });
      return null;
    }
  }

  /**
   * Cache RAWG search results
   */
  setRawgSearch(query, results, ttl = null) {
    try {
      const key = this.getRawgSearchKey(query);
      const success = cacheService.setApi(key, results, ttl);
      
      if (success) {
        systemLogger.debug('RAWG search cached', { 
          query, 
          resultCount: results?.length || 0,
          ttl: ttl || 'default'
        });
      }
      
      return success;
    } catch (error) {
      systemLogger.error('Error caching RAWG search', { 
        query, 
        error: error.message 
      });
      return false;
    }
  }

  /**
   * Get cached game list
   */
  getGameList(filter = 'all') {
    try {
      const key = this.getGameListKey(filter);
      const cached = cacheService.getGameList(key);
      
      if (cached) {
        systemLogger.debug('Game list served from cache', { filter });
        return cached;
      }
      
      systemLogger.debug('Game list cache miss', { filter });
      return null;
    } catch (error) {
      systemLogger.error('Error getting game list from cache', { 
        filter, 
        error: error.message 
      });
      return null;
    }
  }

  /**
   * Cache game list
   */
  setGameList(filter = 'all', games, ttl = null) {
    try {
      const key = this.getGameListKey(filter);
      const success = cacheService.setGameList(key, games, ttl);
      
      if (success) {
        systemLogger.debug('Game list cached', { 
          filter, 
          gameCount: games?.length || 0,
          ttl: ttl || 'default'
        });
      }
      
      return success;
    } catch (error) {
      systemLogger.error('Error caching game list', { 
        filter, 
        error: error.message 
      });
      return false;
    }
  }

  /**
   * Get or fetch games for admin dropdowns
   */
  async getGamesForDropdown(models, filter = 'approved') {
    try {
      // Try to get from cache first
      const cached = this.getGameList(filter);
      if (cached) {
        return cached;
      }

      // Fetch fresh data
      systemLogger.debug('Fetching fresh game list for dropdown', { filter });
      
      let query = {};
      if (filter === 'approved') {
        query.status = 'approved';
      } else if (filter === 'pending') {
        query.status = 'pending';
      }
      // 'all' filter uses empty query

      const games = await models.Game.find(query)
        .select('_id name source status')
        .sort({ name: 1 });
      
      // Cache the results
      this.setGameList(filter, games);
      
      return games;
    } catch (error) {
      systemLogger.error('Error getting games for dropdown', { 
        filter, 
        error: error.message 
      });
      return [];
    }
  }

  /**
   * Get cached pending API count
   */
  getPendingApiCount() {
    try {
      const cached = cacheService.getUserCount(this.cacheKeys.PENDING_API_COUNT);
      
      if (cached) {
        systemLogger.debug('Pending API count served from cache');
        return cached;
      }
      
      return null;
    } catch (error) {
      systemLogger.error('Error getting pending API count from cache', { 
        error: error.message 
      });
      return null;
    }
  }

  /**
   * Cache pending API count
   */
  setPendingApiCount(count, ttl = null) {
    try {
      const success = cacheService.setUserCount(this.cacheKeys.PENDING_API_COUNT, count, ttl);
      
      if (success) {
        systemLogger.debug('Pending API count cached', { count, ttl: ttl || 'default' });
      }
      
      return success;
    } catch (error) {
      systemLogger.error('Error caching pending API count', { 
        count, 
        error: error.message 
      });
      return false;
    }
  }

  /**
   * Invalidate search caches
   */
  invalidateSearchCaches() {
    try {
      // Clear all Steam search caches
      const allKeys = cacheService.getAllKeys();
      const steamKeys = allKeys.api.filter(key => key.startsWith(this.cacheKeys.STEAM_SEARCH));
      const rawgKeys = allKeys.api.filter(key => key.startsWith(this.cacheKeys.RAWG_SEARCH));
      
      steamKeys.forEach(key => cacheService.delete('api', key));
      rawgKeys.forEach(key => cacheService.delete('api', key));
      
      systemLogger.info('Search caches invalidated', { 
        steamKeysCleared: steamKeys.length,
        rawgKeysCleared: rawgKeys.length
      });
    } catch (error) {
      systemLogger.error('Error invalidating search caches', { error: error.message });
    }
  }

  /**
   * Invalidate game list caches
   */
  invalidateGameListCaches() {
    try {
      // Clear all game list caches
      const allKeys = cacheService.getAllKeys();
      const gameListKeys = allKeys.gameLists.filter(key => key.startsWith(this.cacheKeys.GAME_LISTS));
      
      gameListKeys.forEach(key => cacheService.delete('gameLists', key));
      
      systemLogger.info('Game list caches invalidated', { 
        keysCleared: gameListKeys.length
      });
    } catch (error) {
      systemLogger.error('Error invalidating game list caches', { error: error.message });
    }
  }

  /**
   * Clear old search caches (for cleanup)
   */
  clearOldSearchCaches(olderThanHours = 24) {
    try {
      const cutoffTime = Date.now() - (olderThanHours * 60 * 60 * 1000);
      let clearedCount = 0;
      
      // This is a simplified cleanup - in a real implementation,
      // you might want to store timestamps with cache entries
      const allKeys = cacheService.getAllKeys();
      const searchKeys = allKeys.api.filter(key => 
        key.startsWith(this.cacheKeys.STEAM_SEARCH) || 
        key.startsWith(this.cacheKeys.RAWG_SEARCH)
      );
      
      // For now, just clear all search caches as a cleanup mechanism
      searchKeys.forEach(key => {
        if (cacheService.delete('api', key)) {
          clearedCount++;
        }
      });
      
      systemLogger.info('Old search caches cleared', { 
        clearedCount,
        olderThanHours
      });
      
      return clearedCount;
    } catch (error) {
      systemLogger.error('Error clearing old search caches', { 
        olderThanHours,
        error: error.message 
      });
      return 0;
    }
  }

  /**
   * Get API cache statistics
   */
  getApiCacheStats() {
    try {
      const allKeys = cacheService.getAllKeys();
      
      const steamSearchCount = allKeys.api.filter(key => 
        key.startsWith(this.cacheKeys.STEAM_SEARCH)
      ).length;
      
      const rawgSearchCount = allKeys.api.filter(key => 
        key.startsWith(this.cacheKeys.RAWG_SEARCH)
      ).length;
      
      const gameListCount = allKeys.gameLists.filter(key => 
        key.startsWith(this.cacheKeys.GAME_LISTS)
      ).length;
      
      return {
        steamSearchCaches: steamSearchCount,
        rawgSearchCaches: rawgSearchCount,
        gameListCaches: gameListCount,
        totalApiCaches: allKeys.api.length,
        totalGameListCaches: allKeys.gameLists.length
      };
    } catch (error) {
      systemLogger.error('Error getting API cache stats', { error: error.message });
      return {
        steamSearchCaches: 0,
        rawgSearchCaches: 0,
        gameListCaches: 0,
        totalApiCaches: 0,
        totalGameListCaches: 0
      };
    }
  }

  /**
   * Warm up API caches
   */
  async warmUp(models) {
    try {
      systemLogger.info('Warming up API caches');
      
      // Pre-load approved games for dropdowns
      await this.getGamesForDropdown(models, 'approved');
      
      // Pre-load all games for admin
      await this.getGamesForDropdown(models, 'all');
      
      systemLogger.info('API cache warm-up completed');
    } catch (error) {
      systemLogger.error('API cache warm-up error', { error: error.message });
    }
  }

  /**
   * Create cache key with query normalization
   */
  normalizeQuery(query) {
    return query.toLowerCase().trim().replace(/\s+/g, ' ');
  }

  /**
   * Check if search result should be cached
   */
  shouldCacheSearchResult(results) {
    // Don't cache empty results or errors
    if (!results || !Array.isArray(results) || results.length === 0) {
      return false;
    }
    
    // Don't cache if results contain error indicators
    if (results.some(result => result.error || result.status === 'error')) {
      return false;
    }
    
    return true;
  }

  /**
   * Enhanced Steam search with caching
   */
  async cachedSteamSearch(query, steamService) {
    try {
      const normalizedQuery = this.normalizeQuery(query);
      
      // Check cache first
      const cached = this.getSteamSearch(normalizedQuery);
      if (cached) {
        return cached;
      }
      
      // Fetch from Steam API
      systemLogger.debug('Fetching Steam search from API', { query: normalizedQuery });
      const results = await steamService.searchGames(normalizedQuery);
      
      // Cache if results are valid
      if (this.shouldCacheSearchResult(results)) {
        this.setSteamSearch(normalizedQuery, results);
      }
      
      return results;
    } catch (error) {
      systemLogger.error('Error in cached Steam search', { 
        query, 
        error: error.message 
      });
      throw error;
    }
  }

  /**
   * Enhanced RAWG search with caching
   */
  async cachedRawgSearch(query, rawgService) {
    try {
      const normalizedQuery = this.normalizeQuery(query);
      
      // Check cache first
      const cached = this.getRawgSearch(normalizedQuery);
      if (cached) {
        return cached;
      }
      
      // Fetch from RAWG API
      systemLogger.debug('Fetching RAWG search from API', { query: normalizedQuery });
      const results = await rawgService.searchGames(normalizedQuery);
      
      // Cache if results are valid
      if (this.shouldCacheSearchResult(results)) {
        this.setRawgSearch(normalizedQuery, results);
      }
      
      return results;
    } catch (error) {
      systemLogger.error('Error in cached RAWG search', { 
        query, 
        error: error.message 
      });
      throw error;
    }
  }
}

// Create singleton instance
const apiCacheService = new ApiCacheService();

module.exports = apiCacheService;
