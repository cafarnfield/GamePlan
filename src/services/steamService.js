const axios = require('axios');

class SteamService {
  constructor() {
    this.baseUrl = 'https://api.steampowered.com';
    this.storeUrl = 'https://store.steampowered.com/api';
    this.appListCache = null;
    this.cacheExpiry = null;
    this.cacheTimeout = 24 * 60 * 60 * 1000; // 24 hours
  }

  /**
   * Get the full list of Steam apps
   */
  async getAppList() {
    // Check if cache is valid
    if (this.appListCache && this.cacheExpiry && Date.now() < this.cacheExpiry) {
      return this.appListCache;
    }

    try {
      const response = await axios.get(`${this.baseUrl}/ISteamApps/GetAppList/v2/`, {
        timeout: 10000
      });

      if (response.data && response.data.applist && response.data.applist.apps) {
        this.appListCache = response.data.applist.apps;
        this.cacheExpiry = Date.now() + this.cacheTimeout;
        return this.appListCache;
      }
      
      throw new Error('Invalid response format from Steam API');
    } catch (error) {
      console.error('Error fetching Steam app list:', error.message);
      throw new Error('Failed to fetch Steam app list');
    }
  }

  /**
   * Search for games by name using fuzzy matching
   */
  async searchGames(searchTerm, limit = 10) {
    if (!searchTerm || searchTerm.trim().length < 2) {
      return [];
    }

    try {
      const apps = await this.getAppList();
      const searchTermLower = searchTerm.toLowerCase().trim();
      
      // Filter and score matches
      const matches = apps
        .filter(app => app.name && app.name.toLowerCase().includes(searchTermLower))
        .map(app => ({
          ...app,
          score: this.calculateMatchScore(app.name.toLowerCase(), searchTermLower)
        }))
        .sort((a, b) => b.score - a.score)
        .slice(0, limit);

      // Get detailed info for top matches
      const detailedMatches = await Promise.allSettled(
        matches.map(async (app) => {
          try {
            const details = await this.getGameDetails(app.appid);
            return {
              appid: app.appid,
              name: app.name,
              score: app.score,
              ...details
            };
          } catch (error) {
            // Return basic info if detailed fetch fails
            return {
              appid: app.appid,
              name: app.name,
              score: app.score,
              short_description: 'Details unavailable',
              header_image: null,
              developers: [],
              publishers: []
            };
          }
        })
      );

      return detailedMatches
        .filter(result => result.status === 'fulfilled')
        .map(result => result.value);

    } catch (error) {
      console.error('Error searching Steam games:', error.message);
      return [];
    }
  }

  /**
   * Get detailed information about a specific game
   */
  async getGameDetails(appId) {
    try {
      const response = await axios.get(`${this.storeUrl}/appdetails`, {
        params: {
          appids: appId,
          filters: 'basic'
        },
        timeout: 5000
      });

      const gameData = response.data[appId];
      if (gameData && gameData.success && gameData.data) {
        const data = gameData.data;
        return {
          short_description: data.short_description || '',
          header_image: data.header_image || null,
          developers: data.developers || [],
          publishers: data.publishers || [],
          platforms: this.extractPlatforms(data.platforms),
          release_date: data.release_date ? data.release_date.date : null
        };
      }
      
      return {
        short_description: 'Details unavailable',
        header_image: null,
        developers: [],
        publishers: [],
        platforms: [],
        release_date: null
      };
    } catch (error) {
      console.error(`Error fetching details for app ${appId}:`, error.message);
      return {
        short_description: 'Details unavailable',
        header_image: null,
        developers: [],
        publishers: [],
        platforms: [],
        release_date: null
      };
    }
  }

  /**
   * Extract platform information from Steam data
   */
  extractPlatforms(steamPlatforms) {
    const platforms = [];
    if (steamPlatforms) {
      if (steamPlatforms.windows) platforms.push('PC');
      if (steamPlatforms.mac) platforms.push('PC');
      if (steamPlatforms.linux) platforms.push('PC');
    }
    return platforms;
  }

  /**
   * Calculate match score for search results
   */
  calculateMatchScore(gameName, searchTerm) {
    const name = gameName.toLowerCase();
    const term = searchTerm.toLowerCase();
    
    // Exact match gets highest score
    if (name === term) return 100;
    
    // Starts with search term gets high score
    if (name.startsWith(term)) return 90;
    
    // Contains search term as whole word gets good score
    if (name.includes(` ${term} `) || name.includes(` ${term}`) || name.includes(`${term} `)) {
      return 80;
    }
    
    // Contains search term gets moderate score
    if (name.includes(term)) return 70;
    
    // Calculate similarity based on common characters
    const commonChars = this.getCommonCharacters(name, term);
    return Math.floor((commonChars / Math.max(name.length, term.length)) * 60);
  }

  /**
   * Count common characters between two strings
   */
  getCommonCharacters(str1, str2) {
    const chars1 = str1.split('');
    const chars2 = str2.split('');
    let common = 0;
    
    chars1.forEach(char => {
      const index = chars2.indexOf(char);
      if (index !== -1) {
        common++;
        chars2.splice(index, 1);
      }
    });
    
    return common;
  }

  /**
   * Get news for a specific Steam app (for update checking)
   */
  async getGameNews(appId, count = 5) {
    try {
      const response = await axios.get(`${this.baseUrl}/ISteamNews/GetNewsForApp/v2/`, {
        params: {
          appid: appId,
          count: count
        },
        timeout: 5000
      });

      if (response.data && response.data.appnews) {
        return response.data.appnews.newsitems || [];
      }
      
      return [];
    } catch (error) {
      console.error(`Error fetching news for app ${appId}:`, error.message);
      return [];
    }
  }

  /**
   * Check if a game has recent updates
   */
  async checkForUpdates(appId) {
    try {
      const news = await this.getGameNews(appId, 10);
      
      const updateFound = news.some(item => {
        const title = item.title.toLowerCase();
        const content = item.contents ? item.contents.toLowerCase() : '';
        return (
          title.includes('update') ||
          title.includes('patch') ||
          title.includes('hotfix') ||
          title.includes('new version') ||
          content.includes('update') ||
          content.includes('patch') ||
          content.includes('hotfix')
        );
      });

      return {
        hasUpdate: updateFound,
        news: updateFound ? news.slice(0, 3) : []
      };
    } catch (error) {
      console.error(`Error checking updates for app ${appId}:`, error.message);
      return { hasUpdate: false, news: [] };
    }
  }
}

module.exports = new SteamService();
