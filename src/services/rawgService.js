const axios = require('axios');

class RawgService {
  constructor() {
    this.baseUrl = 'https://api.rawg.io/api';
    this.apiKey = process.env.RAWG_API_KEY || '3963501b74354e0688413453cb8c6bc4';
    this.gameListCache = new Map();
    this.cacheTimeout = 24 * 60 * 60 * 1000; // 24 hours
    this.requestDelay = 100; // 100ms delay between requests to respect rate limits
    this.lastRequestTime = 0;
  }

  /**
   * Add delay between requests to respect rate limits
   */
  async rateLimitDelay() {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    if (timeSinceLastRequest < this.requestDelay) {
      await new Promise(resolve => setTimeout(resolve, this.requestDelay - timeSinceLastRequest));
    }
    this.lastRequestTime = Date.now();
  }

  /**
   * Search for games by name
   */
  async searchGames(searchTerm, limit = 10) {
    if (!searchTerm || searchTerm.trim().length < 2) {
      return [];
    }

    const cacheKey = `search_${searchTerm.toLowerCase()}_${limit}`;
    
    // Check cache first
    if (this.gameListCache.has(cacheKey)) {
      const cached = this.gameListCache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTimeout) {
        return cached.data;
      }
    }

    try {
      await this.rateLimitDelay();
      
      const response = await axios.get(`${this.baseUrl}/games`, {
        params: {
          key: this.apiKey,
          search: searchTerm.trim(),
          page_size: limit,
          ordering: '-rating', // Order by rating descending
        },
        timeout: 10000
      });

      if (response.data && response.data.results) {
        const games = response.data.results.map(game => this.formatGameData(game));
        
        // Cache the results
        this.gameListCache.set(cacheKey, {
          data: games,
          timestamp: Date.now()
        });
        
        return games;
      }
      
      return [];
    } catch (error) {
      console.error('Error searching RAWG games:', error.message);
      return [];
    }
  }

  /**
   * Get detailed information about a specific game
   */
  async getGameDetails(gameId) {
    const cacheKey = `details_${gameId}`;
    
    // Check cache first
    if (this.gameListCache.has(cacheKey)) {
      const cached = this.gameListCache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTimeout) {
        return cached.data;
      }
    }

    try {
      await this.rateLimitDelay();
      
      const response = await axios.get(`${this.baseUrl}/games/${gameId}`, {
        params: {
          key: this.apiKey
        },
        timeout: 10000
      });

      if (response.data) {
        const gameDetails = this.formatGameDetails(response.data);
        
        // Cache the results
        this.gameListCache.set(cacheKey, {
          data: gameDetails,
          timestamp: Date.now()
        });
        
        return gameDetails;
      }
      
      return null;
    } catch (error) {
      console.error(`Error fetching RAWG game details for ID ${gameId}:`, error.message);
      return null;
    }
  }

  /**
   * Format game data from RAWG API response
   */
  formatGameData(rawgGame) {
    return {
      id: rawgGame.id,
      name: rawgGame.name,
      description: rawgGame.description_raw || rawgGame.description || '',
      short_description: this.truncateDescription(rawgGame.description_raw || rawgGame.description || ''),
      background_image: rawgGame.background_image,
      rating: rawgGame.rating,
      rating_top: rawgGame.rating_top,
      released: rawgGame.released,
      platforms: this.extractPlatforms(rawgGame.platforms),
      genres: this.extractGenres(rawgGame.genres),
      developers: this.extractDevelopers(rawgGame.developers),
      publishers: this.extractPublishers(rawgGame.publishers),
      tags: this.extractTags(rawgGame.tags),
      metacritic: rawgGame.metacritic
    };
  }

  /**
   * Format detailed game data from RAWG API response
   */
  formatGameDetails(rawgGame) {
    return {
      id: rawgGame.id,
      name: rawgGame.name,
      description: rawgGame.description_raw || rawgGame.description || '',
      short_description: this.truncateDescription(rawgGame.description_raw || rawgGame.description || ''),
      background_image: rawgGame.background_image,
      website: rawgGame.website,
      rating: rawgGame.rating,
      rating_top: rawgGame.rating_top,
      released: rawgGame.released,
      platforms: this.extractPlatforms(rawgGame.platforms),
      genres: this.extractGenres(rawgGame.genres),
      developers: this.extractDevelopers(rawgGame.developers),
      publishers: this.extractPublishers(rawgGame.publishers),
      tags: this.extractTags(rawgGame.tags),
      metacritic: rawgGame.metacritic,
      esrb_rating: rawgGame.esrb_rating ? rawgGame.esrb_rating.name : null
    };
  }

  /**
   * Extract and map platforms to our application's platform enum
   */
  extractPlatforms(rawgPlatforms) {
    if (!rawgPlatforms || !Array.isArray(rawgPlatforms)) {
      return [];
    }

    const platformMap = {
      // PC platforms
      'pc': 'PC',
      'linux': 'PC',
      'macos': 'PC',
      
      // PlayStation platforms
      'playstation-4': 'PlayStation',
      'playstation-5': 'PlayStation',
      'playstation-3': 'PlayStation',
      'playstation-2': 'PlayStation',
      'playstation-1': 'PlayStation',
      'ps-vita': 'PlayStation',
      'psp': 'PlayStation',
      
      // Xbox platforms
      'xbox-one': 'Xbox',
      'xbox-series-x': 'Xbox',
      'xbox360': 'Xbox',
      'xbox-old': 'Xbox',
      
      // Nintendo platforms
      'nintendo-switch': 'Nintendo Switch',
      'nintendo-3ds': 'Nintendo Switch',
      'nintendo-ds': 'Nintendo Switch',
      'wii-u': 'Nintendo Switch',
      'wii': 'Nintendo Switch'
    };

    const mappedPlatforms = new Set();
    
    rawgPlatforms.forEach(platformObj => {
      const platformSlug = platformObj.platform ? platformObj.platform.slug : null;
      if (platformSlug && platformMap[platformSlug]) {
        mappedPlatforms.add(platformMap[platformSlug]);
      }
    });

    return Array.from(mappedPlatforms);
  }

  /**
   * Extract and map genres to our application's categories
   */
  extractGenres(rawgGenres) {
    if (!rawgGenres || !Array.isArray(rawgGenres)) {
      return [];
    }

    const genreMap = {
      'action': 'Action',
      'adventure': 'Adventure',
      'strategy': 'Strategy',
      'role-playing-games-rpg': 'RPG',
      'shooter': 'FPS',
      'racing': 'Racing',
      'sports': 'Sports',
      'simulation': 'Simulation',
      'puzzle': 'Puzzle',
      'platformer': 'Platformer',
      'fighting': 'Fighting',
      'horror': 'Horror',
      'survival': 'Survival',
      'massively-multiplayer': 'MMO',
      'indie': 'Indie',
      'casual': 'Casual'
    };

    const mappedGenres = rawgGenres
      .map(genre => genreMap[genre.slug] || null)
      .filter(genre => genre !== null);

    return mappedGenres.length > 0 ? mappedGenres : ['Other'];
  }

  /**
   * Extract developers
   */
  extractDevelopers(rawgDevelopers) {
    if (!rawgDevelopers || !Array.isArray(rawgDevelopers)) {
      return [];
    }
    return rawgDevelopers.map(dev => dev.name);
  }

  /**
   * Extract publishers
   */
  extractPublishers(rawgPublishers) {
    if (!rawgPublishers || !Array.isArray(rawgPublishers)) {
      return [];
    }
    return rawgPublishers.map(pub => pub.name);
  }

  /**
   * Extract tags (limited to most relevant ones)
   */
  extractTags(rawgTags) {
    if (!rawgTags || !Array.isArray(rawgTags)) {
      return [];
    }
    
    // Get top 5 most popular tags
    return rawgTags
      .slice(0, 5)
      .map(tag => tag.name);
  }

  /**
   * Truncate description to a reasonable length
   */
  truncateDescription(description) {
    if (!description) return '';
    
    const maxLength = 200;
    if (description.length <= maxLength) {
      return description;
    }
    
    return description.substring(0, maxLength).trim() + '...';
  }

  /**
   * Calculate match score for search results (similar to Steam service)
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
   * Clear cache (useful for testing or manual cache refresh)
   */
  clearCache() {
    this.gameListCache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return {
      size: this.gameListCache.size,
      keys: Array.from(this.gameListCache.keys())
    };
  }
}

module.exports = new RawgService();
