const Game = require('../models/Game');

class DuplicateDetectionService {
  /**
   * Calculate Levenshtein distance between two strings
   */
  static levenshteinDistance(str1, str2) {
    const matrix = [];
    
    // Create matrix
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }
    
    // Fill matrix
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    
    return matrix[str2.length][str1.length];
  }

  /**
   * Normalize game name for comparison
   */
  static normalizeGameName(name) {
    return name
      .toLowerCase()
      .replace(/[^\w\s]/g, '') // Remove special characters
      .replace(/\b(the|a|an|game|edition|deluxe|ultimate|goty|remastered|enhanced|definitive)\b/g, '') // Remove common words
      .replace(/\s+/g, ' ') // Normalize whitespace
      .trim();
  }

  /**
   * Check for common abbreviations and expansions
   */
  static checkAbbreviations(name1, name2) {
    const abbreviations = {
      'cod': 'call of duty',
      'cs': 'counter strike',
      'lol': 'league of legends',
      'wow': 'world of warcraft',
      'gta': 'grand theft auto',
      'bf': 'battlefield',
      'dota': 'defense of the ancients',
      'tf': 'team fortress',
      'hl': 'half life',
      'sc': 'starcraft',
      'wc': 'warcraft'
    };

    const normalized1 = this.normalizeGameName(name1);
    const normalized2 = this.normalizeGameName(name2);

    // Check if one is an abbreviation of the other
    for (const [abbr, full] of Object.entries(abbreviations)) {
      if ((normalized1.includes(abbr) && normalized2.includes(full)) ||
          (normalized1.includes(full) && normalized2.includes(abbr))) {
        return true;
      }
    }

    return false;
  }

  /**
   * Calculate similarity score between two game names
   */
  static calculateSimilarity(name1, name2) {
    const normalized1 = this.normalizeGameName(name1);
    const normalized2 = this.normalizeGameName(name2);

    // Exact match
    if (normalized1 === normalized2) {
      return 100;
    }

    // Check abbreviations
    if (this.checkAbbreviations(name1, name2)) {
      return 95;
    }

    // Levenshtein distance based similarity
    const maxLength = Math.max(normalized1.length, normalized2.length);
    if (maxLength === 0) return 100;

    const distance = this.levenshteinDistance(normalized1, normalized2);
    const similarity = ((maxLength - distance) / maxLength) * 100;

    // Boost score for substring matches
    if (normalized1.includes(normalized2) || normalized2.includes(normalized1)) {
      return Math.max(similarity, 85);
    }

    return similarity;
  }

  /**
   * Find potential duplicate games
   */
  static async findPotentialDuplicates(gameName, excludeId = null) {
    try {
      // Get all approved games (excluding the current game if editing)
      const query = { 
        status: { $in: ['approved', 'pending'] },
        canonicalGame: { $exists: false } // Don't include games that are already marked as duplicates
      };
      
      if (excludeId) {
        query._id = { $ne: excludeId };
      }

      const existingGames = await Game.find(query).lean();
      const duplicates = [];

      for (const game of existingGames) {
        const similarity = this.calculateSimilarity(gameName, game.name);
        
        // Consider games with 80%+ similarity as potential duplicates
        if (similarity >= 80) {
          duplicates.push({
            game: game,
            similarity: Math.round(similarity),
            reason: this.getSimilarityReason(gameName, game.name, similarity)
          });
        }

        // Also check aliases
        if (game.aliases && game.aliases.length > 0) {
          for (const alias of game.aliases) {
            const aliasSimilarity = this.calculateSimilarity(gameName, alias);
            if (aliasSimilarity >= 80) {
              duplicates.push({
                game: game,
                similarity: Math.round(aliasSimilarity),
                reason: `Similar to alias "${alias}"`
              });
              break; // Don't add the same game multiple times
            }
          }
        }
      }

      // Sort by similarity score (highest first) and remove duplicates
      const uniqueDuplicates = duplicates
        .filter((item, index, self) => 
          index === self.findIndex(t => t.game._id.toString() === item.game._id.toString())
        )
        .sort((a, b) => b.similarity - a.similarity)
        .slice(0, 5); // Limit to top 5 matches

      return uniqueDuplicates;
    } catch (error) {
      console.error('Error finding potential duplicates:', error);
      return [];
    }
  }

  /**
   * Get reason for similarity match
   */
  static getSimilarityReason(name1, name2, similarity) {
    const normalized1 = this.normalizeGameName(name1);
    const normalized2 = this.normalizeGameName(name2);

    if (normalized1 === normalized2) {
      return 'Exact match (ignoring common words)';
    }

    if (this.checkAbbreviations(name1, name2)) {
      return 'Abbreviation match';
    }

    if (normalized1.includes(normalized2) || normalized2.includes(normalized1)) {
      return 'Substring match';
    }

    if (similarity >= 90) {
      return 'Very similar name';
    }

    return 'Similar name';
  }

  /**
   * Merge duplicate games
   */
  static async mergeDuplicateGames(duplicateGameId, canonicalGameId, adminUser) {
    try {
      const duplicateGame = await Game.findById(duplicateGameId);
      const canonicalGame = await Game.findById(canonicalGameId);

      if (!duplicateGame || !canonicalGame) {
        throw new Error('One or both games not found');
      }

      // Update all events using the duplicate game to use the canonical game
      const Event = require('../models/Event');
      await Event.updateMany(
        { game: duplicateGameId },
        { game: canonicalGameId }
      );

      // Add duplicate game's name as alias to canonical game if not already present
      if (!canonicalGame.aliases.includes(duplicateGame.name)) {
        canonicalGame.aliases.push(duplicateGame.name);
      }

      // Merge tags and categories
      const newTags = duplicateGame.tags.filter(tag => !canonicalGame.tags.includes(tag));
      canonicalGame.tags.push(...newTags);

      const newCategories = duplicateGame.categories.filter(cat => !canonicalGame.categories.includes(cat));
      canonicalGame.categories.push(...newCategories);

      await canonicalGame.save();

      // Mark duplicate game as merged
      duplicateGame.canonicalGame = canonicalGameId;
      duplicateGame.status = 'rejected';
      await duplicateGame.save();

      return {
        success: true,
        message: `Successfully merged "${duplicateGame.name}" into "${canonicalGame.name}"`
      };
    } catch (error) {
      console.error('Error merging duplicate games:', error);
      return {
        success: false,
        message: error.message
      };
    }
  }
}

module.exports = DuplicateDetectionService;
