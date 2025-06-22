const crypto = require('crypto');
const User = require('../models/User');
const { logger } = require('./logger');

/**
 * Token utilities for password reset functionality
 */
class TokenUtils {
  
  /**
   * Generate a cryptographically secure reset token
   * @returns {string} - Secure random token
   */
  static generateResetToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Generate token expiry date
   * @param {number} expiryMs - Expiry time in milliseconds (default: 1 hour)
   * @returns {Date} - Expiry date
   */
  static generateTokenExpiry(expiryMs = null) {
    const expiry = expiryMs || parseInt(process.env.RESET_TOKEN_EXPIRY) || 3600000; // 1 hour default
    return new Date(Date.now() + expiry);
  }

  /**
   * Create and store a password reset token for a user
   * @param {Object} user - User document
   * @returns {Promise<string>} - Generated token
   */
  static async createPasswordResetToken(user) {
    try {
      const token = this.generateResetToken();
      const expiry = this.generateTokenExpiry();

      // Update user with reset token
      user.resetToken = token;
      user.resetTokenExpiry = expiry;
      user.resetTokenUsed = false;

      await user.save();

      logger.info('Password reset token created', {
        userId: user._id,
        email: user.email,
        tokenExpiry: expiry
      });

      return token;

    } catch (error) {
      logger.error('Failed to create password reset token', {
        error: error.message,
        userId: user._id,
        email: user.email
      });
      throw error;
    }
  }

  /**
   * Validate a password reset token
   * @param {string} token - Token to validate
   * @returns {Promise<Object|null>} - User object if valid, null if invalid
   */
  static async validateResetToken(token) {
    try {
      if (!token || typeof token !== 'string') {
        return null;
      }

      const user = await User.findOne({
        resetToken: token,
        resetTokenExpiry: { $gt: new Date() },
        resetTokenUsed: false
      });

      if (!user) {
        logger.warn('Invalid or expired reset token used', {
          token: token.substring(0, 8) + '...' // Log only first 8 chars for security
        });
        return null;
      }

      logger.info('Valid reset token accessed', {
        userId: user._id,
        email: user.email
      });

      return user;

    } catch (error) {
      logger.error('Error validating reset token', {
        error: error.message,
        token: token ? token.substring(0, 8) + '...' : 'null'
      });
      return null;
    }
  }

  /**
   * Mark a reset token as used
   * @param {Object} user - User document
   * @returns {Promise<boolean>} - Success status
   */
  static async markTokenAsUsed(user) {
    try {
      user.resetTokenUsed = true;
      user.resetToken = undefined;
      user.resetTokenExpiry = undefined;

      await user.save();

      logger.info('Reset token marked as used', {
        userId: user._id,
        email: user.email
      });

      return true;

    } catch (error) {
      logger.error('Failed to mark token as used', {
        error: error.message,
        userId: user._id,
        email: user.email
      });
      return false;
    }
  }

  /**
   * Clean up expired reset tokens
   * @returns {Promise<number>} - Number of tokens cleaned up
   */
  static async cleanupExpiredTokens() {
    try {
      const result = await User.updateMany(
        {
          resetTokenExpiry: { $lt: new Date() },
          resetToken: { $exists: true }
        },
        {
          $unset: {
            resetToken: "",
            resetTokenExpiry: ""
          },
          $set: {
            resetTokenUsed: false
          }
        }
      );

      if (result.modifiedCount > 0) {
        logger.info('Expired reset tokens cleaned up', {
          count: result.modifiedCount
        });
      }

      return result.modifiedCount;

    } catch (error) {
      logger.error('Failed to cleanup expired tokens', {
        error: error.message
      });
      return 0;
    }
  }

  /**
   * Check if a user has an active reset token
   * @param {string} email - User email
   * @returns {Promise<boolean>} - True if user has active token
   */
  static async hasActiveResetToken(email) {
    try {
      const user = await User.findOne({
        email: email.toLowerCase(),
        resetToken: { $exists: true },
        resetTokenExpiry: { $gt: new Date() },
        resetTokenUsed: false
      });

      return !!user;

    } catch (error) {
      logger.error('Error checking for active reset token', {
        error: error.message,
        email: email
      });
      return false;
    }
  }

  /**
   * Get reset token statistics
   * @returns {Promise<Object>} - Token statistics
   */
  static async getTokenStatistics() {
    try {
      const stats = await User.aggregate([
        {
          $match: {
            resetToken: { $exists: true }
          }
        },
        {
          $group: {
            _id: null,
            totalTokens: { $sum: 1 },
            activeTokens: {
              $sum: {
                $cond: [
                  {
                    $and: [
                      { $gt: ['$resetTokenExpiry', new Date()] },
                      { $eq: ['$resetTokenUsed', false] }
                    ]
                  },
                  1,
                  0
                ]
              }
            },
            expiredTokens: {
              $sum: {
                $cond: [
                  { $lt: ['$resetTokenExpiry', new Date()] },
                  1,
                  0
                ]
              }
            },
            usedTokens: {
              $sum: {
                $cond: [
                  { $eq: ['$resetTokenUsed', true] },
                  1,
                  0
                ]
              }
            }
          }
        }
      ]);

      const result = stats[0] || {
        totalTokens: 0,
        activeTokens: 0,
        expiredTokens: 0,
        usedTokens: 0
      };

      return result;

    } catch (error) {
      logger.error('Failed to get token statistics', {
        error: error.message
      });
      return {
        totalTokens: 0,
        activeTokens: 0,
        expiredTokens: 0,
        usedTokens: 0
      };
    }
  }

  /**
   * Revoke all reset tokens for a user (security measure)
   * @param {string} userId - User ID
   * @returns {Promise<boolean>} - Success status
   */
  static async revokeUserTokens(userId) {
    try {
      const result = await User.updateOne(
        { _id: userId },
        {
          $unset: {
            resetToken: "",
            resetTokenExpiry: ""
          },
          $set: {
            resetTokenUsed: false
          }
        }
      );

      if (result.modifiedCount > 0) {
        logger.info('User reset tokens revoked', {
          userId: userId
        });
      }

      return result.modifiedCount > 0;

    } catch (error) {
      logger.error('Failed to revoke user tokens', {
        error: error.message,
        userId: userId
      });
      return false;
    }
  }
}

module.exports = TokenUtils;
