/**
 * IP Analysis Service for GamePlan Application
 * Handles IP risk assessment, pattern detection, and management operations
 */

const IPAddress = require('../models/IPAddress');
const User = require('../models/User');
const { adminLogger, securityLogger } = require('../utils/logger');

class IPAnalysisService {
  constructor() {
    this.suspiciousThreshold = 50;
    this.highRiskThreshold = 70;
    this.autoBlockThreshold = 85;
  }

  /**
   * Process a new user registration and update IP tracking
   * @param {string} ipAddress - The IP address
   * @param {Object} user - The user object
   * @param {string} userAgent - User agent string
   */
  async processUserRegistration(ipAddress, user, userAgent = null) {
    try {
      if (!ipAddress) return null;

      // Find or create IP record
      let ipRecord = await IPAddress.findOrCreateIP(ipAddress, userAgent);
      
      // Update registration count and associate user
      ipRecord.registrationCount += 1;
      if (!ipRecord.associatedUsers.includes(user._id)) {
        ipRecord.associatedUsers.push(user._id);
      }
      
      // Check for suspicious patterns
      await this.detectSuspiciousPatterns(ipRecord, user);
      
      // Save the updated record
      await ipRecord.save();
      
      // Log if IP becomes suspicious
      if (ipRecord.status === 'suspicious' || ipRecord.riskScore >= this.suspiciousThreshold) {
        securityLogger.logSecurityEvent('SUSPICIOUS_IP_DETECTED', 'warn', {
          ipAddress: ipAddress,
          riskScore: ipRecord.riskScore,
          registrationCount: ipRecord.registrationCount,
          userId: user._id,
          userEmail: user.email
        });
      }
      
      return ipRecord;
    } catch (error) {
      console.error('Error processing user registration for IP analysis:', error);
      return null;
    }
  }

  /**
   * Detect suspicious patterns in user registrations from the same IP
   * @param {Object} ipRecord - The IP record
   * @param {Object} newUser - The newly registered user
   */
  async detectSuspiciousPatterns(ipRecord, newUser) {
    try {
      // Get all users from this IP
      const users = await User.find({ 
        _id: { $in: ipRecord.associatedUsers } 
      }).select('email name gameNickname createdAt status');

      // Pattern 1: Rapid registrations
      const recentUsers = users.filter(user => {
        const timeDiff = (new Date() - user.createdAt) / (1000 * 60); // minutes
        return timeDiff <= 60; // Within last hour
      });

      if (recentUsers.length >= 3) {
        ipRecord.addSuspiciousPattern('rapid_registrations', 'high');
      } else if (recentUsers.length >= 2) {
        ipRecord.addSuspiciousPattern('rapid_registrations', 'medium');
      }

      // Pattern 2: Sequential email addresses
      const emails = users.map(u => u.email).sort();
      if (this.detectSequentialEmails(emails)) {
        ipRecord.addSuspiciousPattern('sequential_emails', 'high');
      }

      // Pattern 3: Similar usernames/nicknames
      const names = users.map(u => u.name || '').concat(users.map(u => u.gameNickname || ''));
      if (this.detectSimilarNames(names)) {
        ipRecord.addSuspiciousPattern('similar_usernames', 'medium');
      }

      // Pattern 4: High rejection rate
      const rejectedCount = users.filter(u => u.status === 'rejected').length;
      const rejectionRate = users.length > 0 ? rejectedCount / users.length : 0;
      
      if (rejectionRate >= 0.7 && users.length >= 3) {
        ipRecord.addSuspiciousPattern('high_rejection_rate', 'high');
      }

      // Pattern 5: Multiple registrations in very short time (bot-like behavior)
      const sortedUsers = users.sort((a, b) => a.createdAt - b.createdAt);
      for (let i = 1; i < sortedUsers.length; i++) {
        const timeDiff = (sortedUsers[i].createdAt - sortedUsers[i-1].createdAt) / 1000; // seconds
        if (timeDiff < 30) { // Less than 30 seconds between registrations
          ipRecord.addSuspiciousPattern('bot_like_behavior', 'high');
          break;
        }
      }

    } catch (error) {
      console.error('Error detecting suspicious patterns:', error);
    }
  }

  /**
   * Detect sequential email patterns (user1@domain.com, user2@domain.com, etc.)
   * @param {Array} emails - Array of email addresses
   * @returns {boolean} - True if sequential pattern detected
   */
  detectSequentialEmails(emails) {
    const patterns = {};
    
    emails.forEach(email => {
      const match = email.match(/^(.+?)(\d+)@(.+)$/);
      if (match) {
        const [, prefix, number, domain] = match;
        const key = `${prefix}@${domain}`;
        if (!patterns[key]) patterns[key] = [];
        patterns[key].push(parseInt(number));
      }
    });

    // Check if any pattern has sequential numbers
    for (const pattern in patterns) {
      const numbers = patterns[pattern].sort((a, b) => a - b);
      if (numbers.length >= 3) {
        let sequential = 0;
        for (let i = 1; i < numbers.length; i++) {
          if (numbers[i] === numbers[i-1] + 1) {
            sequential++;
            if (sequential >= 2) return true; // 3 sequential numbers
          } else {
            sequential = 0;
          }
        }
      }
    }
    
    return false;
  }

  /**
   * Detect similar usernames or nicknames
   * @param {Array} names - Array of names
   * @returns {boolean} - True if similar names detected
   */
  detectSimilarNames(names) {
    const cleanNames = names.filter(name => name && name.length > 2).map(name => name.toLowerCase());
    
    if (cleanNames.length < 2) return false;

    // Check for names that are very similar (Levenshtein distance)
    for (let i = 0; i < cleanNames.length; i++) {
      for (let j = i + 1; j < cleanNames.length; j++) {
        const distance = this.levenshteinDistance(cleanNames[i], cleanNames[j]);
        const maxLength = Math.max(cleanNames[i].length, cleanNames[j].length);
        const similarity = 1 - (distance / maxLength);
        
        if (similarity >= 0.8 && maxLength >= 4) { // 80% similar and at least 4 characters
          return true;
        }
      }
    }

    // Check for names with common prefixes/suffixes
    const prefixes = {};
    const suffixes = {};
    
    cleanNames.forEach(name => {
      if (name.length >= 4) {
        const prefix = name.substring(0, 3);
        const suffix = name.substring(name.length - 3);
        
        prefixes[prefix] = (prefixes[prefix] || 0) + 1;
        suffixes[suffix] = (suffixes[suffix] || 0) + 1;
      }
    });

    // If 3+ names share the same prefix or suffix
    return Object.values(prefixes).some(count => count >= 3) || 
           Object.values(suffixes).some(count => count >= 3);
  }

  /**
   * Calculate Levenshtein distance between two strings
   * @param {string} str1 - First string
   * @param {string} str2 - Second string
   * @returns {number} - Edit distance
   */
  levenshteinDistance(str1, str2) {
    const matrix = [];
    
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    
    return matrix[str2.length][str1.length];
  }

  /**
   * Block an IP address manually
   * @param {string} ipAddress - The IP address to block
   * @param {Object} adminUser - The admin user performing the action
   * @param {string} reason - Reason for blocking
   * @returns {Object} - Result object
   */
  async blockIP(ipAddress, adminUser, reason) {
    try {
      let ipRecord = await IPAddress.findOrCreateIP(ipAddress);
      
      if (ipRecord.status === 'blocked') {
        return { success: false, message: 'IP is already blocked' };
      }

      if (ipRecord.status === 'whitelisted') {
        return { success: false, message: 'Cannot block whitelisted IP. Remove from whitelist first.' };
      }

      ipRecord.blockIP(adminUser, reason);
      await ipRecord.save();

      // Log the action
      adminLogger.logAdminAction('IP_BLOCKED', adminUser._id, null, {
        ipAddress: ipAddress,
        reason: reason,
        previousStatus: ipRecord.status,
        riskScore: ipRecord.riskScore
      });

      securityLogger.logSecurityEvent('IP_MANUALLY_BLOCKED', 'info', {
        ipAddress: ipAddress,
        blockedBy: adminUser.email,
        reason: reason
      });

      return { success: true, message: 'IP blocked successfully', ipRecord };
    } catch (error) {
      console.error('Error blocking IP:', error);
      return { success: false, message: 'Error blocking IP address' };
    }
  }

  /**
   * Unblock an IP address manually
   * @param {string} ipAddress - The IP address to unblock
   * @param {Object} adminUser - The admin user performing the action
   * @returns {Object} - Result object
   */
  async unblockIP(ipAddress, adminUser) {
    try {
      const ipRecord = await IPAddress.findOne({ ipAddress });
      
      if (!ipRecord) {
        return { success: false, message: 'IP address not found' };
      }

      if (ipRecord.status !== 'blocked') {
        return { success: false, message: 'IP is not currently blocked' };
      }

      const previousStatus = ipRecord.status;
      ipRecord.unblockIP(adminUser);
      await ipRecord.save();

      // Log the action
      adminLogger.logAdminAction('IP_UNBLOCKED', adminUser._id, null, {
        ipAddress: ipAddress,
        previousStatus: previousStatus,
        newStatus: ipRecord.status,
        riskScore: ipRecord.riskScore
      });

      securityLogger.logSecurityEvent('IP_MANUALLY_UNBLOCKED', 'info', {
        ipAddress: ipAddress,
        unblockedBy: adminUser.email,
        newStatus: ipRecord.status
      });

      return { success: true, message: 'IP unblocked successfully', ipRecord };
    } catch (error) {
      console.error('Error unblocking IP:', error);
      return { success: false, message: 'Error unblocking IP address' };
    }
  }

  /**
   * Add IP to whitelist
   * @param {string} ipAddress - The IP address to whitelist
   * @param {Object} adminUser - The admin user performing the action
   * @param {string} reason - Reason for whitelisting
   * @returns {Object} - Result object
   */
  async whitelistIP(ipAddress, adminUser, reason) {
    try {
      let ipRecord = await IPAddress.findOrCreateIP(ipAddress);
      
      if (ipRecord.status === 'whitelisted') {
        return { success: false, message: 'IP is already whitelisted' };
      }

      const previousStatus = ipRecord.status;
      ipRecord.whitelistIP(adminUser, reason);
      await ipRecord.save();

      // Log the action
      adminLogger.logAdminAction('IP_WHITELISTED', adminUser._id, null, {
        ipAddress: ipAddress,
        reason: reason,
        previousStatus: previousStatus
      });

      securityLogger.logSecurityEvent('IP_WHITELISTED', 'info', {
        ipAddress: ipAddress,
        whitelistedBy: adminUser.email,
        reason: reason
      });

      return { success: true, message: 'IP whitelisted successfully', ipRecord };
    } catch (error) {
      console.error('Error whitelisting IP:', error);
      return { success: false, message: 'Error whitelisting IP address' };
    }
  }

  /**
   * Remove IP from whitelist
   * @param {string} ipAddress - The IP address to remove from whitelist
   * @param {Object} adminUser - The admin user performing the action
   * @returns {Object} - Result object
   */
  async removeFromWhitelist(ipAddress, adminUser) {
    try {
      const ipRecord = await IPAddress.findOne({ ipAddress });
      
      if (!ipRecord) {
        return { success: false, message: 'IP address not found' };
      }

      if (ipRecord.status !== 'whitelisted') {
        return { success: false, message: 'IP is not currently whitelisted' };
      }

      ipRecord.removeFromWhitelist(adminUser);
      await ipRecord.save();

      // Log the action
      adminLogger.logAdminAction('IP_REMOVED_FROM_WHITELIST', adminUser._id, null, {
        ipAddress: ipAddress,
        newStatus: ipRecord.status,
        riskScore: ipRecord.riskScore
      });

      return { success: true, message: 'IP removed from whitelist successfully', ipRecord };
    } catch (error) {
      console.error('Error removing IP from whitelist:', error);
      return { success: false, message: 'Error removing IP from whitelist' };
    }
  }

  /**
   * Add a note to an IP record
   * @param {string} ipAddress - The IP address
   * @param {Object} adminUser - The admin user adding the note
   * @param {string} content - Note content
   * @returns {Object} - Result object
   */
  async addIPNote(ipAddress, adminUser, content) {
    try {
      let ipRecord = await IPAddress.findOrCreateIP(ipAddress);
      ipRecord.addNote(adminUser, content);
      await ipRecord.save();

      return { success: true, message: 'Note added successfully', ipRecord };
    } catch (error) {
      console.error('Error adding IP note:', error);
      return { success: false, message: 'Error adding note to IP' };
    }
  }

  /**
   * Get comprehensive IP statistics
   * @returns {Object} - IP statistics
   */
  async getIPStatistics() {
    try {
      const stats = await IPAddress.getIPStats();
      
      // Additional statistics
      const recentSuspicious = await IPAddress.countDocuments({
        status: 'suspicious',
        updatedAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      });

      const autoBlocked = await IPAddress.countDocuments({
        status: 'blocked',
        riskScore: { $gte: this.autoBlockThreshold }
      });

      return {
        ...stats,
        recentSuspicious,
        autoBlocked,
        thresholds: {
          suspicious: this.suspiciousThreshold,
          highRisk: this.highRiskThreshold,
          autoBlock: this.autoBlockThreshold
        }
      };
    } catch (error) {
      console.error('Error getting IP statistics:', error);
      return null;
    }
  }

  /**
   * Perform bulk operations on multiple IPs
   * @param {Array} ipAddresses - Array of IP addresses
   * @param {string} action - Action to perform (block, unblock, whitelist)
   * @param {Object} adminUser - Admin user performing the action
   * @param {string} reason - Reason for the action
   * @returns {Object} - Result object with success/failure counts
   */
  async bulkIPOperation(ipAddresses, action, adminUser, reason = '') {
    const results = {
      success: 0,
      failed: 0,
      errors: []
    };

    for (const ipAddress of ipAddresses) {
      try {
        let result;
        
        switch (action) {
          case 'block':
            result = await this.blockIP(ipAddress, adminUser, reason);
            break;
          case 'unblock':
            result = await this.unblockIP(ipAddress, adminUser);
            break;
          case 'whitelist':
            result = await this.whitelistIP(ipAddress, adminUser, reason);
            break;
          default:
            result = { success: false, message: 'Invalid action' };
        }

        if (result.success) {
          results.success++;
        } else {
          results.failed++;
          results.errors.push(`${ipAddress}: ${result.message}`);
        }
      } catch (error) {
        results.failed++;
        results.errors.push(`${ipAddress}: ${error.message}`);
      }
    }

    // Log bulk operation
    adminLogger.logAdminAction(`BULK_IP_${action.toUpperCase()}`, adminUser._id, null, {
      action: action,
      totalIPs: ipAddresses.length,
      successful: results.success,
      failed: results.failed,
      reason: reason
    });

    return results;
  }

  /**
   * Migrate existing user registration IPs to the new IP management system
   * @returns {Object} - Migration results
   */
  async migrateExistingIPs() {
    try {
      console.log('Starting IP migration...');
      
      // Get all users with registration IPs
      const users = await User.find({ 
        registrationIP: { $exists: true, $ne: null, $ne: '' } 
      }).select('registrationIP email createdAt status');

      const ipMap = new Map();
      
      // Group users by IP
      users.forEach(user => {
        const ip = user.registrationIP;
        if (!ipMap.has(ip)) {
          ipMap.set(ip, []);
        }
        ipMap.get(ip).push(user);
      });

      let created = 0;
      let updated = 0;
      let errors = 0;

      // Process each IP
      for (const [ipAddress, ipUsers] of ipMap) {
        try {
          let ipRecord = await IPAddress.findOne({ ipAddress });
          
          if (!ipRecord) {
            // Create new IP record
            ipRecord = new IPAddress({
              ipAddress,
              registrationCount: ipUsers.length,
              firstSeen: new Date(Math.min(...ipUsers.map(u => u.createdAt))),
              lastSeen: new Date(Math.max(...ipUsers.map(u => u.createdAt))),
              associatedUsers: ipUsers.map(u => u._id)
            });
            created++;
          } else {
            // Update existing record
            ipRecord.registrationCount = ipUsers.length;
            ipRecord.firstSeen = new Date(Math.min(...ipUsers.map(u => u.createdAt)));
            ipRecord.lastSeen = new Date(Math.max(...ipUsers.map(u => u.createdAt)));
            ipRecord.associatedUsers = [...new Set([...ipRecord.associatedUsers, ...ipUsers.map(u => u._id)])];
            updated++;
          }

          // Calculate risk score and detect patterns
          ipRecord.calculateRiskScore();
          
          // Force recalculation by marking registrationCount as modified
          ipRecord.markModified('registrationCount');
          await ipRecord.save();

        } catch (error) {
          console.error(`Error processing IP ${ipAddress}:`, error);
          errors++;
        }
      }

      console.log(`IP migration completed: ${created} created, ${updated} updated, ${errors} errors`);
      
      return {
        success: true,
        created,
        updated,
        errors,
        totalIPs: ipMap.size,
        totalUsers: users.length
      };

    } catch (error) {
      console.error('Error during IP migration:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new IPAnalysisService();
