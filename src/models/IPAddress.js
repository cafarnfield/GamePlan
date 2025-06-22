const mongoose = require('mongoose');

const ipAddressSchema = new mongoose.Schema({
  ipAddress: {
    type: String,
    required: true,
    unique: true,
    index: true,
    validate: {
      validator: function(v) {
        // Basic IP validation (IPv4 and IPv6)
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        // More comprehensive IPv6 regex that handles compressed notation like ::1
        const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
        return ipv4Regex.test(v) || ipv6Regex.test(v);
      },
      message: 'Invalid IP address format'
    }
  },
  status: {
    type: String,
    enum: ['allowed', 'blocked', 'suspicious', 'whitelisted'],
    default: 'allowed',
    index: true
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0,
    index: true
  },
  registrationCount: {
    type: Number,
    default: 0,
    index: true
  },
  firstSeen: {
    type: Date,
    default: Date.now,
    index: true
  },
  lastSeen: {
    type: Date,
    default: Date.now,
    index: true
  },
  blockedAt: {
    type: Date,
    sparse: true,
    index: true
  },
  blockedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    sparse: true
  },
  blockReason: {
    type: String,
    maxlength: 500
  },
  unblockedAt: {
    type: Date,
    sparse: true
  },
  unblockedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    sparse: true
  },
  whitelistedAt: {
    type: Date,
    sparse: true
  },
  whitelistedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    sparse: true
  },
  whitelistReason: {
    type: String,
    maxlength: 500
  },
  associatedUsers: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  metadata: {
    country: String,
    region: String,
    city: String,
    isp: String,
    isProxy: Boolean,
    isVPN: Boolean,
    threatLevel: String,
    lastUserAgent: String
  },
  analytics: {
    totalRequests: { type: Number, default: 0 },
    failedLogins: { type: Number, default: 0 },
    successfulLogins: { type: Number, default: 0 },
    rateLimitHits: { type: Number, default: 0 },
    lastActivity: Date,
    suspiciousPatterns: [{
      type: String,
      detectedAt: Date,
      severity: String
    }]
  },
  notes: [{
    content: String,
    addedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true
});

// Compound indexes for efficient querying
ipAddressSchema.index({ status: 1, riskScore: -1 });
ipAddressSchema.index({ registrationCount: -1, firstSeen: -1 });
ipAddressSchema.index({ lastSeen: -1, status: 1 });
ipAddressSchema.index({ 'analytics.lastActivity': -1 });

// Instance methods
ipAddressSchema.methods.calculateRiskScore = function() {
  let score = 0;
  
  // Base score from registration count
  if (this.registrationCount >= 10) score += 70;
  else if (this.registrationCount >= 5) score += 50;
  else if (this.registrationCount >= 3) score += 30;
  
  // Failed login attempts
  if (this.analytics.failedLogins >= 10) score += 20;
  else if (this.analytics.failedLogins >= 5) score += 10;
  
  // Rate limit violations
  if (this.analytics.rateLimitHits >= 5) score += 15;
  
  // Proxy/VPN detection
  if (this.metadata.isProxy || this.metadata.isVPN) score += 10;
  
  // Suspicious patterns
  if (this.analytics.suspiciousPatterns.length >= 3) score += 20;
  else if (this.analytics.suspiciousPatterns.length >= 1) score += 10;
  
  // Time-based factors
  const now = new Date();
  const daysSinceFirstSeen = (now - this.firstSeen) / (1000 * 60 * 60 * 24);
  
  // Rapid registrations (multiple registrations in short time)
  if (this.registrationCount >= 3 && daysSinceFirstSeen < 1) score += 25;
  else if (this.registrationCount >= 2 && daysSinceFirstSeen < 0.1) score += 15;
  
  // Cap at 100
  this.riskScore = Math.min(score, 100);
  return this.riskScore;
};

ipAddressSchema.methods.addSuspiciousPattern = function(pattern, severity = 'medium') {
  this.analytics.suspiciousPatterns.push({
    type: pattern,
    detectedAt: new Date(),
    severity: severity
  });
  
  // Keep only last 10 patterns
  if (this.analytics.suspiciousPatterns.length > 10) {
    this.analytics.suspiciousPatterns = this.analytics.suspiciousPatterns.slice(-10);
  }
  
  this.calculateRiskScore();
};

ipAddressSchema.methods.blockIP = function(adminUser, reason) {
  this.status = 'blocked';
  this.blockedAt = new Date();
  this.blockedBy = adminUser._id;
  this.blockReason = reason;
  this.unblockedAt = undefined;
  this.unblockedBy = undefined;
};

ipAddressSchema.methods.unblockIP = function(adminUser) {
  this.status = this.riskScore >= 50 ? 'suspicious' : 'allowed';
  this.unblockedAt = new Date();
  this.unblockedBy = adminUser._id;
  this.blockedAt = undefined;
  this.blockedBy = undefined;
  this.blockReason = undefined;
};

ipAddressSchema.methods.whitelistIP = function(adminUser, reason) {
  this.status = 'whitelisted';
  this.whitelistedAt = new Date();
  this.whitelistedBy = adminUser._id;
  this.whitelistReason = reason;
  this.riskScore = 0;
  
  // Clear any blocks
  this.blockedAt = undefined;
  this.blockedBy = undefined;
  this.blockReason = undefined;
};

ipAddressSchema.methods.removeFromWhitelist = function(adminUser) {
  this.status = this.riskScore >= 50 ? 'suspicious' : 'allowed';
  this.whitelistedAt = undefined;
  this.whitelistedBy = undefined;
  this.whitelistReason = undefined;
  this.calculateRiskScore();
};

ipAddressSchema.methods.addNote = function(adminUser, content) {
  this.notes.push({
    content: content,
    addedBy: adminUser._id,
    addedAt: new Date()
  });
  
  // Keep only last 20 notes
  if (this.notes.length > 20) {
    this.notes = this.notes.slice(-20);
  }
};

ipAddressSchema.methods.updateActivity = function() {
  this.lastSeen = new Date();
  this.analytics.lastActivity = new Date();
  this.analytics.totalRequests += 1;
};

ipAddressSchema.methods.recordFailedLogin = function() {
  this.analytics.failedLogins += 1;
  this.updateActivity();
  
  // Add suspicious pattern if too many failed logins
  if (this.analytics.failedLogins >= 5) {
    this.addSuspiciousPattern('excessive_failed_logins', 'high');
  }
};

ipAddressSchema.methods.recordSuccessfulLogin = function() {
  this.analytics.successfulLogins += 1;
  this.updateActivity();
};

ipAddressSchema.methods.recordRateLimitHit = function() {
  this.analytics.rateLimitHits += 1;
  this.updateActivity();
  
  // Add suspicious pattern if too many rate limit hits
  if (this.analytics.rateLimitHits >= 3) {
    this.addSuspiciousPattern('rate_limit_violations', 'medium');
  }
};

// Static methods
ipAddressSchema.statics.findOrCreateIP = async function(ipAddress, userAgent = null) {
  let ipRecord = await this.findOne({ ipAddress });
  
  if (!ipRecord) {
    ipRecord = new this({
      ipAddress,
      metadata: {
        lastUserAgent: userAgent
      }
    });
    await ipRecord.save();
  } else {
    ipRecord.updateActivity();
    if (userAgent) {
      ipRecord.metadata.lastUserAgent = userAgent;
    }
    await ipRecord.save();
  }
  
  return ipRecord;
};

ipAddressSchema.statics.getSuspiciousIPs = async function(threshold = 50) {
  return this.find({
    $or: [
      { status: 'suspicious' },
      { status: 'blocked' },
      { riskScore: { $gte: threshold } },
      { registrationCount: { $gte: 3 } }
    ]
  }).populate('blockedBy whitelistedBy associatedUsers', 'name email')
    .sort({ riskScore: -1, registrationCount: -1 });
};

ipAddressSchema.statics.getBlockedIPs = async function() {
  return this.find({ status: 'blocked' })
    .populate('blockedBy', 'name email')
    .sort({ blockedAt: -1 });
};

ipAddressSchema.statics.getWhitelistedIPs = async function() {
  return this.find({ status: 'whitelisted' })
    .populate('whitelistedBy', 'name email')
    .sort({ whitelistedAt: -1 });
};

ipAddressSchema.statics.getIPStats = async function() {
  const stats = await this.aggregate([
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        avgRiskScore: { $avg: '$riskScore' }
      }
    }
  ]);
  
  const totalIPs = await this.countDocuments();
  const highRiskIPs = await this.countDocuments({ riskScore: { $gte: 70 } });
  const recentActivity = await this.countDocuments({
    'analytics.lastActivity': { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
  });
  
  return {
    total: totalIPs,
    highRisk: highRiskIPs,
    recentActivity,
    byStatus: stats.reduce((acc, stat) => {
      acc[stat._id] = {
        count: stat.count,
        avgRiskScore: Math.round(stat.avgRiskScore || 0)
      };
      return acc;
    }, {})
  };
};

// Pre-save middleware to update risk score
ipAddressSchema.pre('save', function(next) {
  if (this.isModified('registrationCount') || 
      this.isModified('analytics.failedLogins') || 
      this.isModified('analytics.rateLimitHits') ||
      this.isModified('analytics.suspiciousPatterns')) {
    this.calculateRiskScore();
    
    // Auto-flag as suspicious if risk score is high
    if (this.riskScore >= 50 && this.status === 'allowed') {
      this.status = 'suspicious';
    }
  }
  next();
});

const IPAddress = mongoose.model('IPAddress', ipAddressSchema);

module.exports = IPAddress;
