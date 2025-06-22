const mongoose = require('mongoose');

const errorLogSchema = new mongoose.Schema({
  // Basic Error Information
  requestId: {
    type: String,
    required: true,
    index: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  errorType: {
    type: String,
    required: true,
    index: true
  },
  statusCode: {
    type: Number,
    required: true,
    index: true
  },
  message: {
    type: String,
    required: true
  },
  errorCode: {
    type: String,
    index: true
  },
  
  // Request Context
  requestContext: {
    method: String,
    url: String,
    originalUrl: String,
    baseUrl: String,
    path: String,
    query: mongoose.Schema.Types.Mixed,
    body: mongoose.Schema.Types.Mixed, // Sanitized body
    headers: mongoose.Schema.Types.Mixed,
    ip: {
      type: String,
      index: true
    },
    userAgent: String,
    referer: String,
    protocol: String,
    secure: Boolean,
    xhr: Boolean
  },
  
  // User Context
  userContext: {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      index: true
    },
    email: String,
    name: String,
    isAdmin: Boolean,
    isSuperAdmin: Boolean,
    isAuthenticated: Boolean,
    sessionId: String,
    probationaryStatus: Boolean
  },
  
  // Error Details
  errorDetails: {
    stack: String,
    originalError: mongoose.Schema.Types.Mixed,
    validationErrors: [mongoose.Schema.Types.Mixed],
    databaseError: mongoose.Schema.Types.Mixed,
    externalServiceError: mongoose.Schema.Types.Mixed
  },
  
  // Environment Context
  environment: {
    nodeVersion: String,
    nodeEnv: String,
    appVersion: String,
    platform: String,
    hostname: String,
    pid: Number,
    uptime: Number,
    memoryUsage: mongoose.Schema.Types.Mixed
  },
  
  // Resolution Tracking
  resolution: {
    status: {
      type: String,
      enum: ['new', 'investigating', 'resolved', 'ignored'],
      default: 'new',
      index: true
    },
    resolvedAt: Date,
    resolvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    adminNotes: String,
    resolution: String,
    tags: [String]
  },
  
  // Analytics
  analytics: {
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      index: true
    },
    category: {
      type: String,
      enum: ['validation', 'authentication', 'authorization', 'database', 'external', 'system', 'user', 'security'],
      index: true
    },
    impact: {
      type: String,
      enum: ['none', 'low', 'medium', 'high', 'critical']
    },
    frequency: {
      type: Number,
      default: 1
    },
    relatedErrors: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ErrorLog'
    }]
  },
  
  // Metadata
  metadata: {
    source: {
      type: String,
      default: 'application'
    },
    version: {
      type: String,
      default: '1.0'
    },
    processed: {
      type: Boolean,
      default: false
    },
    exported: {
      type: Boolean,
      default: false
    },
    notified: {
      type: Boolean,
      default: false
    }
  }
}, {
  timestamps: true,
  collection: 'errorlogs'
});

// Indexes for performance
errorLogSchema.index({ timestamp: -1 });
errorLogSchema.index({ errorType: 1, timestamp: -1 });
errorLogSchema.index({ statusCode: 1, timestamp: -1 });
errorLogSchema.index({ 'userContext.userId': 1, timestamp: -1 });
errorLogSchema.index({ 'requestContext.ip': 1, timestamp: -1 });
errorLogSchema.index({ 'resolution.status': 1, timestamp: -1 });
errorLogSchema.index({ 'analytics.severity': 1, timestamp: -1 });
errorLogSchema.index({ 'analytics.category': 1, timestamp: -1 });

// Compound indexes for common queries
errorLogSchema.index({ errorType: 1, statusCode: 1, timestamp: -1 });
errorLogSchema.index({ 'analytics.severity': 1, 'resolution.status': 1, timestamp: -1 });

// Methods
errorLogSchema.methods.markAsResolved = function(adminUser, resolution, notes) {
  this.resolution.status = 'resolved';
  this.resolution.resolvedAt = new Date();
  this.resolution.resolvedBy = adminUser._id;
  this.resolution.resolution = resolution;
  this.resolution.adminNotes = notes;
  return this.save();
};

errorLogSchema.methods.addAdminNote = function(adminUser, note) {
  const existingNotes = this.resolution.adminNotes || '';
  const timestamp = new Date().toISOString();
  const newNote = `[${timestamp}] ${adminUser.name}: ${note}`;
  this.resolution.adminNotes = existingNotes ? `${existingNotes}\n${newNote}` : newNote;
  return this.save();
};

errorLogSchema.methods.getSimilarErrors = function(timeWindow = 24) {
  const timeAgo = new Date(Date.now() - timeWindow * 60 * 60 * 1000);
  return this.constructor.find({
    _id: { $ne: this._id },
    errorType: this.errorType,
    'requestContext.url': this.requestContext.url,
    timestamp: { $gte: timeAgo }
  }).sort({ timestamp: -1 }).limit(10);
};

errorLogSchema.methods.getAIAnalysisFormat = function() {
  return {
    summary: {
      type: this.errorType,
      occurred: this.timestamp,
      endpoint: `${this.requestContext.method} ${this.requestContext.url}`,
      user: this.userContext.email || 'Anonymous',
      status: this.resolution.status,
      severity: this.analytics.severity
    },
    context: {
      userAction: this.getUserActionDescription(),
      errorMessage: this.message,
      statusCode: this.statusCode,
      requestId: this.requestId
    },
    technical: {
      stack: this.errorDetails.stack,
      originalError: this.errorDetails.originalError,
      environment: this.environment.nodeEnv
    },
    patterns: {
      frequency: this.analytics.frequency,
      category: this.analytics.category,
      impact: this.analytics.impact
    }
  };
};

errorLogSchema.methods.getUserActionDescription = function() {
  const requestContext = this.requestContext || {};
  const method = requestContext.method || 'UNKNOWN';
  const url = requestContext.url || requestContext.originalUrl || 'unknown endpoint';
  
  if (!url || url === 'unknown endpoint') {
    return 'Unknown user action';
  }
  
  if (url.includes('/login')) return 'User attempting to log in';
  if (url.includes('/register')) return 'User attempting to register';
  if (url.includes('/event') && method === 'POST') return 'User creating new event';
  if (url.includes('/event') && method === 'PUT') return 'User updating event';
  if (url.includes('/admin')) return 'Admin performing administrative action';
  if (url.includes('/api/')) return 'API request';
  
  return `User ${method.toLowerCase()} request to ${url}`;
};

// Static methods
errorLogSchema.statics.getErrorStats = function(timeWindow = 24) {
  const timeAgo = new Date(Date.now() - timeWindow * 60 * 60 * 1000);
  
  return this.aggregate([
    { $match: { timestamp: { $gte: timeAgo } } },
    {
      $group: {
        _id: {
          errorType: '$errorType',
          statusCode: '$statusCode'
        },
        count: { $sum: 1 },
        lastOccurred: { $max: '$timestamp' },
        severity: { $first: '$analytics.severity' }
      }
    },
    { $sort: { count: -1 } }
  ]);
};

errorLogSchema.statics.getErrorTrends = function(days = 7) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  return this.aggregate([
    { $match: { timestamp: { $gte: startDate } } },
    {
      $group: {
        _id: {
          date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
          errorType: '$errorType'
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { '_id.date': 1 } }
  ]);
};

errorLogSchema.statics.findSimilarErrors = function(errorLog, limit = 10) {
  return this.find({
    _id: { $ne: errorLog._id },
    $or: [
      { errorType: errorLog.errorType, 'requestContext.url': errorLog.requestContext.url },
      { 'userContext.userId': errorLog.userContext.userId, errorType: errorLog.errorType },
      { 'requestContext.ip': errorLog.requestContext.ip, errorType: errorLog.errorType }
    ]
  }).sort({ timestamp: -1 }).limit(limit);
};

// Auto-cleanup old logs (configurable retention)
errorLogSchema.statics.cleanupOldLogs = function(retentionDays = 90) {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
  
  return this.deleteMany({
    timestamp: { $lt: cutoffDate },
    'resolution.status': { $in: ['resolved', 'ignored'] }
  });
};

// Pre-save middleware to set analytics
errorLogSchema.pre('save', function(next) {
  if (this.isNew) {
    // Set severity based on status code
    if (this.statusCode >= 500) {
      this.analytics.severity = 'high';
    } else if (this.statusCode >= 400) {
      this.analytics.severity = 'medium';
    } else {
      this.analytics.severity = 'low';
    }
    
    // Set category based on error type
    if (this.errorType.includes('Validation')) {
      this.analytics.category = 'validation';
    } else if (this.errorType.includes('Authentication')) {
      this.analytics.category = 'authentication';
    } else if (this.errorType.includes('Authorization')) {
      this.analytics.category = 'authorization';
    } else if (this.errorType.includes('Database')) {
      this.analytics.category = 'database';
    } else if (this.errorType.includes('ExternalService')) {
      this.analytics.category = 'external';
    } else {
      this.analytics.category = 'system';
    }
    
    // Set impact based on user context and error type
    if (this.userContext.isAdmin && this.statusCode >= 500) {
      this.analytics.impact = 'high';
    } else if (this.statusCode >= 500) {
      this.analytics.impact = 'medium';
    } else {
      this.analytics.impact = 'low';
    }
  }
  next();
});

module.exports = mongoose.model('ErrorLog', errorLogSchema);
