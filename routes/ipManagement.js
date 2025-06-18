const express = require('express');
const rateLimit = require('express-rate-limit');

// Import models
const IPAddress = require('../models/IPAddress');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

// Import services
const ipAnalysisService = require('../services/ipAnalysisService');

// Import validation middleware
const { handleValidationErrors } = require('../middleware/validation');
const { validateIPOperation, validateBulkIPOperation } = require('../validators/adminValidators');

// Import centralized error handling
const { asyncErrorHandler } = require('../middleware/errorHandler');

// Import custom errors
const { NotFoundError, ValidationError, AuthorizationError } = require('../utils/errors');

// Import loggers
const { adminLogger, securityLogger } = require('../utils/logger');

const router = express.Router();

// Helper function to get client IP address
const getClientIP = (req) => {
  return req.headers['x-forwarded-for'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         req.ip;
};

// Helper function to create audit log for IP operations
const createIPAuditLog = async (adminUser, action, ipAddress, notes = '', details = {}) => {
  try {
    const auditLog = new AuditLog({
      adminId: adminUser._id,
      adminName: adminUser.name,
      action,
      targetUserId: null,
      targetUserEmail: null,
      targetUserName: ipAddress, // Store IP in targetUserName field for IP operations
      notes,
      ipAddress: getClientIP({ headers: {}, connection: {} }), // Admin's IP
      details: {
        targetIP: ipAddress,
        ...details
      }
    });
    await auditLog.save();
  } catch (err) {
    console.error('Error creating IP audit log:', err);
  }
};

// Import authentication middleware
const { ensureAuthenticated, ensureAdmin, ensureSuperAdmin } = require('../middleware/auth');

// Rate limiter for IP management operations
const ipManagementLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // 50 operations per window per admin
  message: {
    error: 'Too many IP management operations. Please try again later.'
  },
  keyGenerator: (req) => {
    return `ip_mgmt_${req.user?._id || getClientIP(req)}`;
  }
});

// Apply rate limiting to all IP management routes
router.use(ipManagementLimiter);

// Main IP Management Dashboard
router.get('/', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const { 
      status, 
      search, 
      riskLevel, 
      page = 1, 
      limit = 20,
      sortBy = 'riskScore',
      sortOrder = 'desc'
    } = req.query;

    const skip = (page - 1) * limit;
    let query = {};
    let sort = {};

    // Status filter
    if (status && status !== 'all') {
      query.status = status;
    }

    // Risk level filter
    if (riskLevel) {
      switch (riskLevel) {
        case 'low':
          query.riskScore = { $lt: 30 };
          break;
        case 'medium':
          query.riskScore = { $gte: 30, $lt: 70 };
          break;
        case 'high':
          query.riskScore = { $gte: 70 };
          break;
      }
    }

    // Search filter
    if (search) {
      query.ipAddress = { $regex: search, $options: 'i' };
    }

    // Sorting
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    // Get IP addresses with pagination
    const ipAddresses = await IPAddress.find(query)
      .populate('blockedBy whitelistedBy unblockedBy', 'name email')
      .populate('associatedUsers', 'email name status')
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit));

    const totalIPs = await IPAddress.countDocuments(query);
    const totalPages = Math.ceil(totalIPs / limit);

    // Get statistics
    const stats = await ipAnalysisService.getIPStatistics();

    // Get pending counts for navigation
    const pendingCounts = {
      pendingUsers: await User.countDocuments({ status: 'pending' }),
      pendingEvents: 0, // Will be populated if Event model is available
      pendingGames: 0   // Will be populated if Game model is available
    };

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';

    res.render('adminIPManagement', {
      title: 'IP Management',
      currentPage: 'ip-management',
      ipAddresses,
      stats,
      filters: {
        status,
        search,
        riskLevel,
        sortBy,
        sortOrder
      },
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalIPs,
        limit: parseInt(limit)
      },
      user: req.user,
      isDevelopmentAutoLogin,
      ...pendingCounts
    });

  } catch (error) {
    console.error('Error loading IP management dashboard:', error);
    res.status(500).send('Error loading IP management dashboard');
  }
}));

// Get IP details (API endpoint)
router.get('/api/ip/:ipAddress', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { ipAddress } = req.params;
  
  const ipRecord = await IPAddress.findOne({ ipAddress })
    .populate('blockedBy whitelistedBy unblockedBy', 'name email')
    .populate('associatedUsers', 'email name status createdAt')
    .populate('notes.addedBy', 'name email');

  if (!ipRecord) {
    throw new NotFoundError('IP address', ipAddress);
  }

  res.json(ipRecord);
}));

// Block IP address
router.post('/block/:ipAddress', ensureAuthenticated, ensureAdmin, validateIPOperation, handleValidationErrors, asyncErrorHandler(async (req, res) => {
  const { ipAddress } = req.params;
  const { reason } = req.body;
  const clientIP = getClientIP(req);

  if (!reason || reason.trim() === '') {
    throw new ValidationError('Block reason is required');
  }

  const result = await ipAnalysisService.blockIP(ipAddress, req.user, reason);

  if (result.success) {
    await createIPAuditLog(req.user, 'IP_BLOCKED', ipAddress, reason, {
      adminIP: clientIP,
      riskScore: result.ipRecord.riskScore
    });

    console.log(`IP ${ipAddress} blocked by admin ${req.user.email}: ${reason}`);
    res.json({ 
      success: true, 
      message: result.message,
      ipRecord: result.ipRecord
    });
  } else {
    res.status(400).json({ 
      success: false, 
      message: result.message 
    });
  }
}));

// Unblock IP address
router.post('/unblock/:ipAddress', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { ipAddress } = req.params;
  const clientIP = getClientIP(req);

  const result = await ipAnalysisService.unblockIP(ipAddress, req.user);

  if (result.success) {
    await createIPAuditLog(req.user, 'IP_UNBLOCKED', ipAddress, '', {
      adminIP: clientIP,
      newStatus: result.ipRecord.status,
      riskScore: result.ipRecord.riskScore
    });

    console.log(`IP ${ipAddress} unblocked by admin ${req.user.email}`);
    res.json({ 
      success: true, 
      message: result.message,
      ipRecord: result.ipRecord
    });
  } else {
    res.status(400).json({ 
      success: false, 
      message: result.message 
    });
  }
}));

// Whitelist IP address
router.post('/whitelist/:ipAddress', ensureAuthenticated, ensureAdmin, validateIPOperation, handleValidationErrors, asyncErrorHandler(async (req, res) => {
  const { ipAddress } = req.params;
  const { reason } = req.body;
  const clientIP = getClientIP(req);

  if (!reason || reason.trim() === '') {
    throw new ValidationError('Whitelist reason is required');
  }

  const result = await ipAnalysisService.whitelistIP(ipAddress, req.user, reason);

  if (result.success) {
    await createIPAuditLog(req.user, 'IP_WHITELISTED', ipAddress, reason, {
      adminIP: clientIP
    });

    console.log(`IP ${ipAddress} whitelisted by admin ${req.user.email}: ${reason}`);
    res.json({ 
      success: true, 
      message: result.message,
      ipRecord: result.ipRecord
    });
  } else {
    res.status(400).json({ 
      success: false, 
      message: result.message 
    });
  }
}));

// Remove from whitelist
router.post('/remove-whitelist/:ipAddress', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { ipAddress } = req.params;
  const clientIP = getClientIP(req);

  const result = await ipAnalysisService.removeFromWhitelist(ipAddress, req.user);

  if (result.success) {
    await createIPAuditLog(req.user, 'IP_REMOVED_FROM_WHITELIST', ipAddress, '', {
      adminIP: clientIP,
      newStatus: result.ipRecord.status,
      riskScore: result.ipRecord.riskScore
    });

    console.log(`IP ${ipAddress} removed from whitelist by admin ${req.user.email}`);
    res.json({ 
      success: true, 
      message: result.message,
      ipRecord: result.ipRecord
    });
  } else {
    res.status(400).json({ 
      success: false, 
      message: result.message 
    });
  }
}));

// Add note to IP
router.post('/note/:ipAddress', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { ipAddress } = req.params;
  const { content } = req.body;

  if (!content || content.trim() === '') {
    throw new ValidationError('Note content is required');
  }

  const result = await ipAnalysisService.addIPNote(ipAddress, req.user, content);

  if (result.success) {
    console.log(`Note added to IP ${ipAddress} by admin ${req.user.email}`);
    res.json({ 
      success: true, 
      message: result.message,
      ipRecord: result.ipRecord
    });
  } else {
    res.status(400).json({ 
      success: false, 
      message: result.message 
    });
  }
}));

// Bulk IP operations
router.post('/bulk/:action', ensureAuthenticated, ensureAdmin, validateBulkIPOperation, handleValidationErrors, asyncErrorHandler(async (req, res) => {
  const { action } = req.params;
  const { ipAddresses, reason } = req.body;
  const clientIP = getClientIP(req);

  if (!ipAddresses || !Array.isArray(ipAddresses) || ipAddresses.length === 0) {
    throw new ValidationError('IP addresses array is required');
  }

  if ((action === 'block' || action === 'whitelist') && (!reason || reason.trim() === '')) {
    throw new ValidationError(`Reason is required for bulk ${action} operation`);
  }

  const result = await ipAnalysisService.bulkIPOperation(ipAddresses, action, req.user, reason);

  // Create audit log for bulk operation
  await createIPAuditLog(req.user, `BULK_IP_${action.toUpperCase()}`, 'multiple', reason, {
    adminIP: clientIP,
    totalIPs: ipAddresses.length,
    successful: result.success,
    failed: result.failed,
    ipAddresses: ipAddresses
  });

  console.log(`Bulk IP ${action} completed by admin ${req.user.email}: ${result.success} success, ${result.failed} failed`);

  res.json({
    success: true,
    message: `Bulk ${action} completed: ${result.success} successful, ${result.failed} failed`,
    results: result
  });
}));

// Get IP statistics (API endpoint)
router.get('/api/statistics', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const stats = await ipAnalysisService.getIPStatistics();
  res.json(stats);
}));

// Get suspicious IPs (API endpoint)
router.get('/api/suspicious', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { threshold = 50 } = req.query;
  const suspiciousIPs = await IPAddress.getSuspiciousIPs(parseInt(threshold));
  res.json(suspiciousIPs);
}));

// Get blocked IPs (API endpoint)
router.get('/api/blocked', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const blockedIPs = await IPAddress.getBlockedIPs();
  res.json(blockedIPs);
}));

// Get whitelisted IPs (API endpoint)
router.get('/api/whitelisted', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const whitelistedIPs = await IPAddress.getWhitelistedIPs();
  res.json(whitelistedIPs);
}));

// Search IPs (API endpoint)
router.get('/api/search', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { q, status, limit = 10 } = req.query;
  
  if (!q || q.length < 2) {
    return res.json([]);
  }

  let query = {
    ipAddress: { $regex: q, $options: 'i' }
  };

  if (status && status !== 'all') {
    query.status = status;
  }

  const results = await IPAddress.find(query)
    .select('ipAddress status riskScore registrationCount')
    .limit(parseInt(limit))
    .sort({ riskScore: -1 });

  res.json(results);
}));

// Migrate existing IPs (SuperAdmin only)
router.post('/migrate', ensureAuthenticated, ensureSuperAdmin, asyncErrorHandler(async (req, res) => {
  const clientIP = getClientIP(req);
  
  console.log(`IP migration started by SuperAdmin: ${req.user.email}`);
  
  const result = await ipAnalysisService.migrateExistingIPs();

  // Create audit log for migration
  await createIPAuditLog(req.user, 'IP_MIGRATION_EXECUTED', 'system', 'Migrated existing user registration IPs', {
    adminIP: clientIP,
    migrationResult: result
  });

  if (result.success) {
    console.log(`IP migration completed by SuperAdmin ${req.user.email}:`, result);
    res.json({
      success: true,
      message: `Migration completed: ${result.created} created, ${result.updated} updated, ${result.errors} errors`,
      details: result
    });
  } else {
    console.error(`IP migration failed for SuperAdmin ${req.user.email}:`, result.error);
    res.status(500).json({
      success: false,
      message: 'Migration failed',
      error: result.error
    });
  }
}));

// Export IP data (CSV format)
router.get('/export', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { status, riskLevel } = req.query;
  
  let query = {};
  
  if (status && status !== 'all') {
    query.status = status;
  }
  
  if (riskLevel) {
    switch (riskLevel) {
      case 'low':
        query.riskScore = { $lt: 30 };
        break;
      case 'medium':
        query.riskScore = { $gte: 30, $lt: 70 };
        break;
      case 'high':
        query.riskScore = { $gte: 70 };
        break;
    }
  }

  const ipAddresses = await IPAddress.find(query)
    .populate('blockedBy whitelistedBy', 'name email')
    .sort({ riskScore: -1 })
    .limit(1000); // Limit export to 1000 records

  // Create CSV content
  const csvHeader = 'IP Address,Status,Risk Score,Registration Count,First Seen,Last Seen,Blocked By,Block Reason,Whitelisted By,Whitelist Reason\n';
  const csvRows = ipAddresses.map(ip => {
    const ipAddress = ip.ipAddress;
    const status = ip.status;
    const riskScore = ip.riskScore;
    const registrationCount = ip.registrationCount;
    const firstSeen = ip.firstSeen.toISOString();
    const lastSeen = ip.lastSeen.toISOString();
    const blockedBy = ip.blockedBy ? ip.blockedBy.email : '';
    const blockReason = `"${(ip.blockReason || '').replace(/"/g, '""')}"`;
    const whitelistedBy = ip.whitelistedBy ? ip.whitelistedBy.email : '';
    const whitelistReason = `"${(ip.whitelistReason || '').replace(/"/g, '""')}"`;
    
    return `${ipAddress},${status},${riskScore},${registrationCount},${firstSeen},${lastSeen},${blockedBy},${blockReason},${whitelistedBy},${whitelistReason}`;
  }).join('\n');

  const csvContent = csvHeader + csvRows;

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="ip-addresses-${new Date().toISOString().split('T')[0]}.csv"`);
  res.send(csvContent);
}));

// Health check endpoint
router.get('/health', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const stats = await ipAnalysisService.getIPStatistics();
  const recentActivity = await IPAddress.countDocuments({
    'analytics.lastActivity': { $gte: new Date(Date.now() - 60 * 60 * 1000) } // Last hour
  });

  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    statistics: stats,
    recentActivity
  });
}));

module.exports = router;
