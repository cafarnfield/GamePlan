const express = require('express');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');

// Import models
const User = require('../models/User');
const Event = require('../models/Event');
const Game = require('../models/Game');
const AuditLog = require('../models/AuditLog');
const RejectedEmail = require('../models/RejectedEmail');
const ErrorLog = require('../models/ErrorLog');

// Import validation middleware and validators
const { handleValidationErrors } = require('../middleware/validation');
const {
  validateUserApproval,
  validateUserRejection,
  validateBulkUserOperation,
  validateGameApproval,
  validateAdminGameAddition,
  validateBulkEventOperation
} = require('../validators/adminValidators');

// Import centralized error handling
const {
  asyncErrorHandler
} = require('../middleware/errorHandler');

// Import custom errors
const {
  NotFoundError,
  AuthorizationError,
  ValidationError,
  DatabaseError
} = require('../utils/errors');

// Import loggers
const { adminLogger, systemLogger } = require('../utils/logger');

const router = express.Router();

// Helper function to get client IP address
const getClientIP = (req) => {
  return req.headers['x-forwarded-for'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         req.ip;
};

// Helper function to create audit log
const createAuditLog = async (adminUser, action, targetUser, notes = '', ipAddress = '', bulkCount = 1, details = {}) => {
  try {
    const auditLog = new AuditLog({
      adminId: adminUser._id,
      adminName: adminUser.name,
      action,
      targetUserId: targetUser ? targetUser._id : null,
      targetUserEmail: targetUser ? targetUser.email : null,
      targetUserName: targetUser ? targetUser.name : null,
      notes,
      ipAddress,
      bulkCount,
      details
    });
    await auditLog.save();
    adminLogger.logAdminAction(action, adminUser._id, targetUser?._id, {
      targetEmail: targetUser?.email,
      notes,
      ipAddress,
      bulkCount,
      details
    });
  } catch (err) {
    adminLogger.error('Error creating audit log', {
      error: err.message,
      action,
      adminId: adminUser._id,
      targetUserId: targetUser?._id
    });
  }
};

// Helper function to get pending counts for admin navigation
const getPendingCounts = async () => {
  try {
    return {
      pendingUsers: await User.countDocuments({ status: 'pending' }),
      pendingEvents: await Event.countDocuments({ gameStatus: 'pending' }),
      pendingGames: await Game.countDocuments({ status: 'pending' })
    };
  } catch (err) {
    adminLogger.error('Error getting pending counts', {
      error: err.message,
      stack: err.stack
    });
    return {
      pendingUsers: 0,
      pendingEvents: 0,
      pendingGames: 0
    };
  }
};

// Helper function to set probationary period
const setProbationaryPeriod = (user, days = 30) => {
  const probationEnd = new Date();
  probationEnd.setDate(probationEnd.getDate() + days);
  user.probationaryUntil = probationEnd;
  return user;
};

// Middleware to check if user is authenticated
const ensureAuthenticated = (req, res, next) => {
  // Check for auto-login in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development') {
    return next();
  }
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

// Middleware to check if user is admin
const ensureAdmin = (req, res, next) => {
  console.log('ensureAdmin middleware accessed');
  console.log('req.isAuthenticated():', req.isAuthenticated());
  console.log('req.user:', req.user);

  // Check for auto-login admin in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development' && req.user && req.user.isAdmin) {
    return next();
  }

  if (req.isAuthenticated() && req.user && req.user.isAdmin) {
    return next();
  }
  
  throw new AuthorizationError('You are not authorized to perform this action');
};

// Middleware to check if user is super admin
const ensureSuperAdmin = (req, res, next) => {
  console.log('ensureSuperAdmin middleware accessed');
  console.log('req.user:', req.user);

  // Check for auto-login super admin in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development' && req.user && req.user.isSuperAdmin) {
    return next();
  }

  if (req.isAuthenticated() && req.user && req.user.isSuperAdmin) {
    return next();
  }
  
  throw new AuthorizationError('Super Admin privileges required for this action');
};

// Middleware to check admin operation permissions
const checkAdminOperationPermission = async (req, res, next) => {
  try {
    const targetUser = await User.findById(req.params.id);
    
    if (!targetUser) {
      return res.status(404).send('User not found');
    }
    
    // Flamma protection - only Flamma can modify itself
    if (targetUser.isProtected && req.user.email !== targetUser.email) {
      return res.status(403).send('This user is protected and can only be modified by themselves');
    }
    
    // Super Admin operations on admins require super admin privileges
    if (targetUser.isAdmin && !req.user.isSuperAdmin) {
      return res.status(403).send('Super Admin privileges required to modify admin users');
    }
    
    // Cannot delete Super Admins directly (must demote first)
    if (targetUser.isSuperAdmin && req.route.path.includes('delete')) {
      return res.status(403).send('Cannot delete Super Admin directly. Must demote to Admin first.');
    }
    
    // Store target user for use in route handler
    req.targetUser = targetUser;
    next();
  } catch (err) {
    console.error('Error in checkAdminOperationPermission:', err);
    res.status(500).send('Error checking permissions');
  }
};

// Admin Dashboard
router.get('/', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    // Calculate statistics for dashboard
    const stats = {
      totalUsers: await User.countDocuments(),
      approvedUsers: await User.countDocuments({ status: 'approved' }),
      pendingUsers: await User.countDocuments({ status: 'pending' }),
      blockedUsers: await User.countDocuments({ isBlocked: true }),
      totalEvents: await Event.countDocuments(),
      activeEvents: await Event.countDocuments({ date: { $gte: new Date() } }),
      eventsToday: await Event.countDocuments({ 
        date: { 
          $gte: new Date(new Date().setHours(0, 0, 0, 0)),
          $lt: new Date(new Date().setHours(23, 59, 59, 999))
        }
      }),
      eventsThisWeek: await Event.countDocuments({ 
        date: { 
          $gte: new Date(new Date().setDate(new Date().getDate() - new Date().getDay())),
          $lt: new Date(new Date().setDate(new Date().getDate() - new Date().getDay() + 7))
        }
      }),
      totalGames: await Game.countDocuments(),
      steamGames: await Game.countDocuments({ source: 'steam' }),
      manualGames: await Game.countDocuments({ source: 'manual' }),
      pendingGames: await Game.countDocuments({ gameStatus: 'pending' }),
      recentRegistrations: await User.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
      }),
      probationaryUsers: await User.countDocuments({ 
        probationaryUntil: { $gte: new Date() }
      })
    };

    // Calculate approval rate
    const totalProcessed = stats.approvedUsers + await User.countDocuments({ status: 'rejected' });
    stats.approvalRate = totalProcessed > 0 ? Math.round((stats.approvedUsers / totalProcessed) * 100) : 100;

    // Get recent admin activity
    const recentActivity = await AuditLog.find()
      .sort({ timestamp: -1 })
      .limit(10);

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminDashboard', { 
      stats, 
      recentActivity, 
      user: req.user, 
      isDevelopmentAutoLogin 
    });
  } catch (err) {
    console.error('Error loading admin dashboard:', err);
    res.status(500).send('Error loading admin dashboard');
  }
});

// Admin users management
router.get('/users', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const { filter, search, page = 1 } = req.query;
    const limit = 20;
    const skip = (page - 1) * limit;

    let query = {};
    if (filter === 'pending') query.status = 'pending';
    else if (filter === 'approved') query.status = 'approved';
    else if (filter === 'rejected') query.status = 'rejected';
    else if (filter === 'blocked') query.isBlocked = true;
    else if (filter === 'admin') query.isAdmin = true;

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { gameNickname: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const totalUsers = await User.countDocuments(query);
    const totalPages = Math.ceil(totalUsers / limit);

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminUsers', { 
      users, 
      filter, 
      search, 
      currentPage: parseInt(page), 
      totalPages, 
      user: req.user, 
      isDevelopmentAutoLogin 
    });
  } catch (err) {
    console.error('Error loading admin users:', err);
    res.status(500).send('Error loading users');
  }
});

// Admin events management
router.get('/events', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const { status, search, page = 1, game: selectedGame, dateFrom, dateTo, creator } = req.query;
    const limit = 20;
    const skip = (page - 1) * limit;

    let query = {};

    // Status/filter logic
    if (status === 'upcoming') {
      query.date = { $gte: new Date() };
    } else if (status === 'past') {
      query.date = { $lt: new Date() };
    } else if (status === 'live') {
      const now = new Date();
      const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);
      query.date = { $gte: twoHoursAgo, $lte: now };
    } else if (status === 'pending') {
      query.gameStatus = 'pending';
    }

    // Game filter
    if (selectedGame) {
      query.game = selectedGame;
    }

    // Date range filters
    if (dateFrom || dateTo) {
      query.date = query.date || {};
      if (dateFrom) {
        query.date.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        const endDate = new Date(dateTo);
        endDate.setHours(23, 59, 59, 999); // End of day
        query.date.$lte = endDate;
      }
    }

    // Search filter
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    // Creator filter
    if (creator) {
      const creatorUsers = await User.find({
        $or: [
          { name: { $regex: creator, $options: 'i' } },
          { gameNickname: { $regex: creator, $options: 'i' } }
        ]
      }).select('_id');

      if (creatorUsers.length > 0) {
        query.createdBy = { $in: creatorUsers.map(u => u._id) };
      }
    }

    const events = await Event.find(query)
      .populate('createdBy')
      .populate('players')
      .populate('game')
      .sort({ date: -1 })
      .skip(skip)
      .limit(limit);

    const totalEvents = await Event.countDocuments(query);
    const totalPages = Math.ceil(totalEvents / limit);

    // Get all games for the filter dropdown
    const games = await Game.find().sort({ name: 1 });

    // Get pending counts for navigation badges
    const pendingCounts = await getPendingCounts();

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminEvents', {
      events,
      filter: status, // Pass status as filter for template compatibility
      search,
      selectedGame,
      dateFrom,
      dateTo,
      creator,
      games, // Added games list
      currentPage: parseInt(page),
      totalPages,
      user: req.user,
      isDevelopmentAutoLogin,
      ...pendingCounts // Spread the pending counts for navigation badges
    });
  } catch (err) {
    console.error('Error loading admin events:', err);
    res.status(500).send('Error loading events');
  }
});

// Admin games management
router.get('/games', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const { status: filter, source: sourceFilter, search, page = 1, addedBy } = req.query;
    const limit = 20;
    const skip = (page - 1) * limit;

    let query = {};
    
    // Status/filter logic
    if (filter === 'pending') {
      query.status = 'pending';
    } else if (filter === 'approved') {
      query.status = 'approved';
    } else if (filter === 'rejected') {
      query.status = 'rejected';
    }

    // Source filter
    if (sourceFilter) {
      query.source = sourceFilter;
    }

    // Search filter
    if (search) {
      query.name = { $regex: search, $options: 'i' };
    }

    // Added by filter
    if (addedBy) {
      const addedByUsers = await User.find({
        $or: [
          { name: { $regex: addedBy, $options: 'i' } },
          { email: { $regex: addedBy, $options: 'i' } },
          { gameNickname: { $regex: addedBy, $options: 'i' } }
        ]
      }).select('_id');
      
      if (addedByUsers.length > 0) {
        query.addedBy = { $in: addedByUsers.map(u => u._id) };
      }
    }

    const games = await Game.find(query)
      .populate('addedBy')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const totalGames = await Game.countDocuments(query);
    const totalPages = Math.ceil(totalGames / limit);

    // Get pending counts for navigation badges
    const pendingCounts = await getPendingCounts();

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminGames', { 
      games, 
      filter, // Changed from 'source' to 'filter' for status filtering
      sourceFilter, // Changed from 'source' to 'sourceFilter' for source filtering
      search, 
      addedBy, // Added addedBy filter
      currentPage: parseInt(page), 
      totalPages, 
      user: req.user, 
      isDevelopmentAutoLogin,
      ...pendingCounts // Spread the pending counts for navigation badges
    });
  } catch (err) {
    console.error('Error loading admin games:', err);
    res.status(500).send('Error loading games');
  }
});

// Admin system management
router.get('/system', ensureAuthenticated, ensureSuperAdmin, async (req, res) => {
  try {
    // Gather system health data
    const systemHealth = {
      databaseConnected: mongoose.connection.readyState === 1,
      uptime: process.uptime(),
      nodeVersion: process.version,
      environment: process.env.NODE_ENV || 'development',
      memoryUsage: process.memoryUsage()
    };

    // Gather system statistics
    const systemStats = {
      totalUsers: await User.countDocuments(),
      totalEvents: await Event.countDocuments(),
      totalGames: await Game.countDocuments(),
      totalAuditLogs: await AuditLog.countDocuments(),
      blockedUsers: await User.countDocuments({ isBlocked: true }),
      rejectedUsers: await User.countDocuments({ status: 'rejected' }),
      probationaryUsers: await User.countDocuments({ 
        probationaryUntil: { $gte: new Date() }
      }),
      recentUsers: await User.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      }),
      recentEvents: await Event.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      })
    };

    // Find suspicious IP addresses (3+ registrations)
    const suspiciousIPs = await User.aggregate([
      {
        $group: {
          _id: '$registrationIP',
          count: { $sum: 1 },
          users: {
            $push: {
              email: '$email',
              status: '$status',
              createdAt: '$createdAt'
            }
          }
        }
      },
      {
        $match: {
          count: { $gte: 3 },
          _id: { $ne: null }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    // Get recent audit logs
    const recentAuditLogs = await AuditLog.find()
      .sort({ timestamp: -1 })
      .limit(20);

    // Get pending counts for navigation badges
    const pendingCounts = await getPendingCounts();

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminSystem', { 
      user: req.user, 
      isDevelopmentAutoLogin,
      systemHealth,
      systemStats,
      suspiciousIPs,
      recentAuditLogs,
      ...pendingCounts // Spread the pending counts for navigation badges
    });
  } catch (err) {
    console.error('Error loading admin system:', err);
    res.status(500).send('Error loading system page');
  }
});

// Add game page
router.get('/add-game', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('addGame', { 
      user: req.user, 
      isDevelopmentAutoLogin 
    });
  } catch (err) {
    console.error('Error loading add game page:', err);
    res.status(500).send('Error loading add game page');
  }
});

// API endpoint for pending count (used by dashboard auto-refresh)
router.get('/api/pending-count', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const pendingUsers = await User.countDocuments({ status: 'pending' });
    const pendingEvents = await Event.countDocuments({ gameStatus: 'pending' });
    const pendingGames = await Game.countDocuments({ gameStatus: 'pending' });
    
    res.json({ 
      count: pendingUsers + pendingEvents + pendingGames,
      users: pendingUsers,
      events: pendingEvents,
      games: pendingGames
    });
  } catch (err) {
    console.error('Error getting pending count:', err);
    res.status(500).json({ error: 'Error getting pending count' });
  }
});

// Database monitoring API endpoints
router.get('/api/database/status', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { getStatus } = require('../utils/database');
  const status = getStatus();
  res.json(status);
}));

router.get('/api/database/health', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { healthCheck } = require('../utils/database');
  const health = await healthCheck();
  res.json(health);
}));

router.get('/api/database/monitoring', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { getReport } = require('../utils/connectionMonitor');
  const report = getReport();
  res.json(report);
}));

router.get('/api/database/trends', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { getTrends } = require('../utils/connectionMonitor');
  const trends = getTrends();
  res.json(trends);
}));

// Game Management Routes

// Approve game
router.post('/game/approve/:id', ensureAuthenticated, ensureAdmin, validateGameApproval, handleValidationErrors, async (req, res) => {
  try {
    const { notes } = req.body;
    const game = await Game.findById(req.params.id);
    const clientIP = getClientIP(req);

    if (!game) {
      return res.status(404).json({ error: 'Game not found' });
    }

    // Update game status
    game.status = 'approved';
    game.approvedAt = new Date();
    game.approvedBy = req.user._id;
    game.approvalNotes = notes || '';
    
    await game.save();

    // Create audit log
    await createAuditLog(req.user, 'GAME_APPROVED', null, notes, clientIP, 1, {
      gameId: game._id,
      gameName: game.name,
      gameSource: game.source
    });

    console.log('Game approved:', game.name, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'Game approved successfully' });
  } catch (err) {
    console.error('Error approving game:', err);
    res.status(500).json({ error: 'Error approving game' });
  }
});

// Reject game
router.post('/game/reject/:id', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const { notes } = req.body;
    const game = await Game.findById(req.params.id);
    const clientIP = getClientIP(req);

    if (!game) {
      return res.status(404).json({ error: 'Game not found' });
    }

    if (!notes || notes.trim() === '') {
      return res.status(400).json({ error: 'Rejection reason is required' });
    }

    // Update game status
    game.status = 'rejected';
    game.rejectedAt = new Date();
    game.rejectedBy = req.user._id;
    game.rejectionReason = notes;
    
    await game.save();

    // Create audit log
    await createAuditLog(req.user, 'GAME_REJECTED', null, notes, clientIP, 1, {
      gameId: game._id,
      gameName: game.name,
      gameSource: game.source
    });

    console.log('Game rejected:', game.name, 'by:', req.user.email, 'reason:', notes);
    res.status(200).json({ success: true, message: 'Game rejected successfully' });
  } catch (err) {
    console.error('Error rejecting game:', err);
    res.status(500).json({ error: 'Error rejecting game' });
  }
});

// Delete game
router.post('/game/delete/:id', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const game = await Game.findById(req.params.id);
    const clientIP = getClientIP(req);

    if (!game) {
      return res.status(404).json({ error: 'Game not found' });
    }

    // Check if game is used in any events
    const eventCount = await Event.countDocuments({ game: game._id });
    if (eventCount > 0) {
      return res.status(400).json({ 
        error: `Cannot delete game. It is used in ${eventCount} event(s). Please remove it from all events first.` 
      });
    }

    // Create audit log before deletion
    await createAuditLog(req.user, 'GAME_DELETED', null, '', clientIP, 1, {
      gameId: game._id,
      gameName: game.name,
      gameSource: game.source
    });

    // Delete the game
    await Game.findByIdAndDelete(game._id);

    console.log('Game deleted:', game.name, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'Game deleted successfully' });
  } catch (err) {
    console.error('Error deleting game:', err);
    res.status(500).json({ error: 'Error deleting game' });
  }
});

// Add game manually
router.post('/game/add', ensureAuthenticated, ensureAdmin, validateAdminGameAddition, handleValidationErrors, async (req, res) => {
  try {
    const { name, description, imageUrl, steamAppId } = req.body;
    const clientIP = getClientIP(req);

    // Check if game already exists
    const existingGame = await Game.findOne({ 
      $or: [
        { name: { $regex: new RegExp(`^${name}$`, 'i') } },
        ...(steamAppId ? [{ steamAppId: steamAppId }] : [])
      ]
    });

    if (existingGame) {
      return res.status(400).json({ error: 'Game already exists' });
    }

    // Create new game
    const game = new Game({
      name: name.trim(),
      description: description?.trim() || '',
      imageUrl: imageUrl?.trim() || '',
      steamAppId: steamAppId || null,
      source: 'manual',
      status: 'approved', // Admin-added games are auto-approved
      addedBy: req.user._id,
      approvedBy: req.user._id,
      approvedAt: new Date()
    });

    await game.save();

    // Create audit log
    await createAuditLog(req.user, 'GAME_ADDED_MANUAL', null, `Added game: ${name}`, clientIP, 1, {
      gameId: game._id,
      gameName: game.name,
      gameSource: game.source
    });

    console.log('Game added manually:', game.name, 'by:', req.user.email);
    res.status(201).json({ success: true, message: 'Game added successfully', game });
  } catch (err) {
    console.error('Error adding game:', err);
    res.status(500).json({ error: 'Error adding game' });
  }
});

// Event Management Routes

// Delete event
router.post('/event/delete/:id', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('createdBy');
    const clientIP = getClientIP(req);

    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    // Create audit log before deletion
    await createAuditLog(req.user, 'EVENT_DELETED', event.createdBy, `Deleted event: ${event.name}`, clientIP, 1, {
      eventId: event._id,
      eventName: event.name,
      eventDate: event.date,
      createdBy: event.createdBy?.email
    });

    // Delete the event
    await Event.findByIdAndDelete(event._id);

    console.log('Event deleted:', event.name, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'Event deleted successfully' });
  } catch (err) {
    console.error('Error deleting event:', err);
    res.status(500).json({ error: 'Error deleting event' });
  }
});

// Bulk delete events
router.post('/events/bulk-delete', ensureAuthenticated, ensureAdmin, validateBulkEventOperation, handleValidationErrors, async (req, res) => {
  try {
    const { eventIds, notes } = req.body;
    const clientIP = getClientIP(req);

    if (!eventIds || !Array.isArray(eventIds) || eventIds.length === 0) {
      return res.status(400).json({ error: 'Event IDs array is required' });
    }

    const events = await Event.find({ _id: { $in: eventIds } }).populate('createdBy');
    let successCount = 0;
    let errorCount = 0;

    for (const event of events) {
      try {
        // Create audit log before deletion
        await createAuditLog(req.user, 'EVENT_DELETED', event.createdBy, notes, clientIP, 1, {
          eventId: event._id,
          eventName: event.name,
          eventDate: event.date,
          createdBy: event.createdBy?.email
        });

        // Delete the event
        await Event.findByIdAndDelete(event._id);

        successCount++;
      } catch (err) {
        console.error('Error in bulk delete for event:', event.name, err);
        errorCount++;
      }
    }

    // Create bulk audit log
    await createAuditLog(req.user, 'BULK_EVENT_DELETED', null, notes, clientIP, successCount, { 
      successCount, 
      errorCount, 
      totalRequested: eventIds.length 
    });

    console.log('Bulk event delete completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    res.status(200).json({ 
      success: true, 
      message: `Bulk delete completed: ${successCount} successful, ${errorCount} errors`,
      successCount,
      errorCount
    });
  } catch (err) {
    console.error('Error in bulk event delete:', err);
    res.status(500).json({ error: 'Error in bulk delete operation' });
  }
});

// Audit Logs Management Routes
router.get('/logs', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    const { action, admin, page = 1, dateFrom, dateTo, search } = req.query;
    const limit = 50;
    const skip = (page - 1) * limit;

    let query = {};

    // Action filter
    if (action) {
      query.action = action;
    }

    // Admin filter
    if (admin) {
      const adminUsers = await User.find({
        $or: [
          { name: { $regex: admin, $options: 'i' } },
          { email: { $regex: admin, $options: 'i' } }
        ]
      }).select('_id');

      if (adminUsers.length > 0) {
        query.adminId = { $in: adminUsers.map(u => u._id) };
      }
    }

    // Date range filters
    if (dateFrom || dateTo) {
      query.timestamp = {};
      if (dateFrom) {
        query.timestamp.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        const endDate = new Date(dateTo);
        endDate.setHours(23, 59, 59, 999);
        query.timestamp.$lte = endDate;
      }
    }

    // Search filter
    if (search) {
      query.$or = [
        { adminName: { $regex: search, $options: 'i' } },
        { targetUserEmail: { $regex: search, $options: 'i' } },
        { notes: { $regex: search, $options: 'i' } }
      ];
    }

    const auditLogs = await AuditLog.find(query)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit);

    const totalLogs = await AuditLog.countDocuments(query);
    const totalPages = Math.ceil(totalLogs / limit);

    // Get unique actions for filter dropdown
    const actions = await AuditLog.distinct('action');

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminLogs', {
      auditLogs,
      actions,
      action,
      admin,
      search,
      dateFrom,
      dateTo,
      currentPage: parseInt(page),
      totalPages,
      user: req.user,
      isDevelopmentAutoLogin
    });
  } catch (err) {
    console.error('Error loading audit logs:', err);
    res.status(500).send('Error loading audit logs');
  }
});

// User Management Routes

// Approve user
router.post('/user/approve/:id', ensureAuthenticated, ensureAdmin, validateUserApproval, handleValidationErrors, checkAdminOperationPermission, async (req, res) => {
  try {
    const { notes } = req.body;
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    // Update user status
    user.status = 'approved';
    user.approvedAt = new Date();
    user.approvedBy = req.user._id;
    user.approvalNotes = notes || '';
    
    // Set probationary period for new users (30 days)
    setProbationaryPeriod(user, 30);
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'USER_APPROVED', user, notes, clientIP);

    console.log('User approved:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User approved successfully' });
  } catch (err) {
    console.error('Error approving user:', err);
    res.status(500).json({ error: 'Error approving user' });
  }
});

// Reject user
router.post('/user/reject/:id', ensureAuthenticated, ensureAdmin, validateUserRejection, handleValidationErrors, checkAdminOperationPermission, async (req, res) => {
  try {
    const { notes } = req.body;
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    if (!notes || notes.trim() === '') {
      return res.status(400).json({ error: 'Rejection reason is required' });
    }

    // Update user status
    user.status = 'rejected';
    user.rejectedAt = new Date();
    user.rejectedBy = req.user._id;
    user.rejectionReason = notes;
    
    await user.save();

    // Add email to rejected list to prevent re-registration
    const rejectedEmail = new RejectedEmail({
      email: user.email.toLowerCase(),
      rejectedBy: req.user._id,
      reason: notes,
      originalUserId: user._id
    });
    await rejectedEmail.save();

    // Create audit log
    await createAuditLog(req.user, 'USER_REJECTED', user, notes, clientIP);

    console.log('User rejected:', user.email, 'by:', req.user.email, 'reason:', notes);
    res.status(200).json({ success: true, message: 'User rejected successfully' });
  } catch (err) {
    console.error('Error rejecting user:', err);
    res.status(500).json({ error: 'Error rejecting user' });
  }
});

// Block user
router.post('/user/block/:id', ensureAuthenticated, ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    user.isBlocked = true;
    user.blockedAt = new Date();
    user.blockedBy = req.user._id;
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'USER_BLOCKED', user, '', clientIP);

    console.log('User blocked:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User blocked successfully' });
  } catch (err) {
    console.error('Error blocking user:', err);
    res.status(500).json({ error: 'Error blocking user' });
  }
});

// Unblock user
router.post('/user/unblock/:id', ensureAuthenticated, ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    user.isBlocked = false;
    user.unblockedAt = new Date();
    user.unblockedBy = req.user._id;
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'USER_UNBLOCKED', user, '', clientIP);

    console.log('User unblocked:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User unblocked successfully' });
  } catch (err) {
    console.error('Error unblocking user:', err);
    res.status(500).json({ error: 'Error unblocking user' });
  }
});

// Delete user
router.post('/user/delete/:id', ensureAuthenticated, ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    // Create audit log before deletion
    await createAuditLog(req.user, 'USER_DELETED', user, '', clientIP);

    // Delete the user
    await User.findByIdAndDelete(user._id);

    console.log('User deleted:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User deleted successfully' });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Error deleting user' });
  }
});

// Toggle admin status
router.post('/user/toggle-admin/:id', ensureAuthenticated, ensureSuperAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    const wasAdmin = user.isAdmin;
    user.isAdmin = !user.isAdmin;
    
    if (user.isAdmin) {
      user.adminPromotedAt = new Date();
      user.adminPromotedBy = req.user._id;
    } else {
      user.adminDemotedAt = new Date();
      user.adminDemotedBy = req.user._id;
      // If demoting from admin, also remove super admin status
      user.isSuperAdmin = false;
    }
    
    await user.save();

    // Create audit log
    const action = wasAdmin ? 'ADMIN_DEMOTED' : 'ADMIN_PROMOTED';
    await createAuditLog(req.user, action, user, '', clientIP);

    console.log('User admin status toggled:', user.email, 'by:', req.user.email, 'isAdmin:', user.isAdmin);
    res.status(200).json({ success: true, message: `User ${user.isAdmin ? 'promoted to' : 'demoted from'} admin successfully` });
  } catch (err) {
    console.error('Error toggling admin status:', err);
    res.status(500).json({ error: 'Error updating admin status' });
  }
});

// End probation
router.post('/user/end-probation/:id', ensureAuthenticated, ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    user.probationaryUntil = null;
    user.probationEndedAt = new Date();
    user.probationEndedBy = req.user._id;
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'PROBATION_ENDED', user, '', clientIP);

    console.log('Probation ended for user:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'Probation ended successfully' });
  } catch (err) {
    console.error('Error ending probation:', err);
    res.status(500).json({ error: 'Error ending probation' });
  }
});

// Promote to super admin
router.post('/user/promote-super-admin/:id', ensureAuthenticated, ensureSuperAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    if (!user.isAdmin) {
      return res.status(400).json({ error: 'User must be an admin before promoting to super admin' });
    }

    if (user.isSuperAdmin) {
      return res.status(400).json({ error: 'User is already a super admin' });
    }

    user.isSuperAdmin = true;
    user.superAdminPromotedAt = new Date();
    user.superAdminPromotedBy = req.user._id;
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'SUPER_ADMIN_PROMOTED', user, '', clientIP);

    console.log('User promoted to super admin:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User promoted to super admin successfully' });
  } catch (err) {
    console.error('Error promoting to super admin:', err);
    res.status(500).json({ error: 'Error promoting to super admin' });
  }
});

// Demote super admin
router.post('/user/demote-super-admin/:id', ensureAuthenticated, ensureSuperAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const user = req.targetUser;
    const clientIP = getClientIP(req);

    if (!user.isSuperAdmin) {
      return res.status(400).json({ error: 'User is not a super admin' });
    }

    if (user.isProtected) {
      return res.status(403).json({ error: 'Cannot demote protected super admin' });
    }

    user.isSuperAdmin = false;
    user.superAdminDemotedAt = new Date();
    user.superAdminDemotedBy = req.user._id;
    
    await user.save();

    // Create audit log
    await createAuditLog(req.user, 'SUPER_ADMIN_DEMOTED', user, '', clientIP);

    console.log('User demoted from super admin:', user.email, 'by:', req.user.email);
    res.status(200).json({ success: true, message: 'User demoted from super admin successfully' });
  } catch (err) {
    console.error('Error demoting super admin:', err);
    res.status(500).json({ error: 'Error demoting super admin' });
  }
});

// Bulk approve users
router.post('/users/bulk-approve', ensureAuthenticated, ensureAdmin, validateBulkUserOperation, handleValidationErrors, async (req, res) => {
  try {
    const { userIds, notes } = req.body;
    const clientIP = getClientIP(req);

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'User IDs array is required' });
    }

    const users = await User.find({ _id: { $in: userIds } });
    let successCount = 0;
    let errorCount = 0;

    for (const user of users) {
      try {
        // Check if user can be approved
        if (user.status !== 'pending') {
          errorCount++;
          continue;
        }

        // Update user status
        user.status = 'approved';
        user.approvedAt = new Date();
        user.approvedBy = req.user._id;
        user.approvalNotes = notes || '';
        
        // Set probationary period
        setProbationaryPeriod(user, 30);
        
        await user.save();

        // Create audit log
        await createAuditLog(req.user, 'USER_APPROVED', user, notes, clientIP);

        successCount++;
      } catch (err) {
        console.error('Error in bulk approve for user:', user.email, err);
        errorCount++;
      }
    }

    // Create bulk audit log
    await createAuditLog(req.user, 'BULK_USER_APPROVED', null, notes, clientIP, successCount, { 
      successCount, 
      errorCount, 
      totalRequested: userIds.length 
    });

    console.log('Bulk approve completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    res.status(200).json({ 
      success: true, 
      message: `Bulk approve completed: ${successCount} successful, ${errorCount} errors`,
      successCount,
      errorCount
    });
  } catch (err) {
    console.error('Error in bulk approve:', err);
    res.status(500).json({ error: 'Error in bulk approve operation' });
  }
});

// Bulk reject users
router.post('/users/bulk-reject', ensureAuthenticated, ensureAdmin, validateBulkUserOperation, handleValidationErrors, async (req, res) => {
  try {
    const { userIds, notes } = req.body;
    const clientIP = getClientIP(req);

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'User IDs array is required' });
    }

    if (!notes || notes.trim() === '') {
      return res.status(400).json({ error: 'Rejection reason is required for bulk rejection' });
    }

    const users = await User.find({ _id: { $in: userIds } });
    let successCount = 0;
    let errorCount = 0;

    for (const user of users) {
      try {
        // Update user status
        user.status = 'rejected';
        user.rejectedAt = new Date();
        user.rejectedBy = req.user._id;
        user.rejectionReason = notes;
        
        await user.save();

        // Add email to rejected list
        const rejectedEmail = new RejectedEmail({
          email: user.email.toLowerCase(),
          rejectedBy: req.user._id,
          reason: notes,
          originalUserId: user._id
        });
        await rejectedEmail.save();

        // Create audit log
        await createAuditLog(req.user, 'USER_REJECTED', user, notes, clientIP);

        successCount++;
      } catch (err) {
        console.error('Error in bulk reject for user:', user.email, err);
        errorCount++;
      }
    }

    // Create bulk audit log
    await createAuditLog(req.user, 'BULK_USER_REJECTED', null, notes, clientIP, successCount, { 
      successCount, 
      errorCount, 
      totalRequested: userIds.length 
    });

    console.log('Bulk reject completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    res.status(200).json({ 
      success: true, 
      message: `Bulk reject completed: ${successCount} successful, ${errorCount} errors`,
      successCount,
      errorCount
    });
  } catch (err) {
    console.error('Error in bulk reject:', err);
    res.status(500).json({ error: 'Error in bulk reject operation' });
  }
});

// Bulk delete users
router.post('/users/bulk-delete', ensureAuthenticated, ensureAdmin, validateBulkUserOperation, handleValidationErrors, async (req, res) => {
  try {
    const { userIds, notes } = req.body;
    const clientIP = getClientIP(req);

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'User IDs array is required' });
    }

    const users = await User.find({ _id: { $in: userIds } });
    let successCount = 0;
    let errorCount = 0;

    for (const user of users) {
      try {
        // Check permissions for each user
        if (user.isProtected && req.user.email !== user.email) {
          errorCount++;
          continue;
        }

        if (user.isAdmin && !req.user.isSuperAdmin) {
          errorCount++;
          continue;
        }

        if (user.isSuperAdmin) {
          errorCount++;
          continue;
        }

        // Create audit log before deletion
        await createAuditLog(req.user, 'USER_DELETED', user, notes, clientIP);

        // Delete the user
        await User.findByIdAndDelete(user._id);

        successCount++;
      } catch (err) {
        console.error('Error in bulk delete for user:', user.email, err);
        errorCount++;
      }
    }

    // Create bulk audit log
    await createAuditLog(req.user, 'BULK_USER_DELETED', null, notes, clientIP, successCount, { 
      successCount, 
      errorCount, 
      totalRequested: userIds.length 
    });

    console.log('Bulk delete completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    res.status(200).json({ 
      success: true, 
      message: `Bulk delete completed: ${successCount} successful, ${errorCount} errors`,
      successCount,
      errorCount
    });
  } catch (err) {
    console.error('Error in bulk delete:', err);
    res.status(500).json({ error: 'Error in bulk delete operation' });
  }
});

// Error Logs Management Routes
router.get('/error-logs', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  try {
    const { 
      filter, 
      errorType, 
      severity, 
      status, 
      search, 
      dateFrom, 
      dateTo, 
      page = 1 
    } = req.query;
    
    const limit = 20;
    const skip = (page - 1) * limit;
    
    // Build query
    let query = {};
    
    // Quick filters
    if (filter === 'unresolved') {
      query['resolution.status'] = { $in: ['new', 'investigating'] };
    } else if (filter === 'critical') {
      query['analytics.severity'] = 'critical';
    } else if (filter === 'today') {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const tomorrow = new Date(today);
      tomorrow.setDate(tomorrow.getDate() + 1);
      query.timestamp = { $gte: today, $lt: tomorrow };
    } else if (filter === 'hour') {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      query.timestamp = { $gte: oneHourAgo };
    }
    
    // Specific filters
    if (errorType) query.errorType = errorType;
    if (severity) query['analytics.severity'] = severity;
    if (status) query['resolution.status'] = status;
    
    // Date range
    if (dateFrom || dateTo) {
      query.timestamp = {};
      if (dateFrom) query.timestamp.$gte = new Date(dateFrom);
      if (dateTo) {
        const endDate = new Date(dateTo);
        endDate.setHours(23, 59, 59, 999);
        query.timestamp.$lte = endDate;
      }
    }
    
    // Search
    if (search) {
      query.$or = [
        { message: { $regex: search, $options: 'i' } },
        { 'userContext.email': { $regex: search, $options: 'i' } },
        { 'requestContext.url': { $regex: search, $options: 'i' } }
      ];
    }
    
    // Get error logs
    const errorLogs = await ErrorLog.find(query)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit);
    
    const totalErrors = await ErrorLog.countDocuments(query);
    const totalPages = Math.ceil(totalErrors / limit);
    
    // Calculate statistics
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    
    const stats = {
      total: await ErrorLog.countDocuments(),
      unresolved: await ErrorLog.countDocuments({ 'resolution.status': { $in: ['new', 'investigating'] } }),
      critical: await ErrorLog.countDocuments({ 'analytics.severity': 'critical' }),
      today: await ErrorLog.countDocuments({ timestamp: { $gte: today } }),
      lastHour: await ErrorLog.countDocuments({ timestamp: { $gte: oneHourAgo } })
    };
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    res.render('adminErrorLogs', {
      title: 'Error Logs',
      currentPage: 'error-logs',
      errorLogs,
      stats,
      filter,
      errorType,
      severity,
      status,
      search,
      dateFrom,
      dateTo,
      page: parseInt(page),
      totalPages,
      totalErrors,
      user: req.user,
      isDevelopmentAutoLogin,
      req // Pass req for URL building in template
    });
  } catch (err) {
    console.error('Error loading error logs:', err);
    throw new DatabaseError('Failed to load error logs');
  }
}));

// Export error logs (must come before parameterized routes)
router.get('/error-logs/export', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { 
    filter, 
    errorType, 
    severity, 
    status, 
    search, 
    dateFrom, 
    dateTo 
  } = req.query;
  
  // Build same query as main listing
  let query = {};
  
  if (filter === 'unresolved') {
    query['resolution.status'] = { $in: ['new', 'investigating'] };
  } else if (filter === 'critical') {
    query['analytics.severity'] = 'critical';
  } else if (filter === 'today') {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    query.timestamp = { $gte: today, $lt: tomorrow };
  } else if (filter === 'hour') {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    query.timestamp = { $gte: oneHourAgo };
  }
  
  if (errorType) query.errorType = errorType;
  if (severity) query['analytics.severity'] = severity;
  if (status) query['resolution.status'] = status;
  
  if (dateFrom || dateTo) {
    query.timestamp = {};
    if (dateFrom) query.timestamp.$gte = new Date(dateFrom);
    if (dateTo) {
      const endDate = new Date(dateTo);
      endDate.setHours(23, 59, 59, 999);
      query.timestamp.$lte = endDate;
    }
  }
  
  if (search) {
    query.$or = [
      { message: { $regex: search, $options: 'i' } },
      { 'userContext.email': { $regex: search, $options: 'i' } },
      { 'requestContext.url': { $regex: search, $options: 'i' } }
    ];
  }
  
  const errorLogs = await ErrorLog.find(query)
    .sort({ timestamp: -1 })
    .limit(1000); // Limit export to 1000 records
  
  // Create CSV content
  const csvHeader = 'Timestamp,Type,Message,User,URL,Severity,Status,Request ID\n';
  const csvRows = errorLogs.map(error => {
    const timestamp = error.timestamp.toISOString();
    const type = error.errorType;
    const message = `"${error.message.replace(/"/g, '""')}"`;
    const user = error.userContext.email || 'Anonymous';
    const url = `"${error.requestContext.originalUrl}"`;
    const severity = error.analytics.severity;
    const status = error.resolution.status;
    const requestId = error.requestId;
    
    return `${timestamp},${type},${message},${user},${url},${severity},${status},${requestId}`;
  }).join('\n');
  
  const csvContent = csvHeader + csvRows;
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="error-logs-${new Date().toISOString().split('T')[0]}.csv"`);
  res.send(csvContent);
}));

// Get single error log details
router.get('/error-logs/:id', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const errorLog = await ErrorLog.findById(req.params.id);
  if (!errorLog) {
    throw new NotFoundError('Error log', req.params.id);
  }
  res.json(errorLog);
}));

// Get error log in AI-friendly format
router.get('/error-logs/:id/ai-format', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const errorLog = await ErrorLog.findById(req.params.id);
  if (!errorLog) {
    throw new NotFoundError('Error log', req.params.id);
  }
  
  const aiFormat = `ERROR ANALYSIS REQUEST

Error Summary:
- Type: ${errorLog.errorType}
- Occurred: ${errorLog.timestamp.toISOString()}
- Endpoint: ${errorLog.requestContext.method} ${errorLog.requestContext.originalUrl}
- User: ${errorLog.userContext.email || 'Anonymous'}
- Status: ${errorLog.resolution.status}
- Severity: ${errorLog.analytics.severity}

Context:
- User Action: ${errorLog.getUserActionDescription()}
- Error Message: ${errorLog.message}
- Status Code: ${errorLog.statusCode}
- Request ID: ${errorLog.requestId}

Technical Details:
${errorLog.errorDetails.stack || 'No stack trace available'}

Request Context:
${JSON.stringify(errorLog.requestContext, null, 2)}

User Context:
${JSON.stringify(errorLog.userContext, null, 2)}

Environment:
- Node.js: ${errorLog.environment.nodeVersion}
- Environment: ${errorLog.environment.nodeEnv}
- Platform: ${errorLog.environment.platform}

${errorLog.analytics.frequency > 1 ? `
Pattern Analysis:
- This error has occurred ${errorLog.analytics.frequency} times
- Category: ${errorLog.analytics.category}
- Impact Level: ${errorLog.analytics.impact}
` : ''}

${errorLog.resolution.adminNotes ? `
Admin Notes:
${errorLog.resolution.adminNotes}
` : ''}

Please analyze this error and provide:
1. Root cause analysis
2. Potential fixes
3. Prevention strategies
4. Impact assessment`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(aiFormat);
}));

// Get technical details
router.get('/error-logs/:id/technical', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const errorLog = await ErrorLog.findById(req.params.id);
  if (!errorLog) {
    throw new NotFoundError('Error log', req.params.id);
  }
  
  const technical = `TECHNICAL ERROR DETAILS

Error Information:
- Type: ${errorLog.errorType}
- Message: ${errorLog.message}
- Status Code: ${errorLog.statusCode}
- Request ID: ${errorLog.requestId}
- Timestamp: ${errorLog.timestamp.toISOString()}

Stack Trace:
${errorLog.errorDetails.stack || 'No stack trace available'}

Request Details:
- Method: ${errorLog.requestContext.method}
- URL: ${errorLog.requestContext.originalUrl}
- IP: ${errorLog.requestContext.ip}
- User Agent: ${errorLog.requestContext.userAgent}
- Query: ${JSON.stringify(errorLog.requestContext.query, null, 2)}
- Body: ${JSON.stringify(errorLog.requestContext.body, null, 2)}

Environment:
- Node.js: ${errorLog.environment.nodeVersion}
- Environment: ${errorLog.environment.nodeEnv}
- Platform: ${errorLog.environment.platform}
- PID: ${errorLog.environment.pid}
- Uptime: ${errorLog.environment.uptime}s
- Memory: ${JSON.stringify(errorLog.environment.memoryUsage, null, 2)}

Original Error:
${JSON.stringify(errorLog.errorDetails.originalError, null, 2)}`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(technical);
}));

// Get user context
router.get('/error-logs/:id/user-context', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const errorLog = await ErrorLog.findById(req.params.id);
  if (!errorLog) {
    throw new NotFoundError('Error log', req.params.id);
  }
  
  const userContext = `USER CONTEXT ANALYSIS

User Information:
- Email: ${errorLog.userContext.email || 'Anonymous'}
- Name: ${errorLog.userContext.name || 'N/A'}
- Authenticated: ${errorLog.userContext.isAuthenticated ? 'Yes' : 'No'}
- Admin: ${errorLog.userContext.isAdmin ? 'Yes' : 'No'}
- Super Admin: ${errorLog.userContext.isSuperAdmin ? 'Yes' : 'No'}
- Probationary: ${errorLog.userContext.probationaryStatus ? 'Yes' : 'No'}

Session Information:
- Session ID: ${errorLog.userContext.sessionId || 'N/A'}
- IP Address: ${errorLog.requestContext.ip}
- User Agent: ${errorLog.requestContext.userAgent}

User Journey:
- Action Attempted: ${errorLog.getUserActionDescription()}
- Endpoint: ${errorLog.requestContext.method} ${errorLog.requestContext.originalUrl}
- Referer: ${errorLog.requestContext.referer || 'Direct access'}
- Time: ${errorLog.timestamp.toISOString()}

Request Details:
- Protocol: ${errorLog.requestContext.protocol}
- Secure: ${errorLog.requestContext.secure ? 'Yes' : 'No'}
- XHR: ${errorLog.requestContext.xhr ? 'Yes (AJAX)' : 'No (Page load)'}

Error Impact:
- Severity: ${errorLog.analytics.severity}
- Category: ${errorLog.analytics.category}
- User Impact: ${errorLog.analytics.impact}`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(userContext);
}));

// Update error status
router.post('/error-logs/:id/status', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { status, resolution, notes } = req.body;
  
  const errorLog = await ErrorLog.findById(req.params.id);
  if (!errorLog) {
    throw new NotFoundError('Error log', req.params.id);
  }
  
  if (status === 'resolved') {
    await errorLog.markAsResolved(req.user, resolution, notes);
  } else {
    errorLog.resolution.status = status;
    if (notes) {
      await errorLog.addAdminNote(req.user, notes);
    }
    await errorLog.save();
  }
  
  res.json({ success: true, message: 'Status updated successfully' });
}));

// Cleanup old error logs
router.post('/error-logs/cleanup', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const result = await ErrorLog.cleanupOldLogs(90); // 90 days retention
  res.json({ 
    success: true, 
    deletedCount: result.deletedCount,
    message: `Cleaned up ${result.deletedCount} old error logs`
  });
}));

// Clear all error logs (SuperAdmin only)
router.post('/error-logs/clear-all', ensureAuthenticated, ensureSuperAdmin, asyncErrorHandler(async (req, res) => {
  const clientIP = getClientIP(req);
  
  try {
    // Count logs before deletion for audit
    const totalLogs = await ErrorLog.countDocuments();
    
    // Delete all error logs
    const result = await ErrorLog.deleteMany({});
    
    // Create audit log for this critical action
    await createAuditLog(req.user, 'ERROR_LOGS_CLEARED_ALL', null, `Cleared all ${totalLogs} error logs`, clientIP, totalLogs, {
      totalDeleted: result.deletedCount,
      action: 'CLEAR_ALL_ERROR_LOGS'
    });
    
    console.log('All error logs cleared by SuperAdmin:', req.user.email, 'Count:', result.deletedCount);
    
    res.json({ 
      success: true, 
      deletedCount: result.deletedCount,
      message: `All error logs cleared: ${result.deletedCount} logs deleted`
    });
  } catch (err) {
    console.error('Error clearing all logs:', err);
    throw new DatabaseError('Failed to clear all error logs');
  }
}));

// Bulk mark as investigating
router.post('/error-logs/bulk-investigate', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { errorIds, notes } = req.body;
  const clientIP = getClientIP(req);
  
  if (!errorIds || !Array.isArray(errorIds) || errorIds.length === 0) {
    throw new ValidationError('Error IDs array is required');
  }
  
  let successCount = 0;
  let errorCount = 0;
  
  try {
    for (const errorId of errorIds) {
      try {
        const errorLog = await ErrorLog.findById(errorId);
        if (!errorLog) {
          errorCount++;
          continue;
        }
        
        errorLog.resolution.status = 'investigating';
        if (notes) {
          await errorLog.addAdminNote(req.user, notes);
        }
        await errorLog.save();
        
        successCount++;
      } catch (err) {
        console.error('Error in bulk investigate for log:', errorId, err);
        errorCount++;
      }
    }
    
    // Create audit log
    await createAuditLog(req.user, 'BULK_ERROR_LOGS_INVESTIGATING', null, notes, clientIP, successCount, {
      successCount,
      errorCount,
      totalRequested: errorIds.length,
      action: 'BULK_MARK_INVESTIGATING'
    });
    
    console.log('Bulk investigate completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    
    res.json({ 
      success: true, 
      successCount,
      errorCount,
      message: `Bulk operation completed: ${successCount} updated, ${errorCount} errors`
    });
  } catch (err) {
    console.error('Error in bulk investigate:', err);
    throw new DatabaseError('Failed to perform bulk investigate operation');
  }
}));

// Bulk mark as resolved
router.post('/error-logs/bulk-resolve', ensureAuthenticated, ensureAdmin, asyncErrorHandler(async (req, res) => {
  const { errorIds, resolution, notes } = req.body;
  const clientIP = getClientIP(req);
  
  if (!errorIds || !Array.isArray(errorIds) || errorIds.length === 0) {
    throw new ValidationError('Error IDs array is required');
  }
  
  if (!resolution || resolution.trim() === '') {
    throw new ValidationError('Resolution details are required');
  }
  
  let successCount = 0;
  let errorCount = 0;
  
  try {
    for (const errorId of errorIds) {
      try {
        const errorLog = await ErrorLog.findById(errorId);
        if (!errorLog) {
          errorCount++;
          continue;
        }
        
        await errorLog.markAsResolved(req.user, resolution, notes);
        successCount++;
      } catch (err) {
        console.error('Error in bulk resolve for log:', errorId, err);
        errorCount++;
      }
    }
    
    // Create audit log
    await createAuditLog(req.user, 'BULK_ERROR_LOGS_RESOLVED', null, `Resolution: ${resolution}. Notes: ${notes || 'None'}`, clientIP, successCount, {
      successCount,
      errorCount,
      totalRequested: errorIds.length,
      resolution,
      action: 'BULK_MARK_RESOLVED'
    });
    
    console.log('Bulk resolve completed:', successCount, 'success,', errorCount, 'errors, by:', req.user.email);
    
    res.json({ 
      success: true, 
      successCount,
      errorCount,
      message: `Bulk operation completed: ${successCount} resolved, ${errorCount} errors`
    });
  } catch (err) {
    console.error('Error in bulk resolve:', err);
    throw new DatabaseError('Failed to perform bulk resolve operation');
  }
}));

// Bulk delete error logs (SuperAdmin only)
router.post('/error-logs/bulk-delete', ensureAuthenticated, ensureSuperAdmin, asyncErrorHandler(async (req, res) => {
  const { errorIds } = req.body;
  const clientIP = getClientIP(req);
  
  if (!errorIds || !Array.isArray(errorIds) || errorIds.length === 0) {
    throw new ValidationError('Error IDs array is required');
  }
  
  try {
    // Get error logs for audit before deletion
    const errorLogs = await ErrorLog.find({ _id: { $in: errorIds } }).select('_id timestamp errorType message');
    
    // Delete the error logs
    const result = await ErrorLog.deleteMany({ _id: { $in: errorIds } });
    
    // Create audit log
    await createAuditLog(req.user, 'BULK_ERROR_LOGS_DELETED', null, `Deleted ${result.deletedCount} error logs`, clientIP, result.deletedCount, {
      deletedCount: result.deletedCount,
      requestedCount: errorIds.length,
      action: 'BULK_DELETE_ERROR_LOGS',
      deletedIds: errorLogs.map(log => log._id.toString())
    });
    
    console.log('Bulk delete completed:', result.deletedCount, 'deleted by SuperAdmin:', req.user.email);
    
    res.json({ 
      success: true, 
      deletedCount: result.deletedCount,
      message: `Bulk deletion completed: ${result.deletedCount} error logs deleted`
    });
  } catch (err) {
    console.error('Error in bulk delete:', err);
    throw new DatabaseError('Failed to perform bulk delete operation');
  }
}));

module.exports = router;
