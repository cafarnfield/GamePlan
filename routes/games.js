const express = require('express');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');

// Import models
const Game = require('../models/Game');
const Event = require('../models/Event');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

// Import services
const steamService = require('../services/steamService');
const rawgService = require('../services/rawgService');

// Import validation middleware and validators
const { handleValidationErrors } = require('../middleware/validation');
const {
  validateGameApproval,
  validateAdminGameAddition
} = require('../validators/adminValidators');
const {
  validateSteamSearch,
  validateRawgSearch
} = require('../validators/searchValidators');

// Import new Joi validation system
const {
  validateBody,
  validateQuery,
  validateParams,
  gameSchemas,
  commonSchemas
} = require('../validators');

// Import authentication middleware
const { ensureAuthenticated, ensureAdmin } = require('../middleware/auth');

// Import centralized error handling
const {
  asyncErrorHandler
} = require('../middleware/errorHandler');

// Import custom errors
const {
  ValidationError,
  DatabaseError
} = require('../utils/errors');

// Import loggers
const { adminLogger } = require('../utils/logger');

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

// API rate limiter (for search endpoints)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window per IP
  message: {
    error: 'Too many API requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return getClientIP(req);
  },
  handler: (req, res) => {
    console.log(`API rate limit exceeded for IP: ${getClientIP(req)} on ${req.path}`);
    res.status(429).json({
      error: 'Too many API requests from this IP, please try again later.',
      retryAfter: Math.round(15 * 60) // 15 minutes in seconds
    });
  }
});

// =============================================================================
// ADMIN GAME MANAGEMENT ROUTES
// =============================================================================

// Admin games management
router.get('/', ensureAuthenticated, ensureAdmin, async (req, res) => {
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

// Approve game
router.post('/approve/:id', ensureAuthenticated, ensureAdmin, validateGameApproval, handleValidationErrors, async (req, res) => {
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
router.post('/reject/:id', ensureAuthenticated, ensureAdmin, validateBody(gameSchemas.gameRejectionSchema), async (req, res) => {
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
router.post('/delete/:id', ensureAuthenticated, ensureAdmin, async (req, res) => {
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
router.post('/add', ensureAuthenticated, ensureAdmin, validateAdminGameAddition, handleValidationErrors, async (req, res) => {
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

module.exports = router;
