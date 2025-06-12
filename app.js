const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const axios = require('axios'); // Add axios for HTTP requests
const steamService = require('./services/steamService');
const rawgService = require('./services/rawgService');

// Initialize Express
const app = express();

// Middleware with debug logging
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use((req, res, next) => {
  console.log('Session middleware accessed');
  console.log('Session before middleware:', req.session);
  next();
});
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_secret_key',
  resave: true,
  saveUninitialized: true,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 1 day
    httpOnly: true,
    secure: false, // Set to true if using HTTPS
    sameSite: 'lax' // Add sameSite option
  },
  name: 'gameplan.sid', // Custom session cookie name
  store: new session.MemoryStore() // Use in-memory store for testing
}));
app.use((req, res, next) => {
  console.log('Session middleware accessed');
  console.log('Session before middleware:', req.session);
  console.log('Authenticated user:', req.isAuthenticated(), req.user);
  next();
});
app.use((req, res, next) => {
  console.log('Session after middleware:', req.session);
  next();
});
app.use(passport.initialize());
app.use(passport.session());

// View engine setup
app.set('view engine', 'ejs');

// MongoDB connection
require('dotenv').config();

// Mock database connection for testing
if (process.env.MOCK_DB) {
  mongoose.connect('mongodb://localhost:27017/gameplan', {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
} else {
  mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
}

// Models
const User = require('./models/User');
const Extension = require('./models/Extension');
const Event = require('./models/Event');
const Game = require('./models/Game');
const AuditLog = require('./models/AuditLog');
const RejectedEmail = require('./models/RejectedEmail');

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
    console.log('Audit log created:', action, targetUser ? targetUser.email : 'bulk action');
  } catch (err) {
    console.error('Error creating audit log:', err);
  }
};

// Helper function to verify reCAPTCHA
const verifyRecaptcha = async (recaptchaResponse) => {
  if (!process.env.RECAPTCHA_SECRET_KEY) {
    console.warn('reCAPTCHA secret key not configured, skipping verification');
    return true; // Skip verification if not configured
  }

  try {
    const response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
      params: {
        secret: process.env.RECAPTCHA_SECRET_KEY,
        response: recaptchaResponse
      }
    });
    return response.data.success;
  } catch (error) {
    console.error('reCAPTCHA verification error:', error);
    return false;
  }
};

// Helper function to set probationary period
const setProbationaryPeriod = (user, days = 30) => {
  const probationEnd = new Date();
  probationEnd.setDate(probationEnd.getDate() + days);
  user.probationaryUntil = probationEnd;
  return user;
};

// Helper function to check if user is in probation
const isUserInProbation = (user) => {
  return user.probationaryUntil && new Date() < user.probationaryUntil;
};

// Mock admin user for development auto-login
const mockAdminUser = {
  _id: 'dev-admin-id',
  name: 'Development Admin',
  email: 'dev-admin@gameplan.local',
  gameNickname: 'DevAdmin',
  isAdmin: true,
  isSuperAdmin: true,
  isProtected: false,
  isBlocked: false,
  save: async function() { return this; } // Mock save method
};

// Development auto-login middleware
const autoLoginMiddleware = (req, res, next) => {
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development') {
    // Inject mock admin user
    req.user = mockAdminUser;
    req.isAuthenticated = () => true;
    console.log('Development mode: Auto-logged in as admin');
  }
  next();
};

// Apply auto-login middleware after passport initialization
app.use(autoLoginMiddleware);

// Passport configuration with debug logging
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      console.log('Passport strategy accessed');
      console.log('Authentication attempt with email:', email);
      const user = await User.findOne({ email });
      if (!user) {
        console.log('No user found with email:', email);
        return done(null, false, { message: 'No user with that email' });
      }

      // Check user status before password verification
      if (user.status === 'pending') {
        console.log('User account pending approval:', email);
        return done(null, false, { message: 'Your account is pending admin approval. Please wait for approval before logging in.' });
      }

      if (user.status === 'rejected') {
        console.log('User account rejected:', email);
        return done(null, false, { message: 'Your account has been rejected. Please contact support for more information.' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        console.log('Password incorrect for user:', email);
        return done(null, false, { message: 'Password incorrect' });
      }

      // Only allow approved users to login
      if (user.status !== 'approved') {
        console.log('User not approved:', email, 'Status:', user.status);
        return done(null, false, { message: 'Your account is not approved for login.' });
      }

      console.log('Authentication successful for user:', email);
      return done(null, user);
    } catch (err) {
      console.error('Error during authentication:', err);
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Middleware to check if user is authenticated
const ensureAuthenticated = (req, res, next) => {
  // Check for auto-login in development mode
  if (process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development') {
    return next();
  }
  if (req.isAuthenticated()) {
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
  res.status(403).send('You are not authorized to perform this action');
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
  res.status(403).send('Super Admin privileges required for this action');
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

// Middleware to check if user is blocked
const ensureNotBlocked = (req, res, next) => {
  if (req.isAuthenticated() && req.user.isBlocked) {
    req.logout((err) => {
      if (err) {
        console.error('Error during logout:', err);
      }
      res.status(403).send('Your account has been blocked. Please contact support.');
    });
  } else {
    next();
  }
};

// Route to show admin dashboard
app.get('/admin/dashboard', ensureAdmin, async (req, res) => {
  try {
    const { q: searchQuery, status, blocked, admin, dateFrom, dateTo } = req.query;
    
    // Calculate statistics
    const totalUsers = await User.countDocuments();
    const approvedUsers = await User.countDocuments({ status: 'approved' });
    const pendingUsers = await User.countDocuments({ status: 'pending' });
    const rejectedUsers = await User.countDocuments({ status: 'rejected' });
    const blockedUsers = await User.countDocuments({ isBlocked: true });
    
    // Recent registrations (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentRegistrations = await User.countDocuments({ createdAt: { $gte: sevenDaysAgo } });
    
    // Monthly registrations
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const monthlyRegistrations = await User.countDocuments({ createdAt: { $gte: thirtyDaysAgo } });
    
    // Approval rate
    const totalProcessed = approvedUsers + rejectedUsers;
    const approvalRate = totalProcessed > 0 ? Math.round((approvedUsers / totalProcessed) * 100) : 0;
    
    // Probationary users
    const probationaryUsers = await User.countDocuments({ 
      probationaryUntil: { $exists: true, $gte: new Date() } 
    });
    
    // Suspicious IP analysis (more than 3 registrations from same IP)
    const suspiciousIPs = await User.aggregate([
      { $match: { registrationIP: { $exists: true, $ne: null } } },
      { $group: { _id: '$registrationIP', count: { $sum: 1 } } },
      { $match: { count: { $gte: 3 } } },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);
    
    // Enhanced event statistics
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const tomorrow = new Date(today.getTime() + 24 * 60 * 60 * 1000);
    const nextWeek = new Date(today.getTime() + 7 * 24 * 60 * 60 * 1000);
    
    const activeEvents = await Event.countDocuments({ date: { $gte: now } });
    const eventsToday = await Event.countDocuments({ 
      date: { $gte: today, $lt: tomorrow } 
    });
    const eventsThisWeek = await Event.countDocuments({ 
      date: { $gte: today, $lt: nextWeek } 
    });
    const totalEvents = await Event.countDocuments();
    
    // Game statistics
    const totalGames = await Game.countDocuments();
    const steamGames = await Game.countDocuments({ source: 'steam' });
    const manualGames = await Game.countDocuments({ source: 'manual' });
    const pendingGames = await Game.countDocuments({ status: 'pending' });
    
    // Recent admin activity
    const recentActivity = await AuditLog.find()
      .sort({ timestamp: -1 })
      .limit(10)
      .lean();
    
    const stats = {
      totalUsers,
      approvedUsers,
      pendingUsers,
      rejectedUsers,
      blockedUsers,
      recentRegistrations,
      monthlyRegistrations,
      approvalRate,
      probationaryUsers,
      suspiciousIPs,
      activeEvents,
      eventsToday,
      eventsThisWeek,
      totalEvents,
      totalGames,
      steamGames,
      manualGames,
      pendingGames
    };
    
    const searchFilters = { status, blocked, admin, dateFrom, dateTo };
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    res.render('adminDashboard', { 
      stats, 
      recentActivity, 
      searchQuery, 
      searchFilters, 
      isDevelopmentAutoLogin,
      user: req.user
    });
  } catch (err) {
    console.error('Error loading admin dashboard:', err);
    res.status(500).send('Error loading dashboard');
  }
});

// Route to show admin panel (redirect to dashboard)
app.get('/admin', ensureAdmin, async (req, res) => {
  res.redirect('/admin/dashboard');
});

// Route to show admin system management
app.get('/admin/system', ensureAdmin, async (req, res) => {
  try {
    // System statistics
    const systemStats = {
      // Database statistics
      totalUsers: await User.countDocuments(),
      totalEvents: await Event.countDocuments(),
      totalGames: await Game.countDocuments(),
      totalAuditLogs: await AuditLog.countDocuments(),
      
      // Recent activity counts
      recentUsers: await User.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } 
      }),
      recentEvents: await Event.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } 
      }),
      
      // Security metrics
      blockedUsers: await User.countDocuments({ isBlocked: true }),
      rejectedUsers: await User.countDocuments({ status: 'rejected' }),
      probationaryUsers: await User.countDocuments({ 
        probationaryUntil: { $exists: true, $gte: new Date() } 
      })
    };
    
    // Suspicious IP analysis
    const suspiciousIPs = await User.aggregate([
      { $match: { registrationIP: { $exists: true, $ne: null } } },
      { $group: { 
        _id: '$registrationIP', 
        count: { $sum: 1 },
        users: { $push: { email: '$email', createdAt: '$createdAt', status: '$status' } }
      }},
      { $match: { count: { $gte: 3 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    // Recent audit logs
    const recentAuditLogs = await AuditLog.find()
      .sort({ timestamp: -1 })
      .limit(50)
      .lean();
    
    // System health indicators
    const systemHealth = {
      databaseConnected: mongoose.connection.readyState === 1,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      nodeVersion: process.version,
      environment: process.env.NODE_ENV || 'development'
    };
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    res.render('adminSystem', {
      systemStats,
      suspiciousIPs,
      recentAuditLogs,
      systemHealth,
      isDevelopmentAutoLogin,
      user: req.user
    });
  } catch (err) {
    console.error('Error loading system page:', err);
    res.status(500).send('Error loading system page');
  }
});


// Route to show admin games management
app.get('/admin/games', ensureAdmin, async (req, res) => {
  try {
    const { status, source } = req.query;
    let query = {};
    
    // Apply filters
    if (status === 'pending') {
      query.status = 'pending';
    } else if (status === 'approved') {
      query.status = 'approved';
    } else if (status === 'rejected') {
      query.status = 'rejected';
    }
    
    if (source === 'steam') {
      query.source = 'steam';
    } else if (source === 'manual') {
      query.source = 'manual';
    } else if (source === 'admin') {
      query.source = 'admin';
    }
    
    const games = await Game.find(query)
      .populate('addedBy')
      .populate('approvedBy')
      .sort({ createdAt: -1 });
    
    // Get potential duplicates for pending games
    const DuplicateDetectionService = require('./services/duplicateDetectionService');
    const gamesWithDuplicates = await Promise.all(
      games.map(async (game) => {
        if (game.status === 'pending') {
          const duplicates = await DuplicateDetectionService.findPotentialDuplicates(game.name, game._id);
          return { ...game.toObject(), potentialDuplicates: duplicates };
        }
        return game.toObject();
      })
    );
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    res.render('adminGames', { 
      games: gamesWithDuplicates,
      filter: status || null,
      sourceFilter: source || null,
      isDevelopmentAutoLogin,
      user: req.user
    });
  } catch (err) {
    console.error('Error fetching games:', err);
    res.status(500).send('Error fetching games');
  }
});

// Route to approve a game
app.post('/admin/game/approve/:id', ensureAdmin, async (req, res) => {
  try {
    const { notes } = req.body;
    const game = await Game.findById(req.params.id).populate('addedBy');
    
    if (!game) {
      return res.status(404).json({ error: 'Game not found' });
    }
    
    game.status = 'approved';
    game.approvedAt = new Date();
    game.approvedBy = req.user._id;
    
    await game.save();
    
    // Update all events using this game to be visible
    await Event.updateMany(
      { game: game._id, gameStatus: 'pending' },
      { gameStatus: 'approved', isVisible: true }
    );
    
    // Create audit log
    await createAuditLog(
      req.user, 
      'approve_game', 
      game.addedBy, 
      `Approved game: ${game.name}. ${notes || ''}`, 
      getClientIP(req),
      1,
      { gameId: game._id, gameName: game.name }
    );
    
    console.log('Game approved:', game.name, 'by:', req.user.email);
    res.json({ success: true });
  } catch (err) {
    console.error('Error approving game:', err);
    res.status(500).json({ error: 'Error approving game' });
  }
});

// Route to reject a game
app.post('/admin/game/reject/:id', ensureAdmin, async (req, res) => {
  try {
    const { notes } = req.body;
    const game = await Game.findById(req.params.id).populate('addedBy');
    
    if (!game) {
      return res.status(404).json({ error: 'Game not found' });
    }
    
    game.status = 'rejected';
    game.rejectedAt = new Date();
    game.rejectedBy = req.user._id;
    
    await game.save();
    
    // Delete all events using this rejected game
    await Event.deleteMany({ game: game._id, gameStatus: 'pending' });
    
    // Create audit log
    await createAuditLog(
      req.user, 
      'reject_game', 
      game.addedBy, 
      `Rejected game: ${game.name}. ${notes || ''}`, 
      getClientIP(req),
      1,
      { gameId: game._id, gameName: game.name }
    );
    
    console.log('Game rejected:', game.name, 'by:', req.user.email);
    res.json({ success: true });
  } catch (err) {
    console.error('Error rejecting game:', err);
    res.status(500).json({ error: 'Error rejecting game' });
  }
});

// Route to merge duplicate games
app.post('/admin/game/merge/:duplicateId/:canonicalId', ensureAdmin, async (req, res) => {
  try {
    const DuplicateDetectionService = require('./services/duplicateDetectionService');
    const result = await DuplicateDetectionService.mergeDuplicateGames(
      req.params.duplicateId,
      req.params.canonicalId,
      req.user
    );
    
    if (result.success) {
      // Create audit log
      await createAuditLog(
        req.user, 
        'merge_games', 
        null, 
        result.message, 
        getClientIP(req),
        1,
        { duplicateId: req.params.duplicateId, canonicalId: req.params.canonicalId }
      );
      
      console.log('Games merged by admin:', req.user.email, result.message);
      res.json({ success: true, message: result.message });
    } else {
      res.status(400).json({ error: result.message });
    }
  } catch (err) {
    console.error('Error merging games:', err);
    res.status(500).json({ error: 'Error merging games' });
  }
});

// Route to show admin events management
app.get('/admin/events', ensureAdmin, async (req, res) => {
  try {
    const { 
      status, 
      game: selectedGame, 
      dateFrom, 
      dateTo, 
      search, 
      creator 
    } = req.query;
    
    let query = {};
    
    // Apply filters
    if (status === 'upcoming') {
      query.date = { $gte: new Date() };
    } else if (status === 'past') {
      query.date = { $lt: new Date() };
    } else if (status === 'live') {
      const now = new Date();
      const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);
      query.date = { $gte: twoHoursAgo, $lte: now };
    }
    
    if (selectedGame) {
      query.game = selectedGame;
    }
    
    if (dateFrom) {
      query.date = { ...query.date, $gte: new Date(dateFrom) };
    }
    
    if (dateTo) {
      const endDate = new Date(dateTo);
      endDate.setHours(23, 59, 59, 999);
      query.date = { ...query.date, $lte: endDate };
    }
    
    if (search && search.trim()) {
      query.name = { $regex: search.trim(), $options: 'i' };
    }
    
    const events = await Event.find(query)
      .populate('game')
      .populate('createdBy')
      .populate('players')
      .sort({ date: -1 });
    
    // Filter by creator if specified
    let filteredEvents = events;
    if (creator && creator.trim()) {
      filteredEvents = events.filter(event => {
        if (!event.createdBy) return false;
        const creatorName = (event.createdBy.gameNickname || event.createdBy.name || '').toLowerCase();
        return creatorName.includes(creator.trim().toLowerCase());
      });
    }
    
    const games = await Game.find().sort({ name: 1 });
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    // Get pending counts for navigation
    const pendingUsers = await User.countDocuments({ status: 'pending' });
    const pendingGames = await Game.countDocuments({ status: 'pending' });
    
    res.render('adminEvents', { 
      events: filteredEvents, 
      games,
      filter: status || null,
      selectedGame: selectedGame || null,
      dateFrom: dateFrom || null,
      dateTo: dateTo || null,
      search: search || null,
      creator: creator || null,
      pendingUsers,
      pendingGames,
      isDevelopmentAutoLogin,
      user: req.user
    });
  } catch (err) {
    console.error('Error fetching events:', err);
    res.status(500).send('Error fetching events');
  }
});

// Route to show admin events calendar view
app.get('/admin/events/calendar', ensureAdmin, async (req, res) => {
  try {
    const { 
      status, 
      game: selectedGame, 
      dateFrom, 
      dateTo, 
      search, 
      creator 
    } = req.query;
    
    let query = {};
    
    // Apply filters
    if (status === 'upcoming') {
      query.date = { $gte: new Date() };
    } else if (status === 'past') {
      query.date = { $lt: new Date() };
    } else if (status === 'live') {
      const now = new Date();
      const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);
      query.date = { $gte: twoHoursAgo, $lte: now };
    }
    
    if (selectedGame) {
      query.game = selectedGame;
    }
    
    if (dateFrom) {
      query.date = { ...query.date, $gte: new Date(dateFrom) };
    }
    
    if (dateTo) {
      const endDate = new Date(dateTo);
      endDate.setHours(23, 59, 59, 999);
      query.date = { ...query.date, $lte: endDate };
    }
    
    if (search && search.trim()) {
      query.name = { $regex: search.trim(), $options: 'i' };
    }
    
    const events = await Event.find(query)
      .populate('game')
      .populate('createdBy')
      .populate('players')
      .sort({ date: 1 });
    
    // Filter by creator if specified
    let filteredEvents = events;
    if (creator && creator.trim()) {
      filteredEvents = events.filter(event => {
        if (!event.createdBy) return false;
        const creatorName = (event.createdBy.gameNickname || event.createdBy.name || '').toLowerCase();
        return creatorName.includes(creator.trim().toLowerCase());
      });
    }
    
    const games = await Game.find().sort({ name: 1 });
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    // Get pending counts for navigation
    const pendingUsers = await User.countDocuments({ status: 'pending' });
    const pendingGames = await Game.countDocuments({ status: 'pending' });
    
    res.render('adminEventsCalendar', { 
      events: filteredEvents, 
      games,
      filter: status || null,
      selectedGame: selectedGame || null,
      dateFrom: dateFrom || null,
      dateTo: dateTo || null,
      search: search || null,
      creator: creator || null,
      pendingUsers,
      pendingGames,
      isDevelopmentAutoLogin,
      user: req.user
    });
  } catch (err) {
    console.error('Error fetching events for calendar:', err);
    res.status(500).send('Error fetching events for calendar');
  }
});

// Route for admin to delete events
app.post('/admin/event/:id/delete', ensureAdmin, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('createdBy');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Create audit log for admin deletion
    await createAuditLog(
      req.user, 
      'admin_delete_event', 
      event.createdBy, 
      `Admin deleted event: ${event.name}`, 
      getClientIP(req),
      1,
      { eventId: event._id, eventName: event.name }
    );
    
    // Delete the event
    await Event.findByIdAndDelete(req.params.id);
    
    console.log(`Event "${event.name}" deleted by admin ${req.user.email}`);
    res.redirect('/admin/events');
  } catch (err) {
    console.error('Error deleting event:', err);
    res.status(500).send('Error deleting event');
  }
});

// Bulk delete events (admin only)
app.post('/admin/events/bulk-delete', ensureAdmin, async (req, res) => {
  try {
    const { eventIds, notes } = req.body;
    
    if (!Array.isArray(eventIds) || eventIds.length === 0) {
      return res.status(400).send('No events selected');
    }
    
    const events = await Event.find({ _id: { $in: eventIds } }).populate('createdBy');
    const deletedCount = events.length;
    
    // Create audit log for bulk deletion
    await createAuditLog(
      req.user, 
      'admin_bulk_delete_events', 
      null, 
      notes || 'Bulk deletion of events by admin', 
      getClientIP(req),
      deletedCount,
      { eventIds, eventNames: events.map(e => e.name) }
    );
    
    // Delete the events
    await Event.deleteMany({ _id: { $in: eventIds } });
    
    console.log(`Bulk deleted ${deletedCount} events by admin ${req.user.email}`);
    res.redirect('/admin/events');
  } catch (err) {
    console.error('Error bulk deleting events:', err);
    res.status(500).send('Error bulk deleting events');
  }
});

// Route to show all registered users with filtering
app.get('/admin/users', ensureAdmin, async (req, res) => {
  try {
    const { filter, search, dateFrom, dateTo } = req.query;
    let query = {};
    
    // Apply filters
    if (filter === 'pending') {
      query.status = 'pending';
    } else if (filter === 'approved') {
      query.status = 'approved';
    } else if (filter === 'rejected') {
      query.status = 'rejected';
    } else if (filter === 'blocked') {
      query.isBlocked = true;
    } else if (filter === 'probation') {
      query.probationaryUntil = { $exists: true, $gte: new Date() };
    }
    
    // Search filter
    if (search && search.trim()) {
      const searchRegex = { $regex: search.trim(), $options: 'i' };
      query.$or = [
        { name: searchRegex },
        { email: searchRegex },
        { gameNickname: searchRegex }
      ];
    }
    
    // Date range filter
    if (dateFrom || dateTo) {
      query.createdAt = {};
      if (dateFrom) {
        query.createdAt.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        const endDate = new Date(dateTo);
        endDate.setHours(23, 59, 59, 999);
        query.createdAt.$lte = endDate;
      }
    }
    
    const users = await User.find(query).sort({ createdAt: -1 });
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    // Get pending counts for navigation
    const pendingEvents = await Event.countDocuments({ gameStatus: 'pending' });
    const pendingGames = await Game.countDocuments({ status: 'pending' });
    
    res.render('adminUsers', { 
      users, 
      filter: filter || null,
      search: search || null,
      dateFrom: dateFrom || null,
      dateTo: dateTo || null,
      pendingEvents,
      pendingGames,
      isDevelopmentAutoLogin,
      user: req.user
    });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).send('Error fetching users');
  }
});

// Route to delete a user
app.post('/admin/user/delete/:id', ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const targetUser = req.targetUser; // Set by middleware
    
    // Create audit log
    await createAuditLog(req.user, 'delete_user', targetUser, 'User deleted by admin', getClientIP(req));
    
    await User.findByIdAndDelete(req.params.id);
    console.log(`User ${targetUser.email} deleted by admin ${req.user.email}`);
    res.redirect('/admin/users');
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).send('Error deleting user');
  }
});

// Route to block a user
app.post('/admin/user/block/:id', ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const targetUser = req.targetUser; // Set by middleware
    
    targetUser.isBlocked = true;
    await targetUser.save();
    
    // Create audit log
    await createAuditLog(req.user, 'block_user', targetUser, 'User blocked by admin', getClientIP(req));
    
    console.log(`User ${targetUser.email} blocked by admin ${req.user.email}`);
    res.redirect('/admin/users');
  } catch (err) {
    console.error('Error blocking user:', err);
    res.status(500).send('Error blocking user');
  }
});

// Route to unblock a user
app.post('/admin/user/unblock/:id', ensureAdmin, checkAdminOperationPermission, async (req, res) => {
  try {
    const targetUser = req.targetUser; // Set by middleware
    
    targetUser.isBlocked = false;
    await targetUser.save();
    
    // Create audit log
    await createAuditLog(req.user, 'unblock_user', targetUser, 'User unblocked by admin', getClientIP(req));
    
    console.log(`User ${targetUser.email} unblocked by admin ${req.user.email}`);
    res.redirect('/admin/users');
  } catch (err) {
    console.error('Error unblocking user:', err);
    res.status(500).send('Error unblocking user');
  }
});

// Route to toggle admin status for a user
app.post('/admin/user/toggle-admin/:id', ensureSuperAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('User not found');
    }
    
    // Prevent modification of protected users by others
    if (user.isProtected && req.user.email !== user.email) {
      return res.status(403).send('This user is protected and can only be modified by themselves');
    }
    
    user.isAdmin = !user.isAdmin;
    await user.save();
    
    // Create audit log
    await createAuditLog(req.user, user.isAdmin ? 'promote_admin' : 'demote_admin', user, '', getClientIP(req));
    
    console.log(`User ${user.email} admin status toggled to ${user.isAdmin} by super admin ${req.user.email}`);
    res.redirect('/admin/users');
  } catch (err) {
    console.error('Error updating user admin status:', err);
    res.status(500).send('Error updating user');
  }
});

// Route to approve a user
app.post('/admin/user/approve/:id', ensureAdmin, async (req, res) => {
  try {
    const { notes } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.status = 'approved';
    user.approvedAt = new Date();
    user.approvedBy = req.user._id;
    if (notes) {
      user.approvalNotes = notes;
    }
    
    await user.save();
    
    // Create audit log
    await createAuditLog(req.user, 'approve_user', user, notes, getClientIP(req));
    
    console.log('User approved:', user.email, 'by:', req.user.email);
    res.json({ success: true });
  } catch (err) {
    console.error('Error approving user:', err);
    res.status(500).json({ error: 'Error approving user' });
  }
});

// Route to reject a user
app.post('/admin/user/reject/:id', ensureAdmin, async (req, res) => {
  try {
    const { notes } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.status = 'rejected';
    user.rejectedAt = new Date();
    user.rejectedBy = req.user._id;
    if (notes) {
      user.rejectedReason = notes;
    }
    
    await user.save();
    
    // Add email to rejected list to prevent re-registration
    const rejectedEmail = new RejectedEmail({
      email: user.email.toLowerCase(),
      rejectedBy: req.user._id,
      reason: notes || 'Account rejected by admin'
    });
    await rejectedEmail.save();
    
    // Create audit log
    await createAuditLog(req.user, 'reject_user', user, notes, getClientIP(req));
    
    console.log('User rejected:', user.email, 'by:', req.user.email);
    res.json({ success: true });
  } catch (err) {
    console.error('Error rejecting user:', err);
    res.status(500).json({ error: 'Error rejecting user' });
  }
});

// Route to end probation for a user
app.post('/admin/user/end-probation/:id', ensureAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.probationaryUntil = undefined;
    await user.save();
    
    // Create audit log
    await createAuditLog(req.user, 'end_probation', user, '', getClientIP(req));
    
    console.log('Probation ended for user:', user.email, 'by:', req.user.email);
    res.json({ success: true });
  } catch (err) {
    console.error('Error ending probation:', err);
    res.status(500).json({ error: 'Error ending probation' });
  }
});

// Route to promote user to super admin
app.post('/admin/user/promote-super-admin/:id', ensureSuperAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('User not found');
    }
    
    // Prevent modification of protected users by others
    if (user.isProtected && req.user.email !== user.email) {
      return res.status(403).send('This user is protected and can only be modified by themselves');
    }
    
    // User must be admin first
    if (!user.isAdmin) {
      return res.status(400).send('User must be an admin before being promoted to Super Admin');
    }
    
    // Check if already super admin
    if (user.isSuperAdmin) {
      return res.status(400).send('User is already a Super Admin');
    }
    
    user.isSuperAdmin = true;
    await user.save();
    
    // Create audit log
    await createAuditLog(req.user, 'promote_super_admin', user, 'User promoted to Super Admin', getClientIP(req));
    
    console.log(`User ${user.email} promoted to Super Admin by ${req.user.email}`);
    res.redirect('/admin/users');
  } catch (err) {
    console.error('Error promoting user to super admin:', err);
    res.status(500).send('Error promoting user to super admin');
  }
});

// Route to demote super admin to admin
app.post('/admin/user/demote-super-admin/:id', ensureSuperAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('User not found');
    }
    
    // Prevent modification of protected users by others
    if (user.isProtected && req.user.email !== user.email) {
      return res.status(403).send('This user is protected and can only be modified by themselves');
    }
    
    // Check if user is super admin
    if (!user.isSuperAdmin) {
      return res.status(400).send('User is not a Super Admin');
    }
    
    // Prevent self-demotion
    if (req.user._id.equals(user._id)) {
      return res.status(403).send('Super Admins cannot demote themselves');
    }
    
    user.isSuperAdmin = false;
    await user.save();
    
    // Create audit log
    await createAuditLog(req.user, 'demote_super_admin', user, 'Super Admin demoted to Admin', getClientIP(req));
    
    console.log(`Super Admin ${user.email} demoted to Admin by ${req.user.email}`);
    res.redirect('/admin/users');
  } catch (err) {
    console.error('Error demoting super admin:', err);
    res.status(500).send('Error demoting super admin');
  }
});

// Bulk approve users
app.post('/admin/users/bulk-approve', ensureAdmin, async (req, res) => {
  try {
    const { userIds, notes } = req.body;
    
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'No users selected' });
    }
    
    const users = await User.find({ _id: { $in: userIds } });
    const approvedCount = users.length;
    
    for (const user of users) {
      user.status = 'approved';
      user.approvedAt = new Date();
      user.approvedBy = req.user._id;
      if (notes) {
        user.approvalNotes = notes;
      }
      await user.save();
    }
    
    // Create bulk audit log
    await createAuditLog(req.user, 'bulk_approve', null, notes, getClientIP(req), approvedCount, { userIds });
    
    console.log('Bulk approved', approvedCount, 'users by:', req.user.email);
    res.json({ success: true, count: approvedCount });
  } catch (err) {
    console.error('Error bulk approving users:', err);
    res.status(500).json({ error: 'Error bulk approving users' });
  }
});

// Bulk reject users
app.post('/admin/users/bulk-reject', ensureAdmin, async (req, res) => {
  try {
    const { userIds, notes } = req.body;
    
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'No users selected' });
    }
    
    const users = await User.find({ _id: { $in: userIds } });
    const rejectedCount = users.length;
    
    for (const user of users) {
      user.status = 'rejected';
      user.rejectedAt = new Date();
      user.rejectedBy = req.user._id;
      if (notes) {
        user.rejectedReason = notes;
      }
      await user.save();
      
      // Add email to rejected list
      const rejectedEmail = new RejectedEmail({
        email: user.email.toLowerCase(),
        rejectedBy: req.user._id,
        reason: notes || 'Account rejected by admin (bulk action)'
      });
      await rejectedEmail.save();
    }
    
    // Create bulk audit log
    await createAuditLog(req.user, 'bulk_reject', null, notes, getClientIP(req), rejectedCount, { userIds });
    
    console.log('Bulk rejected', rejectedCount, 'users by:', req.user.email);
    res.json({ success: true, count: rejectedCount });
  } catch (err) {
    console.error('Error bulk rejecting users:', err);
    res.status(500).json({ error: 'Error bulk rejecting users' });
  }
});

// Bulk delete users
app.post('/admin/users/bulk-delete', ensureAdmin, async (req, res) => {
  try {
    const { userIds, notes } = req.body;
    
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'No users selected' });
    }
    
    const users = await User.find({ _id: { $in: userIds } });
    const deletedCount = users.length;
    
    // Remove users from events first
    await Event.updateMany(
      { players: { $in: userIds } },
      { $pull: { players: { $in: userIds } } }
    );
    
    // Delete users
    await User.deleteMany({ _id: { $in: userIds } });
    
    // Create bulk audit log
    await createAuditLog(req.user, 'bulk_delete', null, notes, getClientIP(req), deletedCount, { userIds });
    
    console.log('Bulk deleted', deletedCount, 'users by:', req.user.email);
    res.json({ success: true, count: deletedCount });
  } catch (err) {
    console.error('Error bulk deleting users:', err);
    res.status(500).json({ error: 'Error bulk deleting users' });
  }
});

// Steam API routes - Updated to allow authenticated users (not just admins)
app.get('/api/steam/search', ensureAuthenticated, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.trim().length < 2) {
      return res.json([]);
    }
    
    const results = await steamService.searchGames(q, 10);
    
    // Check which games already exist in the database
    const enrichedResults = await Promise.all(results.map(async (game) => {
      const existingGame = await Game.findOne({ 
        steamAppId: game.appid, 
        status: 'approved' 
      });
      
      return {
        ...game,
        existsInDatabase: !!existingGame,
        existingGameId: existingGame ? existingGame._id : null,
        existingGameName: existingGame ? existingGame.name : null
      };
    }));
    
    res.json(enrichedResults);
  } catch (error) {
    console.error('Error searching Steam games:', error);
    res.status(500).json({ error: 'Failed to search Steam games' });
  }
});

// RAWG API routes
app.get('/api/rawg/search', ensureAuthenticated, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.trim().length < 2) {
      return res.json([]);
    }
    
    const results = await rawgService.searchGames(q, 10);
    
    // Check which games already exist in the database and if Steam equivalent exists
    const enrichedResults = await Promise.all(results.map(async (game) => {
      // Check if this RAWG game already exists
      const existingRawgGame = await Game.findOne({ 
        rawgId: game.id, 
        status: 'approved' 
      });
      
      // Check if a Steam equivalent exists (prefer Steam over RAWG)
      const steamEquivalent = await Game.findOne({
        name: { $regex: new RegExp(`^${game.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') },
        source: 'steam',
        status: 'approved'
      });
      
      return {
        ...game,
        existsInDatabase: !!existingRawgGame,
        existingGameId: existingRawgGame ? existingRawgGame._id : null,
        existingGameName: existingRawgGame ? existingRawgGame.name : null,
        hasSteamEquivalent: !!steamEquivalent,
        steamEquivalentId: steamEquivalent ? steamEquivalent._id : null,
        steamEquivalentName: steamEquivalent ? steamEquivalent.name : null
      };
    }));
    
    res.json(enrichedResults);
  } catch (error) {
    console.error('Error searching RAWG games:', error);
    res.status(500).json({ error: 'Failed to search RAWG games' });
  }
});

// API route to check if RAWG game has Steam equivalent
app.post('/api/games/check-steam-equivalent', ensureAuthenticated, async (req, res) => {
  try {
    const { gameName } = req.body;
    if (!gameName || gameName.trim().length < 2) {
      return res.json({ hasSteamEquivalent: false });
    }
    
    const steamEquivalent = await Game.findOne({
      name: { $regex: new RegExp(`^${gameName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') },
      source: 'steam',
      status: 'approved'
    });
    
    res.json({
      hasSteamEquivalent: !!steamEquivalent,
      steamGame: steamEquivalent ? {
        id: steamEquivalent._id,
        name: steamEquivalent.name,
        steamAppId: steamEquivalent.steamAppId
      } : null
    });
  } catch (error) {
    console.error('Error checking Steam equivalent:', error);
    res.status(500).json({ error: 'Failed to check Steam equivalent' });
  }
});

// Duplicate detection API
app.post('/api/games/check-duplicates', ensureAuthenticated, async (req, res) => {
  try {
    const { gameName } = req.body;
    if (!gameName || gameName.trim().length < 3) {
      return res.json([]);
    }
    
    const DuplicateDetectionService = require('./services/duplicateDetectionService');
    const duplicates = await DuplicateDetectionService.findPotentialDuplicates(gameName);
    res.json(duplicates);
  } catch (error) {
    console.error('Error checking for duplicates:', error);
    res.status(500).json({ error: 'Failed to check for duplicates' });
  }
});

// Route to display add game form (admin only)
app.get('/admin/add-game', ensureAdmin, async (req, res) => {
  try {
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    // Get pending counts for navigation
    const pendingUsers = await User.countDocuments({ status: 'pending' });
    const pendingEvents = await Event.countDocuments({ gameStatus: 'pending' });
    const pendingGames = await Game.countDocuments({ status: 'pending' });
    const totalPending = pendingUsers + pendingEvents + pendingGames;
    
    res.render('addGame', { 
      user: req.user,
      error: null,
      success: null,
      title: 'Add Game',
      currentPage: 'add-game',
      pageTitle: 'Add New Game',
      pageSubtitle: 'Add games to the GamePlan library',
      breadcrumbs: [{ name: 'Games', url: '/admin/games' }, { name: 'Add Game' }],
      pendingUsers,
      pendingEvents,
      pendingGames,
      totalPending,
      isDevelopmentAutoLogin
    });
  } catch (err) {
    console.error('Error loading add game form:', err);
    res.status(500).send('Error loading add game form');
  }
});

// Route to add a new game with Steam integration (admin only)
app.post('/admin/add-game', ensureAdmin, async (req, res) => {
  try {
    const { name, description, steamAppId, steamData, rawgId, rawgData, source } = req.body;
    
    // Helper function to get template variables
    const getTemplateVars = async () => {
      const pendingUsers = await User.countDocuments({ status: 'pending' });
      const pendingEvents = await Event.countDocuments({ gameStatus: 'pending' });
      const pendingGames = await Game.countDocuments({ status: 'pending' });
      const totalPending = pendingUsers + pendingEvents + pendingGames;
      
      return {
        user: req.user,
        title: 'Add Game',
        currentPage: 'add-game',
        pageTitle: 'Add New Game',
        pageSubtitle: 'Add games to the GamePlan library',
        breadcrumbs: [{ name: 'Games', url: '/admin/games' }, { name: 'Add Game' }],
        pendingUsers,
        pendingEvents,
        pendingGames,
        totalPending,
        isDevelopmentAutoLogin: process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development'
      };
    };
    
    if (!name || !name.trim()) {
      const templateVars = await getTemplateVars();
      return res.render('addGame', { 
        ...templateVars,
        error: 'Game name is required',
        success: null
      });
    }
    
    const gameData = {
      name: name.trim(),
      description: description || '',
      addedBy: req.user._id,
      source: source || 'manual',
      status: 'approved' // Admin-added games are automatically approved
    };

    // Handle Steam games
    if (source === 'steam' && steamAppId && steamData) {
      try {
        const parsedSteamData = typeof steamData === 'string' ? JSON.parse(steamData) : steamData;
        
        // Check if Steam game already exists
        const existingGame = await Game.findOne({ steamAppId: parseInt(steamAppId) });
        if (existingGame) {
          const templateVars = await getTemplateVars();
          return res.render('addGame', { 
            ...templateVars,
            error: `This Steam game already exists in the database: ${existingGame.name}`,
            success: null
          });
        }
        
        gameData.steamAppId = parseInt(steamAppId);
        gameData.steamData = parsedSteamData;
        
        // Extract platforms from Steam data
        if (parsedSteamData.platforms && parsedSteamData.platforms.length > 0) {
          gameData.platforms = parsedSteamData.platforms;
        } else {
          gameData.platforms = ['PC']; // Default for Steam games
        }
        
        // Use Steam description if no custom description provided
        if (!description && parsedSteamData.short_description) {
          gameData.description = parsedSteamData.short_description;
        }
      } catch (parseError) {
        console.error('Error parsing Steam data:', parseError);
        const templateVars = await getTemplateVars();
        return res.render('addGame', { 
          ...templateVars,
          error: 'Invalid Steam game data',
          success: null
        });
      }
    }
    
    // Handle RAWG games
    else if (source === 'rawg' && rawgId && rawgData) {
      try {
        const parsedRawgData = typeof rawgData === 'string' ? JSON.parse(rawgData) : rawgData;
        
        // Check if RAWG game already exists
        const existingGame = await Game.findOne({ rawgId: parseInt(rawgId) });
        if (existingGame) {
          const templateVars = await getTemplateVars();
          return res.render('addGame', { 
            ...templateVars,
            error: `This RAWG game already exists in the database: ${existingGame.name}`,
            success: null
          });
        }
        
        gameData.rawgId = parseInt(rawgId);
        gameData.rawgData = parsedRawgData;
        
        // Extract platforms from RAWG data
        if (parsedRawgData.platforms && parsedRawgData.platforms.length > 0) {
          gameData.platforms = parsedRawgData.platforms.map(p => p.platform ? p.platform.name : p.name || p);
        }
        
        // Extract categories/genres from RAWG data
        if (parsedRawgData.genres && parsedRawgData.genres.length > 0) {
          gameData.categories = parsedRawgData.genres.map(g => g.name);
        }
        
        // Use RAWG description if no custom description provided
        if (!description && parsedRawgData.description) {
          gameData.description = parsedRawgData.description;
        }
      } catch (parseError) {
        console.error('Error parsing RAWG data:', parseError);
        const templateVars = await getTemplateVars();
        return res.render('addGame', { 
          ...templateVars,
          error: 'Invalid RAWG game data',
          success: null
        });
      }
    }
    
    // Handle manual games
    else if (source === 'manual') {
      // Check for potential duplicates
      const existingGame = await Game.findOne({ 
        name: { $regex: new RegExp(`^${name.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') },
        status: 'approved'
      });
      
      if (existingGame) {
        const templateVars = await getTemplateVars();
        return res.render('addGame', { 
          ...templateVars,
          error: `A game with this name already exists: ${existingGame.name}`,
          success: null
        });
      }
    }

    const game = new Game(gameData);
    await game.save();
    
    // Create audit log
    await createAuditLog(
      req.user, 
      'add_game', 
      null, 
      `Added game: ${game.name} (${source})`, 
      getClientIP(req),
      1,
      { gameId: game._id, gameName: game.name, source: source }
    );
    
    console.log(`Game "${game.name}" added by admin ${req.user.email} (source: ${source})`);
    
    const templateVars = await getTemplateVars();
    res.render('addGame', { 
      ...templateVars,
      error: null,
      success: `Game "${game.name}" has been successfully added to the database!`
    });
  } catch (err) {
    console.error('Error adding game:', err);
    const templateVars = await getTemplateVars();
    res.render('addGame', { 
      ...templateVars,
      error: 'Error adding game. Please try again.',
      success: null
    });
  }
});

// Route to add a new game directly (for testing)
app.post('/test/add-game', async (req, res) => {
  try {
    const { name, description } = req.body;
    const game = new Game({ name, description });
    await game.save();
    res.status(200).json({ id: game._id, name: game.name });
  } catch (err) {
    res.status(500).send('Error adding game');
  }
});

// Route to delete a game
app.post('/admin/delete-game/:id', ensureAdmin, async (req, res) => {
  try {
    await Game.findByIdAndDelete(req.params.id);
    res.redirect('/admin');
  } catch (err) {
    res.status(500).send('Error deleting game');
  }
});

// Route to toggle admin status for a user
app.post('/admin/toggle-admin', ensureAdmin, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).send('User not found');
    }
    user.isAdmin = !user.isAdmin;
    await user.save();
    res.send(`User's admin status has been updated to: ${user.isAdmin}`);
  } catch (err) {
    res.status(500).send('Error updating user');
  }
});

// Route to manually set a user as admin (for initial setup)
app.post('/setup-admin', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).send('User not found');
    }
    user.isAdmin = true;
    await user.save();
    res.send(`User has been set as admin`);
  } catch (err) {
    res.status(500).send('Error setting admin status');
  }
});

// API endpoint for pending user count
app.get('/api/admin/pending-count', ensureAdmin, async (req, res) => {
  try {
    const pendingCount = await User.countDocuments({ status: 'pending' });
    res.json({ count: pendingCount });
  } catch (err) {
    console.error('Error fetching pending user count:', err);
    res.status(500).json({ error: 'Error fetching pending user count' });
  }
});

// API endpoint for filtering events
app.get('/api/events/filter', async (req, res) => {
  try {
    const {
      search,
      gameSearch,
      dateFrom,
      dateTo,
      status,
      platforms,
      playerAvailability,
      host,
      categories,
      sortBy
    } = req.query;

    let query = {};
    
    // Base visibility filter based on user role
    if (!req.user) {
      query.isVisible = true;
    } else if (!req.user.isAdmin) {
      query = {
        $or: [
          { isVisible: true },
          { createdBy: req.user._id, gameStatus: 'pending' }
        ]
      };
    }

    // Default: Hide events that started more than 1 hour ago
    const oneHourAgo = new Date(Date.now() - 3600000);
    if (!status || status !== 'past') {
      query.date = { $gte: oneHourAgo };
    }

    // Event name search
    if (search && search.trim()) {
      query.name = { $regex: search.trim(), $options: 'i' };
    }

    // Date range filter
    if (dateFrom) {
      query.date = { ...query.date, $gte: new Date(dateFrom) };
    }
    if (dateTo) {
      const endDate = new Date(dateTo);
      endDate.setHours(23, 59, 59, 999); // End of day
      query.date = { ...query.date, $lte: endDate };
    }

    // Status filter
    if (status) {
      const now = new Date();
      const twoHoursAgo = new Date(now.getTime() - 7200000);
      
      if (status === 'live') {
        query.date = {
          $gte: twoHoursAgo,
          $lte: now
        };
      } else if (status === 'upcoming') {
        query.date = { $gt: now };
      } else if (status === 'past') {
        query.date = { $lt: twoHoursAgo };
      }
    }

    // Platform filter
    if (platforms) {
      const platformArray = Array.isArray(platforms) ? platforms : [platforms];
      query.platforms = { $in: platformArray };
    }

    // Build aggregation pipeline
    let pipeline = [
      { $match: query },
      {
        $lookup: {
          from: 'users',
          localField: 'createdBy',
          foreignField: '_id',
          as: 'createdBy'
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: 'players',
          foreignField: '_id',
          as: 'players'
        }
      },
      {
        $lookup: {
          from: 'extensions',
          localField: 'requiredExtensions',
          foreignField: '_id',
          as: 'requiredExtensions'
        }
      },
      {
        $lookup: {
          from: 'games',
          localField: 'game',
          foreignField: '_id',
          as: 'game'
        }
      },
      { $unwind: { path: '$createdBy', preserveNullAndEmptyArrays: true } },
      { $unwind: { path: '$game', preserveNullAndEmptyArrays: true } }
    ];

    // Game name search
    if (gameSearch && gameSearch.trim()) {
      pipeline.push({
        $match: {
          'game.name': { $regex: gameSearch.trim(), $options: 'i' }
        }
      });
    }

    // Host filter
    if (host && host.trim()) {
      pipeline.push({
        $match: {
          $or: [
            { 'createdBy.name': { $regex: host.trim(), $options: 'i' } },
            { 'createdBy.gameNickname': { $regex: host.trim(), $options: 'i' } }
          ]
        }
      });
    }

    // Game categories filter
    if (categories) {
      const categoryArray = Array.isArray(categories) ? categories : [categories];
      pipeline.push({
        $match: {
          'game.categories': { $in: categoryArray }
        }
      });
    }

    // Player availability filter
    if (playerAvailability) {
      if (playerAvailability === 'available') {
        pipeline.push({
          $match: {
            $expr: { $lt: [{ $size: '$players' }, '$playerLimit'] }
          }
        });
      } else if (playerAvailability === 'full') {
        pipeline.push({
          $match: {
            $expr: { $gte: [{ $size: '$players' }, '$playerLimit'] }
          }
        });
      }
    }

    // Sorting
    let sortOptions = { date: 1 }; // Default: next game order
    if (sortBy) {
      switch (sortBy) {
        case 'recent':
          sortOptions = { createdAt: -1 };
          break;
        case 'players':
          sortOptions = { playerLimit: -1 };
          break;
        case 'alphabetical':
          sortOptions = { name: 1 };
          break;
        default:
          sortOptions = { date: 1 };
      }
    }

    pipeline.push({ $sort: sortOptions });

    const events = await Event.aggregate(pipeline);
    
    res.json({
      events,
      total: events.length
    });

  } catch (error) {
    console.error('Error filtering events:', error);
    res.status(500).json({ error: 'Failed to filter events' });
  }
});

// Routes
app.get('/', async (req, res) => {
  let query = {};
  
  // Filter events based on user role and visibility
  if (!req.user) {
    // Non-authenticated users only see visible events
    query.isVisible = true;
  } else if (!req.user.isAdmin) {
    // Regular authenticated users see visible events + their own pending events
    query = {
      $or: [
        { isVisible: true },
        { createdBy: req.user._id, gameStatus: 'pending' }
      ]
    };
  }
  // Admins see all events (no query filter)
  
  // Default: Hide events that started more than 1 hour ago
  const oneHourAgo = new Date(Date.now() - 3600000);
  query.date = { $gte: oneHourAgo };
  
  const events = await Event.find(query).populate('createdBy').populate({
    path: 'players',
    populate: { path: 'players' }
  }).populate('requiredExtensions').populate('game').sort({ date: 1 }); // Sort by date ascending (soonest first)
  
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('index', { events, user: req.user, isDevelopmentAutoLogin });
});

// User profile route
app.get('/profile', ensureAuthenticated, ensureNotBlocked, (req, res) => {
  console.log('Profile route accessed');
  console.log('User:', req.user);
  // For development, if no user is authenticated, create a mock user
  const user = req.user || { name: 'Development User', email: 'dev@example.com', gameNickname: 'DevNick' };
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('profile', { user, isDevelopmentAutoLogin });
});

// Update profile route
app.post('/profile/update', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const { gameNickname } = req.body;
    req.user.gameNickname = gameNickname;
    await req.user.save();
    res.redirect('/profile');
  } catch (err) {
    res.status(500).send('Error updating profile');
  }
});

app.get('/register', (req, res) => {
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
  res.render('register', { isDevelopmentAutoLogin, recaptchaSiteKey, error: null });
});

app.post('/register', async (req, res) => {
  try {
    const { name, email, password, gameNickname, 'g-recaptcha-response': recaptchaResponse } = req.body;
    const clientIP = getClientIP(req);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';

    // Check if email is in rejected list
    const rejectedEmail = await RejectedEmail.findOne({ email: email.toLowerCase() });
    if (rejectedEmail) {
      return res.render('register', { 
        isDevelopmentAutoLogin, 
        recaptchaSiteKey,
        error: 'This email address has been rejected and cannot be used for registration. Please contact support if you believe this is an error.' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.render('register', { 
        isDevelopmentAutoLogin, 
        recaptchaSiteKey,
        error: 'An account with this email already exists.' 
      });
    }

    // Verify reCAPTCHA
    const recaptchaValid = await verifyRecaptcha(recaptchaResponse);
    if (!recaptchaValid) {
      return res.render('register', { 
        isDevelopmentAutoLogin, 
        recaptchaSiteKey,
        error: 'Please complete the CAPTCHA verification.' 
      });
    }

    // Create user with pending status
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ 
      name, 
      email: email.toLowerCase(), 
      password: hashedPassword, 
      gameNickname: gameNickname || '',
      status: 'pending',
      registrationIP: clientIP
    });
    
    await user.save();
    console.log('New user registered with pending status:', email, 'IP:', clientIP);
    
    // Redirect to a pending approval page
    res.render('registrationPending', { isDevelopmentAutoLogin });
  } catch (err) {
    console.error('Error registering user:', err);
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    const recaptchaSiteKey = process.env.RECAPTCHA_SITE_KEY || '';
    res.render('register', { 
      isDevelopmentAutoLogin, 
      recaptchaSiteKey,
      error: 'Error registering user. Please try again.' 
    });
  }
});

app.get('/login', (req, res) => {
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('login', { isDevelopmentAutoLogin });
});

app.post('/login', (req, res, next) => {
  console.log('Login route accessed');
  console.log('Login attempt with email:', req.body.email);

  passport.authenticate('local', (err, user, info) => {
    if (err) {
      console.error('Error during authentication:', err);
      return next(err);
    }
    if (!user) {
      console.log('Authentication failed:', info.message);
      return res.redirect('/login');
    }
    console.log('Authentication successful:', user);
    req.logIn(user, (err) => {
      if (err) {
        console.error('Error during login:', err);
        return next(err);
      }
      console.log('User logged in:', req.isAuthenticated());
      console.log('Session after login:', req.session);
      res.redirect('/');
    });
  })(req, res, next);
});

// Simplify logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log('Error destroying session:', err);
      return res.status(500).send('Logout failed');
    }
    res.clearCookie('connect.sid', { path: '/' });
    res.redirect('/'); // or res.status(200).send('Logout successful')
  });
});

// Protected route for creating events
app.get('/event/new', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  const games = await Game.find();
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  
  // Prepare games data for client-side JavaScript
  const gamesData = games.map(game => ({
    _id: game._id.toString(),
    name: game.name,
    steamAppId: game.steamAppId || null,
    description: game.description || ''
  }));
  
  res.render('newEvent', { user: req.user, games, gamesData: JSON.stringify(gamesData), isDevelopmentAutoLogin });
});

app.post('/event/new', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    console.log('Event creation request received');
    console.log('Request body:', req.body);

    const { name, description, playerLimit, date, extensions, platforms, gameSelection } = req.body;

    // Parse game selection data
    let gameSelectionData;
    try {
      gameSelectionData = JSON.parse(gameSelection);
    } catch (parseError) {
      console.error('Error parsing game selection:', parseError);
      return res.status(400).send('Invalid game selection data');
    }

    console.log('Game selection data:', gameSelectionData);

    let game;
    let gameStatus = 'approved';
    let isVisible = true;

    // Handle different game selection types
    if (gameSelectionData.type === 'existing') {
      // Use existing game
      game = await Game.findById(gameSelectionData.gameId);
      if (!game) {
        console.error('Invalid existing game ID:', gameSelectionData.gameId);
        return res.status(400).send('Invalid game selection');
      }
      console.log('Using existing game:', game.name);

    } else if (gameSelectionData.type === 'steam') {
      // Create or find Steam game
      const steamData = gameSelectionData.data;
      
      // Check if this Steam game already exists
      let existingGame = await Game.findOne({ steamAppId: steamData.appid });
      
      if (existingGame) {
        game = existingGame;
        console.log('Using existing Steam game:', game.name);
      } else {
        // Create new Steam game
        game = new Game({
          name: steamData.name,
          description: steamData.short_description || '',
          steamAppId: steamData.appid,
          steamData: {
            name: steamData.name,
            short_description: steamData.short_description,
            header_image: steamData.header_image,
            developers: steamData.developers || [],
            publishers: steamData.publishers || []
          },
          source: 'steam',
          status: 'approved',
          platforms: steamData.platforms || ['PC'],
          createdAt: new Date()
        });
        
        await game.save();
        console.log('Created new Steam game:', game.name);
      }

    } else if (gameSelectionData.type === 'rawg') {
      // Create or find RAWG game
      const rawgData = gameSelectionData.data;
      
      // Check if this RAWG game already exists
      let existingGame = await Game.findOne({ rawgId: rawgData.id });
      
      if (existingGame) {
        game = existingGame;
        console.log('Using existing RAWG game:', game.name);
      } else {
        // Create new RAWG game
        game = new Game({
          name: rawgData.name,
          description: rawgData.short_description || rawgData.description || '',
          rawgId: rawgData.id,
          rawgData: {
            name: rawgData.name,
            description: rawgData.description || rawgData.short_description || '',
            background_image: rawgData.background_image,
            developers: rawgData.developers || [],
            publishers: rawgData.publishers || [],
            genres: rawgData.genres || [],
            rating: rawgData.rating,
            released: rawgData.released
          },
          source: 'rawg',
          status: 'approved',
          platforms: rawgData.platforms || [],
          categories: rawgData.genres || [],
          createdAt: new Date()
        });
        
        await game.save();
        console.log('Created new RAWG game:', game.name);
      }

    } else if (gameSelectionData.type === 'manual') {
      // Create manual game (pending approval)
      const manualData = gameSelectionData.data;
      
      game = new Game({
        name: manualData.name,
        description: manualData.description,
        categories: manualData.categories || [],
        tags: manualData.tags || [],
        source: 'manual',
        status: 'pending',
        addedBy: req.user._id,
        createdAt: new Date()
      });
      
      await game.save();
      console.log('Created new manual game (pending approval):', game.name);
      
      // Set event status to pending and invisible
      gameStatus = 'pending';
      isVisible = false;
    } else {
      return res.status(400).send('Invalid game selection type');
    }

    // Process platforms properly - handle single string, array, or undefined
    let processedPlatforms = [];
    console.log('Raw platforms received:', platforms, 'Type:', typeof platforms);
    
    if (platforms) {
      if (Array.isArray(platforms)) {
        processedPlatforms = platforms;
      } else if (typeof platforms === 'string') {
        processedPlatforms = [platforms];
      }
    }
    console.log('Processed platforms:', processedPlatforms);

    // Create the event
    const event = new Event({
      name,
      game: game._id,
      description,
      playerLimit,
      date: new Date(date),
      players: [req.user._id], // Add the creator as the first player
      platforms: processedPlatforms,
      steamAppId: game.steamAppId || null,
      createdBy: req.user._id,
      gameStatus: gameStatus,
      isVisible: isVisible
    });

    // Process extensions if provided and not empty
    if (extensions && extensions.trim() !== '' && extensions.trim() !== '[]') {
      try {
        console.log('Processing extensions:', extensions);

        let extensionData;
        if (Array.isArray(extensions)) {
          const lastEntry = extensions[extensions.length - 1];
          if (lastEntry && lastEntry.trim() !== '[]') {
            extensionData = JSON.parse(lastEntry);
          } else {
            extensionData = [];
          }
        } else {
          extensionData = JSON.parse(extensions);
        }

        if (Array.isArray(extensionData) && extensionData.length > 0) {
          for (const ext of extensionData) {
            if (typeof ext.name !== 'string' ||
                typeof ext.downloadLink !== 'string' ||
                typeof ext.installationTime !== 'string') {
              console.error('Invalid extension data structure:', ext);
              return res.status(400).send('Invalid extension data structure');
            }

            if (ext.name.trim() && ext.downloadLink.trim() && ext.installationTime.trim()) {
              const extension = new Extension({
                name: ext.name,
                downloadLink: ext.downloadLink,
                installationTime: ext.installationTime
              });
              await extension.save();
              event.requiredExtensions.push(extension._id);
            }
          }
        }
      } catch (parseError) {
        console.error('Error parsing extensions:', parseError);
        return res.status(400).send('Invalid extensions data');
      }
    }

    console.log('Saving event:', event);
    const savedEvent = await event.save();
    console.log('Saved event:', savedEvent);

    // Redirect with appropriate message
    if (gameStatus === 'pending') {
      // Redirect to a pending approval page or show message
      res.redirect(`/event/${savedEvent._id}?pending=true`);
    } else {
      res.redirect(`/event/${savedEvent._id}`);
    }
  } catch (err) {
    console.error('Error creating event:', err);
    res.status(500).send('Error creating event');
  }
});

// Helper function to check Steam updates
async function checkSteamUpdates(appId) {
  const url = `https://api.steampowered.com/ISteamNews/GetNewsForApp/v2/?appid=${appId}&count=5`;

  try {
    const response = await axios.get(url, { timeout: 5000 });
    const newsData = response.data;

    // Check for update indicators in the news
    const updateFound = newsData.appnews.newsitems.some(item => {
      const title = item.title.toLowerCase();
      const content = item.contents.toLowerCase();
      return (
        title.includes('update') ||
        title.includes('patch') ||
        title.includes('new version') ||
        content.includes('update') ||
        content.includes('patch') ||
        content.includes('new version')
      );
    });

    return {
      hasUpdate: updateFound,
      news: updateFound ? newsData.appnews.newsitems : []
    };
  } catch (error) {
    console.error('Error fetching Steam news:', error);
    return { hasUpdate: false, news: [] };
  }
}

app.get('/event/:id', async (req, res) => {
  try {
    console.log('Fetching event with ID:', req.params.id);
    console.log('Authenticated user:', req.isAuthenticated(), req.user);
    
    // First, try to fetch the event
    const event = await Event.findById(req.params.id).populate('players').populate('requiredExtensions').populate('game').populate('createdBy');
    
    if (!event) {
      console.error('Event not found with ID:', req.params.id);
      return res.status(404).send('Event not found');
    }
    
    console.log('Fetched event:', event.name, 'Steam App ID:', event.steamAppId);

    // Initialize update properties
    event.hasUpdate = false;
    event.updateNews = [];

    // Check for updates if Steam App ID is available
    if (event.steamAppId) {
      try {
        console.log('Checking Steam updates for App ID:', event.steamAppId);
        const updateInfo = await checkSteamUpdates(event.steamAppId);
        event.hasUpdate = updateInfo.hasUpdate;
        event.updateNews = updateInfo.news;
        console.log('Steam update check completed. Has update:', event.hasUpdate);
      } catch (steamError) {
        console.warn('Steam API check failed, continuing without update info:', steamError.message);
        // Continue rendering the event even if Steam check fails
      }
    } else {
      console.log('No Steam App ID available for this event, skipping update check');
    }

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('event', { event, user: req.user, isDevelopmentAutoLogin });
  } catch (err) {
    console.error('Error fetching event:', err);
    console.error('Error details:', {
      message: err.message,
      stack: err.stack,
      eventId: req.params.id
    });
    res.status(500).send('Error fetching event');
  }
});

app.post('/event/:id/join', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (event.players.length >= event.playerLimit) {
      return res.status(400).send('Event is full');
    }
    event.players.push(req.user._id);
    await event.save();
    res.redirect(`/event/${req.params.id}`);
  } catch (err) {
    res.status(500).send('Error joining event');
  }
});

app.post('/event/:id/leave', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    event.players.pull(req.user._id);
    await event.save();
    res.redirect(`/event/${req.params.id}`);
  } catch (err) {
    res.status(500).send('Error leaving event');
  }
});

// Route to show event duplicate form
app.get('/event/:id/duplicate', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const originalEvent = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!originalEvent) {
      return res.status(404).send('Event not found');
    }
    
    // Check if user is authorized to duplicate (event creator or admin)
    const isCreator = originalEvent.createdBy && originalEvent.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !originalEvent.createdBy && originalEvent.players.length > 0 && originalEvent.players[0]._id.equals(req.user._id);
    const isAdmin = req.user.isAdmin;
    
    if (!isCreator && !isLegacyCreator && !isAdmin) {
      return res.status(403).send('You are not authorized to duplicate this event');
    }
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    res.render('duplicateEvent', { 
      originalEvent, 
      user: req.user, 
      isDevelopmentAutoLogin 
    });
  } catch (err) {
    console.error('Error loading event duplicate form:', err);
    res.status(500).send('Error loading event duplicate form');
  }
});

// Route to process event duplication
app.post('/event/:id/duplicate', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const originalEvent = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!originalEvent) {
      return res.status(404).send('Original event not found');
    }
    
    // Check if user is authorized to duplicate (event creator or admin)
    const isCreator = originalEvent.createdBy && originalEvent.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !originalEvent.createdBy && originalEvent.players.length > 0 && originalEvent.players[0]._id.equals(req.user._id);
    const isAdmin = req.user.isAdmin;
    
    if (!isCreator && !isLegacyCreator && !isAdmin) {
      return res.status(403).send('You are not authorized to duplicate this event');
    }
    
    const { name, description, playerLimit, date, platforms, originalGameId, originalSteamAppId } = req.body;
    
    // Validate the new date is in the future
    const newDate = new Date(date);
    const now = new Date();
    if (newDate <= now) {
      return res.status(400).send('Event date must be in the future');
    }
    
    // Process platforms properly
    let processedPlatforms = [];
    if (platforms) {
      if (Array.isArray(platforms)) {
        processedPlatforms = platforms;
      } else if (typeof platforms === 'string') {
        processedPlatforms = [platforms];
      }
    }
    
    // Validate at least one platform is selected
    if (processedPlatforms.length === 0) {
      return res.status(400).send('Please select at least one platform');
    }
    
    // Create the new event with copied data
    const newEvent = new Event({
      name: name || `${originalEvent.name} - Copy`,
      game: originalGameId || originalEvent.game._id,
      description: description || originalEvent.description,
      playerLimit: parseInt(playerLimit) || originalEvent.playerLimit,
      date: newDate,
      players: [req.user._id], // Add the creator as the first player
      platforms: processedPlatforms,
      steamAppId: originalSteamAppId || originalEvent.steamAppId,
      createdBy: req.user._id,
      gameStatus: originalEvent.gameStatus || 'approved',
      isVisible: originalEvent.isVisible !== false // Default to true unless explicitly false
    });
    
    // Handle extensions duplication
    if (req.body['copy-extensions'] && originalEvent.requiredExtensions && originalEvent.requiredExtensions.length > 0) {
      for (const originalExtension of originalEvent.requiredExtensions) {
        const newExtension = new Extension({
          name: originalExtension.name,
          downloadLink: originalExtension.downloadLink,
          installationTime: originalExtension.installationTime,
          description: originalExtension.description
        });
        await newExtension.save();
        newEvent.requiredExtensions.push(newExtension._id);
      }
    }
    
    const savedEvent = await newEvent.save();
    
    // Create audit log for admin duplications
    if (isAdmin && !isCreator && !isLegacyCreator) {
      await createAuditLog(
        req.user, 
        'duplicate_event', 
        originalEvent.createdBy, 
        `Admin duplicated event: "${originalEvent.name}" → "${savedEvent.name}"`, 
        getClientIP(req),
        1,
        { 
          originalEventId: originalEvent._id, 
          originalEventName: originalEvent.name,
          newEventId: savedEvent._id,
          newEventName: savedEvent.name
        }
      );
    }
    
    console.log(`Event "${originalEvent.name}" duplicated as "${savedEvent.name}" by ${req.user.email} (${isAdmin && !isCreator && !isLegacyCreator ? 'admin' : 'creator'})`);
    res.redirect(`/event/${savedEvent._id}`);
  } catch (err) {
    console.error('Error duplicating event:', err);
    res.status(500).send('Error duplicating event');
  }
});

// Route to show event edit form
app.get('/event/:id/edit', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check if user is authorized to edit (event creator or admin)
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isAdmin = req.user.isAdmin;
    
    if (!isCreator && !isAdmin) {
      return res.status(403).send('You are not authorized to edit this event');
    }
    
    const games = await Game.find();
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    // Prepare games data for client-side JavaScript
    const gamesData = games.map(game => ({
      _id: game._id.toString(),
      name: game.name,
      steamAppId: game.steamAppId || null,
      description: game.description || ''
    }));
    
    res.render('editEvent', { 
      event, 
      games, 
      gamesData: JSON.stringify(gamesData), 
      user: req.user, 
      isDevelopmentAutoLogin 
    });
  } catch (err) {
    console.error('Error loading event edit form:', err);
    res.status(500).send('Error loading event edit form');
  }
});

// Route to process event edit form
app.post('/event/:id/edit', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('createdBy').populate('requiredExtensions');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check if user is authorized to edit (event creator or admin)
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isAdmin = req.user.isAdmin;
    
    if (!isCreator && !isAdmin) {
      return res.status(403).send('You are not authorized to edit this event');
    }
    
    const { name, gameId, description, playerLimit, date, extensions, platforms } = req.body;
    
    // Validate game ID
    const game = await Game.findById(gameId);
    if (!game) {
      return res.status(400).send('Invalid game ID');
    }
    
    // Store original values for audit log
    const originalValues = {
      name: event.name,
      game: event.game.toString(),
      description: event.description,
      playerLimit: event.playerLimit,
      date: event.date,
      platforms: event.platforms
    };
    
    // Process platforms properly
    let processedPlatforms = [];
    if (platforms) {
      if (Array.isArray(platforms)) {
        processedPlatforms = platforms;
      } else if (typeof platforms === 'string') {
        processedPlatforms = [platforms];
      }
    }
    
    // Update event fields
    event.name = name;
    event.game = gameId;
    event.description = description;
    event.playerLimit = playerLimit;
    event.date = new Date(date);
    event.platforms = processedPlatforms;
    event.steamAppId = game.steamAppId || req.body.steamAppId;
    
    // Handle extensions - remove old ones and add new ones
    if (event.requiredExtensions && event.requiredExtensions.length > 0) {
      // Delete old extensions
      await Extension.deleteMany({ _id: { $in: event.requiredExtensions } });
    }
    event.requiredExtensions = [];
    
    // Process new extensions if provided
    if (extensions && extensions.trim() !== '' && extensions.trim() !== '[]') {
      try {
        let extensionData;
        if (Array.isArray(extensions)) {
          const lastEntry = extensions[extensions.length - 1];
          if (lastEntry && lastEntry.trim() !== '[]') {
            extensionData = JSON.parse(lastEntry);
          } else {
            extensionData = [];
          }
        } else {
          extensionData = JSON.parse(extensions);
        }
        
        if (Array.isArray(extensionData) && extensionData.length > 0) {
          for (const ext of extensionData) {
            if (typeof ext.name !== 'string' ||
                typeof ext.downloadLink !== 'string' ||
                typeof ext.installationTime !== 'string') {
              return res.status(400).send('Invalid extension data structure');
            }
            
            if (ext.name.trim() && ext.downloadLink.trim() && ext.installationTime.trim()) {
              const extension = new Extension({
                name: ext.name,
                downloadLink: ext.downloadLink,
                installationTime: ext.installationTime
              });
              await extension.save();
              event.requiredExtensions.push(extension._id);
            }
          }
        }
      } catch (parseError) {
        console.error('Error parsing extensions:', parseError);
        return res.status(400).send('Invalid extensions data');
      }
    }
    
    await event.save();
    
    // Create audit log for admin edits
    if (isAdmin && !isCreator) {
      const changes = [];
      if (originalValues.name !== name) changes.push(`name: "${originalValues.name}" → "${name}"`);
      if (originalValues.game !== gameId) changes.push(`game changed`);
      if (originalValues.description !== description) changes.push(`description updated`);
      if (originalValues.playerLimit !== parseInt(playerLimit)) changes.push(`player limit: ${originalValues.playerLimit} → ${playerLimit}`);
      if (originalValues.date.getTime() !== new Date(date).getTime()) changes.push(`date changed`);
      if (JSON.stringify(originalValues.platforms) !== JSON.stringify(processedPlatforms)) changes.push(`platforms updated`);
      
      await createAuditLog(
        req.user, 
        'admin_edit_event', 
        event.createdBy, 
        `Admin edited event: ${event.name}. Changes: ${changes.join(', ')}`, 
        getClientIP(req),
        1,
        { eventId: event._id, eventName: event.name, changes }
      );
    }
    
    console.log(`Event "${event.name}" edited by ${req.user.email} (${isAdmin && !isCreator ? 'admin' : 'creator'})`);
    res.redirect(`/event/${event._id}`);
  } catch (err) {
    console.error('Error updating event:', err);
    res.status(500).send('Error updating event');
  }
});

// Add event deletion route
app.post('/event/:id/delete', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('createdBy').populate('players');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check if user is authorized to delete (event creator or admin)
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isAdmin = req.user.isAdmin;
    
    if (!isCreator && !isAdmin) {
      return res.status(403).send('You are not authorized to delete this event');
    }
    
    // Create audit log for admin deletions
    if (isAdmin && !isCreator) {
      await createAuditLog(
        req.user, 
        'delete_event', 
        event.createdBy, 
        `Deleted event: ${event.name}`, 
        getClientIP(req),
        1,
        { eventId: event._id, eventName: event.name }
      );
    }
    
    // Delete the event using the modern method
    await Event.findByIdAndDelete(req.params.id);
    
    console.log(`Event "${event.name}" deleted by ${req.user.email} (${isAdmin ? 'admin' : 'creator'})`);
    res.redirect('/');
  } catch (err) {
    console.error('Error deleting event:', err);
    res.status(500).send('Error deleting event');
  }
});

// Debug route to check game existence
app.get('/debug/game/:id', async (req, res) => {
  try {
    const game = await Game.findById(req.params.id);
    if (game) {
      res.send(`Game found: ${game.name}`);
    } else {
      res.send('Game not found');
    }
  } catch (err) {
    res.status(500).send('Error checking game');
  }
});

// Route to check for game updates
app.get('/check-updates/:appId', async (req, res) => {
  const appId = req.params.appId;
  const url = `https://api.steampowered.com/ISteamNews/GetNewsForApp/v2/?appid=${appId}&count=5`;

  try {
    const response = await axios.get(url);
    const newsData = response.data;

    // Check for update indicators in the news
    const updateFound = newsData.appnews.newsitems.some(item => {
      const title = item.title.toLowerCase();
      const content = item.contents.toLowerCase();
      return (
        title.includes('update') ||
        title.includes('patch') ||
        title.includes('new version') ||
        content.includes('update') ||
        content.includes('patch') ||
        content.includes('new version')
      );
    });

    if (updateFound) {
      res.json({ hasUpdate: true, news: newsData.appnews.newsitems });
    } else {
      res.json({ hasUpdate: false });
    }
  } catch (error) {
    console.error('Error fetching Steam news:', error);
    res.status(500).send('Error checking for updates');
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
