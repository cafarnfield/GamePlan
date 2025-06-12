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
    
    // System health
    const activeEvents = await Event.countDocuments({ date: { $gte: new Date() } });
    const totalGames = await Game.countDocuments();
    
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
      totalGames
    };
    
    const searchFilters = { status, blocked, admin, dateFrom, dateTo };
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    
    res.render('adminDashboard', { 
      stats, 
      recentActivity, 
      searchQuery, 
      searchFilters, 
      isDevelopmentAutoLogin 
    });
  } catch (err) {
    console.error('Error loading admin dashboard:', err);
    res.status(500).send('Error loading dashboard');
  }
});

// Route to show admin panel
app.get('/admin', ensureAdmin, async (req, res) => {
  const games = await Game.find();
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('admin', { games, isDevelopmentAutoLogin });
});

// Route to show all registered users with filtering
app.get('/admin/users', ensureAdmin, async (req, res) => {
  try {
    const { filter } = req.query;
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
    
    const users = await User.find(query).sort({ createdAt: -1 });
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('adminUsers', { 
      users, 
      filter: filter || null, // Ensure filter is always defined
      isDevelopmentAutoLogin 
    });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).send('Error fetching users');
  }
});

// Route to delete a user
app.post('/admin/user/delete/:id', ensureAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.redirect('/admin/users');
  } catch (err) {
    res.status(500).send('Error deleting user');
  }
});

// Route to block a user
app.post('/admin/user/block/:id', ensureAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('User not found');
    }
    user.isBlocked = true;
    await user.save();
    res.redirect('/admin/users');
  } catch (err) {
    res.status(500).send('Error blocking user');
  }
});

// Route to unblock a user
app.post('/admin/user/unblock/:id', ensureAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('User not found');
    }
    user.isBlocked = false;
    await user.save();
    res.redirect('/admin/users');
  } catch (err) {
    res.status(500).send('Error unblocking user');
  }
});

// Route to toggle admin status for a user
app.post('/admin/user/toggle-admin/:id', ensureAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('User not found');
    }
    user.isAdmin = !user.isAdmin;
    await user.save();
    
    // Create audit log
    await createAuditLog(req.user, user.isAdmin ? 'promote_admin' : 'demote_admin', user, '', getClientIP(req));
    
    res.redirect('/admin/users');
  } catch (err) {
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

// Steam API routes
app.get('/api/steam/search', ensureAdmin, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.trim().length < 2) {
      return res.json([]);
    }
    
    const results = await steamService.searchGames(q, 10);
    res.json(results);
  } catch (error) {
    console.error('Error searching Steam games:', error);
    res.status(500).json({ error: 'Failed to search Steam games' });
  }
});

// Route to add a new game with Steam integration (admin only)
app.post('/admin/add-game', ensureAdmin, async (req, res) => {
  try {
    const { name, description, steamAppId, steamData } = req.body;
    
    const gameData = {
      name,
      description: description || ''
    };

    // Add Steam data if provided
    if (steamAppId) {
      gameData.steamAppId = parseInt(steamAppId);
    }
    
    if (steamData) {
      try {
        const parsedSteamData = typeof steamData === 'string' ? JSON.parse(steamData) : steamData;
        gameData.steamData = parsedSteamData;
        
        // Extract platforms from Steam data
        if (parsedSteamData.platforms && parsedSteamData.platforms.length > 0) {
          gameData.platforms = parsedSteamData.platforms;
        }
        
        // Use Steam description if no custom description provided
        if (!description && parsedSteamData.short_description) {
          gameData.description = parsedSteamData.short_description;
        }
      } catch (parseError) {
        console.error('Error parsing Steam data:', parseError);
      }
    }

    const game = new Game(gameData);
    await game.save();
    res.redirect('/admin');
  } catch (err) {
    console.error('Error adding game:', err);
    res.status(500).send('Error adding game');
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

// Routes
app.get('/', async (req, res) => {
  const events = await Event.find().populate({
    path: 'players',
    populate: { path: 'players' }
  }).populate('requiredExtensions').populate('game');
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

    const { name, gameId, description, playerLimit, date, extensions, platforms } = req.body;

    // Validate game ID
    console.log('Validating game ID:', gameId);
    const game = await Game.findById(gameId);
    if (!game) {
      console.error('Invalid game ID:', gameId);
      return res.status(400).send('Invalid game ID');
    }
    console.log('Game found:', game);

// Create the event with automatic Steam App ID from game
    const event = new Event({
      name,
      game: gameId,
      description,
      playerLimit,
      date: new Date(date), // Ensure date is a Date object
      players: [req.user._id], // Add the creator as the first player
      platforms: Array.isArray(platforms) ? platforms : [],
      steamAppId: game.steamAppId || req.body.steamAppId // Use game's Steam App ID or manual override
    });

    // Process extensions if provided
    if (extensions) {
      try {
        console.log('Processing extensions:', extensions);

        // Handle case where extensions might be an array (from old form)
        let extensionData;
        if (Array.isArray(extensions)) {
          // Take the last valid entry if it's an array
          const lastEntry = extensions[extensions.length - 1];
          if (lastEntry && lastEntry.trim() !== '[]') {
            extensionData = JSON.parse(lastEntry);
          } else {
            extensionData = [];
          }
        } else {
          // Normal case - single string
          extensionData = JSON.parse(extensions);
        }

        for (const ext of extensionData) {
          // Validate extension data structure
          if (typeof ext.name !== 'string' ||
              typeof ext.downloadLink !== 'string' ||
              typeof ext.installationTime !== 'string') {
            console.error('Invalid extension data structure:', ext);
            return res.status(400).send('Invalid extension data structure');
          }

          const extension = new Extension({
            name: ext.name,
            downloadLink: ext.downloadLink,
            installationTime: ext.installationTime
          });
          await extension.save();
          event.requiredExtensions.push(extension._id);
        }
      } catch (parseError) {
        console.error('Error parsing extensions:', parseError);
        return res.status(400).send('Invalid extensions data');
      }
    }

    console.log('Saving event:', event);
    const savedEvent = await event.save();
    console.log('Saved event:', savedEvent);

    // Redirect to the event page
    res.redirect(`/event/${savedEvent._id}`);
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
    const event = await Event.findById(req.params.id).populate('players').populate('requiredExtensions').populate('game');
    
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

// Add event deletion route
app.post('/event/:id/delete', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('players');
    // Only allow the event creator or admins to delete the event
    if (event.players.length === 0 || (!event.players[0]._id.equals(req.user._id) && !req.user.isAdmin)) {
      return res.status(403).send('You are not authorized to delete this event');
    }
    await event.remove();
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
