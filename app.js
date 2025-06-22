const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

// Import application configuration
const { configureApp, initializeApp } = require('./config/app');

// Import authentication middleware
const { ensurePasswordNotExpired } = require('./src/middleware/auth');

// Import centralized error handling
const {
  notFoundHandler,
  errorHandler,
  handleDatabaseErrors: handleDbErrors
} = require('./src/middleware/errorHandler');

// Models
const User = require('./src/models/User');
const Event = require('./src/models/Event');

// Initialize Express
const app = express();

// Configure the application with all middleware
configureApp(app);

// Initialize database and caches
initializeApp();

// Import and use authentication routes
app.use('/', require('./src/routes/auth'));

// Import and use admin routes
app.use('/admin', require('./src/routes/admin'));

// Import and use event routes
app.use('/event', require('./src/routes/events'));

// Import and use game routes
app.use('/games', require('./src/routes/games'));

// Import and use cache management routes
app.use('/api/cache', require('./src/routes/cache'));

// Import and use IP management routes
app.use('/admin/ip-management', require('./src/routes/ipManagement'));

// Import and use well-known URI routes (must be before 404 handler)
app.use('/.well-known', require('./src/routes/wellKnown'));

// Swagger API Documentation (Admin-only access)
const { specs, swaggerUi, swaggerUiOptions } = require('./config/swagger');
const { ensureAdmin } = require('./src/middleware/auth');

// Swagger UI endpoint with admin authentication
app.use('/api-docs', ensureAdmin, swaggerUi.serve);
app.get('/api-docs', ensureAdmin, swaggerUi.setup(specs, swaggerUiOptions));

// Import and use API routes (Steam/RAWG search, version, etc.)
app.use('/api', require('./src/routes/api'));

// Import and use health check routes
app.use('/api/health', require('./src/routes/health'));



// Home page route - Display all events
app.get('/', ensurePasswordNotExpired, async (req, res) => {
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
  
  const events = await Event.find(query).populate('createdBy').populate('players').populate('requiredExtensions').populate('game').sort({ date: 1 }); // Sort by date ascending (soonest first)
  
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('index', { events, user: req.user, isDevelopmentAutoLogin });
});







// Add database-specific error handler before general error handler
app.use(handleDbErrors);

// Add 404 handler for unmatched routes
app.use(notFoundHandler);

// Add centralized error handling middleware (must be last)
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
