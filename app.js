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
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        console.log('Password incorrect for user:', email);
        return done(null, false, { message: 'Password incorrect' });
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

// Route to show admin panel
app.get('/admin', ensureAdmin, async (req, res) => {
  const games = await Game.find();
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('admin', { games, isDevelopmentAutoLogin });
});

// Route to show all registered users
app.get('/admin/users', ensureAdmin, async (req, res) => {
  const users = await User.find();
  const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
  res.render('adminUsers', { users, isDevelopmentAutoLogin });
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
    res.redirect('/admin/users');
  } catch (err) {
    res.status(500).send('Error updating user');
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
  res.render('register', { isDevelopmentAutoLogin });
});

app.post('/register', async (req, res) => {
  try {
    const { name, email, password, gameNickname } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, gameNickname });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    res.status(500).send('Error registering user');
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
