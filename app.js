const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');

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
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 1 day
    httpOnly: true,
    secure: false, // Set to true if using HTTPS
    sameSite: 'lax' // Add sameSite option
  },
  rolling: true, // Renew session cookie on each request
  name: 'gameplan.sid', // Custom session cookie name
  store: new session.MemoryStore(), // Use in-memory store for testing
  saveUninitialized: true, // Save uninitialized sessions
  resave: true, // Resave sessions
  proxy: true // Trust first proxy
}));
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
  res.render('admin', { games });
});

// Route to show all registered users
app.get('/admin/users', ensureAdmin, async (req, res) => {
  const users = await User.find();
  res.render('adminUsers', { users });
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

// Route to add a new game
app.post('/admin/add-game', ensureAdmin, async (req, res) => {
  try {
    const { name, description } = req.body;
    const game = new Game({ name, description });
    await game.save();
    res.redirect('/admin');
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
  res.render('index', { events, user: req.user });
});

// User profile route
app.get('/profile', ensureAuthenticated, ensureNotBlocked, (req, res) => {
  console.log('Profile route accessed');
  console.log('User:', req.user);
  res.render('profile', { user: req.user });
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
  res.render('register');
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
  res.render('login');
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
  res.render('newEvent', { user: req.user, games });
});

app.post('/event/new', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const { name, gameId, description, playerLimit, date, extensions, platforms } = req.body;
    const event = new Event({
      name,
      game: gameId,
      description,
      playerLimit,
      date,
      players: [req.user._id], // Add the creator as the first player
      platforms: platforms ? platforms.split(',') : []
    });

    // Process extensions if provided
    if (extensions) {
      const extensionData = JSON.parse(extensions);
      for (const ext of extensionData) {
        const extension = new Extension({
          name: ext.name,
          downloadLink: ext.downloadLink,
          installationTime: ext.installationTime
        });
        await extension.save();
        event.requiredExtensions.push(extension._id);
      }
    }

    await event.save();
    res.redirect('/');
  } catch (err) {
    res.status(500).send('Error creating event');
  }
});

app.get('/event/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('players').populate('requiredExtensions').populate('game');
    res.render('event', { event, user: req.user });
  } catch (err) {
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
    const event = await Event.findById(req.params.id);
    // Only allow the event creator or admins to delete the event
    if (event.players.length === 0 || (!event.players[0].equals(req.user._id) && !req.user.isAdmin)) {
      return res.status(403).send('You are not authorized to delete this event');
    }
    await event.remove();
    res.redirect('/');
  } catch (err) {
    res.status(500).send('Error deleting event');
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
