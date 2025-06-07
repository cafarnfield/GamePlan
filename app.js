const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const session = require('express-session');

// Initialize Express
const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_secret_key',
  resave: false,
  saveUninitialized: false
}));
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

// User model
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  email: String,
  password: String
}));

// Event model
const Event = mongoose.model('Event', new mongoose.Schema({
  name: String,
  description: String,
  playerLimit: Number,
  date: Date,
  players: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}));

// Mock database models for testing
if (process.env.MOCK_DB) {
  // Mock data
  const mockUser = new User({ name: 'Test User', email: 'test@example.com', password: 'password' });
  const mockEvent = new Event({ name: 'Test Event', description: 'Test Description', playerLimit: 10, date: new Date() });

  mockUser.save().then(() => {
    mockEvent.players.push(mockUser._id);
    mockEvent.save().then(() => {
      console.log('Mock data saved');
    });
  });
} else {
  // Mock data for testing
  const mockUser = new User({ name: 'Test User', email: 'test@example.com', password: 'password' });
  const mockEvent = new Event({ name: 'Test Event', description: 'Test Description', playerLimit: 10, date: new Date() });

  mockUser.save().then(() => {
    mockEvent.players.push(mockUser._id);
    mockEvent.save().then(() => {
      console.log('Mock data saved');
    });
  });
}

// Passport configuration
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await User.findOne({ email });
      if (!user) return done(null, false, { message: 'No user with that email' });
      const isMatch = await bcrypt.compare(password, user.password);
      return isMatch ? done(null, user) : done(null, false, { message: 'Password incorrect' });
    } catch (err) {
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

// Routes
app.get('/', async (req, res) => {
  const events = await Event.find().populate('players');
  res.render('index', { events });
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    res.status(500).send('Error registering user');
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

app.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

app.get('/event/new', (req, res) => {
  res.render('newEvent');
});

app.post('/event/new', async (req, res) => {
  try {
    const { name, description, playerLimit, date } = req.body;
    const event = new Event({ name, description, playerLimit, date });
    await event.save();
    res.redirect('/');
  } catch (err) {
    res.status(500).send('Error creating event');
  }
});

app.get('/event/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('players');
    res.render('event', { event });
  } catch (err) {
    res.status(500).send('Error fetching event');
  }
});

app.post('/event/:id/join', async (req, res) => {
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

app.post('/event/:id/leave', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    event.players.pull(req.user._id);
    await event.save();
    res.redirect(`/event/${req.params.id}`);
  } catch (err) {
    res.status(500).send('Error leaving event');
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
