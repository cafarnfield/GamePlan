const express = require('express');
const mongoose = require('mongoose');

// Import models
const Event = require('../models/Event');
const Extension = require('../models/Extension');
const Game = require('../models/Game');
const User = require('../models/User');

// Import validation middleware and validators
const { handleValidationErrors } = require('../middleware/validation');
const {
  validateEventCreation,
  validateEventEdit,
  validateEventDuplication
} = require('../validators/eventValidators');

// Import authentication middleware
const { ensureAuthenticated, ensureNotBlocked } = require('../middleware/auth');

// Import centralized error handling
const {
  asyncErrorHandler
} = require('../middleware/errorHandler');

// Import logger
const { systemLogger } = require('../utils/logger');

const router = express.Router();


// New event route must come before /:id to avoid conflicts
router.get('/new', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    // Get approved games for the game selection
    const games = await Game.find({ status: 'approved' }).sort({ name: 1 });

    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('newEvent', {
      user: req.user,
      isDevelopmentAutoLogin,
      games: games // Make sure to pass games as an array
    });
  } catch (err) {
    console.error('Error loading new event page:', err);
    res.status(500).send('Error loading new event page');
  }
});

// View specific event
router.get('/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('players')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('event', { event, user: req.user, isDevelopmentAutoLogin });
  } catch (err) {
    console.error('Error fetching event:', err);
    res.status(500).send('Error loading event');
  }
});

// Join event route
router.post('/:id/join', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check if user is already in the event
    if (event.players.includes(req.user._id)) {
      return res.redirect(`/event/${req.params.id}`);
    }
    
    // Check if event is full
    if (event.players.length >= event.playerLimit) {
      return res.status(400).send('Event is full');
    }
    
    // Add user to event
    event.players.push(req.user._id);
    await event.save();
    
    res.redirect(`/event/${req.params.id}`);
  } catch (err) {
    console.error('Error joining event:', err);
    res.status(500).send('Error joining event');
  }
});

// Leave event route
router.post('/:id/leave', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Remove user from event
    event.players = event.players.filter(playerId => !playerId.equals(req.user._id));
    await event.save();
    
    res.redirect(`/event/${req.params.id}`);
  } catch (err) {
    console.error('Error leaving event:', err);
    res.status(500).send('Error leaving event');
  }
});

// Edit event route
router.get('/:id/edit', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('players')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check permissions
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !event.createdBy && event.players.length > 0 && event.players[0]._id.equals(req.user._id);
    const canEdit = isCreator || isLegacyCreator || req.user.isAdmin;
    
    if (!canEdit) {
      return res.status(403).send('You are not authorized to edit this event');
    }
    
    // Get approved games for the game selection
    const games = await Game.find({ status: 'approved' }).sort({ name: 1 });
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('editEvent', { event, games, user: req.user, isDevelopmentAutoLogin });
  } catch (err) {
    console.error('Error loading event for editing:', err);
    res.status(500).send('Error loading event');
  }
});

// Update event route (POST)
router.post('/:id/edit', ensureAuthenticated, ensureNotBlocked, validateEventEdit, handleValidationErrors, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('players')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check permissions
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !event.createdBy && event.players.length > 0 && event.players[0]._id.equals(req.user._id);
    const canEdit = isCreator || isLegacyCreator || req.user.isAdmin;
    
    if (!canEdit) {
      return res.status(403).send('You are not authorized to edit this event');
    }
    
    const { name, gameId, description, playerLimit, date, platforms, extensions } = req.body;
    
    // Update basic event fields
    event.name = name;
    event.description = description;
    event.playerLimit = parseInt(playerLimit);
    event.date = new Date(date);
    event.platforms = Array.isArray(platforms) ? platforms : [platforms];
    
    // Handle game change
    if (gameId && gameId !== event.game._id.toString()) {
      event.game = gameId;
    }
    
    // Handle extensions
    if (extensions && extensions.trim() !== '') {
      try {
        const extensionsData = JSON.parse(extensions);
        
        // Delete old extensions
        if (event.requiredExtensions && event.requiredExtensions.length > 0) {
          await Extension.deleteMany({ _id: { $in: event.requiredExtensions } });
        }
        
        // Create new extensions
        const extensionIds = [];
        for (const extData of extensionsData) {
          if (extData.name && extData.downloadLink && extData.installationTime) {
            const extension = new Extension({
              name: extData.name,
              downloadLink: extData.downloadLink,
              installationTime: parseInt(extData.installationTime),
              description: extData.description || ''
            });
            await extension.save();
            extensionIds.push(extension._id);
          }
        }
        event.requiredExtensions = extensionIds;
      } catch (err) {
        console.error('Error parsing extensions:', err);
        // Continue without extensions if parsing fails
        event.requiredExtensions = [];
      }
    } else {
      // No extensions provided, clear existing ones
      if (event.requiredExtensions && event.requiredExtensions.length > 0) {
        await Extension.deleteMany({ _id: { $in: event.requiredExtensions } });
      }
      event.requiredExtensions = [];
    }
    
    await event.save();
    
    console.log('Event updated successfully:', {
      eventId: event._id,
      updatedBy: req.user.email,
      changes: { name, gameId, description, playerLimit, date, platforms }
    });
    
    res.redirect(`/event/${event._id}`);
  } catch (err) {
    console.error('Error updating event:', err);
    res.status(500).send('Error updating event');
  }
});

// Duplicate event route
router.get('/:id/duplicate', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('players')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check permissions
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !event.createdBy && event.players.length > 0 && event.players[0]._id.equals(req.user._id);
    const canDuplicate = isCreator || isLegacyCreator || req.user.isAdmin;
    
    if (!canDuplicate) {
      return res.status(403).send('You are not authorized to duplicate this event');
    }
    
    const isDevelopmentAutoLogin = process.env.AUTO_LOGIN_ADMIN === 'true' && process.env.NODE_ENV === 'development';
    res.render('duplicateEvent', { originalEvent: event, user: req.user, isDevelopmentAutoLogin });
  } catch (err) {
    console.error('Error loading event for duplication:', err);
    res.status(500).send('Error loading event');
  }
});

// Duplicate event POST route
router.post('/:id/duplicate', ensureAuthenticated, ensureNotBlocked, validateEventDuplication, handleValidationErrors, async (req, res) => {
  try {
    const originalEvent = await Event.findById(req.params.id)
      .populate('createdBy')
      .populate('players')
      .populate('requiredExtensions')
      .populate('game');
    
    if (!originalEvent) {
      return res.status(404).send('Original event not found');
    }
    
    // Check permissions (same as GET route)
    const isCreator = originalEvent.createdBy && originalEvent.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !originalEvent.createdBy && originalEvent.players.length > 0 && originalEvent.players[0]._id.equals(req.user._id);
    const canDuplicate = isCreator || isLegacyCreator || req.user.isAdmin;
    
    if (!canDuplicate) {
      return res.status(403).send('You are not authorized to duplicate this event');
    }
    
    const { name, description, date, playerLimit, platforms, 'copy-extensions': copyExtensions } = req.body;
    
    // Create the new event data
    const newEventData = {
      name: name || originalEvent.name,
      description: description || originalEvent.description,
      date: new Date(date),
      playerLimit: parseInt(playerLimit) || originalEvent.playerLimit,
      platforms: Array.isArray(platforms) ? platforms : [platforms],
      game: originalEvent.game._id,
      createdBy: req.user._id,
      players: [req.user._id], // Creator automatically joins
      isVisible: originalEvent.game && originalEvent.game.status === 'approved' ? true : false,
      gameStatus: originalEvent.game && originalEvent.game.status === 'approved' ? 'approved' : 'pending'
    };
    
    // Handle extensions if copy-extensions is checked
    if (copyExtensions && originalEvent.requiredExtensions && originalEvent.requiredExtensions.length > 0) {
      const newExtensionIds = [];
      
      for (const originalExtension of originalEvent.requiredExtensions) {
        // Create a new extension (duplicate the original)
        const newExtension = new Extension({
          name: originalExtension.name,
          downloadLink: originalExtension.downloadLink,
          installationTime: originalExtension.installationTime,
          description: originalExtension.description || ''
        });
        await newExtension.save();
        newExtensionIds.push(newExtension._id);
      }
      
      newEventData.requiredExtensions = newExtensionIds;
    }
    
    // Create the new event
    const newEvent = new Event(newEventData);
    await newEvent.save();
    
    console.log('Event duplicated successfully:', {
      originalId: originalEvent._id,
      newId: newEvent._id,
      creator: req.user.email
    });
    
    res.redirect(`/event/${newEvent._id}`);
  } catch (err) {
    console.error('Error duplicating event:', err);
    res.status(500).send('Error duplicating event');
  }
});

// Delete event route
router.post('/:id/delete', ensureAuthenticated, ensureNotBlocked, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('createdBy').populate('players');
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    // Check permissions
    const isCreator = event.createdBy && event.createdBy._id.equals(req.user._id);
    const isLegacyCreator = !event.createdBy && event.players.length > 0 && event.players[0]._id.equals(req.user._id);
    const canDelete = isCreator || isLegacyCreator || req.user.isAdmin;
    
    if (!canDelete) {
      return res.status(403).send('You are not authorized to delete this event');
    }
    
    await Event.findByIdAndDelete(req.params.id);
    res.redirect('/');
  } catch (err) {
    console.error('Error deleting event:', err);
    res.status(500).send('Error deleting event');
  }
});

// Create new event route
router.post('/new', ensureAuthenticated, ensureNotBlocked, validateEventCreation, handleValidationErrors, async (req, res) => {
  try {
    const { name, description, date, playerLimit, platforms, gameSelection, extensions } = req.body;
    
    // Parse game selection and extensions
    const gameData = JSON.parse(gameSelection);
    const extensionsData = extensions ? JSON.parse(extensions) : [];
    
    // Create the event object
    const eventData = {
      name,
      description,
      date: new Date(date),
      playerLimit: parseInt(playerLimit),
      platforms: Array.isArray(platforms) ? platforms : [platforms],
      createdBy: req.user._id,
      players: [req.user._id], // Creator automatically joins
      isVisible: true
    };
    
    // Handle game selection based on type
    if (gameData.type === 'existing') {
      eventData.game = gameData.gameId;
    } else if (gameData.type === 'steam') {
      // Create or find Steam game
      let game = await Game.findOne({ steamAppId: gameData.data.appid });
      if (!game) {
        game = new Game({
          name: gameData.data.name,
          description: gameData.data.short_description || '',
          source: 'steam',
          steamAppId: gameData.data.appid,
          steamData: gameData.data,
          status: 'approved',
          addedBy: req.user._id
        });
        await game.save();
      }
      eventData.game = game._id;
    } else if (gameData.type === 'rawg') {
      // Create or find RAWG game
      let game = await Game.findOne({ rawgId: gameData.data.id });
      if (!game) {
        game = new Game({
          name: gameData.data.name,
          description: gameData.data.short_description || '',
          source: 'rawg',
          rawgId: gameData.data.id,
          rawgData: gameData.data,
          status: 'approved',
          addedBy: req.user._id
        });
        await game.save();
      }
      eventData.game = game._id;
    } else if (gameData.type === 'manual') {
      // Create manual game (requires approval)
      const game = new Game({
        name: gameData.data.name,
        description: gameData.data.description,
        source: 'manual',
        categories: gameData.data.categories,
        status: 'pending',
        addedBy: req.user._id
      });
      await game.save();
      eventData.game = game._id;
      eventData.gameStatus = 'pending';
      eventData.isVisible = false; // Hide until game is approved
    }
    
    // Handle extensions
    if (extensionsData.length > 0) {
      const extensionIds = [];
      for (const extData of extensionsData) {
        const extension = new Extension({
          name: extData.name,
          downloadLink: extData.downloadLink,
          installationTime: parseInt(extData.installationTime),
          description: extData.description || ''
        });
        await extension.save();
        extensionIds.push(extension._id);
      }
      eventData.requiredExtensions = extensionIds;
    }
    
    // Create the event
    const event = new Event(eventData);
    await event.save();
    
    res.redirect(`/event/${event._id}`);
  } catch (err) {
    console.error('Error creating event:', err);
    res.status(500).send('Error creating event');
  }
});

module.exports = router;
