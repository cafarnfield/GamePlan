const axios = require('axios');
const mongoose = require('mongoose');
const Game = require('./models/Game');
const Event = require('./models/Event');
const Extension = require('./models/Extension');

require('dotenv').config();

async function testCreateEvent() {
  try {
    // Connect to MongoDB
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

    // Create a new game
    const game = new Game({
      name: 'Test Game',
      description: 'Test Game Description'
    });
    await game.save();
    console.log('Game created:', game);

    // Create a new event
    const event = new Event({
      name: 'Test Event',
      game: game._id,
      description: 'Test Description',
      playerLimit: 10,
      date: new Date('2025-06-07T18:50:06.030Z'),
      players: [], // No players yet
      platforms: ['PC', 'PlayStation']
    });
    await event.save();
    console.log('Event created:', event);

    // Create an extension
    const extension = new Extension({
      name: 'Test Extension',
      downloadLink: 'http://example.com/extension',
      installationTime: 10 // minutes
    });
    await extension.save();
    console.log('Extension created:', extension);

    // Add the extension to the event
    event.requiredExtensions.push(extension._id);
    await event.save();
    console.log('Extension added to event:', event);

    console.log('Test completed successfully');
  } catch (error) {
    console.error('Error:', error);
  } finally {
    mongoose.disconnect();
  }
}

testCreateEvent();
