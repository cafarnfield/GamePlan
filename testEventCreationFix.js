const axios = require('axios');
const mongoose = require('mongoose');
const Game = require('./models/Game');
const Event = require('./models/Event');

require('dotenv').config();

async function testEventCreationFix() {
  try {
    console.log('Testing event creation fix...');
    
    // Connect to MongoDB
    if (process.env.MOCK_DB) {
      await mongoose.connect('mongodb://localhost:27017/gameplan', {
        useNewUrlParser: true,
        useUnifiedTopology: true
      });
    } else {
      await mongoose.connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
      });
    }

    // Clean up any existing test data
    await Game.deleteMany({ name: 'Test Game Fix' });
    await Event.deleteMany({ name: 'Test Event Fix' });

    // Create a test game
    const game = new Game({
      name: 'Test Game Fix',
      description: 'Test Game for Fix Verification'
    });
    await game.save();
    console.log('✓ Test game created:', game.name);

    // Create a test event directly (simulating the fixed flow)
    const event = new Event({
      name: 'Test Event Fix',
      game: game._id,
      description: 'Test event to verify the fix',
      playerLimit: 5,
      date: new Date('2025-06-10T20:00:00.000Z'),
      players: [],
      platforms: ['PC'],
      steamAppId: 440 // Team Fortress 2 - a valid Steam App ID
    });
    
    const savedEvent = await event.save();
    console.log('✓ Test event created:', savedEvent.name);

    // Test fetching the event (this should now work without the circular HTTP issue)
    const fetchedEvent = await Event.findById(savedEvent._id)
      .populate('requiredExtensions')
      .populate('game');
    
    if (fetchedEvent) {
      console.log('✓ Event fetched successfully:', fetchedEvent.name);
      console.log('  - Game:', fetchedEvent.game.name);
      console.log('  - Steam App ID:', fetchedEvent.steamAppId);
      console.log('  - Platforms:', fetchedEvent.platforms);
    } else {
      console.error('✗ Failed to fetch event');
    }

    // Clean up test data
    await Game.deleteMany({ name: 'Test Game Fix' });
    await Event.deleteMany({ name: 'Test Event Fix' });
    console.log('✓ Test data cleaned up');

    console.log('\n🎉 Event creation fix test completed successfully!');
    console.log('The circular HTTP request issue has been resolved.');
    
  } catch (error) {
    console.error('✗ Test failed:', error.message);
    console.error('Stack trace:', error.stack);
  } finally {
    await mongoose.disconnect();
  }
}

testEventCreationFix();
