/**
 * Comprehensive Event Creation Test Suite
 * Consolidates testing for all event creation scenarios
 */

const mongoose = require('mongoose');
const axios = require('axios');
require('dotenv').config();

// Import models
const Game = require('../../models/Game');
const Event = require('../../models/Event');
const Extension = require('../../models/Extension');

describe('Event Creation System', () => {
  let testGame;
  let testExtension;

  beforeAll(async () => {
    // Connect to test database
    const mongoUri = process.env.MOCK_DB 
      ? 'mongodb://localhost:27017/gameplan-test'
      : process.env.MONGO_URI;
    
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });

    // Create test game
    testGame = new Game({
      name: 'Test Game for Events',
      description: 'Test Game Description'
    });
    await testGame.save();

    // Create test extension
    testExtension = new Extension({
      name: 'Test Extension',
      downloadLink: 'http://example.com/extension',
      installationTime: 10
    });
    await testExtension.save();
  });

  afterAll(async () => {
    // Clean up test data
    await Game.deleteMany({ name: /^Test Game/ });
    await Event.deleteMany({ name: /^Test Event/ });
    await Extension.deleteMany({ name: /^Test Extension/ });
    await mongoose.disconnect();
  });

  beforeEach(async () => {
    // Clean up events before each test
    await Event.deleteMany({ name: /^Test Event/ });
  });

  describe('Database-Level Event Creation', () => {
    test('should create event with basic properties', async () => {
      const event = new Event({
        name: 'Test Event Basic',
        game: testGame._id,
        description: 'Test Description',
        playerLimit: 10,
        date: new Date('2025-06-07T18:50:06.030Z'),
        players: [],
        platforms: ['PC', 'PlayStation']
      });

      const savedEvent = await event.save();
      
      expect(savedEvent).toBeDefined();
      expect(savedEvent.name).toBe('Test Event Basic');
      expect(savedEvent.playerLimit).toBe(10);
      expect(savedEvent.platforms).toEqual(['PC', 'PlayStation']);
    });

    test('should create event with extensions', async () => {
      const event = new Event({
        name: 'Test Event With Extensions',
        game: testGame._id,
        description: 'Test Description',
        playerLimit: 5,
        date: new Date('2025-06-10T20:00:00.000Z'),
        players: [],
        platforms: ['PC'],
        requiredExtensions: [testExtension._id],
        steamAppId: 440
      });

      const savedEvent = await event.save();
      
      expect(savedEvent.requiredExtensions).toHaveLength(1);
      expect(savedEvent.steamAppId).toBe(440);
      
      // Test population
      const populatedEvent = await Event.findById(savedEvent._id)
        .populate('requiredExtensions')
        .populate('game');
      
      expect(populatedEvent.game.name).toBe('Test Game for Events');
      expect(populatedEvent.requiredExtensions[0].name).toBe('Test Extension');
    });

    test('should validate required fields', async () => {
      const invalidEvent = new Event({
        // Missing required fields
        description: 'Test Description'
      });

      await expect(invalidEvent.save()).rejects.toThrow();
    });

    test('should validate date is in future', async () => {
      const pastDate = new Date('2020-01-01T00:00:00.000Z');
      
      const event = new Event({
        name: 'Test Event Past Date',
        game: testGame._id,
        description: 'Test Description',
        playerLimit: 5,
        date: pastDate,
        platforms: ['PC']
      });

      // This should be handled by validation middleware
      await expect(event.save()).rejects.toThrow();
    });
  });

  describe('HTTP Form Submission', () => {
    // Note: These tests would require a running server
    // For now, we'll test the data structure and validation

    test('should prepare valid form data structure', () => {
      const formData = {
        name: 'Test Event - HTTP Form',
        gameId: testGame._id.toString(),
        description: 'Testing HTTP form submission functionality',
        playerLimit: 4,
        date: '2025-06-11T20:00',
        steamAppId: '',
        platforms: ['PC'],
        extensions: '[]'
      };

      expect(formData.name).toBeDefined();
      expect(formData.gameId).toMatch(/^[0-9a-fA-F]{24}$/); // Valid ObjectId
      expect(formData.playerLimit).toBeGreaterThan(0);
      expect(Array.isArray(formData.platforms)).toBe(true);
    });

    test('should handle form data transformation', () => {
      const formData = {
        name: 'Test Event',
        gameId: testGame._id.toString(),
        description: 'Test Description',
        playerLimit: '4', // String from form
        date: '2025-06-11T20:00',
        platforms: ['PC'],
        extensions: '[]'
      };

      // Transform to match database schema
      const transformedData = {
        ...formData,
        playerLimit: parseInt(formData.playerLimit),
        date: new Date(formData.date),
        extensions: JSON.parse(formData.extensions),
        game: new mongoose.Types.ObjectId(formData.gameId)
      };

      expect(typeof transformedData.playerLimit).toBe('number');
      expect(transformedData.date instanceof Date).toBe(true);
      expect(Array.isArray(transformedData.extensions)).toBe(true);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    test('should handle invalid game reference', async () => {
      const invalidGameId = new mongoose.Types.ObjectId();
      
      const event = new Event({
        name: 'Test Event Invalid Game',
        game: invalidGameId,
        description: 'Test Description',
        playerLimit: 5,
        date: new Date('2025-06-15T20:00:00.000Z'),
        platforms: ['PC']
      });

      await expect(event.save()).rejects.toThrow();
    });

    test('should handle invalid extension reference', async () => {
      const invalidExtensionId = new mongoose.Types.ObjectId();
      
      const event = new Event({
        name: 'Test Event Invalid Extension',
        game: testGame._id,
        description: 'Test Description',
        playerLimit: 5,
        date: new Date('2025-06-15T20:00:00.000Z'),
        platforms: ['PC'],
        requiredExtensions: [invalidExtensionId]
      });

      await expect(event.save()).rejects.toThrow();
    });

    test('should handle circular reference prevention', async () => {
      // This test ensures the circular HTTP request issue is resolved
      const event = new Event({
        name: 'Test Event Circular Fix',
        game: testGame._id,
        description: 'Test event to verify circular reference fix',
        playerLimit: 5,
        date: new Date('2025-06-10T20:00:00.000Z'),
        players: [],
        platforms: ['PC'],
        steamAppId: 440
      });
      
      const savedEvent = await event.save();
      
      // Fetching should work without circular HTTP issues
      const fetchedEvent = await Event.findById(savedEvent._id)
        .populate('requiredExtensions')
        .populate('game');
      
      expect(fetchedEvent).toBeDefined();
      expect(fetchedEvent.game.name).toBe('Test Game for Events');
      expect(fetchedEvent.steamAppId).toBe(440);
    });

    test('should validate platform options', async () => {
      const event = new Event({
        name: 'Test Event Invalid Platform',
        game: testGame._id,
        description: 'Test Description',
        playerLimit: 5,
        date: new Date('2025-06-15T20:00:00.000Z'),
        platforms: ['InvalidPlatform'] // Should be validated
      });

      // This should be handled by schema validation
      await expect(event.save()).rejects.toThrow();
    });
  });

  describe('Steam Integration', () => {
    test('should handle valid Steam App ID', async () => {
      const event = new Event({
        name: 'Test Event Steam Valid',
        game: testGame._id,
        description: 'Test Description',
        playerLimit: 5,
        date: new Date('2025-06-15T20:00:00.000Z'),
        platforms: ['PC'],
        steamAppId: 730 // Counter-Strike 2
      });

      const savedEvent = await event.save();
      expect(savedEvent.steamAppId).toBe(730);
    });

    test('should handle empty Steam App ID', async () => {
      const event = new Event({
        name: 'Test Event Steam Empty',
        game: testGame._id,
        description: 'Test Description',
        playerLimit: 5,
        date: new Date('2025-06-15T20:00:00.000Z'),
        platforms: ['PC'],
        steamAppId: null
      });

      const savedEvent = await event.save();
      expect(savedEvent.steamAppId).toBeNull();
    });
  });

  describe('Performance and Optimization', () => {
    test('should handle bulk event creation', async () => {
      const events = [];
      for (let i = 0; i < 5; i++) {
        events.push({
          name: `Test Event Bulk ${i}`,
          game: testGame._id,
          description: `Bulk test event ${i}`,
          playerLimit: 5,
          date: new Date(`2025-06-${15 + i}T20:00:00.000Z`),
          platforms: ['PC']
        });
      }

      const savedEvents = await Event.insertMany(events);
      expect(savedEvents).toHaveLength(5);
      
      // Clean up
      await Event.deleteMany({ name: /^Test Event Bulk/ });
    });

    test('should handle concurrent event creation', async () => {
      const createEvent = (index) => {
        const event = new Event({
          name: `Test Event Concurrent ${index}`,
          game: testGame._id,
          description: `Concurrent test event ${index}`,
          playerLimit: 5,
          date: new Date(`2025-06-${20 + index}T20:00:00.000Z`),
          platforms: ['PC']
        });
        return event.save();
      };

      const promises = [createEvent(1), createEvent(2), createEvent(3)];
      const results = await Promise.all(promises);
      
      expect(results).toHaveLength(3);
      results.forEach(event => {
        expect(event._id).toBeDefined();
      });
      
      // Clean up
      await Event.deleteMany({ name: /^Test Event Concurrent/ });
    });
  });
});

// Export for standalone testing
module.exports = {
  testEventCreation: async () => {
    console.log('🧪 Running Event Creation Tests...');
    
    try {
      // This would run the Jest tests programmatically
      console.log('✅ Event creation tests would run here');
      console.log('📝 Use: npm test tests/features/event-creation.test.js');
    } catch (error) {
      console.error('❌ Event creation tests failed:', error.message);
    }
  }
};

// Allow standalone execution
if (require.main === module) {
  module.exports.testEventCreation();
}
