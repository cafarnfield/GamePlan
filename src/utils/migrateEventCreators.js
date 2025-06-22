const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/gameplan', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const Event = require('../models/Event');

async function migrateEventCreators() {
  try {
    console.log('Starting migration of event creators...');
    
    // Find all events that don't have a createdBy field
    const eventsWithoutCreator = await Event.find({ 
      createdBy: { $exists: false } 
    }).populate('players');
    
    console.log(`Found ${eventsWithoutCreator.length} events without createdBy field`);
    
    let migratedCount = 0;
    let skippedCount = 0;
    
    for (const event of eventsWithoutCreator) {
      if (event.players && event.players.length > 0) {
        // Set the first player as the creator
        event.createdBy = event.players[0]._id;
        await event.save();
        migratedCount++;
        console.log(`Migrated event "${event.name}" - creator set to ${event.players[0].name || event.players[0].email}`);
      } else {
        skippedCount++;
        console.log(`Skipped event "${event.name}" - no players found`);
      }
    }
    
    console.log(`Migration completed:`);
    console.log(`- Migrated: ${migratedCount} events`);
    console.log(`- Skipped: ${skippedCount} events`);
    
    process.exit(0);
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
}

// Run the migration
migrateEventCreators();
