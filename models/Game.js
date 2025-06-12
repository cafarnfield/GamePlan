const mongoose = require('mongoose');

const gameSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  platforms: [{ type: String, enum: ['PC', 'PlayStation', 'Xbox', 'Nintendo Switch'] }],
  steamAppId: { type: Number }, // Steam App ID for automatic integration
  steamData: {
    name: String,
    short_description: String,
    header_image: String,
    developers: [String],
    publishers: [String]
  },
  
  // RAWG integration fields
  rawgId: { type: Number }, // RAWG game ID
  rawgData: {
    name: String,
    description: String,
    background_image: String,
    developers: [String],
    publishers: [String],
    genres: [String],
    rating: Number,
    released: String
  },
  
  // New fields for enhanced game management
  source: { 
    type: String, 
    enum: ['steam', 'rawg', 'manual', 'admin'], 
    default: 'admin' 
  },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected'], 
    default: 'approved' 
  },
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  
  // Category and tagging system
  categories: [{ 
    type: String, 
    enum: ['Action', 'Adventure', 'Strategy', 'RPG', 'FPS', 'Racing', 'Sports', 'Simulation', 'Puzzle', 'Platformer', 'Fighting', 'Horror', 'Survival', 'MMO', 'Indie', 'Casual', 'Other']
  }],
  tags: [String], // Custom tags
  
  // Duplicate handling
  canonicalGame: { type: mongoose.Schema.Types.ObjectId, ref: 'Game' }, // Points to main game if this is a duplicate
  aliases: [String], // Alternative names
  
  // Metadata
  createdAt: { type: Date, default: Date.now },
  approvedAt: Date,
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

// Remove unique constraint from name to allow duplicates during review process
gameSchema.index({ name: 1, status: 1 });

const Game = mongoose.model('Game', gameSchema);

module.exports = Game;
