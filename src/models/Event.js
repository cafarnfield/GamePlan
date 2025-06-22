const mongoose = require('mongoose');
const Extension = require('./Extension');
const Game = require('./Game');

const eventSchema = new mongoose.Schema({
  name: { type: String, required: true },
  game: { type: mongoose.Schema.Types.ObjectId, ref: 'Game', required: true },
  description: { type: String, required: true },
  playerLimit: { type: Number, required: true },
  date: { type: Date, required: true },
  players: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  requiredExtensions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Extension' }],
  platforms: [{ type: String, enum: ['PC', 'PlayStation', 'Xbox', 'Nintendo Switch'] }],
  steamAppId: { type: Number }, // Add Steam App ID field (optional)
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
  
  // New fields for game approval workflow
  gameStatus: { 
    type: String, 
    enum: ['approved', 'pending'], 
    default: 'approved' 
  },
  isVisible: { type: Boolean, default: true } // False for events with pending games
});

const Event = mongoose.model('Event', eventSchema);

module.exports = Event;
