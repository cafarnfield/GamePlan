const mongoose = require('mongoose');

const gameSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: String,
  platforms: [{ type: String, enum: ['PC', 'PlayStation', 'Xbox', 'Nintendo Switch'] }],
  steamAppId: { type: Number }, // Steam App ID for automatic integration
  steamData: {
    name: String,
    short_description: String,
    header_image: String,
    developers: [String],
    publishers: [String]
  }
});

const Game = mongoose.model('Game', gameSchema);

module.exports = Game;
