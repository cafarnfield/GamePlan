const mongoose = require('mongoose');

const gameSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: String,
  platforms: [{ type: String, enum: ['PC', 'PlayStation', 'Xbox', 'Nintendo Switch'] }]
});

const Game = mongoose.model('Game', gameSchema);

module.exports = Game;
