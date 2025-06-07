const mongoose = require('mongoose');

const EventSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  playerLimit: {
    type: Number,
    required: true
  },
  players: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  dateTime: {
    type: Date,
    required: true
  }
});

module.exports = mongoose.model('Event', EventSchema);
