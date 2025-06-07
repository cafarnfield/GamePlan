const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  isAdmin: { type: Boolean, default: false },
  isBlocked: { type: Boolean, default: false },
  gameNickname: { type: String, default: '' }
});

const User = mongoose.model('User', userSchema);

module.exports = User;
