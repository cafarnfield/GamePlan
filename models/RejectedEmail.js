const mongoose = require('mongoose');

const rejectedEmailSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  rejectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  rejectedByName: { type: String, required: true },
  rejectedAt: { type: Date, default: Date.now },
  reason: String,
  ipAddress: String,
  originalUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Reference to the rejected user
  notes: String
});

// Index for efficient email lookups
rejectedEmailSchema.index({ email: 1 });
rejectedEmailSchema.index({ rejectedAt: -1 });

const RejectedEmail = mongoose.model('RejectedEmail', rejectedEmailSchema);

module.exports = RejectedEmail;
