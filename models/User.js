const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  isAdmin: { type: Boolean, default: false },
  isSuperAdmin: { type: Boolean, default: false },
  isProtected: { type: Boolean, default: false },
  isBlocked: { type: Boolean, default: false },
  gameNickname: { type: String, default: '' },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected'], 
    default: 'pending' 
  },
  approvalNotes: { type: String, default: '' },
  rejectedReason: { type: String, default: '' },
  registrationIP: String,
  probationaryUntil: Date,
  createdAt: { type: Date, default: Date.now },
  approvedAt: Date,
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  // Password reset fields
  resetToken: String,
  resetTokenExpiry: Date,
  resetTokenUsed: { type: Boolean, default: false },
  // Admin password reset fields
  mustChangePassword: { type: Boolean, default: false },
  mustChangePasswordReason: String,
  passwordResetBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  passwordResetAt: Date
});

// Add indexes for password reset functionality
userSchema.index({ resetToken: 1 });
userSchema.index({ resetTokenExpiry: 1 });

const User = mongoose.model('User', userSchema);

module.exports = User;
