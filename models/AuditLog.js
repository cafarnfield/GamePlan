const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  adminName: { type: String, required: true },
  action: { 
    type: String, 
    required: true,
    enum: ['approve', 'reject', 'delete', 'block', 'unblock', 'toggle_admin', 'bulk_approve', 'bulk_reject', 'bulk_delete', 'end_probation']
  },
  targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  targetUserEmail: String,
  targetUserName: String,
  notes: String,
  timestamp: { type: Date, default: Date.now },
  ipAddress: String,
  bulkCount: { type: Number, default: 1 }, // For bulk operations
  details: mongoose.Schema.Types.Mixed // For additional action-specific data
});

// Index for efficient querying
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ adminId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = AuditLog;
