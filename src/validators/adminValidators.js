const { body, param } = require('express-validator');
const { checkXSS } = require('../middleware/validation');

/**
 * Validation rules for admin user approval
 */
const validateUserApproval = [
  param('id')
    .isMongoId()
    .withMessage('Invalid user ID format'),

  body('notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 })
    .withMessage('Notes cannot exceed 500 characters')
    .custom(checkXSS)
    .withMessage('Notes contain potentially dangerous content')
    .escape()
];

/**
 * Validation rules for admin user rejection
 */
const validateUserRejection = [
  param('id')
    .isMongoId()
    .withMessage('Invalid user ID format'),

  body('notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 })
    .withMessage('Rejection reason cannot exceed 500 characters')
    .custom(checkXSS)
    .withMessage('Rejection reason contains potentially dangerous content')
    .escape()
];

/**
 * Validation rules for bulk user operations
 */
const validateBulkUserOperation = [
  body('userIds')
    .isArray({ min: 1, max: 50 })
    .withMessage('User IDs must be an array with 1-50 items')
    .custom((userIds) => {
      for (const id of userIds) {
        if (typeof id !== 'string' || !/^[0-9a-fA-F]{24}$/.test(id)) {
          throw new Error('All user IDs must be valid MongoDB ObjectIds');
        }
      }
      return true;
    }),

  body('notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 })
    .withMessage('Notes cannot exceed 500 characters')
    .custom(checkXSS)
    .withMessage('Notes contain potentially dangerous content')
    .escape()
];

/**
 * Validation rules for game approval/rejection
 */
const validateGameApproval = [
  param('id')
    .isMongoId()
    .withMessage('Invalid game ID format'),

  body('notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 })
    .withMessage('Notes cannot exceed 500 characters')
    .custom(checkXSS)
    .withMessage('Notes contain potentially dangerous content')
    .escape()
];

/**
 * Validation rules for game merging
 */
const validateGameMerge = [
  param('duplicateId')
    .isMongoId()
    .withMessage('Invalid duplicate game ID format'),

  param('canonicalId')
    .isMongoId()
    .withMessage('Invalid canonical game ID format')
];

/**
 * Validation rules for admin game addition
 */
const validateAdminGameAddition = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 200 })
    .withMessage('Game name must be between 2 and 200 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .withMessage('Game name contains invalid characters')
    .custom(checkXSS)
    .withMessage('Game name contains potentially dangerous content')
    .escape(),

  body('description')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Game description cannot exceed 2000 characters')
    .custom(checkXSS)
    .withMessage('Game description contains potentially dangerous content')
    .escape(),

  body('source')
    .isIn(['steam', 'rawg', 'manual'])
    .withMessage('Invalid game source'),

  body('steamAppId')
    .optional({ checkFalsy: true })
    .isInt({ min: 1 })
    .withMessage('Steam App ID must be a positive integer')
    .toInt(),

  body('rawgId')
    .optional({ checkFalsy: true })
    .isInt({ min: 1 })
    .withMessage('RAWG ID must be a positive integer')
    .toInt(),

  body('steamData')
    .optional({ checkFalsy: true })
    .custom((value) => {
      if (!value) return true;
      
      try {
        const data = typeof value === 'string' ? JSON.parse(value) : value;
        
        if (typeof data !== 'object') {
          throw new Error('Steam data must be an object');
        }
        
        // Basic validation of Steam data structure
        if (data.name && typeof data.name !== 'string') {
          throw new Error('Steam data name must be a string');
        }
        
        if (data.short_description && typeof data.short_description !== 'string') {
          throw new Error('Steam data description must be a string');
        }
        
        return true;
      } catch (parseError) {
        throw new Error('Invalid Steam data format');
      }
    }),

  body('rawgData')
    .optional({ checkFalsy: true })
    .custom((value) => {
      if (!value) return true;
      
      try {
        const data = typeof value === 'string' ? JSON.parse(value) : value;
        
        if (typeof data !== 'object') {
          throw new Error('RAWG data must be an object');
        }
        
        // Basic validation of RAWG data structure
        if (data.name && typeof data.name !== 'string') {
          throw new Error('RAWG data name must be a string');
        }
        
        if (data.description && typeof data.description !== 'string') {
          throw new Error('RAWG data description must be a string');
        }
        
        return true;
      } catch (parseError) {
        throw new Error('Invalid RAWG data format');
      }
    })
];

/**
 * Validation rules for bulk event operations
 */
const validateBulkEventOperation = [
  body('eventIds')
    .isArray({ min: 1, max: 50 })
    .withMessage('Event IDs must be an array with 1-50 items')
    .custom((eventIds) => {
      for (const id of eventIds) {
        if (typeof id !== 'string' || !/^[0-9a-fA-F]{24}$/.test(id)) {
          throw new Error('All event IDs must be valid MongoDB ObjectIds');
        }
      }
      return true;
    }),

  body('notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 })
    .withMessage('Notes cannot exceed 500 characters')
    .custom(checkXSS)
    .withMessage('Notes contain potentially dangerous content')
    .escape()
];

/**
 * Validation rules for admin system operations
 */
const validateSystemOperation = [
  body('operation')
    .isIn(['backup', 'cleanup', 'maintenance'])
    .withMessage('Invalid system operation'),

  body('confirm')
    .equals('true')
    .withMessage('Operation must be confirmed'),

  body('notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 })
    .withMessage('Notes cannot exceed 500 characters')
    .custom(checkXSS)
    .withMessage('Notes contain potentially dangerous content')
    .escape()
];

/**
 * Validation rules for user role changes
 */
const validateUserRoleChange = [
  param('id')
    .isMongoId()
    .withMessage('Invalid user ID format'),

  body('role')
    .optional({ checkFalsy: true })
    .isIn(['user', 'admin', 'superadmin'])
    .withMessage('Invalid role value'),

  body('action')
    .isIn(['promote', 'demote', 'toggle'])
    .withMessage('Invalid action value')
];

/**
 * Validation rules for audit log filtering
 */
const validateAuditLogFilter = [
  body('dateFrom')
    .optional({ checkFalsy: true })
    .isISO8601()
    .withMessage('Invalid date format for dateFrom')
    .toDate(),

  body('dateTo')
    .optional({ checkFalsy: true })
    .isISO8601()
    .withMessage('Invalid date format for dateTo')
    .toDate(),

  body('action')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 })
    .withMessage('Action filter cannot exceed 100 characters')
    .matches(/^[a-zA-Z0-9\s\-_]*$/)
    .withMessage('Action filter contains invalid characters')
    .custom(checkXSS)
    .withMessage('Action filter contains potentially dangerous content')
    .escape(),

  body('adminId')
    .optional({ checkFalsy: true })
    .isMongoId()
    .withMessage('Invalid admin ID format'),

  body('targetUserId')
    .optional({ checkFalsy: true })
    .isMongoId()
    .withMessage('Invalid target user ID format')
];

/**
 * Validation rules for IP operations (block, whitelist, etc.)
 */
const validateIPOperation = [
  param('ipAddress')
    .custom((value) => {
      // Basic IP validation (IPv4 and IPv6)
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      // More comprehensive IPv6 regex that handles compressed notation like ::1
      const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
      if (!ipv4Regex.test(value) && !ipv6Regex.test(value)) {
        throw new Error('Invalid IP address format');
      }
      return true;
    }),

  body('reason')
    .trim()
    .isLength({ min: 1, max: 500 })
    .withMessage('Reason must be between 1 and 500 characters')
    .custom(checkXSS)
    .withMessage('Reason contains potentially dangerous content')
    .escape()
];

/**
 * Validation rules for bulk IP operations
 */
const validateBulkIPOperation = [
  body('ipAddresses')
    .isArray({ min: 1, max: 50 })
    .withMessage('IP addresses must be an array with 1-50 items')
    .custom((ipAddresses) => {
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      // More comprehensive IPv6 regex that handles compressed notation like ::1
      const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
      
      for (const ip of ipAddresses) {
        if (typeof ip !== 'string' || (!ipv4Regex.test(ip) && !ipv6Regex.test(ip))) {
          throw new Error('All IP addresses must be valid IPv4 or IPv6 addresses');
        }
      }
      return true;
    }),

  body('reason')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 })
    .withMessage('Reason cannot exceed 500 characters')
    .custom(checkXSS)
    .withMessage('Reason contains potentially dangerous content')
    .escape(),

  param('action')
    .isIn(['block', 'unblock', 'whitelist', 'remove-whitelist'])
    .withMessage('Invalid bulk IP action')
];

/**
 * Validation rules for IP-based operations (legacy - keeping for compatibility)
 */
const validateIpOperation = [
  body('ipAddress')
    .isIP()
    .withMessage('Invalid IP address format'),

  body('action')
    .isIn(['block', 'unblock', 'investigate'])
    .withMessage('Invalid IP action'),

  body('reason')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 })
    .withMessage('Reason cannot exceed 500 characters')
    .custom(checkXSS)
    .withMessage('Reason contains potentially dangerous content')
    .escape()
];

/**
 * Validation rules for admin password reset
 */
const validateAdminPasswordReset = [
  param('id')
    .isMongoId()
    .withMessage('Invalid user ID format'),

  body('newPassword')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),

  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match');
      }
      return true;
    }),

  body('reason')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 })
    .withMessage('Reason cannot exceed 500 characters')
    .custom(checkXSS)
    .withMessage('Reason contains potentially dangerous content')
    .escape(),

  body('notifyUser')
    .optional()
    .isBoolean()
    .withMessage('Notify user must be a boolean value')
    .toBoolean(),

  body('forceChange')
    .optional()
    .isBoolean()
    .withMessage('Force change must be a boolean value')
    .toBoolean()
];

/**
 * Validation rules for admin-triggered password reset email
 */
const validateAdminPasswordResetEmail = [
  param('id')
    .isMongoId()
    .withMessage('Invalid user ID format'),

  body('reason')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 })
    .withMessage('Reason cannot exceed 500 characters')
    .custom(checkXSS)
    .withMessage('Reason contains potentially dangerous content')
    .escape()
];

module.exports = {
  validateUserApproval,
  validateUserRejection,
  validateBulkUserOperation,
  validateGameApproval,
  validateGameMerge,
  validateAdminGameAddition,
  validateBulkEventOperation,
  validateSystemOperation,
  validateUserRoleChange,
  validateAuditLogFilter,
  validateIpOperation,
  validateIPOperation,
  validateBulkIPOperation,
  validateAdminPasswordReset,
  validateAdminPasswordResetEmail
};
