const Joi = require('joi');
const { 
  email, 
  password, 
  name, 
  gameNickname, 
  mongoId, 
  notes,
  userRole,
  userStatus,
  searchQuery,
  pagination,
  dateRange
} = require('./commonSchemas');

/**
 * User registration schema with comprehensive validation
 */
const userRegistrationSchema = Joi.object({
  name: name.required(),
  email: email.required(),
  password: password.required(),
  confirmPassword: Joi.string()
    .valid(Joi.ref('password'))
    .required()
    .messages({
      'any.only': 'Password confirmation does not match password',
      'any.required': 'Password confirmation is required'
    }),
  gameNickname: gameNickname.optional()
}).messages({
  'object.unknown': 'Unknown field provided'
});

/**
 * User login schema
 */
const userLoginSchema = Joi.object({
  email: email.required(),
  password: Joi.string()
    .min(1)
    .max(128)
    .required()
    .messages({
      'string.min': 'Password is required',
      'string.max': 'Password is too long',
      'any.required': 'Password is required'
    }),
  remember: Joi.boolean().optional()
});

/**
 * Profile update schema
 */
const profileUpdateSchema = Joi.object({
  gameNickname: gameNickname.optional()
}).min(1).messages({
  'object.min': 'At least one field must be provided for update'
});

/**
 * Password reset request schema
 */
const passwordResetRequestSchema = Joi.object({
  email: email.required()
});

/**
 * Password reset schema
 */
const passwordResetSchema = Joi.object({
  password: password.required(),
  confirmPassword: Joi.string()
    .valid(Joi.ref('password'))
    .required()
    .messages({
      'any.only': 'Password confirmation does not match password',
      'any.required': 'Password confirmation is required'
    }),
  token: Joi.string()
    .required()
    .min(1)
    .max(500)
    .messages({
      'any.required': 'Reset token is required',
      'string.min': 'Reset token is required',
      'string.max': 'Invalid reset token'
    })
});

/**
 * Change password schema (for authenticated users)
 */
const changePasswordSchema = Joi.object({
  currentPassword: Joi.string()
    .required()
    .messages({
      'any.required': 'Current password is required'
    }),
  newPassword: password.required(),
  confirmPassword: Joi.string()
    .valid(Joi.ref('newPassword'))
    .required()
    .messages({
      'any.only': 'Password confirmation does not match new password',
      'any.required': 'Password confirmation is required'
    })
});

/**
 * User approval schema (admin operation)
 */
const userApprovalSchema = Joi.object({
  userId: mongoId.required(),
  notes: notes.optional()
});

/**
 * User rejection schema (admin operation)
 */
const userRejectionSchema = Joi.object({
  userId: mongoId.required(),
  notes: Joi.string()
    .required()
    .min(1)
    .max(500)
    .trim()
    .messages({
      'any.required': 'Rejection reason is required',
      'string.min': 'Rejection reason is required',
      'string.max': 'Rejection reason cannot exceed 500 characters'
    })
});

/**
 * Bulk user operation schema
 */
const bulkUserOperationSchema = Joi.object({
  userIds: Joi.array()
    .items(mongoId)
    .min(1)
    .max(50)
    .unique()
    .required()
    .messages({
      'array.min': 'At least one user must be selected',
      'array.max': 'Cannot process more than 50 users at once',
      'array.unique': 'Duplicate user IDs are not allowed',
      'any.required': 'User IDs are required'
    }),
  notes: notes.optional(),
  operation: Joi.string()
    .valid('approve', 'reject', 'block', 'unblock', 'delete')
    .required()
    .messages({
      'any.only': 'Invalid bulk operation',
      'any.required': 'Operation type is required'
    })
});

/**
 * User role change schema
 */
const userRoleChangeSchema = Joi.object({
  userId: mongoId.required(),
  role: userRole.optional(),
  action: Joi.string()
    .valid('promote', 'demote', 'toggle')
    .required()
    .messages({
      'any.only': 'Invalid role change action',
      'any.required': 'Action is required'
    })
});

/**
 * User search/filter schema (admin)
 */
const userFilterSchema = Joi.object({
  filter: userStatus.optional(),
  search: searchQuery.optional(),
  dateFrom: Joi.date().optional(),
  dateTo: Joi.date().min(Joi.ref('dateFrom')).optional(),
  role: userRole.optional(),
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20)
}).messages({
  'date.min': 'End date must be after start date'
});

/**
 * User status update schema
 */
const userStatusUpdateSchema = Joi.object({
  userId: mongoId.required(),
  status: userStatus.required(),
  notes: notes.optional(),
  probationDays: Joi.number()
    .integer()
    .min(1)
    .max(365)
    .when('status', {
      is: 'probation',
      then: Joi.required(),
      otherwise: Joi.optional()
    })
    .messages({
      'number.min': 'Probation period must be at least 1 day',
      'number.max': 'Probation period cannot exceed 365 days',
      'any.required': 'Probation period is required when setting probation status'
    })
});

/**
 * Email verification schema
 */
const emailVerificationSchema = Joi.object({
  token: Joi.string()
    .required()
    .min(1)
    .max(500)
    .messages({
      'any.required': 'Verification token is required',
      'string.min': 'Verification token is required',
      'string.max': 'Invalid verification token'
    })
});

/**
 * Resend verification email schema
 */
const resendVerificationSchema = Joi.object({
  email: email.required()
});

module.exports = {
  userRegistrationSchema,
  userLoginSchema,
  profileUpdateSchema,
  passwordResetRequestSchema,
  passwordResetSchema,
  changePasswordSchema,
  userApprovalSchema,
  userRejectionSchema,
  bulkUserOperationSchema,
  userRoleChangeSchema,
  userFilterSchema,
  userStatusUpdateSchema,
  emailVerificationSchema,
  resendVerificationSchema
};
