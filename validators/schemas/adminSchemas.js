const Joi = require('joi');
const { 
  mongoId,
  notes,
  ipAddress,
  userRole,
  userStatus,
  searchQuery,
  pagination
} = require('./commonSchemas');

/**
 * System operation schema
 */
const systemOperationSchema = Joi.object({
  operation: Joi.string()
    .valid('backup', 'cleanup', 'maintenance', 'cache-clear', 'index-rebuild', 'log-rotate')
    .required()
    .messages({
      'any.only': 'Invalid system operation',
      'any.required': 'Operation is required'
    }),
  confirm: Joi.boolean()
    .valid(true)
    .required()
    .messages({
      'any.only': 'Operation must be confirmed',
      'any.required': 'Operation confirmation is required'
    }),
  notes: notes.optional(),
  parameters: Joi.object({
    dryRun: Joi.boolean().default(false),
    force: Joi.boolean().default(false),
    backupLocation: Joi.string().when('$operation', {
      is: 'backup',
      then: Joi.string().max(500).optional(),
      otherwise: Joi.optional()
    }),
    retentionDays: Joi.number().integer().min(1).max(365).when('$operation', {
      is: Joi.valid('cleanup', 'log-rotate'),
      then: Joi.number().default(30),
      otherwise: Joi.optional()
    })
  }).optional().default({})
});

/**
 * Audit log filter schema
 */
const auditLogFilterSchema = Joi.object({
  dateFrom: Joi.date().optional(),
  dateTo: Joi.date().min(Joi.ref('dateFrom')).optional(),
  action: Joi.string()
    .max(100)
    .pattern(/^[a-zA-Z0-9\s\-_]*$/)
    .trim()
    .optional()
    .messages({
      'string.max': 'Action filter cannot exceed 100 characters',
      'string.pattern.base': 'Action filter contains invalid characters'
    }),
  adminId: mongoId.optional(),
  targetUserId: mongoId.optional(),
  ipAddress: ipAddress.optional(),
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20)
}).messages({
  'date.min': 'End date must be after start date'
});

/**
 * IP operation schema (blocking, unblocking, etc.)
 */
const ipOperationSchema = Joi.object({
  ipAddress: ipAddress.required(),
  action: Joi.string()
    .valid('block', 'unblock', 'investigate', 'whitelist', 'blacklist')
    .required()
    .messages({
      'any.only': 'Invalid IP action',
      'any.required': 'Action is required'
    }),
  reason: Joi.string()
    .max(500)
    .trim()
    .when('action', {
      is: Joi.valid('block', 'blacklist'),
      then: Joi.required(),
      otherwise: Joi.optional()
    })
    .messages({
      'string.max': 'Reason cannot exceed 500 characters',
      'any.required': 'Reason is required for blocking actions'
    }),
  duration: Joi.number()
    .integer()
    .min(1)
    .max(365)
    .when('action', {
      is: Joi.valid('block', 'blacklist'),
      then: Joi.optional(),
      otherwise: Joi.optional()
    })
    .messages({
      'number.min': 'Duration must be at least 1 day',
      'number.max': 'Duration cannot exceed 365 days'
    })
});

/**
 * Cache management schema
 */
const cacheManagementSchema = Joi.object({
  operation: Joi.string()
    .valid('clear', 'refresh', 'stats', 'configure')
    .required()
    .messages({
      'any.only': 'Invalid cache operation',
      'any.required': 'Cache operation is required'
    }),
  cacheType: Joi.string()
    .valid('all', 'user', 'game', 'event', 'api', 'session')
    .when('operation', {
      is: Joi.valid('clear', 'refresh'),
      then: Joi.required(),
      otherwise: Joi.optional()
    })
    .messages({
      'any.only': 'Invalid cache type',
      'any.required': 'Cache type is required for this operation'
    }),
  keys: Joi.array()
    .items(Joi.string().max(200))
    .max(100)
    .when('operation', {
      is: 'clear',
      then: Joi.optional(),
      otherwise: Joi.optional()
    })
    .messages({
      'array.max': 'Cannot specify more than 100 cache keys',
      'string.max': 'Cache key cannot exceed 200 characters'
    }),
  configuration: Joi.object({
    ttl: Joi.number().integer().min(60).max(86400).optional(),
    maxSize: Joi.number().integer().min(100).max(10000).optional(),
    checkPeriod: Joi.number().integer().min(60).max(3600).optional()
  }).when('operation', {
    is: 'configure',
    then: Joi.required(),
    otherwise: Joi.optional()
  })
});

/**
 * Error log filter schema
 */
const errorLogFilterSchema = Joi.object({
  dateFrom: Joi.date().optional(),
  dateTo: Joi.date().min(Joi.ref('dateFrom')).optional(),
  level: Joi.string()
    .valid('error', 'warn', 'info', 'debug')
    .optional()
    .messages({
      'any.only': 'Invalid log level'
    }),
  source: Joi.string()
    .max(100)
    .pattern(/^[a-zA-Z0-9\s\-_./]*$/)
    .trim()
    .optional()
    .messages({
      'string.max': 'Source filter cannot exceed 100 characters',
      'string.pattern.base': 'Source filter contains invalid characters'
    }),
  message: searchQuery.optional(),
  userId: mongoId.optional(),
  resolved: Joi.boolean().optional(),
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20)
}).messages({
  'date.min': 'End date must be after start date'
});

/**
 * Database maintenance schema
 */
const databaseMaintenanceSchema = Joi.object({
  operation: Joi.string()
    .valid('optimize', 'reindex', 'compact', 'analyze', 'repair')
    .required()
    .messages({
      'any.only': 'Invalid database operation',
      'any.required': 'Database operation is required'
    }),
  collections: Joi.array()
    .items(Joi.string().valid('users', 'events', 'games', 'auditlogs', 'errorlogs', 'rejectedemails', 'extensions'))
    .min(1)
    .unique()
    .when('operation', {
      is: Joi.valid('reindex', 'compact', 'analyze'),
      then: Joi.required(),
      otherwise: Joi.optional()
    })
    .messages({
      'array.min': 'At least one collection must be specified',
      'array.unique': 'Duplicate collections are not allowed',
      'any.only': 'Invalid collection name',
      'any.required': 'Collections must be specified for this operation'
    }),
  force: Joi.boolean().default(false),
  dryRun: Joi.boolean().default(false)
});

/**
 * Security scan schema
 */
const securityScanSchema = Joi.object({
  scanType: Joi.string()
    .valid('vulnerability', 'permissions', 'access-patterns', 'suspicious-activity')
    .required()
    .messages({
      'any.only': 'Invalid scan type',
      'any.required': 'Scan type is required'
    }),
  scope: Joi.object({
    users: Joi.boolean().default(true),
    events: Joi.boolean().default(true),
    games: Joi.boolean().default(true),
    admin: Joi.boolean().default(true),
    api: Joi.boolean().default(true)
  }).optional().default({}),
  parameters: Joi.object({
    lookbackDays: Joi.number().integer().min(1).max(90).default(7),
    threshold: Joi.number().min(0).max(1).default(0.8),
    includeResolved: Joi.boolean().default(false)
  }).optional().default({})
});

/**
 * Notification management schema
 */
const notificationManagementSchema = Joi.object({
  operation: Joi.string()
    .valid('send', 'schedule', 'cancel', 'template')
    .required()
    .messages({
      'any.only': 'Invalid notification operation',
      'any.required': 'Notification operation is required'
    }),
  recipients: Joi.object({
    type: Joi.string()
      .valid('all', 'admins', 'users', 'specific', 'role', 'status')
      .required(),
    userIds: Joi.array()
      .items(mongoId)
      .when('type', {
        is: 'specific',
        then: Joi.array().items(mongoId).min(1).max(1000).required(),
        otherwise: Joi.optional()
      }),
    role: userRole.when('type', {
      is: 'role',
      then: Joi.required(),
      otherwise: Joi.optional()
    }),
    status: userStatus.when('type', {
      is: 'status',
      then: Joi.required(),
      otherwise: Joi.optional()
    })
  }).when('operation', {
    is: Joi.valid('send', 'schedule'),
    then: Joi.required(),
    otherwise: Joi.optional()
  }),
  message: Joi.object({
    subject: Joi.string().min(1).max(200).required(),
    body: Joi.string().min(1).max(5000).required(),
    priority: Joi.string().valid('low', 'normal', 'high', 'urgent').default('normal'),
    type: Joi.string().valid('info', 'warning', 'error', 'success').default('info')
  }).when('operation', {
    is: Joi.valid('send', 'schedule'),
    then: Joi.required(),
    otherwise: Joi.optional()
  }),
  schedule: Joi.object({
    sendAt: Joi.date().min('now').required(),
    timezone: Joi.string().default('UTC')
  }).when('operation', {
    is: 'schedule',
    then: Joi.required(),
    otherwise: Joi.optional()
  })
});

/**
 * System health check schema
 */
const systemHealthCheckSchema = Joi.object({
  components: Joi.array()
    .items(Joi.string().valid('database', 'cache', 'external-apis', 'file-system', 'memory', 'disk'))
    .min(1)
    .unique()
    .default(['database', 'cache', 'external-apis'])
    .messages({
      'array.min': 'At least one component must be checked',
      'array.unique': 'Duplicate components are not allowed',
      'any.only': 'Invalid component name'
    }),
  detailed: Joi.boolean().default(false),
  includeMetrics: Joi.boolean().default(true)
});

/**
 * Configuration update schema
 */
const configurationUpdateSchema = Joi.object({
  section: Joi.string()
    .valid('security', 'performance', 'features', 'integrations', 'notifications')
    .required()
    .messages({
      'any.only': 'Invalid configuration section',
      'any.required': 'Configuration section is required'
    }),
  settings: Joi.object().min(1).required().messages({
    'object.min': 'At least one setting must be provided',
    'any.required': 'Settings are required'
  }),
  validate: Joi.boolean().default(true),
  backup: Joi.boolean().default(true)
});

module.exports = {
  systemOperationSchema,
  auditLogFilterSchema,
  ipOperationSchema,
  cacheManagementSchema,
  errorLogFilterSchema,
  databaseMaintenanceSchema,
  securityScanSchema,
  notificationManagementSchema,
  systemHealthCheckSchema,
  configurationUpdateSchema
};
