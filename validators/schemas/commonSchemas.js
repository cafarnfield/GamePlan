const Joi = require('joi');

/**
 * Common validation schemas that can be reused across different validators
 */

// MongoDB ObjectId validation
const mongoId = Joi.string()
  .pattern(/^[0-9a-fA-F]{24}$/)
  .message('Invalid MongoDB ObjectId format');

// Email validation with comprehensive rules
const email = Joi.string()
  .email({ 
    minDomainSegments: 2,
    tlds: { allow: true }
  })
  .max(254)
  .lowercase()
  .trim()
  .messages({
    'string.email': 'Please provide a valid email address',
    'string.max': 'Email address is too long'
  });

// Strong password validation
const password = Joi.string()
  .min(8)
  .max(128)
  .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/)
  .messages({
    'string.min': 'Password must be at least 8 characters long',
    'string.max': 'Password cannot exceed 128 characters',
    'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
  });

// Name validation (for users, events, games)
const name = Joi.string()
  .min(2)
  .max(100)
  .pattern(/^[a-zA-Z\s\-'\.]+$/)
  .trim()
  .messages({
    'string.min': 'Name must be at least 2 characters long',
    'string.max': 'Name cannot exceed 100 characters',
    'string.pattern.base': 'Name can only contain letters, spaces, hyphens, apostrophes, and periods'
  });

// Game name validation (more permissive than user names)
const gameName = Joi.string()
  .min(2)
  .max(200)
  .pattern(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
  .trim()
  .messages({
    'string.min': 'Game name must be at least 2 characters long',
    'string.max': 'Game name cannot exceed 200 characters',
    'string.pattern.base': 'Game name contains invalid characters'
  });

// Event name validation
const eventName = Joi.string()
  .min(3)
  .max(200)
  .pattern(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
  .trim()
  .messages({
    'string.min': 'Event name must be at least 3 characters long',
    'string.max': 'Event name cannot exceed 200 characters',
    'string.pattern.base': 'Event name contains invalid characters'
  });

// Description validation
const description = Joi.string()
  .min(10)
  .max(2000)
  .trim()
  .messages({
    'string.min': 'Description must be at least 10 characters long',
    'string.max': 'Description cannot exceed 2000 characters'
  });

// Optional description (for games, etc.)
const optionalDescription = Joi.string()
  .max(2000)
  .trim()
  .allow('')
  .messages({
    'string.max': 'Description cannot exceed 2000 characters'
  });

// Game nickname validation
const gameNickname = Joi.string()
  .max(50)
  .pattern(/^[a-zA-Z0-9\s\-_]+$/)
  .trim()
  .allow('')
  .messages({
    'string.max': 'Game nickname cannot exceed 50 characters',
    'string.pattern.base': 'Game nickname can only contain letters, numbers, spaces, hyphens, and underscores'
  });

// Future date validation (with 30-minute buffer)
const futureDate = Joi.date()
  .min('now')
  .max(new Date(Date.now() + 2 * 365 * 24 * 60 * 60 * 1000)) // 2 years from now
  .messages({
    'date.min': 'Date must be in the future',
    'date.max': 'Date cannot be more than 2 years in the future'
  });

// Platform validation
const platforms = Joi.array()
  .items(Joi.string().valid('PC', 'PlayStation', 'Xbox', 'Nintendo Switch'))
  .min(1)
  .unique()
  .messages({
    'array.min': 'At least one platform must be selected',
    'array.unique': 'Duplicate platforms are not allowed',
    'any.only': 'Invalid platform selected'
  });

// Player limit validation
const playerLimit = Joi.number()
  .integer()
  .min(1)
  .max(100)
  .messages({
    'number.min': 'Player limit must be at least 1',
    'number.max': 'Player limit cannot exceed 100',
    'number.integer': 'Player limit must be a whole number'
  });

// URL validation
const url = Joi.string()
  .uri({ scheme: ['http', 'https'] })
  .max(500)
  .messages({
    'string.uri': 'Must be a valid URL',
    'string.max': 'URL cannot exceed 500 characters'
  });

// Notes validation (for admin operations)
const notes = Joi.string()
  .max(500)
  .trim()
  .allow('')
  .messages({
    'string.max': 'Notes cannot exceed 500 characters'
  });

// IP address validation
const ipAddress = Joi.alternatives()
  .try(
    Joi.string().ip({ version: ['ipv4'] }),
    Joi.string().ip({ version: ['ipv6'] })
  )
  .messages({
    'alternatives.match': 'Invalid IP address format'
  });

// Date range validation
const dateRange = Joi.object({
  dateFrom: Joi.date().optional(),
  dateTo: Joi.date().min(Joi.ref('dateFrom')).optional()
}).messages({
  'date.min': 'End date must be after start date'
});

// Search query validation
const searchQuery = Joi.string()
  .max(200)
  .pattern(/^[a-zA-Z0-9\s\-_:!?.,()&@.]*$/)
  .trim()
  .allow('')
  .messages({
    'string.max': 'Search query cannot exceed 200 characters',
    'string.pattern.base': 'Search query contains invalid characters'
  });

// Pagination validation
const pagination = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20)
});

// Steam App ID validation
const steamAppId = Joi.number()
  .integer()
  .min(1)
  .messages({
    'number.min': 'Steam App ID must be a positive integer',
    'number.integer': 'Steam App ID must be a whole number'
  });

// RAWG ID validation
const rawgId = Joi.number()
  .integer()
  .min(1)
  .messages({
    'number.min': 'RAWG ID must be a positive integer',
    'number.integer': 'RAWG ID must be a whole number'
  });

// User role validation
const userRole = Joi.string()
  .valid('user', 'admin', 'superadmin')
  .messages({
    'any.only': 'Invalid user role'
  });

// User status validation
const userStatus = Joi.string()
  .valid('pending', 'approved', 'rejected', 'blocked', 'probation')
  .messages({
    'any.only': 'Invalid user status'
  });

// Game status validation
const gameStatus = Joi.string()
  .valid('pending', 'approved', 'rejected')
  .messages({
    'any.only': 'Invalid game status'
  });

// Game source validation
const gameSource = Joi.string()
  .valid('steam', 'rawg', 'manual', 'admin')
  .messages({
    'any.only': 'Invalid game source'
  });

// Extension validation schema
const extension = Joi.object({
  name: Joi.string().max(100).required().messages({
    'string.max': 'Extension name cannot exceed 100 characters',
    'any.required': 'Extension name is required'
  }),
  downloadLink: url.required().messages({
    'any.required': 'Extension download link is required'
  }),
  installationTime: Joi.string().max(200).required().messages({
    'string.max': 'Installation time cannot exceed 200 characters',
    'any.required': 'Extension installation time is required'
  })
});

// Extensions array validation
const extensions = Joi.array()
  .items(extension)
  .max(10)
  .messages({
    'array.max': 'Cannot have more than 10 extensions'
  });

module.exports = {
  mongoId,
  email,
  password,
  name,
  gameName,
  eventName,
  description,
  optionalDescription,
  gameNickname,
  futureDate,
  platforms,
  playerLimit,
  url,
  notes,
  ipAddress,
  dateRange,
  searchQuery,
  pagination,
  steamAppId,
  rawgId,
  userRole,
  userStatus,
  gameStatus,
  gameSource,
  extension,
  extensions
};
