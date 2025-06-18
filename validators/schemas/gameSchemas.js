const Joi = require('joi');
const { 
  gameName,
  optionalDescription,
  url,
  steamAppId,
  rawgId,
  gameStatus,
  gameSource,
  mongoId,
  notes,
  searchQuery,
  pagination
} = require('./commonSchemas');

/**
 * Manual game addition schema
 */
const manualGameAdditionSchema = Joi.object({
  name: gameName.required(),
  description: optionalDescription.optional(),
  imageUrl: url.optional().allow(''),
  steamAppId: steamAppId.optional(),
  source: Joi.string()
    .valid('manual')
    .default('manual')
    .messages({
      'any.only': 'Invalid game source for manual addition'
    })
}).messages({
  'object.unknown': 'Unknown field provided'
});

/**
 * Admin game addition schema (more comprehensive)
 */
const adminGameAdditionSchema = Joi.object({
  name: gameName.required(),
  description: optionalDescription.optional(),
  imageUrl: url.optional().allow(''),
  steamAppId: steamAppId.optional(),
  rawgId: rawgId.optional(),
  source: gameSource.required(),
  steamData: Joi.object()
    .when('source', {
      is: 'steam',
      then: Joi.object({
        appid: Joi.number().integer().min(1).required(),
        name: Joi.string().min(1).max(200).required(),
        short_description: Joi.string().max(2000).optional(),
        detailed_description: Joi.string().max(10000).optional(),
        header_image: Joi.string().uri().optional(),
        website: Joi.string().uri().optional(),
        developers: Joi.array().items(Joi.string()).optional(),
        publishers: Joi.array().items(Joi.string()).optional(),
        genres: Joi.array().items(Joi.object()).optional(),
        categories: Joi.array().items(Joi.object()).optional(),
        platforms: Joi.object().optional(),
        release_date: Joi.object().optional(),
        price_overview: Joi.object().optional(),
        screenshots: Joi.array().items(Joi.object()).optional(),
        movies: Joi.array().items(Joi.object()).optional(),
        achievements: Joi.object().optional(),
        supported_languages: Joi.string().optional(),
        requirements: Joi.object().optional()
      }).optional(),
      otherwise: Joi.optional()
    }),
  rawgData: Joi.object()
    .when('source', {
      is: 'rawg',
      then: Joi.object({
        id: Joi.number().integer().min(1).required(),
        name: Joi.string().min(1).max(200).required(),
        description: Joi.string().max(5000).optional(),
        description_raw: Joi.string().max(10000).optional(),
        background_image: Joi.string().uri().optional(),
        background_image_additional: Joi.string().uri().optional(),
        website: Joi.string().uri().optional(),
        developers: Joi.array().items(Joi.object()).optional(),
        publishers: Joi.array().items(Joi.object()).optional(),
        genres: Joi.array().items(Joi.object()).optional(),
        platforms: Joi.array().items(Joi.object()).optional(),
        stores: Joi.array().items(Joi.object()).optional(),
        released: Joi.string().optional(),
        rating: Joi.number().min(0).max(5).optional(),
        rating_top: Joi.number().optional(),
        ratings: Joi.array().items(Joi.object()).optional(),
        metacritic: Joi.number().min(0).max(100).optional(),
        playtime: Joi.number().min(0).optional(),
        screenshots_count: Joi.number().min(0).optional(),
        movies_count: Joi.number().min(0).optional(),
        creators_count: Joi.number().min(0).optional(),
        achievements_count: Joi.number().min(0).optional(),
        parent_achievements_count: Joi.number().min(0).optional(),
        reddit_url: Joi.string().uri().optional(),
        reddit_name: Joi.string().optional(),
        reddit_description: Joi.string().optional(),
        reddit_logo: Joi.string().uri().optional(),
        reddit_count: Joi.number().min(0).optional(),
        twitch_count: Joi.number().min(0).optional(),
        youtube_count: Joi.number().min(0).optional(),
        reviews_text_count: Joi.number().min(0).optional(),
        ratings_count: Joi.number().min(0).optional(),
        suggestions_count: Joi.number().min(0).optional(),
        alternative_names: Joi.array().items(Joi.string()).optional(),
        metacritic_url: Joi.string().uri().optional(),
        parents_count: Joi.number().min(0).optional(),
        additions_count: Joi.number().min(0).optional(),
        game_series_count: Joi.number().min(0).optional()
      }).optional(),
      otherwise: Joi.optional()
    })
}).messages({
  'object.unknown': 'Unknown field provided'
});

/**
 * Game approval schema
 */
const gameApprovalSchema = Joi.object({
  gameId: mongoId.required(),
  notes: notes.optional()
});

/**
 * Game rejection schema
 */
const gameRejectionSchema = Joi.object({
  gameId: mongoId.required(),
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
 * Game merge schema (for handling duplicates)
 */
const gameMergeSchema = Joi.object({
  duplicateId: mongoId.required(),
  canonicalId: mongoId.required(),
  mergeData: Joi.object({
    keepDuplicateData: Joi.boolean().default(false),
    transferEvents: Joi.boolean().default(true),
    notifyUsers: Joi.boolean().default(true)
  }).optional().default({})
});

/**
 * Game update schema (admin)
 */
const gameUpdateSchema = Joi.object({
  gameId: mongoId.required(),
  name: gameName.optional(),
  description: optionalDescription.optional(),
  imageUrl: url.optional().allow(''),
  status: gameStatus.optional(),
  tags: Joi.array()
    .items(Joi.string().max(50).pattern(/^[a-zA-Z0-9\s\-_]+$/))
    .max(10)
    .optional()
    .messages({
      'array.max': 'Cannot have more than 10 tags',
      'string.max': 'Tag cannot exceed 50 characters',
      'string.pattern.base': 'Tag contains invalid characters'
    }),
  featured: Joi.boolean().optional(),
  notes: notes.optional()
}).min(2).messages({
  'object.min': 'At least one field besides gameId must be provided for update'
});

/**
 * Game search schema (Steam)
 */
const steamGameSearchSchema = Joi.object({
  q: Joi.string()
    .min(2)
    .max(100)
    .pattern(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .trim()
    .required()
    .messages({
      'string.min': 'Search query must be at least 2 characters long',
      'string.max': 'Search query cannot exceed 100 characters',
      'string.pattern.base': 'Search query contains invalid characters',
      'any.required': 'Search query is required'
    })
});

/**
 * Game search schema (RAWG)
 */
const rawgGameSearchSchema = Joi.object({
  q: Joi.string()
    .min(2)
    .max(100)
    .pattern(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .trim()
    .required()
    .messages({
      'string.min': 'Search query must be at least 2 characters long',
      'string.max': 'Search query cannot exceed 100 characters',
      'string.pattern.base': 'Search query contains invalid characters',
      'any.required': 'Search query is required'
    }),
  page: Joi.number().integer().min(1).max(100).optional().default(1),
  page_size: Joi.number().integer().min(1).max(40).optional().default(20)
});

/**
 * Duplicate game check schema
 */
const duplicateGameCheckSchema = Joi.object({
  gameName: gameName.required(),
  steamAppId: steamAppId.optional(),
  rawgId: rawgId.optional()
});

/**
 * Steam equivalent check schema
 */
const steamEquivalentCheckSchema = Joi.object({
  gameName: Joi.string()
    .min(2)
    .max(200)
    .pattern(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .trim()
    .required()
    .messages({
      'string.min': 'Game name must be at least 2 characters long',
      'string.max': 'Game name cannot exceed 200 characters',
      'string.pattern.base': 'Game name contains invalid characters',
      'any.required': 'Game name is required'
    })
});

/**
 * Admin game filter schema
 */
const adminGameFilterSchema = Joi.object({
  status: gameStatus.optional(),
  source: gameSource.optional(),
  search: searchQuery.optional(),
  addedBy: Joi.string()
    .max(100)
    .pattern(/^[a-zA-Z0-9\s\-_@.]*$/)
    .trim()
    .optional()
    .messages({
      'string.max': 'Added by search cannot exceed 100 characters',
      'string.pattern.base': 'Added by search contains invalid characters'
    }),
  dateFrom: Joi.date().optional(),
  dateTo: Joi.date().min(Joi.ref('dateFrom')).optional(),
  featured: Joi.boolean().optional(),
  hasEvents: Joi.boolean().optional(),
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20)
}).messages({
  'date.min': 'End date must be after start date'
});

/**
 * Bulk game operation schema
 */
const bulkGameOperationSchema = Joi.object({
  gameIds: Joi.array()
    .items(mongoId)
    .min(1)
    .max(50)
    .unique()
    .required()
    .messages({
      'array.min': 'At least one game must be selected',
      'array.max': 'Cannot process more than 50 games at once',
      'array.unique': 'Duplicate game IDs are not allowed',
      'any.required': 'Game IDs are required'
    }),
  operation: Joi.string()
    .valid('approve', 'reject', 'delete', 'feature', 'unfeature')
    .required()
    .messages({
      'any.only': 'Invalid bulk operation',
      'any.required': 'Operation type is required'
    }),
  notes: Joi.string()
    .max(500)
    .trim()
    .when('operation', {
      is: Joi.valid('reject', 'delete'),
      then: Joi.required(),
      otherwise: Joi.optional()
    })
    .messages({
      'string.max': 'Notes cannot exceed 500 characters',
      'any.required': 'Notes are required for reject or delete operations'
    })
});

/**
 * Game import schema (for bulk imports)
 */
const gameImportSchema = Joi.object({
  games: Joi.array()
    .items(Joi.object({
      name: gameName.required(),
      description: optionalDescription.optional(),
      imageUrl: url.optional().allow(''),
      steamAppId: steamAppId.optional(),
      rawgId: rawgId.optional(),
      source: gameSource.required(),
      tags: Joi.array()
        .items(Joi.string().max(50).pattern(/^[a-zA-Z0-9\s\-_]+$/))
        .max(10)
        .optional()
    }))
    .min(1)
    .max(100)
    .required()
    .messages({
      'array.min': 'At least one game must be provided',
      'array.max': 'Cannot import more than 100 games at once',
      'any.required': 'Games array is required'
    }),
  skipDuplicates: Joi.boolean().default(true),
  autoApprove: Joi.boolean().default(false)
});

module.exports = {
  manualGameAdditionSchema,
  adminGameAdditionSchema,
  gameApprovalSchema,
  gameRejectionSchema,
  gameMergeSchema,
  gameUpdateSchema,
  steamGameSearchSchema,
  rawgGameSearchSchema,
  duplicateGameCheckSchema,
  steamEquivalentCheckSchema,
  adminGameFilterSchema,
  bulkGameOperationSchema,
  gameImportSchema
};
