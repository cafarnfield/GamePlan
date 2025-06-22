const Joi = require('joi');
const { 
  eventName,
  description,
  playerLimit,
  futureDate,
  platforms,
  mongoId,
  extensions,
  searchQuery,
  pagination,
  userStatus
} = require('./commonSchemas');

/**
 * Game selection validation schema
 */
const gameSelectionSchema = Joi.object({
  type: Joi.string()
    .valid('existing', 'steam', 'rawg', 'manual')
    .required()
    .messages({
      'any.only': 'Invalid game selection type',
      'any.required': 'Game selection type is required'
    }),
  gameId: Joi.string()
    .when('type', {
      is: 'existing',
      then: mongoId.required(),
      otherwise: Joi.optional()
    }),
  data: Joi.object()
    .when('type', {
      is: 'steam',
      then: Joi.object({
        appid: Joi.number().integer().min(1).required(),
        name: Joi.string().min(1).max(200).required(),
        short_description: Joi.string().max(2000).optional(),
        header_image: Joi.string().uri().optional(),
        website: Joi.string().uri().optional(),
        developers: Joi.array().items(Joi.string()).optional(),
        publishers: Joi.array().items(Joi.string()).optional(),
        genres: Joi.array().items(Joi.object()).optional(),
        categories: Joi.array().items(Joi.object()).optional(),
        platforms: Joi.object().optional(),
        release_date: Joi.object().optional(),
        price_overview: Joi.object().optional()
      }).required(),
      otherwise: Joi.when('type', {
        is: 'rawg',
        then: Joi.object({
          id: Joi.number().integer().min(1).required(),
          name: Joi.string().min(1).max(200).required(),
          description: Joi.string().max(5000).optional(),
          background_image: Joi.string().uri().optional(),
          website: Joi.string().uri().optional(),
          developers: Joi.array().items(Joi.object()).optional(),
          publishers: Joi.array().items(Joi.object()).optional(),
          genres: Joi.array().items(Joi.object()).optional(),
          platforms: Joi.array().items(Joi.object()).optional(),
          released: Joi.string().optional(),
          rating: Joi.number().optional(),
          metacritic: Joi.number().optional()
        }).required(),
        otherwise: Joi.when('type', {
          is: 'manual',
          then: Joi.object({
            name: Joi.string().min(2).max(200).required(),
            description: Joi.string().max(2000).optional(),
            imageUrl: Joi.string().uri().optional()
          }).required(),
          otherwise: Joi.optional()
        })
      })
    })
});

/**
 * Event creation schema
 */
const eventCreationSchema = Joi.object({
  name: eventName.required(),
  description: description.required(),
  playerLimit: playerLimit.required(),
  date: futureDate.required(),
  platforms: platforms.required(),
  gameSelection: Joi.alternatives()
    .try(
      Joi.string().custom((value, helpers) => {
        try {
          const parsed = JSON.parse(value);
          const { error } = gameSelectionSchema.validate(parsed);
          if (error) {
            throw new Error(error.details[0].message);
          }
          return parsed;
        } catch (parseError) {
          throw new Error('Invalid game selection format');
        }
      }),
      gameSelectionSchema
    )
    .required()
    .messages({
      'any.required': 'Game selection is required'
    }),
  extensions: Joi.alternatives()
    .try(
      Joi.string().custom((value, helpers) => {
        if (!value || value.trim() === '' || value.trim() === '[]') {
          return [];
        }
        try {
          let parsed;
          if (Array.isArray(value)) {
            const lastEntry = value[value.length - 1];
            if (lastEntry && lastEntry.trim() !== '[]') {
              parsed = JSON.parse(lastEntry);
            } else {
              return [];
            }
          } else {
            parsed = JSON.parse(value);
          }
          
          const { error } = extensions.validate(parsed);
          if (error) {
            throw new Error(error.details[0].message);
          }
          return parsed;
        } catch (parseError) {
          throw new Error('Invalid extensions format');
        }
      }),
      extensions,
      Joi.array().items().max(0) // Empty array
    )
    .optional()
    .default([])
}).messages({
  'object.unknown': 'Unknown field provided'
});

/**
 * Event editing schema
 */
const eventEditSchema = Joi.object({
  name: eventName.required(),
  gameId: mongoId.required(),
  description: description.required(),
  playerLimit: playerLimit.required(),
  date: futureDate.required(),
  platforms: platforms.required(),
  extensions: Joi.alternatives()
    .try(
      Joi.string().custom((value, helpers) => {
        if (!value || value.trim() === '' || value.trim() === '[]') {
          return [];
        }
        try {
          let parsed;
          if (Array.isArray(value)) {
            const lastEntry = value[value.length - 1];
            if (lastEntry && lastEntry.trim() !== '[]') {
              parsed = JSON.parse(lastEntry);
            } else {
              return [];
            }
          } else {
            parsed = JSON.parse(value);
          }
          
          const { error } = extensions.validate(parsed);
          if (error) {
            throw new Error(error.details[0].message);
          }
          return parsed;
        } catch (parseError) {
          throw new Error('Invalid extensions format');
        }
      }),
      extensions,
      Joi.array().items().max(0) // Empty array
    )
    .optional()
    .default([])
}).messages({
  'object.unknown': 'Unknown field provided'
});

/**
 * Event duplication schema
 */
const eventDuplicationSchema = Joi.object({
  name: eventName.optional(),
  description: Joi.string()
    .max(2000)
    .trim()
    .optional()
    .messages({
      'string.max': 'Event description cannot exceed 2000 characters'
    }),
  playerLimit: playerLimit.optional(),
  date: futureDate.required(),
  platforms: platforms.required()
}).messages({
  'object.unknown': 'Unknown field provided'
});

/**
 * Event join schema
 */
const eventJoinSchema = Joi.object({
  eventId: mongoId.required()
});

/**
 * Event leave schema
 */
const eventLeaveSchema = Joi.object({
  eventId: mongoId.required()
});

/**
 * Event filter schema (for public event listing)
 */
const eventFilterSchema = Joi.object({
  search: searchQuery.optional(),
  gameSearch: searchQuery.optional(),
  dateFrom: Joi.date().optional(),
  dateTo: Joi.date().min(Joi.ref('dateFrom')).optional(),
  status: Joi.string()
    .valid('live', 'upcoming', 'past')
    .optional()
    .messages({
      'any.only': 'Invalid status value'
    }),
  platforms: Joi.alternatives()
    .try(
      Joi.string().valid('PC', 'PlayStation', 'Xbox', 'Nintendo Switch'),
      Joi.array().items(Joi.string().valid('PC', 'PlayStation', 'Xbox', 'Nintendo Switch'))
    )
    .optional(),
  playerAvailability: Joi.string()
    .valid('available', 'full')
    .optional()
    .messages({
      'any.only': 'Invalid player availability value'
    }),
  host: Joi.string()
    .max(100)
    .pattern(/^[a-zA-Z0-9\s\-_]*$/)
    .trim()
    .optional()
    .messages({
      'string.max': 'Host search cannot exceed 100 characters',
      'string.pattern.base': 'Host search contains invalid characters'
    }),
  categories: Joi.alternatives()
    .try(
      Joi.string().max(50).pattern(/^[a-zA-Z0-9\s\-_]+$/),
      Joi.array().items(Joi.string().max(50).pattern(/^[a-zA-Z0-9\s\-_]+$/))
    )
    .optional(),
  sortBy: Joi.string()
    .valid('recent', 'players', 'alphabetical', 'date')
    .optional()
    .messages({
      'any.only': 'Invalid sort option'
    }),
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20)
}).messages({
  'date.min': 'End date must be after start date'
});

/**
 * Admin event filter schema
 */
const adminEventFilterSchema = Joi.object({
  status: Joi.string()
    .valid('upcoming', 'past', 'live')
    .optional()
    .messages({
      'any.only': 'Invalid status value'
    }),
  game: mongoId.optional(),
  dateFrom: Joi.date().optional(),
  dateTo: Joi.date().min(Joi.ref('dateFrom')).optional(),
  search: searchQuery.optional(),
  creator: Joi.string()
    .max(100)
    .pattern(/^[a-zA-Z0-9\s\-_]*$/)
    .trim()
    .optional()
    .messages({
      'string.max': 'Creator search cannot exceed 100 characters',
      'string.pattern.base': 'Creator search contains invalid characters'
    }),
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20)
}).messages({
  'date.min': 'End date must be after start date'
});

/**
 * Event participant management schema
 */
const eventParticipantSchema = Joi.object({
  eventId: mongoId.required(),
  userId: mongoId.required(),
  action: Joi.string()
    .valid('add', 'remove', 'promote', 'demote')
    .required()
    .messages({
      'any.only': 'Invalid participant action',
      'any.required': 'Action is required'
    })
});

/**
 * Event status update schema (admin)
 */
const eventStatusUpdateSchema = Joi.object({
  eventId: mongoId.required(),
  status: Joi.string()
    .valid('active', 'cancelled', 'completed', 'postponed')
    .required()
    .messages({
      'any.only': 'Invalid event status',
      'any.required': 'Event status is required'
    }),
  reason: Joi.string()
    .max(500)
    .trim()
    .when('status', {
      is: Joi.valid('cancelled', 'postponed'),
      then: Joi.required(),
      otherwise: Joi.optional()
    })
    .messages({
      'string.max': 'Reason cannot exceed 500 characters',
      'any.required': 'Reason is required for cancelled or postponed events'
    })
});

/**
 * Bulk event operation schema (admin)
 */
const bulkEventOperationSchema = Joi.object({
  eventIds: Joi.array()
    .items(mongoId)
    .min(1)
    .max(50)
    .unique()
    .required()
    .messages({
      'array.min': 'At least one event must be selected',
      'array.max': 'Cannot process more than 50 events at once',
      'array.unique': 'Duplicate event IDs are not allowed',
      'any.required': 'Event IDs are required'
    }),
  operation: Joi.string()
    .valid('cancel', 'delete', 'feature', 'unfeature')
    .required()
    .messages({
      'any.only': 'Invalid bulk operation',
      'any.required': 'Operation type is required'
    }),
  reason: Joi.string()
    .max(500)
    .trim()
    .when('operation', {
      is: Joi.valid('cancel', 'delete'),
      then: Joi.required(),
      otherwise: Joi.optional()
    })
    .messages({
      'string.max': 'Reason cannot exceed 500 characters',
      'any.required': 'Reason is required for cancel or delete operations'
    })
});

module.exports = {
  gameSelectionSchema,
  eventCreationSchema,
  eventEditSchema,
  eventDuplicationSchema,
  eventJoinSchema,
  eventLeaveSchema,
  eventFilterSchema,
  adminEventFilterSchema,
  eventParticipantSchema,
  eventStatusUpdateSchema,
  bulkEventOperationSchema
};
