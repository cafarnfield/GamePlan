const { query, body } = require('express-validator');
const { checkXSS } = require('../middleware/validation');

/**
 * Validation rules for Steam game search
 */
const validateSteamSearch = [
  query('q')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Search query must be between 2 and 100 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .withMessage('Search query contains invalid characters')
    .custom(checkXSS)
    .withMessage('Search query contains potentially dangerous content')
    .escape()
];

/**
 * Validation rules for RAWG game search
 */
const validateRawgSearch = [
  query('q')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Search query must be between 2 and 100 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .withMessage('Search query contains invalid characters')
    .custom(checkXSS)
    .withMessage('Search query contains potentially dangerous content')
    .escape()
];

/**
 * Validation rules for event filtering API
 */
const validateEventFilter = [
  // Search query validation
  query('search')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 200 })
    .withMessage('Search query cannot exceed 200 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]*$/)
    .withMessage('Search query contains invalid characters')
    .custom(checkXSS)
    .withMessage('Search query contains potentially dangerous content')
    .escape(),

  // Game search validation
  query('gameSearch')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 200 })
    .withMessage('Game search query cannot exceed 200 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]*$/)
    .withMessage('Game search query contains invalid characters')
    .custom(checkXSS)
    .withMessage('Game search query contains potentially dangerous content')
    .escape(),

  // Date range validation
  query('dateFrom')
    .optional({ checkFalsy: true })
    .isISO8601()
    .withMessage('Invalid date format for dateFrom')
    .toDate(),

  query('dateTo')
    .optional({ checkFalsy: true })
    .isISO8601()
    .withMessage('Invalid date format for dateTo')
    .toDate(),

  // Status validation
  query('status')
    .optional({ checkFalsy: true })
    .isIn(['live', 'upcoming', 'past'])
    .withMessage('Invalid status value'),

  // Platforms validation
  query('platforms')
    .optional({ checkFalsy: true })
    .custom((value) => {
      const allowedPlatforms = ['PC', 'PlayStation', 'Xbox', 'Nintendo Switch'];
      
      // Handle both array and single string
      const platforms = Array.isArray(value) ? value : [value];
      
      for (const platform of platforms) {
        if (!allowedPlatforms.includes(platform)) {
          throw new Error(`Invalid platform: ${platform}`);
        }
      }
      
      return true;
    }),

  // Player availability validation
  query('playerAvailability')
    .optional({ checkFalsy: true })
    .isIn(['available', 'full'])
    .withMessage('Invalid player availability value'),

  // Host validation
  query('host')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 })
    .withMessage('Host search cannot exceed 100 characters')
    .matches(/^[a-zA-Z0-9\s\-_]*$/)
    .withMessage('Host search contains invalid characters')
    .custom(checkXSS)
    .withMessage('Host search contains potentially dangerous content')
    .escape(),

  // Categories validation
  query('categories')
    .optional({ checkFalsy: true })
    .custom((value) => {
      // Handle both array and single string
      const categories = Array.isArray(value) ? value : [value];
      
      for (const category of categories) {
        if (typeof category !== 'string' || category.length > 50) {
          throw new Error('Invalid category format');
        }
        
        if (!/^[a-zA-Z0-9\s\-_]+$/.test(category)) {
          throw new Error('Category contains invalid characters');
        }
        
        checkXSS(category);
      }
      
      return true;
    }),

  // Sort by validation
  query('sortBy')
    .optional({ checkFalsy: true })
    .isIn(['recent', 'players', 'alphabetical', 'date'])
    .withMessage('Invalid sort option')
];

/**
 * Validation rules for duplicate game check
 */
const validateDuplicateCheck = [
  body('gameName')
    .trim()
    .isLength({ min: 3, max: 200 })
    .withMessage('Game name must be between 3 and 200 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .withMessage('Game name contains invalid characters')
    .custom(checkXSS)
    .withMessage('Game name contains potentially dangerous content')
    .escape()
];

/**
 * Validation rules for Steam equivalent check
 */
const validateSteamEquivalentCheck = [
  body('gameName')
    .trim()
    .isLength({ min: 2, max: 200 })
    .withMessage('Game name must be between 2 and 200 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]+$/)
    .withMessage('Game name contains invalid characters')
    .custom(checkXSS)
    .withMessage('Game name contains potentially dangerous content')
    .escape()
];

/**
 * Validation rules for admin user search/filtering
 */
const validateAdminUserFilter = [
  query('filter')
    .optional({ checkFalsy: true })
    .isIn(['pending', 'approved', 'rejected', 'blocked', 'probation'])
    .withMessage('Invalid filter value'),

  query('search')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 200 })
    .withMessage('Search query cannot exceed 200 characters')
    .matches(/^[a-zA-Z0-9\s\-_@.]*$/)
    .withMessage('Search query contains invalid characters')
    .custom(checkXSS)
    .withMessage('Search query contains potentially dangerous content')
    .escape(),

  query('dateFrom')
    .optional({ checkFalsy: true })
    .isISO8601()
    .withMessage('Invalid date format for dateFrom')
    .toDate(),

  query('dateTo')
    .optional({ checkFalsy: true })
    .isISO8601()
    .withMessage('Invalid date format for dateTo')
    .toDate()
];

/**
 * Validation rules for admin game filtering
 */
const validateAdminGameFilter = [
  query('status')
    .optional({ checkFalsy: true })
    .isIn(['pending', 'approved', 'rejected'])
    .withMessage('Invalid status value'),

  query('source')
    .optional({ checkFalsy: true })
    .isIn(['steam', 'manual', 'admin', 'rawg'])
    .withMessage('Invalid source value')
];

/**
 * Validation rules for admin event filtering
 */
const validateAdminEventFilter = [
  query('status')
    .optional({ checkFalsy: true })
    .isIn(['upcoming', 'past', 'live'])
    .withMessage('Invalid status value'),

  query('game')
    .optional({ checkFalsy: true })
    .isMongoId()
    .withMessage('Invalid game ID format'),

  query('dateFrom')
    .optional({ checkFalsy: true })
    .isISO8601()
    .withMessage('Invalid date format for dateFrom')
    .toDate(),

  query('dateTo')
    .optional({ checkFalsy: true })
    .isISO8601()
    .withMessage('Invalid date format for dateTo')
    .toDate(),

  query('search')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 200 })
    .withMessage('Search query cannot exceed 200 characters')
    .matches(/^[a-zA-Z0-9\s\-_:!?.,()&]*$/)
    .withMessage('Search query contains invalid characters')
    .custom(checkXSS)
    .withMessage('Search query contains potentially dangerous content')
    .escape(),

  query('creator')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 })
    .withMessage('Creator search cannot exceed 100 characters')
    .matches(/^[a-zA-Z0-9\s\-_]*$/)
    .withMessage('Creator search contains invalid characters')
    .custom(checkXSS)
    .withMessage('Creator search contains potentially dangerous content')
    .escape()
];

module.exports = {
  validateSteamSearch,
  validateRawgSearch,
  validateEventFilter,
  validateDuplicateCheck,
  validateSteamEquivalentCheck,
  validateAdminUserFilter,
  validateAdminGameFilter,
  validateAdminEventFilter
};
