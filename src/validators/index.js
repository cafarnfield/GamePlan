/**
 * Comprehensive validation system for GamePlan
 * 
 * This module provides both Joi schemas and express-validator validators
 * for all API endpoints. It includes:
 * 
 * - User registration, login, and profile management
 * - Event creation, editing, and management
 * - Game addition, approval, and administration
 * - Admin operations and system management
 * - Search and filtering operations
 * 
 * Usage:
 * const { validateBody, userSchemas, eventSchemas } = require('./validators');
 * 
 * // Using Joi validation
 * router.post('/register', validateBody(userSchemas.userRegistrationSchema), handler);
 * 
 * // Using existing express-validator (for backward compatibility)
 * const { validateRegistration } = require('./validators/authValidators');
 * router.post('/register', validateRegistration, handleValidationErrors, handler);
 */

// Import Joi validation middleware
const {
  createJoiValidator,
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  validateMultiple,
  validateConditional,
  validateFiles
} = require('./middleware/joiValidator');

// Import Joi schemas
const commonSchemas = require('./schemas/commonSchemas');
const userSchemas = require('./schemas/userSchemas');
const eventSchemas = require('./schemas/eventSchemas');
const gameSchemas = require('./schemas/gameSchemas');
const adminSchemas = require('./schemas/adminSchemas');

// Import existing express-validator validators (for backward compatibility)
const authValidators = require('./authValidators');
const eventValidators = require('./eventValidators');
const adminValidators = require('./adminValidators');
const searchValidators = require('./searchValidators');

// Import validation middleware
const { handleValidationErrors } = require('../middleware/validation');

/**
 * Quick access to commonly used validation patterns
 */
const quickValidators = {
  // MongoDB ObjectId validation
  mongoId: validateParams(commonSchemas.mongoId),
  
  // Pagination validation
  pagination: validateQuery(commonSchemas.pagination),
  
  // Search query validation
  searchQuery: validateQuery({ search: commonSchemas.searchQuery }),
  
  // Date range validation
  dateRange: validateQuery(commonSchemas.dateRange),
  
  // User authentication
  userLogin: validateBody(userSchemas.userLoginSchema),
  userRegistration: validateBody(userSchemas.userRegistrationSchema),
  
  // Event operations
  eventCreation: validateBody(eventSchemas.eventCreationSchema),
  eventEdit: validateBody(eventSchemas.eventEditSchema),
  eventFilter: validateQuery(eventSchemas.eventFilterSchema),
  
  // Game operations
  gameSearch: validateQuery(gameSchemas.steamGameSearchSchema),
  gameAddition: validateBody(gameSchemas.manualGameAdditionSchema),
  
  // Admin operations
  userApproval: validateBody(userSchemas.userApprovalSchema),
  systemOperation: validateBody(adminSchemas.systemOperationSchema)
};

/**
 * Validation schema collections organized by domain
 */
const schemas = {
  common: commonSchemas,
  user: userSchemas,
  event: eventSchemas,
  game: gameSchemas,
  admin: adminSchemas
};

/**
 * Express-validator collections (for backward compatibility)
 */
const expressValidators = {
  auth: authValidators,
  event: eventValidators,
  admin: adminValidators,
  search: searchValidators
};

/**
 * Validation middleware functions
 */
const middleware = {
  // Joi middleware
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  validateMultiple,
  validateConditional,
  validateFiles,
  createJoiValidator,
  
  // Express-validator middleware
  handleValidationErrors
};

/**
 * Pre-configured validation middleware for common endpoints
 */
const endpoints = {
  // User endpoints
  'POST /auth/register': validateBody(userSchemas.userRegistrationSchema),
  'POST /auth/login': validateBody(userSchemas.userLoginSchema),
  'POST /auth/forgot-password': validateBody(userSchemas.passwordResetRequestSchema),
  'POST /auth/reset-password': validateBody(userSchemas.passwordResetSchema),
  'PUT /auth/profile': validateBody(userSchemas.profileUpdateSchema),
  'POST /auth/change-password': validateBody(userSchemas.changePasswordSchema),
  
  // Event endpoints
  'POST /events': validateBody(eventSchemas.eventCreationSchema),
  'PUT /events/:id': validateMultiple({
    params: { id: commonSchemas.mongoId },
    body: eventSchemas.eventEditSchema
  }),
  'POST /events/:id/duplicate': validateMultiple({
    params: { id: commonSchemas.mongoId },
    body: eventSchemas.eventDuplicationSchema
  }),
  'GET /events': validateQuery(eventSchemas.eventFilterSchema),
  'POST /events/:id/join': validateParams({ id: commonSchemas.mongoId }),
  'POST /events/:id/leave': validateParams({ id: commonSchemas.mongoId }),
  
  // Game endpoints
  'GET /games/search/steam': validateQuery(gameSchemas.steamGameSearchSchema),
  'GET /games/search/rawg': validateQuery(gameSchemas.rawgGameSearchSchema),
  'POST /games/add': validateBody(gameSchemas.manualGameAdditionSchema),
  'POST /games/check-duplicate': validateBody(gameSchemas.duplicateGameCheckSchema),
  'POST /games/steam-equivalent': validateBody(gameSchemas.steamEquivalentCheckSchema),
  
  // Admin user management
  'POST /admin/users/:id/approve': validateMultiple({
    params: { id: commonSchemas.mongoId },
    body: userSchemas.userApprovalSchema
  }),
  'POST /admin/users/:id/reject': validateMultiple({
    params: { id: commonSchemas.mongoId },
    body: userSchemas.userRejectionSchema
  }),
  'POST /admin/users/bulk': validateBody(userSchemas.bulkUserOperationSchema),
  'GET /admin/users': validateQuery(userSchemas.userFilterSchema),
  
  // Admin game management
  'POST /admin/games/:id/approve': validateMultiple({
    params: { id: commonSchemas.mongoId },
    body: gameSchemas.gameApprovalSchema
  }),
  'POST /admin/games/:id/reject': validateMultiple({
    params: { id: commonSchemas.mongoId },
    body: gameSchemas.gameRejectionSchema
  }),
  'POST /admin/games/add': validateBody(gameSchemas.adminGameAdditionSchema),
  'POST /admin/games/bulk': validateBody(gameSchemas.bulkGameOperationSchema),
  'GET /admin/games': validateQuery(gameSchemas.adminGameFilterSchema),
  
  // Admin event management
  'GET /admin/events': validateQuery(eventSchemas.adminEventFilterSchema),
  'POST /admin/events/bulk': validateBody(eventSchemas.bulkEventOperationSchema),
  'PUT /admin/events/:id/status': validateMultiple({
    params: { id: commonSchemas.mongoId },
    body: eventSchemas.eventStatusUpdateSchema
  }),
  
  // Admin system operations
  'POST /admin/system': validateBody(adminSchemas.systemOperationSchema),
  'GET /admin/audit-logs': validateQuery(adminSchemas.auditLogFilterSchema),
  'POST /admin/ip-operations': validateBody(adminSchemas.ipOperationSchema),
  'POST /admin/cache': validateBody(adminSchemas.cacheManagementSchema),
  'GET /admin/error-logs': validateQuery(adminSchemas.errorLogFilterSchema),
  'POST /admin/database': validateBody(adminSchemas.databaseMaintenanceSchema),
  'POST /admin/security-scan': validateBody(adminSchemas.securityScanSchema),
  'POST /admin/notifications': validateBody(adminSchemas.notificationManagementSchema),
  'GET /admin/health': validateQuery(adminSchemas.systemHealthCheckSchema),
  'PUT /admin/config': validateBody(adminSchemas.configurationUpdateSchema)
};

/**
 * Helper function to get validator for a specific endpoint
 * @param {string} method - HTTP method (GET, POST, PUT, DELETE)
 * @param {string} path - Route path
 * @returns {Function|null} Validation middleware or null if not found
 */
const getValidatorForEndpoint = (method, path) => {
  const key = `${method.toUpperCase()} ${path}`;
  return endpoints[key] || null;
};

/**
 * Helper function to create route-specific validation
 * @param {Object} config - Configuration object
 * @param {Object} config.body - Body schema
 * @param {Object} config.query - Query schema  
 * @param {Object} config.params - Params schema
 * @param {Object} config.headers - Headers schema
 * @returns {Function} Validation middleware
 */
const createRouteValidator = (config) => {
  const schemas = {};
  
  if (config.body) schemas.body = config.body;
  if (config.query) schemas.query = config.query;
  if (config.params) schemas.params = config.params;
  if (config.headers) schemas.headers = config.headers;
  
  if (Object.keys(schemas).length === 1) {
    const [source, schema] = Object.entries(schemas)[0];
    return createJoiValidator(schema, source);
  }
  
  return validateMultiple(schemas);
};

module.exports = {
  // Joi validation system
  schemas,
  middleware,
  quickValidators,
  endpoints,
  
  // Express-validator system (backward compatibility)
  expressValidators,
  
  // Direct exports for convenience
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  validateMultiple,
  validateConditional,
  validateFiles,
  createJoiValidator,
  handleValidationErrors,
  
  // Schema exports
  commonSchemas,
  userSchemas,
  eventSchemas,
  gameSchemas,
  adminSchemas,
  
  // Express-validator exports
  authValidators,
  eventValidators,
  adminValidators,
  searchValidators,
  
  // Utility functions
  getValidatorForEndpoint,
  createRouteValidator
};
