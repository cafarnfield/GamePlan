# GamePlan Validation System Documentation

This document provides comprehensive documentation for the GamePlan validation system, which uses Joi for robust input validation and sanitization across all API endpoints.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Installation & Setup](#installation--setup)
4. [Usage Examples](#usage-examples)
5. [Schema Reference](#schema-reference)
6. [Middleware Reference](#middleware-reference)
7. [Migration Guide](#migration-guide)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

## Overview

The validation system provides:

- **Comprehensive Input Validation**: All user inputs are validated against strict schemas
- **Data Sanitization**: Automatic cleaning and normalization of input data
- **Security**: Protection against injection attacks and malformed data
- **Type Safety**: Automatic type conversion and validation
- **Error Handling**: Standardized error responses with detailed validation messages
- **Backward Compatibility**: Works alongside existing express-validator system

## Architecture

```
validators/
├── schemas/                    # Joi validation schemas
│   ├── commonSchemas.js       # Reusable validation patterns
│   ├── userSchemas.js         # User-related validations
│   ├── eventSchemas.js        # Event-related validations
│   ├── gameSchemas.js         # Game-related validations
│   └── adminSchemas.js        # Admin operation validations
├── middleware/                 # Validation middleware
│   └── joiValidator.js        # Core Joi validation middleware
├── index.js                   # Main export file
└── VALIDATION_SYSTEM.md       # This documentation
```

## Installation & Setup

### Prerequisites

The validation system requires the following dependencies:

```bash
npm install joi
```

### Basic Setup

Import the validation system in your routes:

```javascript
const {
  validateBody,
  validateQuery,
  validateParams,
  userSchemas,
  eventSchemas,
  gameSchemas,
  adminSchemas
} = require('../validators');
```

## Usage Examples

### Basic Route Validation

```javascript
// User registration with body validation
router.post('/register', 
  validateBody(userSchemas.userRegistrationSchema), 
  async (req, res) => {
    // req.body is now validated and sanitized
    const { name, email, password } = req.body;
    // ... handle registration
  }
);

// Event filtering with query validation
router.get('/events', 
  validateQuery(eventSchemas.eventFilterSchema), 
  async (req, res) => {
    // req.query is now validated with defaults applied
    const { page, limit, search, status } = req.query;
    // ... handle event listing
  }
);
```

### Multi-Source Validation

```javascript
// Validate both params and body
router.put('/events/:id', 
  validateMultiple({
    params: { id: commonSchemas.mongoId },
    body: eventSchemas.eventEditSchema
  }), 
  async (req, res) => {
    // Both req.params.id and req.body are validated
    // ... handle event update
  }
);
```

### Conditional Validation

```javascript
// Apply validation only for certain conditions
router.post('/admin/operation', 
  validateConditional(
    (req) => req.user.role === 'superadmin',
    adminSchemas.systemOperationSchema
  ), 
  async (req, res) => {
    // Validation only applied for superadmin users
    // ... handle admin operation
  }
);
```

### Quick Validators

```javascript
// Use pre-configured validators for common patterns
router.get('/users/:id', 
  quickValidators.mongoId,  // Validates req.params.id as MongoDB ObjectId
  async (req, res) => {
    // ... handle user retrieval
  }
);

router.get('/search', 
  quickValidators.searchQuery,  // Validates req.query.search
  async (req, res) => {
    // ... handle search
  }
);
```

## Schema Reference

### Common Schemas (`commonSchemas.js`)

#### Basic Types
- `mongoId`: MongoDB ObjectId validation
- `email`: Email address with comprehensive validation
- `password`: Strong password requirements
- `name`: Person/entity name validation
- `url`: URL validation with protocol requirements

#### Game-Specific
- `gameName`: Game name with special characters allowed
- `gameNickname`: User's game nickname
- `steamAppId`: Steam application ID
- `rawgId`: RAWG database ID

#### Event-Specific
- `eventName`: Event name validation
- `description`: Event/game description
- `playerLimit`: Number of players (1-100)
- `futureDate`: Date validation (must be in future)
- `platforms`: Gaming platform selection

#### Utility
- `searchQuery`: Search term validation
- `pagination`: Page and limit parameters
- `notes`: Admin notes and comments
- `ipAddress`: IP address validation (IPv4/IPv6)

### User Schemas (`userSchemas.js`)

#### Registration & Authentication
```javascript
userRegistrationSchema: {
  name: required,
  email: required,
  password: required,
  confirmPassword: required (must match password),
  gameNickname: optional,
  'g-recaptcha-response': conditional (if CAPTCHA enabled)
}

userLoginSchema: {
  email: required,
  password: required,
  remember: optional boolean
}
```

#### Profile Management
```javascript
profileUpdateSchema: {
  gameNickname: optional
}

changePasswordSchema: {
  currentPassword: required,
  newPassword: required (strong password rules),
  confirmPassword: required (must match newPassword)
}
```

#### Admin Operations
```javascript
userApprovalSchema: {
  userId: required mongoId,
  notes: optional
}

userRejectionSchema: {
  userId: required mongoId,
  notes: required (rejection reason)
}

bulkUserOperationSchema: {
  userIds: required array (1-50 users),
  operation: required ('approve', 'reject', 'block', etc.),
  notes: conditional (required for reject/delete)
}
```

### Event Schemas (`eventSchemas.js`)

#### Event Creation
```javascript
eventCreationSchema: {
  name: required,
  description: required,
  playerLimit: required (1-100),
  date: required (future date),
  platforms: required array,
  gameSelection: required (complex object),
  extensions: optional array
}

gameSelectionSchema: {
  type: required ('existing', 'steam', 'rawg', 'manual'),
  gameId: conditional (required if type='existing'),
  data: conditional (required for steam/rawg/manual)
}
```

#### Event Management
```javascript
eventEditSchema: {
  name: required,
  gameId: required mongoId,
  description: required,
  playerLimit: required,
  date: required (future date),
  platforms: required array,
  extensions: optional array
}

eventFilterSchema: {
  search: optional,
  gameSearch: optional,
  dateFrom: optional,
  dateTo: optional (must be after dateFrom),
  status: optional ('live', 'upcoming', 'past'),
  platforms: optional,
  playerAvailability: optional ('available', 'full'),
  host: optional,
  sortBy: optional ('recent', 'players', 'alphabetical', 'date'),
  page: optional (default: 1),
  limit: optional (default: 20)
}
```

### Game Schemas (`gameSchemas.js`)

#### Game Addition
```javascript
manualGameAdditionSchema: {
  name: required,
  description: optional,
  imageUrl: optional,
  steamAppId: optional,
  source: 'manual' (default)
}

adminGameAdditionSchema: {
  name: required,
  description: optional,
  imageUrl: optional,
  steamAppId: optional,
  rawgId: optional,
  source: required,
  steamData: conditional (required if source='steam'),
  rawgData: conditional (required if source='rawg')
}
```

#### Game Management
```javascript
gameApprovalSchema: {
  gameId: required mongoId,
  notes: optional
}

gameRejectionSchema: {
  gameId: required mongoId,
  notes: required (rejection reason)
}

gameUpdateSchema: {
  gameId: required mongoId,
  name: optional,
  description: optional,
  imageUrl: optional,
  status: optional,
  tags: optional array (max 10),
  featured: optional boolean,
  notes: optional
}
```

### Admin Schemas (`adminSchemas.js`)

#### System Operations
```javascript
systemOperationSchema: {
  operation: required ('backup', 'cleanup', 'maintenance', etc.),
  confirm: required (must be true),
  notes: optional,
  parameters: optional object with operation-specific settings
}

cacheManagementSchema: {
  operation: required ('clear', 'refresh', 'stats', 'configure'),
  cacheType: conditional (required for clear/refresh),
  keys: optional array (for specific cache keys),
  configuration: conditional (required for configure)
}
```

#### Security & Monitoring
```javascript
ipOperationSchema: {
  ipAddress: required,
  action: required ('block', 'unblock', 'investigate', etc.),
  reason: conditional (required for block/blacklist),
  duration: optional (days)
}

securityScanSchema: {
  scanType: required ('vulnerability', 'permissions', etc.),
  scope: optional object (what to scan),
  parameters: optional object (scan settings)
}
```

## Middleware Reference

### Core Middleware Functions

#### `validateBody(schema, options)`
Validates request body against Joi schema.

```javascript
router.post('/endpoint', validateBody(schema), handler);
```

#### `validateQuery(schema, options)`
Validates query parameters against Joi schema.

```javascript
router.get('/endpoint', validateQuery(schema), handler);
```

#### `validateParams(schema, options)`
Validates route parameters against Joi schema.

```javascript
router.get('/endpoint/:id', validateParams(schema), handler);
```

#### `validateMultiple(schemas, options)`
Validates multiple request sources with different schemas.

```javascript
router.put('/endpoint/:id', validateMultiple({
  params: { id: commonSchemas.mongoId },
  body: updateSchema,
  query: filterSchema
}), handler);
```

#### `validateConditional(condition, schema, source, options)`
Applies validation only when condition is met.

```javascript
router.post('/endpoint', validateConditional(
  (req) => req.user.role === 'admin',
  adminSchema
), handler);
```

### Validation Options

```javascript
const options = {
  abortEarly: false,      // Return all errors (default: false)
  allowUnknown: false,    // Allow unknown fields (default: false)
  stripUnknown: true,     // Remove unknown fields (default: true)
  convert: true,          // Convert types when possible (default: true)
  context: {}             // Additional context for validation
};
```

### Error Handling

Validation errors are automatically handled and return standardized responses:

```javascript
{
  "error": "Validation failed",
  "details": [
    {
      "field": "email",
      "message": "Please provide a valid email address",
      "value": "invalid-email"
    },
    {
      "field": "password",
      "message": "Password must be at least 8 characters long",
      "value": "123"
    }
  ]
}
```

## Migration Guide

### From Express-Validator to Joi

#### Before (Express-Validator)
```javascript
const { body, validationResult } = require('express-validator');

router.post('/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('name').trim().isLength({ min: 2 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  // ... handle request
});
```

#### After (Joi)
```javascript
const { validateBody, userSchemas } = require('../validators');

router.post('/register', 
  validateBody(userSchemas.userRegistrationSchema), 
  (req, res) => {
    // Validation is automatic, req.body is sanitized
    // ... handle request
  }
);
```

### Gradual Migration Strategy

1. **Keep existing validators**: The system supports both validation approaches
2. **Migrate route by route**: Replace express-validator with Joi validators gradually
3. **Test thoroughly**: Ensure validation behavior remains consistent
4. **Update error handling**: Adapt frontend to new error response format

## Best Practices

### Schema Design

1. **Use common schemas**: Reuse validation patterns from `commonSchemas.js`
2. **Be specific**: Define precise validation rules for each field
3. **Provide clear messages**: Use custom error messages for better UX
4. **Consider context**: Use conditional validation when appropriate

```javascript
// Good: Specific validation with clear messages
const userSchema = Joi.object({
  email: commonSchemas.email.required(),
  age: Joi.number().integer().min(13).max(120).required().messages({
    'number.min': 'You must be at least 13 years old to register',
    'number.max': 'Please enter a valid age'
  })
});

// Avoid: Generic validation without context
const userSchema = Joi.object({
  email: Joi.string(),
  age: Joi.number()
});
```

### Security Considerations

1. **Validate all inputs**: Never trust client data
2. **Sanitize data**: Use `stripUnknown: true` to remove unexpected fields
3. **Limit input size**: Set reasonable limits on string lengths and array sizes
4. **Use allowlists**: Prefer specific allowed values over denylists

```javascript
// Good: Specific allowed values
status: Joi.string().valid('pending', 'approved', 'rejected')

// Avoid: Open-ended validation
status: Joi.string().pattern(/^[a-z]+$/)
```

### Performance Optimization

1. **Cache compiled schemas**: Joi schemas are compiled once and reused
2. **Use early termination**: Set `abortEarly: true` for simple validations
3. **Minimize schema complexity**: Keep validation logic simple and fast
4. **Profile validation performance**: Monitor validation overhead in production

### Error Handling

1. **Provide helpful messages**: Guide users to fix validation errors
2. **Log validation failures**: Monitor for potential security issues
3. **Handle edge cases**: Consider malformed or malicious inputs
4. **Maintain consistency**: Use standardized error response format

## Troubleshooting

### Common Issues

#### 1. Schema Compilation Errors
```
Error: Schema compilation failed
```

**Solution**: Check schema syntax and ensure all referenced schemas are imported.

```javascript
// Ensure proper imports
const { commonSchemas } = require('./commonSchemas');

// Check schema structure
const schema = Joi.object({
  id: commonSchemas.mongoId.required() // Ensure .required() is called correctly
});
```

#### 2. Validation Context Issues
```
Error: Context variable not found
```

**Solution**: Ensure context variables are properly defined in middleware.

```javascript
// Check context setup in joiValidator.js
const context = {
  user: req.user,
  isAdmin: req.user && req.user.role === 'admin'
};
```

#### 3. Circular Dependency Errors
```
Error: Cannot access before initialization
```

**Solution**: Avoid circular imports between schema files.

```javascript
// Instead of importing between schema files, use commonSchemas
const { mongoId } = require('./commonSchemas');
```

#### 4. Type Conversion Issues
```
Error: Value cannot be converted to required type
```

**Solution**: Check input data types and conversion settings.

```javascript
// Enable type conversion
const options = {
  convert: true,  // Allow "123" -> 123 conversion
  stripUnknown: true
};
```

### Debugging Tips

1. **Enable detailed logging**: Set validation logging to debug level
2. **Test schemas in isolation**: Validate schemas with sample data
3. **Check middleware order**: Ensure validation runs before business logic
4. **Verify error handling**: Test error response format and content

### Performance Monitoring

Monitor validation performance with these metrics:

- Validation execution time
- Memory usage during validation
- Error rates and types
- Schema compilation time

```javascript
// Example performance monitoring
const startTime = Date.now();
const { error, value } = schema.validate(data);
const validationTime = Date.now() - startTime;

if (validationTime > 100) {
  console.warn(`Slow validation detected: ${validationTime}ms`);
}
```

## Conclusion

The GamePlan validation system provides robust, secure, and maintainable input validation for all API endpoints. By following this documentation and best practices, you can ensure data integrity and security throughout the application.

For additional support or questions, refer to the Joi documentation at https://joi.dev/ or consult the GamePlan development team.
