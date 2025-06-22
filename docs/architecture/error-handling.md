# GamePlan Error Handling System

## Overview

The GamePlan application implements a comprehensive centralized error handling system that provides consistent error responses, proper HTTP status codes, structured logging, and improved user experience across both API endpoints and web pages.

## Architecture

### Core Components

1. **Custom Error Classes** (`utils/errors.js`)
   - Base error class with consistent structure
   - Specific error types for different scenarios
   - Proper HTTP status code mapping

2. **Error Utilities** (`utils/errorUtils.js`)
   - Request ID generation and tracking
   - Error context creation and logging
   - Response format standardization

3. **Error Middleware** (`middleware/errorHandler.js`)
   - Centralized error processing
   - Request tracking and correlation
   - Database error handling

4. **Error Logging Model** (`models/ErrorLog.js`)
   - Persistent error storage
   - Analytics and resolution tracking
   - Admin management capabilities

5. **Admin Interface** (`views/adminErrorLogs.ejs`)
   - Error management dashboard
   - Filtering, search, and export
   - Resolution tracking

## Custom Error Classes

### Base Error Class
- `AppError` - Base class for all application errors with consistent structure

### Specific Error Types
- `ValidationError` (400) - Input validation failures
- `AuthenticationError` (401) - Authentication required
- `AuthorizationError` (403) - Access denied/insufficient permissions
- `NotFoundError` (404) - Resource not found
- `ConflictError` (409) - Business logic conflicts
- `RateLimitError` (429) - Rate limiting violations
- `DatabaseError` (500) - Database operation failures
- `ExternalServiceError` (502) - External API failures (Steam, RAWG)
- `AccountStatusError` (403) - Account-specific issues
- `FileUploadError` (400) - File upload problems
- `SessionError` (401) - Session-related issues
- `ConfigurationError` (500) - Server configuration problems
- `BusinessLogicError` (422) - Business rule violations

## Error Response Format

### JSON Response (API Endpoints)
```json
{
  "error": {
    "type": "ValidationError",
    "message": "User-friendly error message",
    "code": "VALIDATION_FAILED",
    "timestamp": "2025-06-15T14:24:40.000Z",
    "requestId": "a1b2c3d4",
    "details": [...] // Only in development or for operational errors
  }
}
```

### HTML Response (Web Pages)
- Renders user-friendly error template with appropriate status code
- Shows helpful navigation options (Home, Back, Admin Dashboard)
- Displays technical details only in development mode
- Responsive design for mobile devices

## Error Logging and Tracking

### Error Log Model
The `ErrorLog` model stores comprehensive error information:

```javascript
{
  type: String,           // Error type (ValidationError, etc.)
  message: String,        // Error message
  stack: String,          // Stack trace (development only)
  statusCode: Number,     // HTTP status code
  requestId: String,      // Unique request identifier
  
  // Request Context
  url: String,            // Request URL
  method: String,         // HTTP method
  userAgent: String,      // Client user agent
  ipAddress: String,      // Client IP address
  
  // User Context
  userId: ObjectId,       // User ID (if authenticated)
  userEmail: String,      // User email
  isAuthenticated: Boolean,
  
  // Error Analytics
  severity: String,       // low, medium, high, critical
  category: String,       // validation, auth, database, etc.
  frequency: Number,      // How often this error occurs
  
  // Resolution Tracking
  status: String,         // new, investigating, resolved, ignored
  adminNotes: String,     // Admin investigation notes
  resolvedAt: Date,       // Resolution timestamp
  resolvedBy: ObjectId    // Admin who resolved
}
```

### Error Severity Levels
- **Low**: Minor issues, logging/validation errors
- **Medium**: Business logic errors, authentication failures
- **High**: Database errors, external service failures
- **Critical**: System failures, security issues

### Error Categories
- **Validation**: Input validation failures
- **Authentication**: Login/session issues
- **Authorization**: Permission denied
- **Database**: Database operation failures
- **External**: Third-party service issues
- **System**: Application/server errors
- **Security**: Security-related errors

## Usage Examples

### 1. Throwing Custom Errors in Route Handlers

```javascript
// Using specific error types
app.get('/api/users/:id', asyncErrorHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    throw new NotFoundError('User', req.params.id);
  }
  
  if (!req.user.isAdmin && user._id !== req.user._id) {
    throw new AuthorizationError('You can only view your own profile');
  }
  
  res.json(user);
}));
```

### 2. Validation Error Handling

```javascript
// The validation middleware automatically converts express-validator errors
app.post('/api/users', validateUserCreation, handleValidationErrors, asyncErrorHandler(async (req, res) => {
  // If validation fails, handleValidationErrors will throw a ValidationError
  const user = await User.create(req.body);
  res.status(201).json(user);
}));
```

### 3. Database Error Handling

```javascript
// Database errors are automatically converted to appropriate error types
app.post('/api/users', asyncErrorHandler(async (req, res) => {
  try {
    const user = await User.create(req.body);
    res.status(201).json(user);
  } catch (error) {
    // Mongoose duplicate key error will be converted to ConflictError
    // Validation errors will be converted to ValidationError
    throw error; // Let the error handler process it
  }
}));
```

### 4. External Service Error Handling

```javascript
// External API errors are automatically handled
app.get('/api/steam/search', asyncErrorHandler(async (req, res) => {
  try {
    const results = await steamService.searchGames(req.query.q);
    res.json(results);
  } catch (error) {
    // Axios errors will be converted to ExternalServiceError
    throw error;
  }
}));
```

## Admin Error Management

### Error Dashboard Features

1. **Error Overview**
   - Total error counts by severity
   - Recent error trends
   - Quick filters (Unresolved, Critical, Today, Last Hour)

2. **Error Listing**
   - Paginated error list with filtering
   - Search across messages, URLs, and user emails
   - Sort by date, severity, or frequency

3. **Error Details**
   - Complete error information including stack traces
   - Request and user context
   - Resolution status and admin notes

4. **Management Actions**
   - Update error status (new → investigating → resolved)
   - Add investigation notes
   - Bulk operations (mark resolved, delete)
   - Export filtered errors to CSV

5. **Cleanup Tools**
   - Automated cleanup of old error logs
   - Configurable retention policies
   - Manual cleanup options

### Access
Navigate to `/admin/error-logs` (requires admin authentication)

## Middleware Setup

### Required Middleware Order

```javascript
// 1. Add request ID tracking (early)
app.use(requestIdMiddleware);

// 2. Other middleware (body parser, sessions, etc.)
app.use(bodyParser.json());
app.use(session(...));

// 3. Routes with async error handling
app.get('/api/route', asyncErrorHandler(async (req, res) => {
  // Route logic that may throw errors
}));

// 4. Database error handling
app.use(handleDatabaseErrors);

// 5. 404 handler (before main error handler)
app.use(notFoundHandler);

// 6. Main error handler (must be last)
app.use(errorHandler);
```

### Key Middleware Functions

- `requestIdMiddleware` - Adds unique request IDs for tracking
- `asyncErrorHandler` - Wraps async route handlers to catch errors
- `handleValidationErrors` - Processes express-validator errors
- `notFoundHandler` - Handles 404 errors for unmatched routes
- `errorHandler` - Main error processing middleware
- `handleDatabaseErrors` - Sets up database error handling

## Security Features

### Production Safety
- Sanitizes error messages in production
- Hides stack traces from end users
- Removes sensitive information from logs
- Prevents information disclosure

### Request Tracking
- Unique request IDs for error correlation
- IP address logging for security monitoring
- User context for audit trails
- Session tracking for debugging

## Configuration

### Environment Variables
```bash
# Error logging retention (days)
ERROR_LOG_RETENTION_DAYS=90

# Error detail visibility
NODE_ENV=production  # Controls error detail visibility

# Error notification settings (optional)
ERROR_NOTIFICATION_WEBHOOK=https://hooks.slack.com/...
CRITICAL_ERROR_EMAIL=admin@gameplan.com
```

### Error Handling Configuration
- Development: Shows full error details and stack traces
- Production: Shows sanitized, user-friendly messages only

## Monitoring and Analytics

### Error Metrics
- Error frequency and trends
- Error severity distribution
- Resolution time tracking
- User impact analysis

### Health Integration
Error handling integrates with the health monitoring system:
- Error rate thresholds
- Critical error alerts
- System health indicators

### Logging Integration
Structured error logging with:
- Request context (method, URL, IP, user agent)
- User context (ID, email, admin status)
- Session context (session ID, authentication status)
- Error details (stack trace, error code, status code)
- Request tracking (unique request ID for correlation)

## Best Practices

### 1. Use Specific Error Types
Choose the most appropriate error class for each scenario:
```javascript
// Good
throw new NotFoundError('User', userId);
throw new ValidationError('Email is required');

// Avoid generic errors
throw new Error('Something went wrong');
```

### 2. Provide Context
Include relevant details in error messages:
```javascript
throw new DatabaseError('Failed to save user', { 
  userId: user.id, 
  operation: 'create' 
});
```

### 3. Wrap Async Handlers
Always use `asyncErrorHandler` for async routes:
```javascript
app.get('/route', asyncErrorHandler(async (req, res) => {
  // Async operations
}));
```

### 4. Let the System Handle Logging
Don't manually log errors - let the centralized system handle it:
```javascript
// Good
throw new ValidationError('Invalid input');

// Avoid manual logging
console.error('Error occurred:', error);
```

### 5. Test Error Scenarios
Verify error handling in different conditions:
```javascript
describe('Error Handling', () => {
  it('should return 404 for non-existent user', async () => {
    const response = await request(app)
      .get('/api/users/nonexistent')
      .expect(404);
    
    expect(response.body.error.type).toBe('NotFoundError');
    expect(response.body.error.code).toBe('RESOURCE_NOT_FOUND');
    expect(response.headers['x-request-id']).toBeDefined();
  });
});
```

## Migration from Old System

### Before (Inconsistent)
```javascript
// Old inconsistent error handling
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('User not found'); // Plain text
    }
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' }); // Generic message
  }
});
```

### After (Centralized)
```javascript
// New centralized error handling
app.get('/api/users/:id', asyncErrorHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    throw new NotFoundError('User', req.params.id); // Consistent format
  }
  res.json(user);
  // Errors automatically handled by centralized middleware
}));
```

## Troubleshooting

### Common Issues

1. **Missing Request IDs**
   - Ensure `requestIdMiddleware` is applied early in middleware chain
   - Check that middleware order is correct

2. **Inconsistent Error Responses**
   - Verify all routes use `asyncErrorHandler`
   - Check that custom errors extend proper base classes

3. **Database Connection Errors**
   - Ensure `handleDatabaseErrors` is called
   - Verify database middleware is properly configured

4. **Missing Error Context**
   - Ensure error handler is the last middleware
   - Check that request ID middleware is first

### Debug Mode
Enable detailed error logging in development:
```bash
NODE_ENV=development
DEBUG_ERRORS=true
```

## Benefits

### For Developers
- **Consistency**: All errors follow the same format
- **Maintainability**: Single place to modify error handling logic
- **Debugging**: Enhanced logging with request correlation
- **Type Safety**: Specific error classes for different scenarios

### For Users
- **Better UX**: User-friendly error messages and pages
- **Consistency**: Same error format across all endpoints
- **Navigation**: Helpful error pages with navigation options
- **Responsiveness**: Mobile-friendly error pages

### For Operations
- **Monitoring**: Structured logs for better observability
- **Debugging**: Request IDs for error correlation
- **Security**: Sanitized error messages in production
- **Audit Trail**: Comprehensive error context logging
- **Analytics**: Error patterns and frequency analysis

## Future Enhancements

- Real-time error dashboard with live updates
- Error trend analysis and pattern detection
- Automated error categorization using ML
- Integration with external monitoring tools (Sentry, DataDog)
- Performance metrics correlation
- User impact analysis and reporting
- Automated alert thresholds and notifications
- Error resolution workflow automation

This centralized error handling system provides a robust foundation for consistent error management, monitoring, and resolution across the entire GamePlan application.
