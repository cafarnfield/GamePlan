# Centralized Error Handling System - GamePlan Application

## Overview

This document describes the centralized error handling system implemented for the GamePlan Express application. The system provides consistent error responses, proper HTTP status codes, structured logging, and improved user experience across both API endpoints and web pages.

## Components

### 1. Custom Error Classes (`utils/errors.js`)

**Base Error Class:**
- `AppError` - Base class for all application errors with consistent structure

**Specific Error Types:**
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

### 2. Error Utilities (`utils/errorUtils.js`)

**Key Functions:**
- `generateRequestId()` - Creates unique request IDs for tracking
- `expectsJson()` - Determines if client expects JSON response
- `createErrorContext()` - Builds comprehensive error context for logging
- `createErrorResponse()` - Creates standardized error response format
- `asyncHandler()` - Wraps async route handlers to catch errors
- `ErrorFactory` - Converts various error types to custom errors

### 3. Centralized Error Middleware (`middleware/errorHandler.js`)

**Middleware Components:**
- `requestIdMiddleware` - Adds unique request IDs
- `notFoundHandler` - Handles 404 errors for unmatched routes
- `errorHandler` - Main error processing middleware
- `asyncErrorHandler` - Wrapper for async route handlers
- `handleValidationErrors` - Processes express-validator errors
- `handleDatabaseErrors` - Sets up database error handling

### 4. Error Template (`views/error.ejs`)

A user-friendly error page that:
- Shows appropriate error icons and messages
- Provides helpful navigation options
- Displays technical details in development mode
- Includes responsive design for mobile devices

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
- Renders the error template with appropriate status code
- Shows user-friendly error messages
- Provides navigation options (Home, Back, Admin Dashboard)
- Displays technical details only in development mode

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

## Error Logging

The system provides structured error logging with:

- **Request Context**: Method, URL, IP address, user agent
- **User Context**: User ID, email, admin status (when available)
- **Session Context**: Session ID, authentication status
- **Error Details**: Stack trace, error code, status code
- **Request Tracking**: Unique request ID for correlation

### Log Levels
- **ERROR** (500+): Server errors, database failures
- **WARN** (400-499): Client errors, validation failures
- **INFO** (<400): Informational messages

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

## Configuration

### Environment Variables
- `NODE_ENV` - Controls error detail visibility
- Development: Shows full error details and stack traces
- Production: Shows sanitized, user-friendly messages only

### Rate Limiting Integration
- Custom rate limit errors with retry-after headers
- Consistent error format for rate limit violations

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

## Best Practices

1. **Use Specific Error Types**: Choose the most appropriate error class
2. **Provide Context**: Include relevant details in error messages
3. **Wrap Async Handlers**: Always use `asyncErrorHandler` for async routes
4. **Log Appropriately**: Let the system handle logging automatically
5. **Test Error Scenarios**: Verify error handling in different conditions

## Testing Error Handling

```javascript
// Example test for error handling
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

This centralized error handling system provides a robust foundation for consistent error management across your entire application.
