# Centralized Error Handling Implementation

This document describes the comprehensive centralized error handling system implemented for the GamePlan Express application.

## Overview

The centralized error handling system replaces inconsistent error responses throughout the application with standardized error handling, proper HTTP status codes, and consistent JSON error formats. It includes error logging, monitoring, and admin management capabilities.

## Components

### 1. Custom Error Classes (`utils/errors.js`)

Custom error classes that extend the base Error class with additional properties:

- **BaseError**: Base class with statusCode, isOperational, and context properties
- **ValidationError**: For input validation failures (400)
- **AuthenticationError**: For authentication failures (401)
- **AuthorizationError**: For authorization failures (403)
- **NotFoundError**: For resource not found errors (404)
- **ConflictError**: For resource conflicts (409)
- **DatabaseError**: For database operation failures (500)
- **ExternalServiceError**: For third-party service failures (502)

### 2. Error Handling Middleware (`middleware/errorHandler.js`)

Comprehensive middleware system including:

- **requestIdMiddleware**: Adds unique request IDs for tracking
- **asyncErrorHandler**: Wrapper for async route handlers
- **notFoundHandler**: Handles 404 errors for unmatched routes
- **errorHandler**: Main error processing middleware
- **handleDatabaseErrors**: Database connection error handling

### 3. Error Logging Model (`models/ErrorLog.js`)

MongoDB model for storing detailed error information:

- Error details (type, message, stack trace)
- Request context (URL, method, IP, user agent)
- User context (authentication status, user info)
- Environment information
- Analytics (severity, frequency, impact)
- Resolution tracking (status, admin notes)

### 4. Admin Error Management (`views/adminErrorLogs.ejs`)

Comprehensive admin interface for error management:

- **Dashboard**: Error statistics and quick filters
- **Filtering**: By type, severity, status, date range
- **Search**: Across error messages and context
- **Details**: Full error information with context
- **Resolution**: Status tracking and admin notes
- **Export**: CSV export functionality
- **Cleanup**: Automated old log cleanup

## Implementation Details

### Error Response Format

All errors return a consistent JSON format:

```json
{
  "error": "Human-readable error message",
  "code": "ERROR_CODE",
  "requestId": "unique-request-id",
  "timestamp": "2025-06-15T14:42:00.000Z",
  "details": {
    "field": "Additional context"
  }
}
```

### Error Severity Levels

- **low**: Minor issues, logging/validation errors
- **medium**: Business logic errors, authentication failures
- **high**: Database errors, external service failures
- **critical**: System failures, security issues

### Error Categories

- **validation**: Input validation failures
- **authentication**: Login/session issues
- **authorization**: Permission denied
- **database**: Database operation failures
- **external**: Third-party service issues
- **system**: Application/server errors
- **security**: Security-related errors

### Resolution Status

- **new**: Newly logged error
- **investigating**: Under investigation
- **resolved**: Issue resolved
- **ignored**: Intentionally ignored

## Usage Examples

### Using Custom Errors in Routes

```javascript
// Validation error
if (!email) {
  throw new ValidationError('Email is required');
}

// Not found error
const user = await User.findById(id);
if (!user) {
  throw new NotFoundError('User', id);
}

// Authorization error
if (!user.isAdmin) {
  throw new AuthorizationError('Admin privileges required');
}
```

### Wrapping Async Routes

```javascript
app.get('/api/users', asyncErrorHandler(async (req, res) => {
  const users = await User.find();
  res.json(users);
}));
```

### Database Error Handling

```javascript
// Automatic handling of database connection errors
handleDatabaseErrors();

// Manual database error handling
try {
  await user.save();
} catch (error) {
  throw new DatabaseError('Failed to save user', { userId: user.id });
}
```

## Admin Interface Features

### Error Log Management

1. **View Errors**: Browse all errors with filtering and pagination
2. **Error Details**: View complete error information including:
   - Stack traces
   - Request context
   - User context
   - Environment details
3. **Status Management**: Update error resolution status
4. **Admin Notes**: Add investigation notes
5. **Export**: Export filtered errors to CSV
6. **Cleanup**: Remove old error logs

### Quick Filters

- **Unresolved**: New and investigating errors
- **Critical**: High-priority errors
- **Today**: Errors from today
- **Last Hour**: Recent errors

### Search Capabilities

- Error messages
- User emails
- Request URLs
- Request IDs

## Configuration

### Environment Variables

```env
# Error logging retention (days)
ERROR_LOG_RETENTION_DAYS=90

# Error notification settings
ERROR_NOTIFICATION_WEBHOOK=https://hooks.slack.com/...
CRITICAL_ERROR_EMAIL=admin@gameplan.com
```

### Middleware Setup

```javascript
// Add request ID tracking
app.use(requestIdMiddleware);

// Handle database errors
handleDatabaseErrors();

// Wrap async routes
app.get('/route', asyncErrorHandler(async (req, res) => {
  // Route logic
}));

// 404 handler (before error handler)
app.use(notFoundHandler);

// Main error handler (must be last)
app.use(errorHandler);
```

## Benefits

1. **Consistency**: Standardized error responses across the application
2. **Monitoring**: Comprehensive error logging and tracking
3. **Debugging**: Detailed context for troubleshooting
4. **Management**: Admin interface for error resolution
5. **Analytics**: Error patterns and frequency analysis
6. **Security**: Proper error sanitization for production
7. **Maintenance**: Automated cleanup and retention policies

## Security Considerations

- Error details are sanitized in production
- Stack traces are not exposed to clients
- Sensitive information is filtered from logs
- Admin access is required for error management
- Request IDs enable secure error tracking

## Performance Impact

- Minimal overhead for error logging
- Async error processing where possible
- Efficient database indexing for error queries
- Configurable retention policies
- Batch operations for cleanup

## Monitoring and Alerts

The system supports integration with external monitoring services:

- Webhook notifications for critical errors
- Email alerts for system failures
- Slack integration for team notifications
- Custom alert thresholds and rules

## Future Enhancements

- Real-time error dashboard
- Error trend analysis
- Automated error categorization
- Integration with external monitoring tools
- Performance metrics correlation
- User impact analysis

## Troubleshooting

### Common Issues

1. **Missing Request IDs**: Ensure requestIdMiddleware is applied early
2. **Inconsistent Errors**: Check that all routes use asyncErrorHandler
3. **Database Errors**: Verify handleDatabaseErrors is called
4. **Missing Context**: Ensure error handler is last middleware

### Debug Mode

Enable detailed error logging in development:

```env
NODE_ENV=development
DEBUG_ERRORS=true
```

This comprehensive error handling system provides robust error management, monitoring, and resolution capabilities for the GamePlan application.
