# Development Mode

This document explains the development mode features in GamePlan, including auto-login functionality and development-specific configurations.

## Overview

Development mode provides convenient features for developers while maintaining security by only activating in development environments. The primary feature is auto-login, which bypasses authentication for faster development iteration.

## Current Status

The app can be configured for **DEVELOPMENT MODE** with auto-login enabled for streamlined development workflow.

## How Development Mode Works

When `AUTO_LOGIN_ADMIN=true` and `NODE_ENV=development` are set in the `.env` file:

- The app automatically logs you in as an admin user
- No login credentials are required
- Full admin access is granted immediately
- A development banner appears at the top of the page
- All protected routes work without authentication

### Mock Admin User Details
- **Name:** Development Admin
- **Email:** dev-admin@gameplan.local
- **Game Nickname:** DevAdmin
- **Admin Status:** Yes
- **Super Admin Status:** Yes (if applicable)
- **Blocked Status:** No

## Configuration

### Environment Variables

#### Enable Development Mode
```bash
# In .env file
NODE_ENV=development
AUTO_LOGIN_ADMIN=true
LOG_LEVEL=debug
LOG_CONSOLE=true
```

#### Disable Development Mode (Production)
```bash
# In .env file
NODE_ENV=production
AUTO_LOGIN_ADMIN=false
# Remove or comment out LOG_CONSOLE
```

### Switching Between Modes

#### To DISABLE Auto-Login (Production Mode)

Edit the `.env` file and change:
```bash
AUTO_LOGIN_ADMIN=false
```

Or remove the line entirely. Then restart the server.

#### To ENABLE Auto-Login (Development Mode)

Edit the `.env` file and set:
```bash
AUTO_LOGIN_ADMIN=true
NODE_ENV=development
```

Then restart the server.

## Visual Indicators

### Development Mode
- **Orange banner** at top: "🔧 DEVELOPMENT MODE - Auto-logged in as Admin"
- **Debug logging** enabled in console
- **Detailed error messages** displayed
- **Development-specific UI elements** may be visible

### Production Mode
- **No banner** displayed
- **Normal login** required
- **Production logging** levels
- **User-friendly error messages**

## Security Features

### Safety Mechanisms
⚠️ **IMPORTANT SECURITY NOTES:**
- Auto-login **only works** when `NODE_ENV=development`
- This **prevents accidental auto-login** in production environments
- Always **verify environment variables** before deploying
- Development mode **should never be used** in production

### Environment Validation
The system includes validation to ensure:
- Auto-login is disabled in production
- Proper environment variable configuration
- Security warnings for misconfigurations

## Development Features

### Enhanced Logging
Development mode enables:
- **Debug level logging** for detailed information
- **Console output** for real-time debugging
- **Request/response logging** for API debugging
- **Database query logging** for performance analysis

### Error Handling
- **Detailed error messages** with stack traces
- **Development-friendly error pages**
- **API error details** for debugging
- **Validation error details**

### Performance Monitoring
- **Response time logging**
- **Database query performance**
- **Cache hit/miss statistics**
- **Memory usage monitoring**

## Testing the Configuration

### Test Development Mode
1. Set `AUTO_LOGIN_ADMIN=true` and `NODE_ENV=development`
2. Restart server
3. Visit homepage - should see development banner
4. Should have immediate admin access
5. Check logs for debug information

### Test Production Mode
1. Set `AUTO_LOGIN_ADMIN=false` and `NODE_ENV=production`
2. Restart server
3. Visit homepage - should redirect to login
4. Normal authentication required
5. No development banner visible

## Implementation Details

### Files Modified for Development Mode
- **`.env`** - Added `AUTO_LOGIN_ADMIN` variable
- **`app.js`** - Added auto-login middleware and mock admin user
- **`views/index.ejs`** - Added development banner
- **`public/styles.css`** - Added banner styling
- **`middleware/auth.js`** - Development mode authentication bypass

### Auto-Login Middleware
```javascript
// Development auto-login middleware
if (process.env.NODE_ENV === 'development' && process.env.AUTO_LOGIN_ADMIN === 'true') {
  // Create mock admin user session
  req.session.user = {
    _id: 'dev-admin-id',
    name: 'Development Admin',
    email: 'dev-admin@gameplan.local',
    gameNickname: 'DevAdmin',
    isAdmin: true,
    isSuperAdmin: true,
    isBlocked: false,
    status: 'approved'
  };
}
```

## Best Practices

### Development Workflow
1. **Always use development mode** for local development
2. **Test production mode** before deploying
3. **Verify environment variables** in deployment
4. **Monitor logs** for security warnings

### Security Considerations
1. **Never deploy** with `AUTO_LOGIN_ADMIN=true`
2. **Always set** `NODE_ENV=production` in production
3. **Review environment variables** before deployment
4. **Use proper authentication** in staging environments

### Configuration Management
1. **Use `.env.example`** for template configuration
2. **Document environment variables** in deployment guides
3. **Validate configuration** during startup
4. **Monitor for misconfigurations**

## Troubleshooting

### Common Issues

#### Auto-login not working
- Check `NODE_ENV=development` is set
- Verify `AUTO_LOGIN_ADMIN=true` is set
- Restart the server after changes
- Check server logs for errors

#### Development banner not showing
- Verify environment variables are set correctly
- Check if CSS is loading properly
- Inspect browser console for errors
- Clear browser cache

#### Production mode issues
- Ensure `AUTO_LOGIN_ADMIN=false` or removed
- Set `NODE_ENV=production`
- Verify authentication system is working
- Check login redirect functionality

### Debugging Steps
1. **Check environment variables**: `echo $NODE_ENV`
2. **Verify configuration**: Review `.env` file
3. **Check server logs**: Look for startup messages
4. **Test authentication**: Try manual login/logout
5. **Inspect network requests**: Use browser dev tools

## Reverting Changes

### To completely remove auto-login functionality:

1. **Remove from environment**:
   ```bash
   # Remove from .env
   # AUTO_LOGIN_ADMIN=true
   ```

2. **Remove from code**:
   - Remove auto-login middleware from `app.js`
   - Remove development banner from `views/index.ejs`
   - Remove banner CSS from `public/styles.css`

3. **Clean up**:
   - Remove development-specific routes
   - Remove mock user creation
   - Remove development middleware

## Related Documentation

- [Local Development](../development/local-development.md) - Local development setup
- [Environment Validation](../operations/environment-validation.md) - Configuration validation
- [Security Features](../operations/security.md) - Security implementation
- [Authentication](../operations/authentication.md) - Authentication system

## Support

For issues with development mode:

1. Check environment variable configuration
2. Verify Node.js environment settings
3. Review server startup logs
4. Test with clean environment
5. Check authentication middleware

Development mode is designed to make development faster and more convenient while maintaining security through environment-based restrictions.
