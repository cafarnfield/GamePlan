# Environment Validation System

## Overview

The GamePlan application now includes a comprehensive environment validation system that ensures production safety, validates configuration, and prevents common security issues. This system performs checks at startup and during runtime to maintain application security and stability.

## Features Implemented

### 1. Startup Environment Validation

**Location**: `middleware/envValidation.js`, `middleware/startupValidation.js`

The application performs comprehensive environment validation on startup:

- ✅ **Required Environment Variables**: Validates all critical variables are present
- ⚠️ **Optional Environment Variables**: Shows helpful warnings for missing optional configs
- 🔒 **AUTO_LOGIN_ADMIN Protection**: Prevents AUTO_LOGIN_ADMIN from being enabled in production
- 🛡️ **Production Safety Checks**: Additional validations for production environments
- 📊 **MongoDB URI Validation**: Ensures database connection string is properly formatted

### 2. Production Safety Protection

**Key Security Features**:

- **AUTO_LOGIN_ADMIN Blocking**: Automatically prevents the dangerous AUTO_LOGIN_ADMIN feature from being enabled in production mode
- **HTTPS Enforcement**: Checks for HTTPS configuration in production
- **Secure Cookies**: Validates secure cookie settings for production deployments
- **Environment Mode Validation**: Ensures proper NODE_ENV configuration

### 3. Runtime Middleware Protection

**Location**: `middleware/productionSafety.js`

- **Request-level validation**: Validates environment on each request
- **HTTPS redirection**: Automatically redirects HTTP to HTTPS in production
- **Secure cookie enforcement**: Ensures cookies are secure in production
- **Development configuration detection**: Warns about development settings in production

### 4. Configuration Health Monitoring

**Location**: `utils/configHealth.js`

- **Health check endpoint**: `/api/config-health` provides configuration status
- **Real-time monitoring**: Continuous validation of critical settings
- **Detailed reporting**: Comprehensive status of all configuration aspects

## Environment Variables

### Required Variables
```env
NODE_ENV=production
MONGO_URI=mongodb://localhost:27017/gameplan
SESSION_SECRET=your_secret_key
MONGO_ROOT_PASSWORD=rootpassword123
MONGO_PASSWORD=gameplanpassword123
ADMIN_EMAIL=admin@gameplan.local
ADMIN_PASSWORD=admin123
ADMIN_NAME=System Administrator
```

### Production Security Variables
```env
# Force HTTPS in production (set to 'true' for production deployments)
FORCE_HTTPS=false

# Enable secure cookies in production (set to 'true' for HTTPS deployments)
SECURE_COOKIES=false
```

### Optional Variables (with warnings if missing)
```env
STEAM_API_KEY=your_steam_api_key
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
```

### Development Safety Variable
```env
# ⚠️ SECURITY WARNING: Never set to 'true' in production!
AUTO_LOGIN_ADMIN=false
```

## Validation Flow

### 1. Application Startup
```
1. Load environment variables (.env file)
2. Run validateAndExitIfInvalid()
3. Check required variables
4. Validate AUTO_LOGIN_ADMIN safety
5. Perform production-specific checks
6. Exit with error code 1 if validation fails
```

### 2. Request Processing
```
1. validateProductionSafety middleware runs
2. Re-validates environment variables
3. Enforces HTTPS in production
4. Sets secure cookies if configured
5. Checks for development configurations
6. Continues to next middleware or returns error
```

## Security Protections

### AUTO_LOGIN_ADMIN Protection

The most critical security feature prevents the AUTO_LOGIN_ADMIN development feature from being accidentally enabled in production:

**Development Mode** (NODE_ENV=development):
- ✅ AUTO_LOGIN_ADMIN=true is allowed
- ⚠️ Shows warning that it should be disabled in production

**Production Mode** (NODE_ENV=production):
- ❌ AUTO_LOGIN_ADMIN=true causes immediate application exit
- ✅ AUTO_LOGIN_ADMIN=false or undefined is required

### Production Environment Checks

When NODE_ENV=production, additional validations are performed:

1. **HTTPS Configuration**: Warns if FORCE_HTTPS is not enabled
2. **Secure Cookies**: Warns if SECURE_COOKIES is not enabled
3. **MongoDB URI**: Validates connection string format
4. **Development Settings**: Detects and warns about development configurations

## Error Handling

### Startup Failures
- Application exits with code 1 if critical validation fails
- Clear error messages indicate what needs to be fixed
- Detailed logging shows exactly which variables are missing or invalid

### Runtime Failures
- HTTP 500 responses for environment validation failures
- HTTPS redirects for insecure requests in production
- Graceful degradation for optional features

## Testing

Run the comprehensive test suite:
```bash
node test-environment-validation.js
```

This test validates:
- ✅ Current environment configuration
- 🔒 AUTO_LOGIN_ADMIN protection in production vs development
- 🛡️ Production safety middleware behavior
- 📊 All validation scenarios

## Integration

The validation system is fully integrated into the main application:

**app.js Integration**:
```javascript
// Import validation middleware
const { validateAndExitIfInvalid, validateProductionSafety, configHealthMiddleware } = require('./middleware/envValidation');

// Perform startup validation
validateAndExitIfInvalid();

// Apply runtime middleware
app.use(validateProductionSafety);
app.use(configHealthMiddleware);
```

## Health Check Endpoints

### Application Health
```
GET /api/health
```
Returns basic application health status.

### Configuration Health
```
GET /api/config-health
```
Returns detailed configuration validation status.

## Benefits

1. **Production Safety**: Prevents dangerous development settings in production
2. **Early Detection**: Catches configuration issues at startup, not runtime
3. **Clear Guidance**: Helpful error messages and warnings guide proper configuration
4. **Comprehensive Coverage**: Validates all critical and optional settings
5. **Runtime Protection**: Continuous validation during application operation
6. **Security First**: Multiple layers of protection against common security issues

## Maintenance

- Environment variables are documented in `.env.example`
- Validation logic is centralized in `middleware/` directory
- Test coverage ensures all scenarios work correctly
- Health endpoints provide monitoring capabilities

This environment validation system ensures that the GamePlan application runs safely and securely in all environments while providing clear guidance for proper configuration.
