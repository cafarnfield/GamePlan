# Environment Validation System

The GamePlan application includes a comprehensive environment validation system that ensures production safety, validates configuration, and prevents common security issues.

## Overview

The environment validation system performs checks at startup and during runtime to maintain application security and stability. It validates required environment variables, enforces production safety measures, and provides clear guidance for proper configuration.

## Features

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
RAWG_API_KEY=your_rawg_api_key
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key

# Note: Steam integration works automatically without requiring an API key
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

## Configuration Validation Details

### Required Variable Validation
The system checks for the presence and validity of:
- **NODE_ENV**: Must be set to 'development' or 'production'
- **MONGO_URI**: Must be a valid MongoDB connection string
- **SESSION_SECRET**: Must be present for session security
- **Database Credentials**: MongoDB passwords must be configured
- **Admin Credentials**: Admin user configuration must be complete

### Optional Variable Warnings
The system provides helpful warnings for missing optional configurations:
- **API Keys**: RAWG API key for enhanced game data
- **reCAPTCHA**: Site and secret keys for spam protection
- **Steam API**: API key for Steam integration (optional)

### Production-Specific Validation
Additional checks performed in production mode:
- **Security Headers**: Validates security-related configurations
- **HTTPS Settings**: Checks for proper HTTPS configuration
- **Cookie Security**: Validates secure cookie settings
- **Development Features**: Ensures development features are disabled

## Benefits

### Security Benefits
1. **Production Safety**: Prevents dangerous development settings in production
2. **Early Detection**: Catches configuration issues at startup, not runtime
3. **Security First**: Multiple layers of protection against common security issues
4. **Runtime Protection**: Continuous validation during application operation

### Operational Benefits
1. **Clear Guidance**: Helpful error messages and warnings guide proper configuration
2. **Comprehensive Coverage**: Validates all critical and optional settings
3. **Health Monitoring**: Provides endpoints for monitoring configuration status
4. **Automated Validation**: Reduces manual configuration errors

## Troubleshooting

### Common Validation Errors

#### Missing Required Variables
```
Error: Required environment variable NODE_ENV is not set
```
**Solution**: Set the NODE_ENV variable in your .env file

#### AUTO_LOGIN_ADMIN in Production
```
Error: AUTO_LOGIN_ADMIN cannot be enabled in production mode
```
**Solution**: Set AUTO_LOGIN_ADMIN=false or remove it from production .env

#### Invalid MongoDB URI
```
Error: MONGO_URI is not a valid MongoDB connection string
```
**Solution**: Check the format of your MongoDB connection string

### Debugging Validation Issues

#### Check Current Configuration
```bash
# View current environment variables (excluding sensitive data)
node -e "console.log(process.env)" | grep -v PASSWORD | grep -v SECRET
```

#### Test Validation
```bash
# Run validation test
node test-environment-validation.js
```

#### Check Health Endpoints
```bash
# Check application health
curl http://localhost:3000/api/health

# Check configuration health
curl http://localhost:3000/api/config-health
```

## Best Practices

### Development Environment
1. **Use .env.local**: Keep local development settings separate
2. **Enable AUTO_LOGIN_ADMIN**: Use for development convenience
3. **Set DEBUG logging**: Enable verbose logging for development
4. **Test validation**: Regularly test with different configurations

### Production Environment
1. **Disable AUTO_LOGIN_ADMIN**: Never enable in production
2. **Enable HTTPS**: Use FORCE_HTTPS=true for production
3. **Secure cookies**: Set SECURE_COOKIES=true with HTTPS
4. **Monitor health**: Regularly check health endpoints

### Configuration Management
1. **Use templates**: Start from .env.example files
2. **Document changes**: Keep track of configuration modifications
3. **Validate regularly**: Test configuration changes thoroughly
4. **Monitor continuously**: Use health endpoints for ongoing validation

## Maintenance

### Regular Tasks
- **Update .env.example**: Keep template files current with new variables
- **Review validation logic**: Ensure validation covers new features
- **Test scenarios**: Verify validation works for all use cases
- **Monitor health**: Check configuration health endpoints regularly

### Future Enhancements
- **Custom validation rules**: Add application-specific validation
- **Configuration templates**: Provide environment-specific templates
- **Automated testing**: Expand test coverage for validation scenarios
- **Integration monitoring**: Add external service validation

## Related Documentation

- [Development Mode](../development/development-mode.md) - Development mode configuration
- [Local Development](../development/local-development.md) - Local development setup
- [Docker Deployment](../deployment/docker-deployment.md) - Production deployment
- [Troubleshooting](../operations/troubleshooting.md) - Common issues and solutions

## Support

For environment validation issues:

1. Check the validation error messages for specific guidance
2. Review the .env.example file for proper variable format
3. Test with the validation test script
4. Check health endpoints for current status
5. Review related documentation for configuration details

The environment validation system ensures that GamePlan runs safely and securely in all environments while providing clear guidance for proper configuration.
