# GamePlan Testing Framework

This directory contains the comprehensive test suite for the GamePlan application using Jest testing framework.

## Test Structure

```
tests/
├── setup/
│   └── jest.setup.js          # Global test setup and configuration
├── helpers/
│   └── testUtils.js           # Shared test utilities and mock functions
├── unit/
│   ├── auth/
│   │   ├── passwordHashing.test.js    # Password hashing and bcrypt tests
│   │   └── authMiddleware.test.js     # Authentication middleware tests
│   └── validation/
│       └── inputValidation.test.js    # Input validation and XSS protection tests
├── integration/
│   ├── cache-system.test.js           # Comprehensive cache system testing
│   ├── cache-error-integration.test.js # Cache error logging integration
│   ├── email-system.test.js           # Email system diagnostic testing
│   └── steam-integration.test.js      # Steam API integration testing
├── system/
│   ├── environment-validation.test.js # Environment validation testing
│   ├── validation-system.test.js      # Schema validation system testing
│   └── deployment-system.test.sh      # Deployment system testing
└── features/
    ├── event-creation.test.js          # Comprehensive event creation testing
    └── update-alerts.test.js           # Update alert functionality testing
```

## Test Coverage

### Unit Tests (110 tests)
- **Password Hashing (28 tests)**: Tests bcrypt password hashing, comparison, security properties, and integration with auth flow
- **Authentication Middleware (38 tests)**: Tests authentication and authorization middleware functions
- **Input Validation (44 tests)**: Tests XSS protection, password validation, game nickname validation, and future date validation

### Integration Tests
- **Cache System**: Comprehensive testing of multi-layer caching implementation
- **Cache Error Integration**: Tests cache error logging and monitoring
- **Email System**: Diagnostic testing for email configuration and SMTP connectivity
- **Steam Integration**: Tests Steam API search, game details, and update checking

### System Tests
- **Environment Validation**: Tests environment variable validation and production safety
- **Validation System**: Tests all Joi validation schemas and error handling
- **Deployment System**: Tests deployment scripts and Docker configuration

### Feature Tests
- **Event Creation**: Comprehensive testing of event creation workflows (database, HTTP, validation)
- **Update Alerts**: Tests Steam update alert functionality

## Running Tests

### Run All Tests
```bash
npm test
```

### Run Tests by Category
```bash
# Run all unit tests
npm test tests/unit/

# Run all integration tests
npm test tests/integration/

# Run all system tests
npm test tests/system/

# Run all feature tests
npm test tests/features/
```

### Run Specific Test Suites
```bash
# Authentication tests
npm test tests/unit/auth/

# Validation tests
npm test tests/unit/validation/

# Cache system tests
npm test tests/integration/cache-system.test.js

# Event creation tests
npm test tests/features/event-creation.test.js

# Email system diagnostics
node tests/integration/email-system.test.js

# Environment validation
node tests/system/environment-validation.test.js

# Deployment system tests
bash tests/system/deployment-system.test.sh
```

### Run Tests with Coverage
```bash
npm run test:coverage
```

### Run Tests in Watch Mode
```bash
npm run test:watch
```

## Test Categories

### 1. Unit Tests
#### Password Hashing Tests
- **Hash Generation**: Tests password hashing with various inputs and edge cases
- **Password Comparison**: Tests password verification and security
- **Error Handling**: Tests handling of invalid inputs and edge cases
- **Security Properties**: Tests timing attack resistance and salt rounds
- **Integration**: Tests integration with authentication flow
- **Performance**: Tests efficiency with multiple operations

#### Authentication Middleware Tests
- **ensureAuthenticated**: Tests user authentication checking
- **ensureNotBlocked**: Tests blocked user handling
- **ensureAdmin**: Tests admin privilege checking
- **ensureSuperAdmin**: Tests super admin privilege checking
- **Integration**: Tests middleware chain behavior
- **Security**: Tests against privilege escalation attempts
- **Edge Cases**: Tests error handling and malformed inputs

#### Input Validation Tests
- **XSS Protection**: Tests against various XSS attack vectors
- **Password Validation**: Tests strong password requirements
- **Game Nickname Validation**: Tests nickname format validation
- **Future Date Validation**: Tests date range validation
- **HTML Sanitization**: Tests HTML escaping functionality
- **Integration**: Tests complete validation workflows

### 2. Integration Tests
#### Cache System Tests
- **Cache Operations**: Tests set, get, clear, and invalidation operations
- **Performance Testing**: Tests cache hit rates and response times
- **Multi-layer Caching**: Tests dashboard, API, and game list caches
- **Error Handling**: Tests cache error logging and recovery
- **Health Monitoring**: Tests cache health metrics and alerts

#### Email System Tests
- **SMTP Configuration**: Tests email server connectivity and authentication
- **Environment Validation**: Tests email-related environment variables
- **Network Connectivity**: Tests firewall and network configuration
- **Test Email Sending**: Sends actual test emails to verify functionality
- **Error Diagnostics**: Provides detailed troubleshooting information

#### Steam Integration Tests
- **Game Search**: Tests Steam API game search functionality
- **Game Details**: Tests retrieval of detailed game information
- **Update Checking**: Tests Steam update detection and alerts
- **Error Handling**: Tests API rate limiting and error responses

### 3. System Tests
#### Environment Validation Tests
- **Startup Validation**: Tests environment variable validation at startup
- **Production Safety**: Tests AUTO_LOGIN_ADMIN protection in production
- **Security Checks**: Tests HTTPS enforcement and secure cookie settings
- **Configuration Health**: Tests MongoDB URI validation and other settings

#### Validation System Tests
- **Schema Validation**: Tests all Joi validation schemas
- **User Registration**: Tests user input validation and sanitization
- **Event Creation**: Tests event form validation and error handling
- **Admin Operations**: Tests admin system operation validation
- **Error Reporting**: Tests comprehensive validation error messages

#### Deployment System Tests
- **Script Validation**: Tests deployment script syntax and functionality
- **Docker Configuration**: Tests Docker Compose file validity
- **Security Checks**: Tests .gitignore protection and configuration quality
- **System Requirements**: Tests Docker and Docker Compose availability

### 4. Feature Tests
#### Event Creation Tests
- **Database Operations**: Tests direct database event creation and validation
- **HTTP Form Submission**: Tests web form data processing and transformation
- **Error Handling**: Tests validation errors and edge cases
- **Steam Integration**: Tests Steam App ID handling and validation
- **Performance**: Tests bulk and concurrent event creation
- **Circular Reference Prevention**: Tests fix for circular HTTP request issues

#### Update Alert Tests
- **Event Creation**: Tests creating events with Steam App IDs
- **Update Detection**: Tests Steam API update checking
- **Alert Display**: Tests update alert rendering on event pages
- **Error Handling**: Tests handling of invalid Steam App IDs

## Test Utilities

The `testUtils.js` file provides shared utilities:

### Mock Functions
- `createMockRequest()`: Creates Express request mock
- `createMockResponse()`: Creates Express response mock
- `createMockNext()`: Creates Express next function mock

### Authentication Mocks
- `createAuthenticatedRequest()`: Creates authenticated user request
- `createAdminRequest()`: Creates admin user request
- `createSuperAdminRequest()`: Creates super admin user request
- `createBlockedUserRequest()`: Creates blocked user request

### Test Data
- `createTestPasswords()`: Provides valid/invalid password test cases
- `createValidationTestCases()`: Provides comprehensive validation test data

### Environment Mocking
- `mockEnvironment()`: Safely mocks environment variables

## Security Testing

The test suite includes comprehensive security testing:

### XSS Protection
- Script tag injection
- JavaScript protocol attacks
- Event handler injection
- CSS expression attacks
- Data URL attacks
- Mixed case bypass attempts

### Authentication Security
- Privilege escalation prevention
- Session manipulation protection
- Type confusion attacks
- Boolean validation bypass attempts

### Input Validation Security
- SQL injection patterns
- Command injection patterns
- Path traversal attempts
- Unicode and encoding attacks

## Best Practices

### Test Organization
- Tests are organized by functionality and component
- Each test file focuses on a specific module or feature
- Tests are grouped into logical describe blocks

### Test Naming
- Test names clearly describe what is being tested
- Use "should" statements for expected behavior
- Include edge cases and error conditions

### Mock Usage
- Mocks are reset between tests using `beforeEach`
- Environment variables are safely mocked and cleaned up
- External dependencies are properly mocked

### Assertions
- Use specific assertions that clearly indicate expected behavior
- Test both positive and negative cases
- Include boundary value testing

## Configuration

### Jest Configuration (package.json)
```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage"
  },
  "jest": {
    "testEnvironment": "node",
    "setupFilesAfterEnv": ["<rootDir>/tests/setup/jest.setup.js"],
    "testMatch": ["**/tests/**/*.test.js"],
    "collectCoverageFrom": [
      "middleware/**/*.js",
      "validators/**/*.js",
      "routes/**/*.js",
      "models/**/*.js",
      "services/**/*.js",
      "utils/**/*.js"
    ],
    "coverageReporters": ["text", "lcov", "html"],
    "coverageDirectory": "coverage"
  }
}
```

### Global Setup
The `jest.setup.js` file configures:
- Global test utilities
- Extended Jest matchers
- Test environment setup
- Mock configurations

## Continuous Integration

These tests are designed to run in CI/CD environments:
- No external dependencies required for unit tests
- Fast execution (typically under 10 seconds)
- Comprehensive coverage of critical functionality
- Clear failure reporting

## Adding New Tests

When adding new tests:

1. **Choose the appropriate directory** based on test type:
   - `unit/` - For testing individual functions, modules, or components in isolation
   - `integration/` - For testing interactions between multiple components or external services
   - `system/` - For testing system-level functionality, configuration, and deployment
   - `features/` - For testing complete user-facing features and workflows

2. **Follow naming conventions**: 
   - `*.test.js` for Jest test files
   - `*.test.sh` for shell script tests
   - Use descriptive names that indicate the component or feature being tested

3. **Use existing utilities** from `testUtils.js` when possible

4. **Include comprehensive test cases**: 
   - Happy path scenarios
   - Edge cases and boundary conditions
   - Error conditions and exception handling
   - Security considerations for user-facing functionality

5. **Add proper test documentation**:
   - Clear test descriptions
   - Setup and teardown procedures
   - Mock data and test fixtures
   - Expected outcomes and assertions

6. **Update this README** if adding new test categories or significant functionality

### Test File Templates

#### Unit Test Template
```javascript
const { functionToTest } = require('../../path/to/module');

describe('Module Name', () => {
  describe('functionToTest', () => {
    test('should handle normal case', () => {
      // Test implementation
    });
    
    test('should handle edge case', () => {
      // Test implementation
    });
    
    test('should throw error for invalid input', () => {
      // Test implementation
    });
  });
});
```

#### Integration Test Template
```javascript
const mongoose = require('mongoose');
require('dotenv').config();

describe('Integration Test Name', () => {
  beforeAll(async () => {
    // Setup database connection, test data
  });
  
  afterAll(async () => {
    // Cleanup test data, close connections
  });
  
  test('should test integration scenario', async () => {
    // Test implementation
  });
});
```

## Troubleshooting

### Common Issues

**Tests hanging or not exiting**
- Check for unclosed database connections
- Ensure all async operations are properly awaited
- Use `--detectOpenHandles` flag to identify leaks

**Mock-related errors**
- Ensure mocks are properly reset in `beforeEach`
- Check that environment variable mocks are cleaned up
- Verify mock function signatures match actual implementations

**Assertion failures**
- Check that test data matches expected formats
- Verify that async operations are properly awaited
- Ensure test isolation (tests don't depend on each other)

### Debug Mode
Run tests with additional debugging:
```bash
npm test -- --verbose --detectOpenHandles
```

## Performance

Current test performance:
- **Unit Tests**: 110 tests (~4-5 seconds)
- **Integration Tests**: Variable execution time depending on external services
- **System Tests**: Quick validation tests (~2-3 seconds)
- **Feature Tests**: Comprehensive scenarios (~5-10 seconds)
- **Total Coverage**: Comprehensive coverage of critical functionality and security

The test suite is optimized for:
- Fast feedback during development
- Reliable CI/CD execution
- Comprehensive security validation
- Easy maintenance and extension
- Modular execution by test category

## Test Organization Benefits

### Before Reorganization
- 13+ test files scattered in root directory
- Unclear test purposes and relationships
- Difficult to run specific test categories
- Redundant test implementations
- Poor maintainability

### After Reorganization
- ✅ **Logical categorization** by test type and purpose
- ✅ **Clear naming conventions** with `.test.js` extensions
- ✅ **Easy test discovery** and execution
- ✅ **Eliminated redundancy** while preserving functionality
- ✅ **Professional structure** following industry best practices
- ✅ **Improved maintainability** and extensibility
- ✅ **Better documentation** and test descriptions

## Troubleshooting

### Running Individual Test Categories

**Unit Tests Only:**
```bash
npm test tests/unit/
```

**Integration Tests (may require services):**
```bash
# Ensure MongoDB is running for database tests
npm test tests/integration/

# Run email tests (requires SMTP configuration)
node tests/integration/email-system.test.js your-email@example.com
```

**System Tests:**
```bash
# Environment validation
node tests/system/environment-validation.test.js

# Deployment system validation
bash tests/system/deployment-system.test.sh
```

**Feature Tests:**
```bash
# Event creation (requires database)
npm test tests/features/event-creation.test.js

# Update alerts (may require running server)
node tests/features/update-alerts.test.js
```
