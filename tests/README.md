# GamePlan Testing Framework

This directory contains the comprehensive test suite for the GamePlan application using Jest testing framework.

## Test Structure

```
tests/
├── setup/
│   └── jest.setup.js          # Global test setup and configuration
├── helpers/
│   └── testUtils.js           # Shared test utilities and mock functions
└── unit/
    ├── auth/
    │   ├── passwordHashing.test.js    # Password hashing and bcrypt tests
    │   └── authMiddleware.test.js     # Authentication middleware tests
    └── validation/
        └── inputValidation.test.js    # Input validation and XSS protection tests
```

## Test Coverage

### Authentication Tests (66 tests)
- **Password Hashing (28 tests)**: Tests bcrypt password hashing, comparison, security properties, and integration with auth flow
- **Authentication Middleware (38 tests)**: Tests authentication and authorization middleware functions

### Validation Tests (44 tests)
- **Input Validation**: Tests XSS protection, password validation, game nickname validation, and future date validation
- **Security**: Tests against various attack vectors and edge cases

## Running Tests

### Run All Tests
```bash
npm test
```

### Run Specific Test Suites
```bash
# Run all unit tests
npm test tests/unit/

# Run authentication tests only
npm test tests/unit/auth/

# Run validation tests only
npm test tests/unit/validation/

# Run specific test file
npm test tests/unit/auth/passwordHashing.test.js
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

### 1. Password Hashing Tests
- **Hash Generation**: Tests password hashing with various inputs and edge cases
- **Password Comparison**: Tests password verification and security
- **Error Handling**: Tests handling of invalid inputs and edge cases
- **Security Properties**: Tests timing attack resistance and salt rounds
- **Integration**: Tests integration with authentication flow
- **Performance**: Tests efficiency with multiple operations

### 2. Authentication Middleware Tests
- **ensureAuthenticated**: Tests user authentication checking
- **ensureNotBlocked**: Tests blocked user handling
- **ensureAdmin**: Tests admin privilege checking
- **ensureSuperAdmin**: Tests super admin privilege checking
- **Integration**: Tests middleware chain behavior
- **Security**: Tests against privilege escalation attempts
- **Edge Cases**: Tests error handling and malformed inputs

### 3. Input Validation Tests
- **XSS Protection**: Tests against various XSS attack vectors
- **Password Validation**: Tests strong password requirements
- **Game Nickname Validation**: Tests nickname format validation
- **Future Date Validation**: Tests date range validation
- **HTML Sanitization**: Tests HTML escaping functionality
- **Integration**: Tests complete validation workflows

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

1. **Choose the appropriate directory** based on functionality
2. **Follow naming conventions**: `*.test.js` for test files
3. **Use existing utilities** from `testUtils.js` when possible
4. **Include comprehensive test cases**: happy path, edge cases, and error conditions
5. **Add security tests** for any user-facing functionality
6. **Update this README** if adding new test categories

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
- **Total Tests**: 110
- **Execution Time**: ~4-5 seconds
- **Coverage**: Comprehensive coverage of critical security functions

The test suite is optimized for:
- Fast feedback during development
- Reliable CI/CD execution
- Comprehensive security validation
- Easy maintenance and extension
