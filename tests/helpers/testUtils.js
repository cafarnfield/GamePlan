/**
 * Test utilities and helper functions for GamePlan tests
 */

const bcrypt = require('bcrypt');

/**
 * Create mock Express request object
 * @param {Object} overrides - Properties to override
 * @returns {Object} Mock request object
 */
const createMockRequest = (overrides = {}) => {
  return {
    body: {},
    params: {},
    query: {},
    headers: {},
    user: null,
    session: {},
    isAuthenticated: jest.fn(() => false),
    logout: jest.fn((callback) => callback && callback()),
    ip: '127.0.0.1',
    connection: { remoteAddress: '127.0.0.1' },
    originalUrl: '/test',
    method: 'GET',
    ...overrides
  };
};

/**
 * Create mock Express response object
 * @param {Object} overrides - Properties to override
 * @returns {Object} Mock response object
 */
const createMockResponse = (overrides = {}) => {
  const res = {
    status: jest.fn(() => res),
    send: jest.fn(() => res),
    json: jest.fn(() => res),
    redirect: jest.fn(() => res),
    render: jest.fn(() => res),
    clearCookie: jest.fn(() => res),
    locals: {},
    ...overrides
  };
  return res;
};

/**
 * Create mock Express next function
 * @returns {Function} Mock next function
 */
const createMockNext = () => jest.fn();

/**
 * Create authenticated user mock request
 * @param {Object} user - User object
 * @param {Object} overrides - Additional request properties
 * @returns {Object} Mock authenticated request
 */
const createAuthenticatedRequest = (user = null, overrides = {}) => {
  const defaultUser = {
    _id: 'user123',
    name: 'Test User',
    email: 'test@example.com',
    isAdmin: false,
    isSuperAdmin: false,
    isBlocked: false,
    status: 'approved'
  };

  return createMockRequest({
    user: user || defaultUser,
    isAuthenticated: jest.fn(() => true),
    ...overrides
  });
};

/**
 * Create admin user mock request
 * @param {Object} overrides - Additional user properties
 * @returns {Object} Mock admin request
 */
const createAdminRequest = (overrides = {}) => {
  const adminUser = {
    _id: 'admin123',
    name: 'Admin User',
    email: 'admin@example.com',
    isAdmin: true,
    isSuperAdmin: false,
    isBlocked: false,
    status: 'approved',
    ...overrides
  };

  return createAuthenticatedRequest(adminUser);
};

/**
 * Create super admin user mock request
 * @param {Object} overrides - Additional user properties
 * @returns {Object} Mock super admin request
 */
const createSuperAdminRequest = (overrides = {}) => {
  const superAdminUser = {
    _id: 'superadmin123',
    name: 'Super Admin User',
    email: 'superadmin@example.com',
    isAdmin: true,
    isSuperAdmin: true,
    isBlocked: false,
    status: 'approved',
    ...overrides
  };

  return createAuthenticatedRequest(superAdminUser);
};

/**
 * Create blocked user mock request
 * @param {Object} overrides - Additional user properties
 * @returns {Object} Mock blocked user request
 */
const createBlockedUserRequest = (overrides = {}) => {
  const blockedUser = {
    _id: 'blocked123',
    name: 'Blocked User',
    email: 'blocked@example.com',
    isAdmin: false,
    isSuperAdmin: false,
    isBlocked: true,
    status: 'approved',
    ...overrides
  };

  return createAuthenticatedRequest(blockedUser);
};

/**
 * Create test user data for database operations
 * @param {Object} overrides - Properties to override
 * @returns {Object} Test user data
 */
const createTestUserData = async (overrides = {}) => {
  const defaultPassword = 'TestPassword123!';
  const hashedPassword = await bcrypt.hash(defaultPassword, 10);

  return {
    name: 'Test User',
    email: 'test@example.com',
    password: hashedPassword,
    gameNickname: 'TestGamer',
    status: 'approved',
    isAdmin: false,
    isSuperAdmin: false,
    isBlocked: false,
    registrationIP: '127.0.0.1',
    createdAt: new Date(),
    ...overrides,
    // Keep the plain password for testing
    plainPassword: defaultPassword
  };
};

/**
 * Create validation test cases for input validation
 * @returns {Object} Test cases for various validation scenarios
 */
const createValidationTestCases = () => {
  return {
    xss: {
      valid: ['Normal text', 'Text with numbers 123', 'Text-with-dashes'],
      invalid: [
        '<script>alert("xss")</script>',
        'javascript:alert("xss")',
        '<iframe src="evil.com"></iframe>',
        'onclick="alert(1)"',
        '<object data="evil.swf"></object>',
        'expression(alert(1))',
        'vbscript:msgbox(1)',
        'data:text/html,<script>alert(1)</script>'
      ]
    },
    passwords: {
      valid: [
        'TestPassword123!',
        'AnotherP@ssw0rd',
        'Complex!Pass123',
        'MySecure#Password1'
      ],
      invalid: [
        'weak',                    // Too short, no uppercase, no special
        'NOLOWERCASE123!',        // No lowercase
        'nouppercase123!',        // No uppercase
        'NoNumbers!',             // No numbers
        'NoSpecialChars123',      // No special characters
        'Short1!',                // Too short
        '',                       // Empty
        'OnlyLetters',            // Only letters
        '12345678'                // Only numbers
      ]
    },
    emails: {
      valid: [
        'test@example.com',
        'user.name@domain.co.uk',
        'user+tag@example.org',
        'user123@test-domain.com'
      ],
      invalid: [
        'invalid-email',
        '@example.com',
        'user@',
        'user..name@example.com',
        'user@.com',
        'user@domain.',
        ''
      ]
    },
    gameNicknames: {
      valid: [
        'TestGamer',
        'Player_123',
        'Pro-Gamer',
        'User 123',
        'SimpleNick'
      ],
      invalid: [
        'Nick@WithSpecial!',      // Special characters not allowed
        'A'.repeat(51),           // Too long
        'Nick<script>',           // XSS attempt
        'Nick"quotes"'            // Quotes not allowed
      ]
    }
  };
};

/**
 * Wait for a specified amount of time (for testing async operations)
 * @param {number} ms - Milliseconds to wait
 * @returns {Promise} Promise that resolves after the specified time
 */
const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Create mock environment variables for testing
 * @param {Object} overrides - Environment variables to set
 * @returns {Function} Cleanup function to restore original environment
 */
const mockEnvironment = (overrides = {}) => {
  const originalEnv = { ...process.env };
  
  Object.assign(process.env, overrides);
  
  // Return cleanup function
  return () => {
    process.env = originalEnv;
  };
};

/**
 * Create mock console methods to capture output
 * @returns {Object} Mock console methods and captured output
 */
const mockConsole = () => {
  const logs = [];
  const errors = [];
  const warns = [];
  
  const originalConsole = {
    log: console.log,
    error: console.error,
    warn: console.warn
  };
  
  console.log = jest.fn((...args) => logs.push(args));
  console.error = jest.fn((...args) => errors.push(args));
  console.warn = jest.fn((...args) => warns.push(args));
  
  return {
    logs,
    errors,
    warns,
    restore: () => {
      console.log = originalConsole.log;
      console.error = originalConsole.error;
      console.warn = originalConsole.warn;
    }
  };
};

module.exports = {
  createMockRequest,
  createMockResponse,
  createMockNext,
  createAuthenticatedRequest,
  createAdminRequest,
  createSuperAdminRequest,
  createBlockedUserRequest,
  createTestUserData,
  createValidationTestCases,
  wait,
  mockEnvironment,
  mockConsole
};
