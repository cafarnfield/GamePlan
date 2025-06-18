/**
 * Jest setup file for GamePlan application tests
 * This file runs before each test suite
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.MONGO_URI = 'mongodb://localhost:27017/gameplan-test';
process.env.SESSION_SECRET = 'test-session-secret';
process.env.AUTO_LOGIN_ADMIN = 'false';

// Increase timeout for database operations
jest.setTimeout(30000);

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  // Uncomment to suppress console.log in tests
  // log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Global test utilities
global.testUtils = {
  // Helper to create test user data
  createTestUser: (overrides = {}) => ({
    name: 'Test User',
    email: 'test@example.com',
    password: 'TestPassword123!',
    gameNickname: 'TestGamer',
    status: 'approved',
    isAdmin: false,
    isSuperAdmin: false,
    isBlocked: false,
    ...overrides
  }),

  // Helper to create test passwords
  createTestPasswords: () => ({
    valid: 'TestPassword123!',
    weak: 'weak',
    noUppercase: 'testpassword123!',
    noLowercase: 'TESTPASSWORD123!',
    noNumber: 'TestPassword!',
    noSpecial: 'TestPassword123',
    tooShort: 'Test1!',
    empty: '',
    null: null,
    undefined: undefined
  })
};
