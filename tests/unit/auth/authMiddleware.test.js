/**
 * Unit tests for authentication middleware
 * Tests middleware functions used for authentication and authorization
 */

const {
  ensureAuthenticated,
  ensureNotBlocked,
  ensureAdmin,
  ensureSuperAdmin
} = require('../../../middleware/auth');

const {
  createMockRequest,
  createMockResponse,
  createMockNext,
  createAuthenticatedRequest,
  createAdminRequest,
  createSuperAdminRequest,
  createBlockedUserRequest,
  mockEnvironment
} = require('../../helpers/testUtils');

describe('Authentication Middleware', () => {
  let req, res, next;

  beforeEach(() => {
    req = createMockRequest();
    res = createMockResponse();
    next = createMockNext();
  });

  describe('ensureAuthenticated', () => {
    test('should call next() for authenticated users', () => {
      req = createAuthenticatedRequest();
      
      ensureAuthenticated(req, res, next);
      
      expect(next).toHaveBeenCalledWith();
      expect(res.redirect).not.toHaveBeenCalled();
    });

    test('should redirect to login for unauthenticated users', () => {
      req.isAuthenticated = jest.fn(() => false);
      
      ensureAuthenticated(req, res, next);
      
      expect(res.redirect).toHaveBeenCalledWith('/login');
      expect(next).not.toHaveBeenCalled();
    });

    test('should redirect to login when isAuthenticated is undefined', () => {
      req.isAuthenticated = undefined;
      
      ensureAuthenticated(req, res, next);
      
      expect(res.redirect).toHaveBeenCalledWith('/login');
      expect(next).not.toHaveBeenCalled();
    });

    test('should allow access in development mode with auto-login', () => {
      const cleanup = mockEnvironment({
        AUTO_LOGIN_ADMIN: 'true',
        NODE_ENV: 'development'
      });

      req.isAuthenticated = jest.fn(() => false);
      
      ensureAuthenticated(req, res, next);
      
      expect(next).toHaveBeenCalledWith();
      expect(res.redirect).not.toHaveBeenCalled();
      
      cleanup();
    });

    test('should not allow auto-login in production', () => {
      const cleanup = mockEnvironment({
        AUTO_LOGIN_ADMIN: 'true',
        NODE_ENV: 'production'
      });

      req.isAuthenticated = jest.fn(() => false);
      
      ensureAuthenticated(req, res, next);
      
      expect(res.redirect).toHaveBeenCalledWith('/login');
      expect(next).not.toHaveBeenCalled();
      
      cleanup();
    });

    test('should handle missing isAuthenticated method gracefully', () => {
      delete req.isAuthenticated;
      
      ensureAuthenticated(req, res, next);
      
      expect(res.redirect).toHaveBeenCalledWith('/login');
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('ensureNotBlocked', () => {
    test('should call next() for non-blocked authenticated users', () => {
      req = createAuthenticatedRequest();
      
      ensureNotBlocked(req, res, next);
      
      expect(next).toHaveBeenCalledWith();
      expect(req.logout).not.toHaveBeenCalled();
    });

    test('should call next() for unauthenticated users', () => {
      req.isAuthenticated = jest.fn(() => false);
      
      ensureNotBlocked(req, res, next);
      
      expect(next).toHaveBeenCalledWith();
      expect(req.logout).not.toHaveBeenCalled();
    });

    test('should logout and send 403 for blocked users', () => {
      req = createBlockedUserRequest();
      
      ensureNotBlocked(req, res, next);
      
      expect(req.logout).toHaveBeenCalledWith(expect.any(Function));
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith('Your account has been blocked. Please contact support.');
      expect(next).not.toHaveBeenCalled();
    });

    test('should handle logout errors gracefully', () => {
      req = createBlockedUserRequest();
      const mockConsole = jest.spyOn(console, 'error').mockImplementation();
      
      // Mock logout to call callback with error
      req.logout = jest.fn((callback) => {
        callback(new Error('Logout error'));
      });
      
      ensureNotBlocked(req, res, next);
      
      expect(mockConsole).toHaveBeenCalledWith('Error during logout:', expect.any(Error));
      expect(res.status).toHaveBeenCalledWith(403);
      
      mockConsole.mockRestore();
    });

    test('should handle users without isBlocked property', () => {
      req = createAuthenticatedRequest();
      delete req.user.isBlocked;
      
      ensureNotBlocked(req, res, next);
      
      expect(next).toHaveBeenCalledWith();
      expect(req.logout).not.toHaveBeenCalled();
    });
  });

  describe('ensureAdmin', () => {
    test('should call next() for admin users', () => {
      req = createAdminRequest();
      
      ensureAdmin(req, res, next);
      
      expect(next).toHaveBeenCalledWith();
      expect(res.redirect).not.toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test('should redirect to login for unauthenticated users', () => {
      req.isAuthenticated = jest.fn(() => false);
      
      ensureAdmin(req, res, next);
      
      expect(res.redirect).toHaveBeenCalledWith('/login');
      expect(next).not.toHaveBeenCalled();
    });

    test('should send 403 for non-admin authenticated users', () => {
      req = createAuthenticatedRequest();
      req.user.isAdmin = false;
      
      ensureAdmin(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith('Access denied. Admin privileges required.');
      expect(next).not.toHaveBeenCalled();
    });

    test('should allow access in development mode with auto-login', () => {
      const cleanup = mockEnvironment({
        AUTO_LOGIN_ADMIN: 'true',
        NODE_ENV: 'development'
      });

      req.isAuthenticated = jest.fn(() => false);
      
      ensureAdmin(req, res, next);
      
      expect(next).toHaveBeenCalledWith();
      expect(res.redirect).not.toHaveBeenCalled();
      
      cleanup();
    });

    test('should handle missing user object', () => {
      req.isAuthenticated = jest.fn(() => true);
      req.user = null;
      
      ensureAdmin(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith('Access denied. Admin privileges required.');
    });

    test('should handle missing isAdmin property', () => {
      req = createAuthenticatedRequest();
      delete req.user.isAdmin;
      
      ensureAdmin(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith('Access denied. Admin privileges required.');
    });

    test('should handle undefined isAuthenticated method', () => {
      req.isAuthenticated = undefined;
      
      ensureAdmin(req, res, next);
      
      expect(res.redirect).toHaveBeenCalledWith('/login');
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('ensureSuperAdmin', () => {
    test('should call next() for super admin users', () => {
      req = createSuperAdminRequest();
      
      ensureSuperAdmin(req, res, next);
      
      expect(next).toHaveBeenCalledWith();
      expect(res.redirect).not.toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test('should redirect to login for unauthenticated users', () => {
      req.isAuthenticated = jest.fn(() => false);
      
      ensureSuperAdmin(req, res, next);
      
      expect(res.redirect).toHaveBeenCalledWith('/login');
      expect(next).not.toHaveBeenCalled();
    });

    test('should send 403 for regular admin users', () => {
      req = createAdminRequest();
      req.user.isSuperAdmin = false;
      
      ensureSuperAdmin(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith('Access denied. Super admin privileges required.');
      expect(next).not.toHaveBeenCalled();
    });

    test('should send 403 for regular authenticated users', () => {
      req = createAuthenticatedRequest();
      
      ensureSuperAdmin(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith('Access denied. Super admin privileges required.');
      expect(next).not.toHaveBeenCalled();
    });

    test('should allow access in development mode with auto-login', () => {
      const cleanup = mockEnvironment({
        AUTO_LOGIN_ADMIN: 'true',
        NODE_ENV: 'development'
      });

      req.isAuthenticated = jest.fn(() => false);
      
      ensureSuperAdmin(req, res, next);
      
      expect(next).toHaveBeenCalledWith();
      expect(res.redirect).not.toHaveBeenCalled();
      
      cleanup();
    });

    test('should handle missing user object', () => {
      req.isAuthenticated = jest.fn(() => true);
      req.user = null;
      
      ensureSuperAdmin(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith('Access denied. Super admin privileges required.');
    });

    test('should handle missing isSuperAdmin property', () => {
      req = createAuthenticatedRequest();
      delete req.user.isSuperAdmin;
      
      ensureSuperAdmin(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith('Access denied. Super admin privileges required.');
    });
  });

  describe('Integration Tests', () => {
    test('should work with middleware chain for authenticated admin', () => {
      req = createAdminRequest();
      
      // Simulate middleware chain
      ensureAuthenticated(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      
      ensureNotBlocked(req, res, next);
      expect(next).toHaveBeenCalledTimes(2);
      
      ensureAdmin(req, res, next);
      expect(next).toHaveBeenCalledTimes(3);
      
      expect(res.redirect).not.toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test('should work with middleware chain for authenticated super admin', () => {
      req = createSuperAdminRequest();
      
      // Simulate middleware chain
      ensureAuthenticated(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      
      ensureNotBlocked(req, res, next);
      expect(next).toHaveBeenCalledTimes(2);
      
      ensureSuperAdmin(req, res, next);
      expect(next).toHaveBeenCalledTimes(3);
      
      expect(res.redirect).not.toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test('should stop middleware chain for unauthenticated user', () => {
      req.isAuthenticated = jest.fn(() => false);
      
      ensureAuthenticated(req, res, next);
      expect(res.redirect).toHaveBeenCalledWith('/login');
      expect(next).not.toHaveBeenCalled();
      
      // Should not proceed to next middleware
      ensureAdmin(req, res, next);
      expect(next).toHaveBeenCalledTimes(0);
    });

    test('should stop middleware chain for blocked user', () => {
      req = createBlockedUserRequest();
      
      ensureAuthenticated(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      
      ensureNotBlocked(req, res, next);
      expect(req.logout).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).toHaveBeenCalledTimes(1); // Should not call next again
    });

    test('should stop middleware chain for non-admin user accessing admin route', () => {
      req = createAuthenticatedRequest();
      
      ensureAuthenticated(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      
      ensureNotBlocked(req, res, next);
      expect(next).toHaveBeenCalledTimes(2);
      
      ensureAdmin(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).toHaveBeenCalledTimes(2); // Should not call next again
    });
  });

  describe('Edge Cases', () => {
    test('should handle null user object gracefully', () => {
      req.isAuthenticated = jest.fn(() => true);
      req.user = null;
      
      ensureNotBlocked(req, res, next);
      expect(next).toHaveBeenCalledWith();
      
      ensureAdmin(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
    });

    test('should handle user object with missing properties', () => {
      req = createAuthenticatedRequest();
      req.user = { _id: 'test123' }; // Missing all boolean properties
      
      ensureNotBlocked(req, res, next);
      expect(next).toHaveBeenCalledWith();
      
      ensureAdmin(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
      
      ensureSuperAdmin(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
    });

    test('should handle environment variables edge cases', () => {
      // Test with AUTO_LOGIN_ADMIN set to 'false'
      const cleanup1 = mockEnvironment({
        AUTO_LOGIN_ADMIN: 'false',
        NODE_ENV: 'development'
      });

      req.isAuthenticated = jest.fn(() => false);
      ensureAuthenticated(req, res, next);
      expect(res.redirect).toHaveBeenCalledWith('/login');
      
      cleanup1();

      // Test with NODE_ENV not set to development
      const cleanup2 = mockEnvironment({
        AUTO_LOGIN_ADMIN: 'true',
        NODE_ENV: 'test'
      });

      req.isAuthenticated = jest.fn(() => false);
      ensureAuthenticated(req, res, next);
      expect(res.redirect).toHaveBeenCalledWith('/login');
      
      cleanup2();
    });

    test('should handle response object without expected methods', () => {
      res = { status: jest.fn(() => ({ send: jest.fn() })) }; // Mock response with basic methods
      req = createAuthenticatedRequest();
      req.user.isAdmin = false;
      
      // Should not throw error even with incomplete response object
      expect(() => ensureAdmin(req, res, next)).not.toThrow();
    });

    test('should handle request object without expected methods', () => {
      req = {}; // Empty request object
      
      // Should not throw error even with incomplete request object
      expect(() => ensureAuthenticated(req, res, next)).not.toThrow();
      expect(res.redirect).toHaveBeenCalledWith('/login');
    });
  });

  describe('Security Tests', () => {
    test('should not allow privilege escalation through user object manipulation', () => {
      req = createAuthenticatedRequest();
      
      // Attempt to escalate privileges - these should be treated as truthy and allow access
      req.user.isAdmin = 'true'; // String instead of boolean
      ensureAdmin(req, res, next);
      expect(next).toHaveBeenCalled();
      
      // Reset mocks
      next.mockClear();
      
      req.user.isAdmin = 1; // Number instead of boolean
      ensureAdmin(req, res, next);
      expect(next).toHaveBeenCalled();
      
      // Reset mocks
      next.mockClear();
      
      req.user.isAdmin = {}; // Object instead of boolean
      ensureAdmin(req, res, next);
      expect(next).toHaveBeenCalled();
      
      // Test falsy values that should be rejected
      req.user.isAdmin = 0;
      ensureAdmin(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
    });

    test('should not allow bypassing authentication through isAuthenticated manipulation', () => {
      req.isAuthenticated = 'true'; // String instead of function
      
      ensureAuthenticated(req, res, next);
      expect(res.redirect).toHaveBeenCalledWith('/login');
      
      req.isAuthenticated = 1; // Number instead of function
      ensureAuthenticated(req, res, next);
      expect(res.redirect).toHaveBeenCalledWith('/login');
      
      req.isAuthenticated = true; // Boolean instead of function
      ensureAuthenticated(req, res, next);
      expect(res.redirect).toHaveBeenCalledWith('/login');
    });

    test('should properly validate boolean properties', () => {
      req = createAuthenticatedRequest();
      
      // Test falsy values that should be treated as false
      const falsyValues = [false, 0, '', null, undefined, NaN];
      
      falsyValues.forEach(value => {
        req.user.isAdmin = value;
        ensureAdmin(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        
        req.user.isSuperAdmin = value;
        ensureSuperAdmin(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        
        req.user.isBlocked = value;
        ensureNotBlocked(req, res, next);
        expect(next).toHaveBeenCalled();
        
        // Reset mocks
        res.status.mockClear();
        next.mockClear();
      });
    });
  });
});
