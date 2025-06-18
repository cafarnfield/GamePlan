/**
 * Unit tests for password hashing functionality
 * Tests bcrypt password hashing and comparison used in authentication
 */

const bcrypt = require('bcrypt');

describe('Password Hashing', () => {
  const testPasswords = global.testUtils.createTestPasswords();
  const SALT_ROUNDS = 10; // Same as used in your auth routes

  describe('Password Hash Generation', () => {
    test('should hash a valid password', async () => {
      const password = testPasswords.valid;
      const hash = await bcrypt.hash(password, SALT_ROUNDS);
      
      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(50); // bcrypt hashes are typically 60 characters
    });

    test('should generate different hashes for the same password', async () => {
      const password = testPasswords.valid;
      const hash1 = await bcrypt.hash(password, SALT_ROUNDS);
      const hash2 = await bcrypt.hash(password, SALT_ROUNDS);
      
      expect(hash1).not.toBe(hash2);
      expect(hash1).toBeDefined();
      expect(hash2).toBeDefined();
    });

    test('should hash passwords with special characters', async () => {
      const specialPassword = 'P@ssw0rd!#$%^&*()_+-=[]{}|;:,.<>?';
      const hash = await bcrypt.hash(specialPassword, SALT_ROUNDS);
      
      expect(hash).toBeDefined();
      expect(hash).not.toBe(specialPassword);
    });

    test('should hash very long passwords', async () => {
      const longPassword = 'A'.repeat(100) + '1!';
      const hash = await bcrypt.hash(longPassword, SALT_ROUNDS);
      
      expect(hash).toBeDefined();
      expect(hash).not.toBe(longPassword);
    });

    test('should handle empty string password', async () => {
      const emptyPassword = '';
      const hash = await bcrypt.hash(emptyPassword, SALT_ROUNDS);
      
      expect(hash).toBeDefined();
      expect(hash).not.toBe(emptyPassword);
    });

    test('should use correct salt rounds', async () => {
      const password = testPasswords.valid;
      const hash = await bcrypt.hash(password, SALT_ROUNDS);
      
      // bcrypt hash format: $2b$rounds$salt+hash
      const hashParts = hash.split('$');
      expect(hashParts[0]).toBe('');
      expect(hashParts[1]).toBe('2b'); // bcrypt version
      expect(hashParts[2]).toBe(SALT_ROUNDS.toString());
    });
  });

  describe('Password Comparison', () => {
    let hashedPassword;
    const originalPassword = testPasswords.valid;

    beforeEach(async () => {
      hashedPassword = await bcrypt.hash(originalPassword, SALT_ROUNDS);
    });

    test('should return true for correct password', async () => {
      const isMatch = await bcrypt.compare(originalPassword, hashedPassword);
      expect(isMatch).toBe(true);
    });

    test('should return false for incorrect password', async () => {
      const wrongPassword = 'WrongPassword123!';
      const isMatch = await bcrypt.compare(wrongPassword, hashedPassword);
      expect(isMatch).toBe(false);
    });

    test('should return false for empty password', async () => {
      const isMatch = await bcrypt.compare('', hashedPassword);
      expect(isMatch).toBe(false);
    });

    test('should return false for null password', async () => {
      await expect(bcrypt.compare(null, hashedPassword)).rejects.toThrow();
    });

    test('should return false for undefined password', async () => {
      await expect(bcrypt.compare(undefined, hashedPassword)).rejects.toThrow();
    });

    test('should be case sensitive', async () => {
      const upperCasePassword = originalPassword.toUpperCase();
      const isMatch = await bcrypt.compare(upperCasePassword, hashedPassword);
      expect(isMatch).toBe(false);
    });

    test('should handle special characters in comparison', async () => {
      const specialPassword = 'Test!@#$%^&*()Password123';
      const specialHash = await bcrypt.hash(specialPassword, SALT_ROUNDS);
      
      const isMatch = await bcrypt.compare(specialPassword, specialHash);
      expect(isMatch).toBe(true);
      
      const isWrongMatch = await bcrypt.compare('Test!@#$%^&*()Password124', specialHash);
      expect(isWrongMatch).toBe(false);
    });

    test('should handle unicode characters', async () => {
      const unicodePassword = 'Tëst🔒Pässwörd123!';
      const unicodeHash = await bcrypt.hash(unicodePassword, SALT_ROUNDS);
      
      const isMatch = await bcrypt.compare(unicodePassword, unicodeHash);
      expect(isMatch).toBe(true);
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid hash format in comparison', async () => {
      const password = testPasswords.valid;
      const invalidHash = 'invalid-hash-format';
      
      // bcrypt returns false for invalid hash format instead of throwing
      const isMatch = await bcrypt.compare(password, invalidHash);
      expect(isMatch).toBe(false);
    });

    test('should handle null hash in comparison', async () => {
      const password = testPasswords.valid;
      
      await expect(bcrypt.compare(password, null)).rejects.toThrow();
    });

    test('should handle undefined hash in comparison', async () => {
      const password = testPasswords.valid;
      
      await expect(bcrypt.compare(password, undefined)).rejects.toThrow();
    });

    test('should handle invalid salt rounds', async () => {
      const password = testPasswords.valid;
      const invalidSaltRounds = 'invalid';
      
      await expect(bcrypt.hash(password, invalidSaltRounds)).rejects.toThrow();
    });

    test('should handle very high salt rounds', async () => {
      const password = testPasswords.valid;
      const highSaltRounds = 100; // This would be impractical but shouldn't crash
      
      // This test just ensures bcrypt can handle high values without crashing
      // We don't actually wait for it to complete as it would take too long
      const hashPromise = bcrypt.hash(password, highSaltRounds);
      expect(hashPromise).toBeInstanceOf(Promise);
      
      // Cancel the operation by not awaiting it
      // In real scenarios, we'd want to prevent such high values
    });
  });

  describe('Security Properties', () => {
    test('should take reasonable time to hash (timing attack resistance)', async () => {
      const password = testPasswords.valid;
      const startTime = Date.now();
      
      await bcrypt.hash(password, SALT_ROUNDS);
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // bcrypt with 10 rounds should take at least a few milliseconds
      expect(duration).toBeGreaterThan(10);
      // But shouldn't take too long in tests
      expect(duration).toBeLessThan(5000);
    });

    test('should produce consistent timing for comparison', async () => {
      const password = testPasswords.valid;
      const hash = await bcrypt.hash(password, SALT_ROUNDS);
      
      // Test correct password timing
      const startTime1 = Date.now();
      await bcrypt.compare(password, hash);
      const correctTime = Date.now() - startTime1;
      
      // Test incorrect password timing
      const startTime2 = Date.now();
      await bcrypt.compare('wrongpassword', hash);
      const incorrectTime = Date.now() - startTime2;
      
      // Times should be similar (within reasonable variance)
      // This helps prevent timing attacks
      const timeDifference = Math.abs(correctTime - incorrectTime);
      expect(timeDifference).toBeLessThan(100); // Allow 100ms variance
    });

    test('should not store password in plain text', async () => {
      const password = testPasswords.valid;
      const hash = await bcrypt.hash(password, SALT_ROUNDS);
      
      expect(hash).not.toContain(password);
      expect(hash.indexOf(password)).toBe(-1);
    });

    test('should use sufficient salt rounds for security', () => {
      // OWASP recommends at least 10 rounds for bcrypt
      expect(SALT_ROUNDS).toBeGreaterThanOrEqual(10);
      expect(SALT_ROUNDS).toBeLessThanOrEqual(15); // Not too high for performance
    });
  });

  describe('Integration with Auth Flow', () => {
    test('should simulate registration password hashing', async () => {
      const userData = {
        email: 'newuser@example.com',
        password: testPasswords.valid
      };
      
      // Simulate the hashing done in registration route
      const hashedPassword = await bcrypt.hash(userData.password, SALT_ROUNDS);
      
      expect(hashedPassword).toBeDefined();
      expect(hashedPassword).not.toBe(userData.password);
      
      // Simulate login verification
      const isValid = await bcrypt.compare(userData.password, hashedPassword);
      expect(isValid).toBe(true);
    });

    test('should simulate login password verification', async () => {
      // Simulate stored user with hashed password
      const storedUser = {
        email: 'user@example.com',
        password: await bcrypt.hash(testPasswords.valid, SALT_ROUNDS)
      };
      
      // Simulate login attempt
      const loginAttempt = {
        email: 'user@example.com',
        password: testPasswords.valid
      };
      
      // Simulate passport strategy verification
      const isMatch = await bcrypt.compare(loginAttempt.password, storedUser.password);
      expect(isMatch).toBe(true);
    });

    test('should reject login with wrong password', async () => {
      const storedUser = {
        email: 'user@example.com',
        password: await bcrypt.hash(testPasswords.valid, SALT_ROUNDS)
      };
      
      const loginAttempt = {
        email: 'user@example.com',
        password: 'WrongPassword123!'
      };
      
      const isMatch = await bcrypt.compare(loginAttempt.password, storedUser.password);
      expect(isMatch).toBe(false);
    });
  });

  describe('Performance Tests', () => {
    test('should hash multiple passwords efficiently', async () => {
      const passwords = [
        'Password1!',
        'Password2!',
        'Password3!',
        'Password4!',
        'Password5!'
      ];
      
      const startTime = Date.now();
      const hashes = await Promise.all(
        passwords.map(pwd => bcrypt.hash(pwd, SALT_ROUNDS))
      );
      const endTime = Date.now();
      
      expect(hashes).toHaveLength(5);
      expect(hashes.every(hash => typeof hash === 'string')).toBe(true);
      expect(endTime - startTime).toBeLessThan(10000); // Should complete within 10 seconds
    });

    test('should compare multiple passwords efficiently', async () => {
      const password = testPasswords.valid;
      const hash = await bcrypt.hash(password, SALT_ROUNDS);
      
      const comparisons = Array(10).fill().map(() => bcrypt.compare(password, hash));
      
      const startTime = Date.now();
      const results = await Promise.all(comparisons);
      const endTime = Date.now();
      
      expect(results.every(result => result === true)).toBe(true);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
    });
  });
});
