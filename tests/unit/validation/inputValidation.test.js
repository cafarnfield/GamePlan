/**
 * Unit tests for input validation functionality
 * Tests validation functions used throughout the application
 */

const {
  checkXSS,
  validateStrongPassword,
  validateGameNickname,
  validateFutureDate,
  sanitizeHtml
} = require('../../../middleware/validation');

const { createValidationTestCases } = require('../../helpers/testUtils');

describe('Input Validation', () => {
  const testCases = createValidationTestCases();

  describe('XSS Protection', () => {
    describe('checkXSS function', () => {
      test('should allow safe text inputs', () => {
        testCases.xss.valid.forEach(input => {
          expect(() => checkXSS(input)).not.toThrow();
        });
      });

      test('should reject XSS attempts', () => {
        testCases.xss.invalid.forEach(input => {
          expect(() => checkXSS(input)).toThrow('Potentially dangerous content detected');
        });
      });

      test('should handle non-string inputs', () => {
        expect(() => checkXSS(123)).not.toThrow();
        expect(() => checkXSS(null)).not.toThrow();
        expect(() => checkXSS(undefined)).not.toThrow();
        expect(() => checkXSS({})).not.toThrow();
        expect(() => checkXSS([])).not.toThrow();
      });

      test('should detect script tags', () => {
        const scriptInputs = [
          '<script>alert("xss")</script>',
          '<SCRIPT>alert("xss")</SCRIPT>',
          '<script type="text/javascript">alert("xss")</script>',
          '<script src="evil.js"></script>'
        ];

        scriptInputs.forEach(input => {
          expect(() => checkXSS(input)).toThrow();
        });
      });

      test('should detect javascript: protocol', () => {
        const jsInputs = [
          'javascript:alert("xss")',
          'JAVASCRIPT:alert("xss")',
          'javascript:void(0)',
          'javascript:document.cookie'
        ];

        jsInputs.forEach(input => {
          expect(() => checkXSS(input)).toThrow();
        });
      });

      test('should detect event handlers', () => {
        const eventInputs = [
          'onclick="alert(1)"',
          'onload="malicious()"',
          'onmouseover="steal()"',
          'onerror="hack()"'
        ];

        eventInputs.forEach(input => {
          expect(() => checkXSS(input)).toThrow();
        });
      });

      test('should detect dangerous HTML tags', () => {
        const dangerousTags = [
          '<iframe src="evil.com"></iframe>',
          '<object data="evil.swf"></object>',
          '<embed src="evil.swf">',
          '<link rel="stylesheet" href="evil.css">',
          '<meta http-equiv="refresh" content="0;url=evil.com">'
        ];

        dangerousTags.forEach(input => {
          expect(() => checkXSS(input)).toThrow();
        });
      });

      test('should detect CSS expressions', () => {
        const cssInputs = [
          'expression(alert(1))',
          'EXPRESSION(alert(1))',
          'expression(document.cookie)'
        ];

        cssInputs.forEach(input => {
          expect(() => checkXSS(input)).toThrow();
        });
      });

      test('should detect vbscript protocol', () => {
        const vbInputs = [
          'vbscript:msgbox(1)',
          'VBSCRIPT:msgbox(1)'
        ];

        vbInputs.forEach(input => {
          expect(() => checkXSS(input)).toThrow();
        });
      });

      test('should detect data URLs with HTML', () => {
        const dataInputs = [
          'data:text/html,<script>alert(1)</script>',
          'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
        ];

        dataInputs.forEach(input => {
          expect(() => checkXSS(input)).toThrow();
        });
      });
    });

    describe('sanitizeHtml function', () => {
      test('should escape HTML characters', () => {
        const testCases = [
          { input: '<script>', expected: '&lt;script&gt;' },
          { input: '"quotes"', expected: '&quot;quotes&quot;' },
          { input: "'single'", expected: '&#x27;single&#x27;' },
          { input: 'path/to/file', expected: 'path&#x2F;to&#x2F;file' },
          { input: '<div>content</div>', expected: '&lt;div&gt;content&lt;&#x2F;div&gt;' }
        ];

        testCases.forEach(({ input, expected }) => {
          expect(sanitizeHtml(input)).toBe(expected);
        });
      });

      test('should handle non-string inputs', () => {
        expect(sanitizeHtml(123)).toBe(123);
        expect(sanitizeHtml(null)).toBe(null);
        expect(sanitizeHtml(undefined)).toBe(undefined);
        expect(sanitizeHtml({})).toEqual({});
      });

      test('should handle empty strings', () => {
        expect(sanitizeHtml('')).toBe('');
      });
    });
  });

  describe('Password Validation', () => {
    describe('validateStrongPassword function', () => {
      test('should accept valid strong passwords', () => {
        testCases.passwords.valid.forEach(password => {
          expect(() => validateStrongPassword(password)).not.toThrow();
        });
      });

      test('should reject weak passwords', () => {
        testCases.passwords.invalid.forEach(password => {
          expect(() => validateStrongPassword(password)).toThrow();
        });
      });

      test('should require minimum length', () => {
        const shortPasswords = ['A1!', 'Aa1!', 'Short1!'];
        
        shortPasswords.forEach(password => {
          expect(() => validateStrongPassword(password)).toThrow(/at least 8 characters/);
        });
      });

      test('should require lowercase letters', () => {
        const noLowercase = ['PASSWORD123!', 'ANOTHER123!'];
        
        noLowercase.forEach(password => {
          expect(() => validateStrongPassword(password)).toThrow(/lowercase letter/);
        });
      });

      test('should require uppercase letters', () => {
        const noUppercase = ['password123!', 'another123!'];
        
        noUppercase.forEach(password => {
          expect(() => validateStrongPassword(password)).toThrow(/uppercase letter/);
        });
      });

      test('should require numbers', () => {
        const noNumbers = ['Password!', 'AnotherPass!'];
        
        noNumbers.forEach(password => {
          expect(() => validateStrongPassword(password)).toThrow(/number/);
        });
      });

      test('should require special characters', () => {
        const noSpecial = ['Password123', 'AnotherPass123'];
        
        noSpecial.forEach(password => {
          expect(() => validateStrongPassword(password)).toThrow(/special character/);
        });
      });

      test('should handle non-string inputs', () => {
        expect(() => validateStrongPassword(123)).toThrow(/must be a string/);
        expect(() => validateStrongPassword(null)).toThrow(/must be a string/);
        expect(() => validateStrongPassword(undefined)).toThrow(/must be a string/);
        expect(() => validateStrongPassword({})).toThrow(/must be a string/);
      });

      test('should accept various special characters', () => {
        const specialChars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '-', '=', '[', ']', '{', '}', ';', "'", ':', '"', '\\', '|', ',', '.', '<', '>', '/', '?'];
        
        specialChars.forEach(char => {
          const password = `Password123${char}`;
          expect(() => validateStrongPassword(password)).not.toThrow();
        });
      });
    });
  });

  describe('Game Nickname Validation', () => {
    describe('validateGameNickname function', () => {
      test('should accept valid game nicknames', () => {
        testCases.gameNicknames.valid.forEach(nickname => {
          expect(() => validateGameNickname(nickname)).not.toThrow();
        });
      });

      test('should reject invalid game nicknames', () => {
        testCases.gameNicknames.invalid.forEach(nickname => {
          expect(() => validateGameNickname(nickname)).toThrow();
        });
      });

      test('should allow empty/null values (optional field)', () => {
        expect(() => validateGameNickname('')).not.toThrow();
        expect(() => validateGameNickname(null)).not.toThrow();
        expect(() => validateGameNickname(undefined)).not.toThrow();
      });

      test('should enforce maximum length', () => {
        const longNickname = 'A'.repeat(51);
        expect(() => validateGameNickname(longNickname)).toThrow(/cannot be longer than 50 characters/);
      });

      test('should allow alphanumeric characters', () => {
        const validNicknames = ['Player123', 'User456', 'Gamer789'];
        
        validNicknames.forEach(nickname => {
          expect(() => validateGameNickname(nickname)).not.toThrow();
        });
      });

      test('should allow spaces, hyphens, and underscores', () => {
        const validNicknames = ['Pro Gamer', 'Pro-Gamer', 'Pro_Gamer', 'Pro Gamer_123'];
        
        validNicknames.forEach(nickname => {
          expect(() => validateGameNickname(nickname)).not.toThrow();
        });
      });

      test('should reject special characters', () => {
        const invalidNicknames = ['Player@123', 'User#456', 'Gamer$789', 'Nick!'];
        
        invalidNicknames.forEach(nickname => {
          expect(() => validateGameNickname(nickname)).toThrow(/can only contain letters, numbers, spaces, hyphens, and underscores/);
        });
      });

      test('should handle non-string inputs', () => {
        expect(() => validateGameNickname(123)).toThrow(/must be a string/);
        expect(() => validateGameNickname({})).toThrow(/must be a string/);
        expect(() => validateGameNickname([])).toThrow(/must be a string/);
      });
    });
  });

  describe('Future Date Validation', () => {
    describe('validateFutureDate function', () => {
      test('should accept valid future dates', () => {
        const futureDate = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours from now
        expect(() => validateFutureDate(futureDate.toISOString())).not.toThrow();
      });

      test('should reject past dates', () => {
        const pastDate = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago
        expect(() => validateFutureDate(pastDate.toISOString())).toThrow(/must be at least/);
      });

      test('should reject dates too close to now', () => {
        const tooSoon = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now
        expect(() => validateFutureDate(tooSoon.toISOString())).toThrow(/must be at least/);
      });

      test('should reject dates too far in the future', () => {
        const tooFar = new Date();
        tooFar.setFullYear(tooFar.getFullYear() + 3); // 3 years from now
        expect(() => validateFutureDate(tooFar.toISOString())).toThrow(/cannot be more than 2 years/);
      });

      test('should handle invalid date formats', () => {
        const invalidDates = ['invalid-date', '2023-13-45', 'not-a-date', ''];
        
        invalidDates.forEach(date => {
          expect(() => validateFutureDate(date)).toThrow(/Invalid date format/);
        });
      });

      test('should accept dates within valid range', () => {
        const validDates = [
          new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
          new Date(Date.now() + 24 * 60 * 60 * 1000), // 1 day from now
          new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
          new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year from now
        ];

        validDates.forEach(date => {
          expect(() => validateFutureDate(date.toISOString())).not.toThrow();
        });
      });
    });
  });

  describe('Integration Tests', () => {
    test('should validate complete user registration data', () => {
      const validUserData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'SecurePassword123!',
        gameNickname: 'JohnGamer'
      };

      // Test that all validation functions pass for valid data
      expect(() => checkXSS(validUserData.name)).not.toThrow();
      expect(() => checkXSS(validUserData.email)).not.toThrow();
      expect(() => validateStrongPassword(validUserData.password)).not.toThrow();
      expect(() => validateGameNickname(validUserData.gameNickname)).not.toThrow();
    });

    test('should reject malicious user registration data', () => {
      const maliciousUserData = {
        name: '<script>alert("xss")</script>',
        email: 'user@evil.com<script>alert("xss")</script>',
        password: 'weak',
        gameNickname: 'Nick@Evil!'
      };

      // Test that validation functions catch malicious data
      expect(() => checkXSS(maliciousUserData.name)).toThrow();
      expect(() => checkXSS(maliciousUserData.email)).toThrow();
      expect(() => validateStrongPassword(maliciousUserData.password)).toThrow();
      expect(() => validateGameNickname(maliciousUserData.gameNickname)).toThrow();
    });

    test('should validate event creation data', () => {
      const futureDate = new Date(Date.now() + 2 * 60 * 60 * 1000);
      const validEventData = {
        title: 'Gaming Tournament',
        description: 'A fun gaming event for everyone',
        date: futureDate.toISOString()
      };

      expect(() => checkXSS(validEventData.title)).not.toThrow();
      expect(() => checkXSS(validEventData.description)).not.toThrow();
      expect(() => validateFutureDate(validEventData.date)).not.toThrow();
    });

    test('should sanitize and validate mixed content', () => {
      const mixedContent = 'Normal text with <script>alert("xss")</script> and "quotes"';
      
      // Should detect XSS
      expect(() => checkXSS(mixedContent)).toThrow();
      
      // Should sanitize properly
      const sanitized = sanitizeHtml(mixedContent);
      expect(sanitized).toContain('&lt;script&gt;');
      expect(sanitized).toContain('&quot;quotes&quot;');
      expect(sanitized).not.toContain('<script>');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle extremely long inputs', () => {
      const veryLongString = 'A'.repeat(10000);
      
      // Should not crash on very long inputs
      expect(() => checkXSS(veryLongString)).not.toThrow();
      expect(() => sanitizeHtml(veryLongString)).not.toThrow();
    });

    test('should handle unicode and special characters', () => {
      const unicodeInputs = [
        'Héllo Wörld',
        '你好世界',
        '🎮🎯🎲',
        'Café résumé naïve'
      ];

      unicodeInputs.forEach(input => {
        expect(() => checkXSS(input)).not.toThrow();
        expect(sanitizeHtml(input)).toBeDefined();
      });
    });

    test('should handle mixed case XSS attempts', () => {
      const mixedCaseXSS = [
        '<ScRiPt>alert("xss")</ScRiPt>',
        'JaVaScRiPt:alert("xss")',
        'OnClIcK="alert(1)"',
        'ExPrEsSiOn(alert(1))'
      ];

      mixedCaseXSS.forEach(input => {
        expect(() => checkXSS(input)).toThrow();
      });
    });

    test('should handle boundary date values', () => {
      const now = new Date();
      const exactly30Minutes = new Date(now.getTime() + 30 * 60 * 1000);
      const exactly31Minutes = new Date(now.getTime() + 31 * 60 * 1000);
      
      // Should reject exactly 30 minutes (boundary)
      expect(() => validateFutureDate(exactly30Minutes.toISOString())).toThrow();
      
      // Should accept 31 minutes (just over boundary)
      expect(() => validateFutureDate(exactly31Minutes.toISOString())).not.toThrow();
    });
  });
});
