const { body } = require('express-validator');
const { checkXSS, validateStrongPassword, validateGameNickname } = require('../middleware/validation');

/**
 * Validation rules for user registration
 */
const validateRegistration = [
  // Name validation
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z\s\-'\.]+$/)
    .withMessage('Name can only contain letters, spaces, hyphens, apostrophes, and periods')
    .custom(checkXSS)
    .withMessage('Name contains potentially dangerous content')
    .escape(), // HTML escape the name

  // Email validation
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail({
      gmail_remove_dots: false,
      gmail_remove_subaddress: false,
      outlookdotcom_remove_subaddress: false,
      yahoo_remove_subaddress: false,
      icloud_remove_subaddress: false
    })
    .isLength({ max: 254 })
    .withMessage('Email address is too long')
    .custom(checkXSS)
    .withMessage('Email contains potentially dangerous content'),

  // Password validation
  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .custom(validateStrongPassword)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),

  // Game nickname validation (optional)
  body('gameNickname')
    .optional({ checkFalsy: true })
    .trim()
    .custom(validateGameNickname)
    .escape(), // HTML escape the game nickname

  // reCAPTCHA validation (conditional - only required if RECAPTCHA_SECRET_KEY is configured)
  body('g-recaptcha-response')
    .custom((value, { req }) => {
      // If reCAPTCHA is not configured, skip validation
      if (!process.env.RECAPTCHA_SECRET_KEY) {
        return true;
      }
      // If reCAPTCHA is configured, require the response
      if (!value || value.trim() === '') {
        throw new Error('Please complete the CAPTCHA verification');
      }
      if (value.length > 2000) {
        throw new Error('Invalid CAPTCHA response');
      }
      return true;
    })
];

/**
 * Validation rules for user login
 */
const validateLogin = [
  // Email validation (less strict for login)
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail({
      gmail_remove_dots: false,
      gmail_remove_subaddress: false,
      outlookdotcom_remove_subaddress: false,
      yahoo_remove_subaddress: false,
      icloud_remove_subaddress: false
    })
    .isLength({ max: 254 })
    .withMessage('Email address is too long')
    .custom(checkXSS)
    .withMessage('Email contains potentially dangerous content'),

  // Password validation (basic for login)
  body('password')
    .isLength({ min: 1, max: 128 })
    .withMessage('Password is required')
    .custom(checkXSS)
    .withMessage('Password contains potentially dangerous content')
];

/**
 * Validation rules for profile updates
 */
const validateProfileUpdate = [
  // Game nickname validation
  body('gameNickname')
    .optional({ checkFalsy: true })
    .trim()
    .custom(validateGameNickname)
    .escape() // HTML escape the game nickname
];

/**
 * Validation rules for password reset request
 */
const validatePasswordResetRequest = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail({
      gmail_remove_dots: false,
      gmail_remove_subaddress: false,
      outlookdotcom_remove_subaddress: false,
      yahoo_remove_subaddress: false,
      icloud_remove_subaddress: false
    })
    .isLength({ max: 254 })
    .withMessage('Email address is too long')
    .custom(checkXSS)
    .withMessage('Email contains potentially dangerous content')
];

/**
 * Validation rules for password reset
 */
const validatePasswordReset = [
  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .custom(validateStrongPassword)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),

  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    }),

  body('token')
    .notEmpty()
    .withMessage('Reset token is required')
    .isLength({ min: 1, max: 500 })
    .withMessage('Invalid reset token')
    .custom(checkXSS)
    .withMessage('Reset token contains potentially dangerous content')
];

module.exports = {
  validateRegistration,
  validateLogin,
  validateProfileUpdate,
  validatePasswordResetRequest,
  validatePasswordReset
};
