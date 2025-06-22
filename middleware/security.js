const helmet = require('helmet');

// Helmet Security Configuration
const helmetConfig = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: [
        "'self'", 
        "'unsafe-inline'", // Required for EJS templates with inline styles
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com" // For any CDN stylesheets
      ],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'", // Allow inline scripts for development
        "'unsafe-eval'", // Allow eval for development
        "https://www.google.com", // reCAPTCHA
        "https://www.gstatic.com", // reCAPTCHA
        "https://cdnjs.cloudflare.com" // For any CDN scripts
      ],
      scriptSrcAttr: ["'unsafe-inline'"], // Allow inline event handlers
      imgSrc: [
        "'self'", 
        "data:", // For data URLs
        "https:", // Allow all HTTPS images (Steam, RAWG, etc.)
        "http:" // Allow HTTP images for development
      ],
      connectSrc: [
        "'self'",
        "https://api.steampowered.com", // Steam API
        "https://api.rawg.io", // RAWG API
        "https://www.google.com" // reCAPTCHA
      ],
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com"
      ],
      frameSrc: [
        "https://www.google.com" // reCAPTCHA
      ],
      objectSrc: ["'none'"], // Disable object/embed tags
      mediaSrc: ["'self'"],
      childSrc: ["'none'"], // Disable child contexts
      workerSrc: ["'self'"],
      manifestSrc: ["'self'"]
    },
    // Disable CSP in development to avoid blocking functionality
    reportOnly: process.env.NODE_ENV !== 'production'
  },
  // Conditional HSTS configuration
  hsts: process.env.NODE_ENV === 'production' ? {
    maxAge: 31536000, // 1 year in seconds
    includeSubDomains: true,
    preload: true
  } : false, // Disable HSTS in development
  noSniff: true, // X-Content-Type-Options: nosniff
  frameguard: { action: 'deny' }, // X-Frame-Options: DENY
  xssFilter: true, // X-XSS-Protection: 1; mode=block
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  permissionsPolicy: {
    camera: ['none'],
    microphone: ['none'],
    geolocation: ['none'],
    payment: ['none'],
    usb: ['none']
  },
  dnsPrefetchControl: { allow: false }, // X-DNS-Prefetch-Control: off
  ieNoOpen: true, // X-Download-Options: noopen
  hidePoweredBy: true // Remove X-Powered-By header
};

/**
 * Security middleware factory
 * @returns {Function} Express middleware for security headers
 */
const createSecurityMiddleware = () => {
  return helmet(helmetConfig);
};

module.exports = {
  helmetConfig,
  createSecurityMiddleware
};
