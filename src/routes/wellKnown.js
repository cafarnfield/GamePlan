/**
 * Well-Known URI Routes for GamePlan Application
 * Handles RFC 8615 compliant well-known URI requests
 * 
 * This module provides handlers for standard well-known endpoints
 * that browsers and tools use for service discovery.
 */

const express = require('express');
const router = express.Router();

// Import logger for non-error logging
const { systemLogger } = require('../utils/logger');

/**
 * @swagger
 * /.well-known/appspecific/com.chrome.devtools.json:
 *   get:
 *     tags: [System]
 *     summary: Chrome DevTools discovery endpoint
 *     description: |
 *       Chrome DevTools automatically requests this endpoint to discover
 *       application-specific debugging capabilities. This prevents 404 errors
 *       in the error logs while providing a proper response.
 *     responses:
 *       200:
 *         description: DevTools discovery information
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 version:
 *                   type: string
 *                   example: "1.0"
 *                 name:
 *                   type: string
 *                   example: "GamePlan Application"
 *                 description:
 *                   type: string
 *                   example: "Gaming event management platform"
 *                 devtools:
 *                   type: object
 *                   properties:
 *                     enabled:
 *                       type: boolean
 *                       example: false
 *                     message:
 *                       type: string
 *                       example: "DevTools integration not currently implemented"
 *                     supportedFeatures:
 *                       type: array
 *                       items:
 *                         type: string
 *                     documentation:
 *                       type: string
 *                       example: "https://github.com/gameplan/docs"
 *                 application:
 *                   type: object
 *                   properties:
 *                     name:
 *                       type: string
 *                       example: "GamePlan"
 *                     version:
 *                       type: string
 *                       example: "1.0.0"
 *                     environment:
 *                       type: string
 *                       example: "development"
 *                 contact:
 *                   type: object
 *                   properties:
 *                     support:
 *                       type: string
 *                       example: "For debugging support, please contact the development team"
 */
router.get('/appspecific/com.chrome.devtools.json', (req, res) => {
  systemLogger.debug('Chrome DevTools discovery request', {
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    requestId: req.requestId
  });

  const devToolsResponse = {
    version: "1.0",
    name: "GamePlan Application",
    description: "Gaming event management platform",
    devtools: {
      enabled: false,
      message: "DevTools integration not currently implemented",
      supportedFeatures: [],
      documentation: "https://github.com/gameplan/docs"
    },
    application: {
      name: "GamePlan",
      version: process.env.npm_package_version || "1.0.0",
      environment: process.env.NODE_ENV || "development"
    },
    contact: {
      support: "For debugging support, please contact the development team"
    }
  };

  // Set appropriate headers
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
  
  res.json(devToolsResponse);
});

/**
 * @swagger
 * /.well-known/security.txt:
 *   get:
 *     tags: [System]
 *     summary: Security contact information
 *     description: |
 *       Provides security contact information following the security.txt standard.
 *       This helps security researchers report vulnerabilities responsibly.
 *     responses:
 *       200:
 *         description: Security contact information in security.txt format
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: |
 *                 Contact: mailto:security@gameplan.local
 *                 Expires: 2025-12-31T23:59:59.000Z
 *                 Preferred-Languages: en
 *                 Policy: https://gameplan.local/security-policy
 *                 Acknowledgments: https://gameplan.local/security-acknowledgments
 */
router.get('/security.txt', (req, res) => {
  systemLogger.debug('Security.txt request', {
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    requestId: req.requestId
  });

  const securityContact = process.env.SECURITY_CONTACT_EMAIL || 'security@gameplan.local';
  const expirationDate = new Date();
  expirationDate.setFullYear(expirationDate.getFullYear() + 1); // 1 year from now

  const securityTxt = `Contact: mailto:${securityContact}
Expires: ${expirationDate.toISOString()}
Preferred-Languages: en
Policy: https://gameplan.local/security-policy
Acknowledgments: https://gameplan.local/security-acknowledgments

# Security Policy
# Please report security vulnerabilities responsibly
# Include detailed information about the vulnerability
# Allow reasonable time for fixes before public disclosure`;

  // Set appropriate headers for security.txt
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours
  
  res.send(securityTxt);
});

/**
 * @swagger
 * /.well-known/robots.txt:
 *   get:
 *     tags: [System]
 *     summary: Web crawler instructions
 *     description: |
 *       Provides web crawler instructions. While not technically a well-known URI,
 *       it's commonly requested and fits well in this module.
 *     responses:
 *       200:
 *         description: Robots.txt content for web crawlers
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: |
 *                 User-agent: *
 *                 Disallow: /admin/
 *                 Disallow: /api/
 *                 Allow: /
 */
router.get('/robots.txt', (req, res) => {
  systemLogger.debug('Robots.txt request via well-known', {
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    requestId: req.requestId
  });

  const isProduction = process.env.NODE_ENV === 'production';
  
  const robotsTxt = isProduction ? 
    `User-agent: *
Disallow: /admin/
Disallow: /api/
Disallow: /login
Disallow: /register
Allow: /

Sitemap: https://gameplan.local/sitemap.xml` :
    `User-agent: *
Disallow: /

# Development environment - crawling disabled`;

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours
  
  res.send(robotsTxt);
});

/**
 * @swagger
 * /.well-known/change-password:
 *   get:
 *     tags: [System]
 *     summary: Password manager discovery endpoint
 *     description: |
 *       Helps password managers discover the change password endpoint.
 *       Part of the Well-Known URI for Changing Passwords specification.
 *     responses:
 *       302:
 *         description: Redirect to the actual change password page
 *         headers:
 *           Location:
 *             schema:
 *               type: string
 *               example: "/change-password"
 */
router.get('/change-password', (req, res) => {
  systemLogger.debug('Change password discovery request', {
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    requestId: req.requestId
  });

  // Redirect to the actual change password page
  res.redirect(302, '/change-password');
});

/**
 * @swagger
 * /.well-known/*:
 *   get:
 *     tags: [System]
 *     summary: Generic well-known URI handler
 *     description: |
 *       Handles requests to unknown well-known URIs without generating error logs.
 *       This prevents noise in error tracking while maintaining proper HTTP semantics.
 *     parameters:
 *       - in: path
 *         name: path
 *         required: true
 *         schema:
 *           type: string
 *         description: The requested well-known URI path
 *     responses:
 *       404:
 *         description: Well-known URI not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Well-known URI not found"
 *                 path:
 *                   type: string
 *                   example: "/unknown-endpoint"
 *                 message:
 *                   type: string
 *                   example: "The requested well-known URI is not implemented"
 *                 availableEndpoints:
 *                   type: array
 *                   items:
 *                     type: string
 *                   example: ["/.well-known/appspecific/com.chrome.devtools.json", "/.well-known/security.txt"]
 *                 documentation:
 *                   type: string
 *                   example: "https://tools.ietf.org/html/rfc8615"
 */
router.get('/*', (req, res) => {
  const requestedPath = req.path;
  
  systemLogger.debug('Unknown well-known URI requested', {
    path: requestedPath,
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    requestId: req.requestId,
    note: 'This is not an error - just an unknown discovery request'
  });

  // Return 404 without triggering error logging
  res.status(404).json({
    error: 'Well-known URI not found',
    path: requestedPath,
    message: 'The requested well-known URI is not implemented',
    availableEndpoints: [
      '/.well-known/appspecific/com.chrome.devtools.json',
      '/.well-known/security.txt',
      '/.well-known/robots.txt',
      '/.well-known/change-password'
    ],
    documentation: 'https://tools.ietf.org/html/rfc8615'
  });
});

module.exports = router;
