const express = require('express');
const router = express.Router();

// Import health service
const healthService = require('../services/healthService');

// Import error handling
const { asyncErrorHandler } = require('../middleware/errorHandler');

// Import winston logger
const { systemLogger } = require('../utils/logger');

// Enhanced health check endpoint
/**
 * @swagger
 * /api/health:
 *   get:
 *     tags: [System]
 *     summary: Comprehensive system health check
 *     description: |
 *       Returns detailed health status of all system components including:
 *       - System resources (memory, CPU)
 *       - Database connectivity and performance
 *       - Cache services status
 *       - External API dependencies
 *       - Configuration validation
 *     parameters:
 *       - in: query
 *         name: detailed
 *         schema:
 *           type: boolean
 *           default: false
 *         description: Include detailed system information
 *       - in: query
 *         name: quick
 *         schema:
 *           type: boolean
 *           default: false
 *         description: Return cached quick status (faster response)
 *       - in: query
 *         name: dependencies
 *         schema:
 *           type: boolean
 *           default: true
 *         description: Include external dependency checks
 *     responses:
 *       200:
 *         description: Health check completed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, degraded, unhealthy]
 *                   example: "healthy"
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: "2023-12-01T10:30:00.000Z"
 *                 uptime:
 *                   type: number
 *                   description: "Server uptime in seconds"
 *                   example: 86400
 *                 environment:
 *                   type: string
 *                   example: "development"
 *                 responseTime:
 *                   type: string
 *                   example: "45ms"
 *                 system:
 *                   type: object
 *                   description: "System resource metrics"
 *                 database:
 *                   type: object
 *                   description: "Database health and metrics"
 *                 cache:
 *                   type: object
 *                   description: "Cache services status"
 *                 dependencies:
 *                   type: object
 *                   description: "External API health status"
 *                 configuration:
 *                   type: object
 *                   description: "Configuration validation results"
 *                 warnings:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: "Non-critical issues"
 *                 errors:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: "Critical issues"
 *       503:
 *         description: System is unhealthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "unhealthy"
 *                 error:
 *                   type: string
 *                   example: "Database connection failed"
 */
router.get('/', asyncErrorHandler(async (req, res) => {
  try {
    const { detailed = false, quick = false, dependencies = true } = req.query;
    
    let healthData;
    
    if (quick === 'true') {
      // Return quick cached status for performance
      healthData = healthService.getQuickStatus();
    } else {
      // Perform comprehensive health check
      healthData = await healthService.getHealthStatus({
        detailed: detailed === 'true',
        includeDependencies: dependencies !== 'false'
      });
    }
    
    // Set appropriate HTTP status code based on health
    const statusCode = healthData.status === 'unhealthy' ? 503 : 
                      healthData.status === 'degraded' ? 200 : 200;
    
    res.status(statusCode).json(healthData);
  } catch (error) {
    systemLogger.error('Health endpoint error', {
      error: error.message,
      stack: error.stack,
      requestId: req.requestId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed',
      message: error.message
    });
  }
}));

// Detailed health endpoints for specific components

/**
 * @swagger
 * /api/health/database:
 *   get:
 *     tags: [System]
 *     summary: Database health check
 *     description: Returns detailed database connectivity and performance metrics
 *     responses:
 *       200:
 *         description: Database health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, degraded, unhealthy]
 *                 responseTime:
 *                   type: string
 *                   example: "12ms"
 *                 connection:
 *                   type: object
 *                   description: "Database connection details"
 *                 metrics:
 *                   type: object
 *                   description: "Database performance metrics"
 */
router.get('/database', asyncErrorHandler(async (req, res) => {
  try {
    const healthData = await healthService.getHealthStatus({ 
      detailed: false, 
      includeDependencies: false 
    });
    
    const statusCode = healthData.database.status === 'unhealthy' ? 503 : 200;
    res.status(statusCode).json({
      timestamp: new Date().toISOString(),
      ...healthData.database
    });
  } catch (error) {
    systemLogger.error('Database health endpoint error', {
      error: error.message,
      requestId: req.requestId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Database health check failed',
      message: error.message
    });
  }
}));

/**
 * @swagger
 * /api/health/system:
 *   get:
 *     tags: [System]
 *     summary: System resource health check
 *     description: Returns system memory, CPU, and resource usage metrics
 *     responses:
 *       200:
 *         description: System health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, degraded, unhealthy]
 *                 memory:
 *                   type: object
 *                   description: "Memory usage metrics"
 *                 cpu:
 *                   type: object
 *                   description: "CPU usage metrics"
 *                 uptime:
 *                   type: object
 *                   description: "System and process uptime"
 */
router.get('/system', asyncErrorHandler(async (req, res) => {
  try {
    const healthData = await healthService.getHealthStatus({ 
      detailed: false, 
      includeDependencies: false 
    });
    
    const statusCode = healthData.system.status === 'unhealthy' ? 503 : 200;
    res.status(statusCode).json({
      timestamp: new Date().toISOString(),
      ...healthData.system
    });
  } catch (error) {
    systemLogger.error('System health endpoint error', {
      error: error.message,
      requestId: req.requestId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'System health check failed',
      message: error.message
    });
  }
}));

/**
 * @swagger
 * /api/health/cache:
 *   get:
 *     tags: [System]
 *     summary: Cache services health check
 *     description: Returns cache performance metrics and hit rates
 *     responses:
 *       200:
 *         description: Cache health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, degraded, unhealthy]
 *                 services:
 *                   type: object
 *                   description: "Individual cache service metrics"
 *                 summary:
 *                   type: object
 *                   description: "Overall cache summary"
 */
router.get('/cache', asyncErrorHandler(async (req, res) => {
  try {
    const healthData = await healthService.getHealthStatus({ 
      detailed: false, 
      includeDependencies: false 
    });
    
    const statusCode = healthData.cache.status === 'unhealthy' ? 503 : 200;
    res.status(statusCode).json({
      timestamp: new Date().toISOString(),
      ...healthData.cache
    });
  } catch (error) {
    systemLogger.error('Cache health endpoint error', {
      error: error.message,
      requestId: req.requestId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Cache health check failed',
      message: error.message
    });
  }
}));

/**
 * @swagger
 * /api/health/dependencies:
 *   get:
 *     tags: [System]
 *     summary: External dependencies health check
 *     description: Returns health status of external APIs (Steam, RAWG)
 *     responses:
 *       200:
 *         description: Dependencies health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, degraded, unhealthy, disabled]
 *                 services:
 *                   type: object
 *                   description: "Individual dependency status"
 */
router.get('/dependencies', asyncErrorHandler(async (req, res) => {
  try {
    const healthData = await healthService.getHealthStatus({ 
      detailed: false, 
      includeDependencies: true 
    });
    
    const statusCode = healthData.dependencies.status === 'unhealthy' ? 503 : 200;
    res.status(statusCode).json({
      timestamp: new Date().toISOString(),
      ...healthData.dependencies
    });
  } catch (error) {
    systemLogger.error('Dependencies health endpoint error', {
      error: error.message,
      requestId: req.requestId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Dependencies health check failed',
      message: error.message
    });
  }
}));

/**
 * @swagger
 * /api/health/history:
 *   get:
 *     tags: [System]
 *     summary: Health check history
 *     description: Returns recent health check history for trend analysis
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *           minimum: 1
 *           maximum: 100
 *         description: Number of recent health checks to return
 *     responses:
 *       200:
 *         description: Health check history
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 history:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       timestamp:
 *                         type: string
 *                         format: date-time
 *                       status:
 *                         type: string
 *                       responseTime:
 *                         type: string
 */
router.get('/history', asyncErrorHandler(async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const history = healthService.getHealthHistory(limit);
    
    res.json({
      timestamp: new Date().toISOString(),
      limit,
      count: history.length,
      history
    });
  } catch (error) {
    systemLogger.error('Health history endpoint error', {
      error: error.message,
      requestId: req.requestId
    });
    
    res.status(500).json({
      error: 'Health history retrieval failed',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
}));

module.exports = router;
