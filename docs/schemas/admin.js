/**
 * @swagger
 * components:
 *   schemas:
 *     AuditLog:
 *       type: object
 *       properties:
 *         _id:
 *           $ref: '#/components/schemas/ObjectId'
 *         action:
 *           $ref: '#/components/schemas/AuditAction'
 *         performedBy:
 *           type: object
 *           properties:
 *             _id:
 *               $ref: '#/components/schemas/ObjectId'
 *             name:
 *               type: string
 *               example: "Admin User"
 *             email:
 *               type: string
 *               format: email
 *               example: "admin@gameplan.local"
 *         targetUser:
 *           type: object
 *           nullable: true
 *           properties:
 *             _id:
 *               $ref: '#/components/schemas/ObjectId'
 *             name:
 *               type: string
 *               example: "Target User"
 *             email:
 *               type: string
 *               format: email
 *               example: "user@example.com"
 *         targetGame:
 *           type: object
 *           nullable: true
 *           properties:
 *             _id:
 *               $ref: '#/components/schemas/ObjectId'
 *             name:
 *               type: string
 *               example: "Counter-Strike 2"
 *         targetEvent:
 *           type: object
 *           nullable: true
 *           properties:
 *             _id:
 *               $ref: '#/components/schemas/ObjectId'
 *             name:
 *               type: string
 *               example: "Friday Tournament"
 *         details:
 *           type: string
 *           example: "User approved after verification"
 *         ipAddress:
 *           type: string
 *           example: "192.168.1.100"
 *         userAgent:
 *           type: string
 *           example: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *     
 *     ErrorLog:
 *       type: object
 *       properties:
 *         _id:
 *           $ref: '#/components/schemas/ObjectId'
 *         message:
 *           type: string
 *           example: "Database connection failed"
 *         stack:
 *           type: string
 *           example: "Error: Database connection failed\n    at connect (/app/utils/database.js:25:15)"
 *         level:
 *           type: string
 *           enum: ['error', 'warn', 'info', 'debug']
 *           example: "error"
 *         context:
 *           type: object
 *           properties:
 *             userId:
 *               $ref: '#/components/schemas/ObjectId'
 *               nullable: true
 *             route:
 *               type: string
 *               example: "/api/events"
 *             method:
 *               type: string
 *               example: "POST"
 *             ip:
 *               type: string
 *               example: "192.168.1.100"
 *             userAgent:
 *               type: string
 *               example: "Mozilla/5.0..."
 *         status:
 *           type: string
 *           enum: ['new', 'investigating', 'resolved']
 *           default: 'new'
 *           example: "new"
 *         resolvedBy:
 *           $ref: '#/components/schemas/ObjectId'
 *           nullable: true
 *         resolvedAt:
 *           type: string
 *           format: date-time
 *           nullable: true
 *         notes:
 *           type: string
 *           example: "Fixed database connection issue"
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *     
 *     CacheStats:
 *       type: object
 *       properties:
 *         cacheType:
 *           type: string
 *           enum: ['steam', 'rawg', 'dashboard', 'api']
 *           example: "steam"
 *         totalKeys:
 *           type: number
 *           example: 150
 *         totalSize:
 *           type: string
 *           example: "2.5 MB"
 *         hitRate:
 *           type: number
 *           format: float
 *           minimum: 0
 *           maximum: 100
 *           example: 85.5
 *         lastAccessed:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:25:00.000Z"
 *         oldestEntry:
 *           type: string
 *           format: date-time
 *           example: "2023-11-30T08:00:00.000Z"
 *         newestEntry:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:25:00.000Z"
 *     
 *     SystemHealth:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           enum: ['healthy', 'warning', 'critical']
 *           example: "healthy"
 *         database:
 *           type: object
 *           properties:
 *             connected:
 *               type: boolean
 *               example: true
 *             responseTime:
 *               type: number
 *               description: "Response time in milliseconds"
 *               example: 25
 *             collections:
 *               type: number
 *               example: 7
 *         cache:
 *           type: object
 *           properties:
 *             totalCaches:
 *               type: number
 *               example: 4
 *             totalKeys:
 *               type: number
 *               example: 500
 *             averageHitRate:
 *               type: number
 *               format: float
 *               example: 82.3
 *         memory:
 *           type: object
 *           properties:
 *             used:
 *               type: string
 *               example: "128 MB"
 *             total:
 *               type: string
 *               example: "512 MB"
 *             percentage:
 *               type: number
 *               format: float
 *               example: 25.0
 *         uptime:
 *           type: string
 *           example: "2 days, 5 hours, 30 minutes"
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *     
 *     ConfigHealth:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           enum: ['healthy', 'warning', 'error']
 *           example: "healthy"
 *         environment:
 *           type: string
 *           example: "development"
 *         requiredVariables:
 *           type: object
 *           properties:
 *             present:
 *               type: array
 *               items:
 *                 type: string
 *               example: ["MONGODB_URI", "SESSION_SECRET", "RECAPTCHA_SECRET_KEY"]
 *             missing:
 *               type: array
 *               items:
 *                 type: string
 *               example: []
 *         optionalVariables:
 *           type: object
 *           properties:
 *             present:
 *               type: array
 *               items:
 *                 type: string
 *               example: ["STEAM_API_KEY", "RAWG_API_KEY"]
 *             missing:
 *               type: array
 *               items:
 *                 type: string
 *               example: ["SENTRY_DSN"]
 *         warnings:
 *           type: array
 *           items:
 *             type: string
 *           example: []
 *         errors:
 *           type: array
 *           items:
 *             type: string
 *           example: []
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *     
 *     ErrorLogUpdateRequest:
 *       type: object
 *       required:
 *         - status
 *       properties:
 *         status:
 *           type: string
 *           enum: ['investigating', 'resolved']
 *           example: "resolved"
 *         notes:
 *           type: string
 *           maxLength: 1000
 *           example: "Issue resolved by restarting database connection"
 *     
 *     BulkErrorLogRequest:
 *       allOf:
 *         - $ref: '#/components/schemas/BulkOperationRequest'
 *         - type: object
 *           required:
 *             - action
 *           properties:
 *             action:
 *               type: string
 *               enum: ['investigating', 'resolved', 'delete']
 *               example: "resolved"
 *             errorLogIds:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/ObjectId'
 *               minItems: 1
 *               example: ["507f1f77bcf86cd799439011", "507f1f77bcf86cd799439012"]
 *     
 *     CacheOperation:
 *       type: object
 *       required:
 *         - operation
 *       properties:
 *         operation:
 *           type: string
 *           enum: ['clear', 'warmup', 'stats']
 *           example: "clear"
 *         cacheType:
 *           type: string
 *           enum: ['steam', 'rawg', 'dashboard', 'api', 'all']
 *           example: "steam"
 *     
 *     AdminDashboardStats:
 *       type: object
 *       properties:
 *         users:
 *           type: object
 *           properties:
 *             total:
 *               type: number
 *               example: 150
 *             pending:
 *               type: number
 *               example: 5
 *             approved:
 *               type: number
 *               example: 140
 *             rejected:
 *               type: number
 *               example: 3
 *             blocked:
 *               type: number
 *               example: 2
 *             admins:
 *               type: number
 *               example: 3
 *             superAdmins:
 *               type: number
 *               example: 1
 *         events:
 *           type: object
 *           properties:
 *             total:
 *               type: number
 *               example: 75
 *             upcoming:
 *               type: number
 *               example: 25
 *             past:
 *               type: number
 *               example: 50
 *             thisMonth:
 *               type: number
 *               example: 12
 *         games:
 *           type: object
 *           properties:
 *             total:
 *               type: number
 *               example: 200
 *             pending:
 *               type: number
 *               example: 8
 *             approved:
 *               type: number
 *               example: 190
 *             rejected:
 *               type: number
 *               example: 2
 *         system:
 *           type: object
 *           properties:
 *             errorLogs:
 *               type: number
 *               example: 15
 *             cacheHitRate:
 *               type: number
 *               format: float
 *               example: 85.2
 *             uptime:
 *               type: string
 *               example: "2 days, 5 hours"
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 */
