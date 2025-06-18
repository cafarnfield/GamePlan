/**
 * @swagger
 * components:
 *   schemas:
 *     SuccessResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: "Operation completed successfully"
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *     
 *     ErrorResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: false
 *         error:
 *           type: string
 *           example: "An error occurred"
 *         details:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               field:
 *                 type: string
 *               message:
 *                 type: string
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *     
 *     PaginationInfo:
 *       type: object
 *       properties:
 *         currentPage:
 *           type: integer
 *           minimum: 1
 *           example: 1
 *         totalPages:
 *           type: integer
 *           minimum: 0
 *           example: 5
 *         totalItems:
 *           type: integer
 *           minimum: 0
 *           example: 100
 *         itemsPerPage:
 *           type: integer
 *           minimum: 1
 *           example: 20
 *         hasNextPage:
 *           type: boolean
 *           example: true
 *         hasPreviousPage:
 *           type: boolean
 *           example: false
 *     
 *     PaginatedResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         data:
 *           type: array
 *           items: {}
 *         pagination:
 *           $ref: '#/components/schemas/PaginationInfo'
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *     
 *     BulkOperationRequest:
 *       type: object
 *       required:
 *         - ids
 *       properties:
 *         ids:
 *           type: array
 *           items:
 *             type: string
 *             pattern: '^[0-9a-fA-F]{24}$'
 *           minItems: 1
 *           example: ["507f1f77bcf86cd799439011", "507f1f77bcf86cd799439012"]
 *         notes:
 *           type: string
 *           maxLength: 500
 *           example: "Bulk operation performed by admin"
 *     
 *     BulkOperationResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: "Bulk operation completed: 5 successful, 1 errors"
 *         successCount:
 *           type: integer
 *           minimum: 0
 *           example: 5
 *         errorCount:
 *           type: integer
 *           minimum: 0
 *           example: 1
 *         totalRequested:
 *           type: integer
 *           minimum: 1
 *           example: 6
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: "2023-12-01T10:30:00.000Z"
 *     
 *     ObjectId:
 *       type: string
 *       pattern: '^[0-9a-fA-F]{24}$'
 *       example: "507f1f77bcf86cd799439011"
 *       description: "MongoDB ObjectId"
 *     
 *     Platform:
 *       type: string
 *       enum: ['PC', 'PlayStation', 'Xbox', 'Nintendo Switch']
 *       example: "PC"
 *     
 *     GameCategory:
 *       type: string
 *       enum: 
 *         - 'Action'
 *         - 'Adventure'
 *         - 'Strategy'
 *         - 'RPG'
 *         - 'FPS'
 *         - 'Racing'
 *         - 'Sports'
 *         - 'Simulation'
 *         - 'Puzzle'
 *         - 'Platformer'
 *         - 'Fighting'
 *         - 'Horror'
 *         - 'Survival'
 *         - 'MMO'
 *         - 'Indie'
 *         - 'Casual'
 *         - 'Other'
 *       example: "Action"
 *     
 *     UserStatus:
 *       type: string
 *       enum: ['pending', 'approved', 'rejected']
 *       example: "approved"
 *     
 *     GameStatus:
 *       type: string
 *       enum: ['pending', 'approved', 'rejected']
 *       example: "approved"
 *     
 *     GameSource:
 *       type: string
 *       enum: ['steam', 'rawg', 'manual', 'admin']
 *       example: "steam"
 *     
 *     AuditAction:
 *       type: string
 *       enum:
 *         - 'USER_APPROVED'
 *         - 'USER_REJECTED'
 *         - 'USER_BLOCKED'
 *         - 'USER_UNBLOCKED'
 *         - 'USER_DELETED'
 *         - 'ADMIN_PROMOTED'
 *         - 'ADMIN_DEMOTED'
 *         - 'SUPER_ADMIN_PROMOTED'
 *         - 'SUPER_ADMIN_DEMOTED'
 *         - 'PROBATION_ENDED'
 *         - 'GAME_APPROVED'
 *         - 'GAME_REJECTED'
 *         - 'GAME_DELETED'
 *         - 'GAME_ADDED_MANUAL'
 *         - 'EVENT_DELETED'
 *         - 'BULK_USER_APPROVED'
 *         - 'BULK_USER_REJECTED'
 *         - 'BULK_USER_DELETED'
 *         - 'BULK_EVENT_DELETED'
 *         - 'ERROR_LOGS_CLEARED_ALL'
 *         - 'BULK_ERROR_LOGS_INVESTIGATING'
 *         - 'BULK_ERROR_LOGS_RESOLVED'
 *         - 'BULK_ERROR_LOGS_DELETED'
 *       example: "USER_APPROVED"
 */
